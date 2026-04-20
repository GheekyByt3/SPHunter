"""
SPHunter Authentication Module

Supports three authentication methods for Microsoft Graph API:
1. Direct access token (stolen/extracted token)
2. Device code flow (useful when MFA is enforced)
3. Client credentials (compromised Azure AD app registration)

Token refresh is handled automatically for MSAL-based flows.
Direct tokens cannot be refreshed — the user is warned on expiry.
"""

import time
import json
import base64
import requests
from msal import ConfidentialClientApplication, PublicClientApplication
from rich.console import Console

console = Console()

GRAPH_BASE_URL = "https://graph.microsoft.com/v1.0"
GRAPH_SCOPES = ["https://graph.microsoft.com/.default"]


def build_scope_priority(tenant: str = None):
    """
    Build scope priority list. Includes SharePoint-resource-specific scopes
    when tenant is known, since Graph API scopes often need admin consent
    but SharePoint-direct scopes may already be pre-authorized.
    """
    scopes = []

    # SharePoint-specific resource scopes (tenant-dependent)
    if tenant:
        # Extract tenant short name from domain
        sp_host = tenant.replace(".onmicrosoft.com", "").replace(".com", "")
        sp_resource = f"https://{sp_host}.sharepoint.com"
        scopes.extend([
            (f"{sp_resource}/.default", "sharepoint"),
            (f"{sp_resource}/AllSites.Read", "sharepoint"),
            (f"{sp_resource}/AllSites.FullControl", "sharepoint"),
        ])

    # Graph API scopes
    scopes.extend([
        ("https://graph.microsoft.com/.default", "graph"),
        ("Sites.Read.All Files.Read.All", "graph"),
        ("User.Read Sites.Read.All", "graph"),
        ("User.Read", "graph"),
    ])

    return [(s.split() if " " in s else [s], api_type) for s, api_type in scopes]

# Refresh the token when less than this many seconds remain
TOKEN_REFRESH_BUFFER = 300  # 5 minutes


class AuthHandler:
    """Handles authentication and automatic token refresh for Microsoft Graph API."""

    def __init__(self):
        self.access_token = None
        self.token_expiry = None
        self.auth_method = None
        self.api_type = "graph"  # "graph", "sharepoint", or "cookies"
        self.sp_base_url = None  # e.g., https://contoso.sharepoint.com
        self.cookies = None  # Cookie string for cookie-based auth
        self._msal_app = None
        self._msal_account = None
        self._scopes = None
        self._refresh_count = 0

    def auth_with_cookies(self, cookie_string: str, target_url: str) -> bool:
        """Authenticate using browser cookies exported from SharePoint session."""
        self.cookies = cookie_string.strip()
        self.auth_method = "cookies"
        self.api_type = "cookies"

        # Derive sp_base_url from target_url
        from urllib.parse import urlparse
        parsed = urlparse(target_url)
        self.sp_base_url = f"{parsed.scheme}://{parsed.netloc}"

        # Determine validation URL
        # If target is a specific site (has /sites/ or /teams/), validate against it
        # If target is just the root, validate against root /_api/web
        validate_url = f"{target_url}/_api/web?$select=Title"

        try:
            response = requests.get(
                validate_url,
                headers={
                    "Accept": "application/json;odata=nometadata",
                    "Cookie": self.cookies,
                },
                timeout=10,
            )
            if response.status_code == 200:
                data = response.json()
                title = data.get("Title", "Unknown")
                console.print(f"[cyan][*] Authenticated to: {title} ({target_url})[/cyan]")
                console.print("[green][+] Cookie authentication successful[/green]")
                return True
            elif response.status_code == 403 and target_url == self.sp_base_url:
                # Root site might deny access but subsites could work
                # Accept this — discovery will handle finding accessible sites
                console.print(f"[yellow][!] Root site returned 403 — will attempt site discovery[/yellow]")
                console.print("[green][+] Cookie authentication accepted (discovery mode)[/green]")
                return True
            else:
                console.print(f"[red][-] Cookie auth failed — status {response.status_code}[/red]")
                return False
        except requests.RequestException as e:
            console.print(f"[red][-] Cookie auth request failed: {e}[/red]")
            return False

    def get_cookie_headers(self) -> dict:
        """Return headers for cookie-based auth."""
        return {
            "Accept": "application/json;odata=nometadata",
            "Cookie": self.cookies,
        }

    def auth_with_token(self, token: str) -> bool:
        """Authenticate using a pre-obtained access token."""
        self.access_token = token.strip()
        self.auth_method = "direct_token"

        # Try to extract expiry from the JWT payload
        self.token_expiry = self._parse_jwt_expiry(self.access_token)

        if self._validate_token():
            console.print("[green][+] Access token validated successfully[/green]")
            if self.token_expiry:
                remaining = int(self.token_expiry - time.time())
                mins = remaining // 60
                console.print(f"[yellow][!] Token expires in ~{mins} minutes (no auto-refresh for direct tokens)[/yellow]")
            else:
                console.print("[yellow][!] Could not determine token expiry (no auto-refresh for direct tokens)[/yellow]")
            return True

        console.print("[red][-] Access token validation failed[/red]")
        return False

    def auth_with_device_code(self, tenant: str, client_id: str = None) -> bool:
        """
        Authenticate using device code flow.

        Tries multiple combinations of client IDs and scope sets until one
        fully succeeds (initiation + user auth + token acquisition).
        """
        # Well-known first-party Microsoft app client IDs
        fallback_client_ids = [
            ("Microsoft Azure CLI",             "04b07795-a71b-4346-935f-02f9a1efa4ce"),
            ("Microsoft Azure PowerShell",      "1950a258-227b-4e31-a9cf-717495945fc2"),
            ("Microsoft Office",                "d3590ed6-52b3-4102-aeff-aad2292ab01c"),
            ("Microsoft Graph PowerShell",      "14d82eec-204b-4c2f-b7e8-296a70dab67e"),
            ("SharePoint Online Client",        "9bc3ab49-b65d-410a-85ad-de819febfddc"),
            ("Microsoft Teams",                 "1fec8e78-bce4-4aaf-ab1b-5451cc387264"),
        ]

        if client_id:
            candidates = [("User-specified", client_id)]
        else:
            candidates = fallback_client_ids

        authority = f"https://login.microsoftonline.com/{tenant}"

        # Build scope priority list (includes SharePoint-specific scopes)
        scope_priority = build_scope_priority(tenant)

        # Try each client ID with each scope set — find a combo that initiates
        console.print("[cyan][*] Finding a working client ID and scope combination...[/cyan]")

        working_combos = []
        for app_name, cid in candidates:
            for scopes, api_type in scope_priority:
                scope_label = ", ".join(scopes)
                console.print(f"[dim]    Trying: {app_name} | {api_type} | {scope_label}[/dim]")

                app = PublicClientApplication(client_id=cid, authority=authority)

                try:
                    flow = app.initiate_device_flow(scopes=scopes)
                except Exception:
                    continue

                if "user_code" not in flow:
                    error = flow.get("error_description", "")
                    if error:
                        console.print(f"[dim]      Blocked: {error[:70]}[/dim]")
                    continue

                # This combo initiated successfully
                working_combos.append((app_name, cid, scopes, api_type, app, flow))
                console.print(f"[green][+] Found working combo: {app_name} | {api_type} | {scope_label}[/green]")
                break

            if working_combos:
                break

        if not working_combos:
            console.print("[red][-] No working client ID / scope combination found.[/red]")
            console.print("[yellow]    Try: python3 sphunter.py --device-code --client-id <your-app-id> --tenant ...[/yellow]")
            return False

        # Use the first (best) working combo
        app_name, cid, scopes, api_type, self._msal_app, flow = working_combos[0]
        self._scopes = scopes
        self.api_type = api_type

        # Determine SharePoint base URL
        sp_host = tenant.replace(".onmicrosoft.com", "").replace(".com", "")
        self.sp_base_url = f"https://{sp_host}.sharepoint.com"

        console.print(f"\n[yellow][*] Device Code Authentication[/yellow]")
        console.print(f"[bold]    1. Open: [cyan]{flow['verification_uri']}[/cyan][/bold]")
        console.print(f"[bold]    2. Enter code: [cyan]{flow['user_code']}[/cyan][/bold]")
        console.print(f"[dim]    App: {app_name} | API: {api_type} | Scopes: {', '.join(scopes)}[/dim]")
        console.print(f"[dim]    Waiting for authentication...[/dim]\n")

        result = self._msal_app.acquire_token_by_device_flow(flow)

        if "access_token" in result:
            self.access_token = result["access_token"]
            self.auth_method = "device_code"
            self.token_expiry = time.time() + result.get("expires_in", 3600)

            # Cache the account for silent refresh later
            accounts = self._msal_app.get_accounts()
            if accounts:
                self._msal_account = accounts[0]

            # Show what permissions we actually got
            granted_scopes = result.get("scope", "").split()
            if granted_scopes:
                console.print(f"[cyan][*] Granted scopes: {', '.join(granted_scopes)}[/cyan]")

            console.print(f"[cyan][*] API mode: {self.api_type}[/cyan]")
            console.print("[green][+] Device code authentication successful[/green]")
            console.print("[dim]    Token refresh: enabled (automatic)[/dim]")
            return True

        error = result.get("error_description", "Unknown error")
        console.print(f"[red][-] Authentication failed: {error}[/red]")
        console.print("[yellow]    The code was accepted but token acquisition failed.[/yellow]")
        console.print("[yellow]    This usually means the app doesn't have consent for the requested scopes.[/yellow]")
        return False

    def auth_with_client_credentials(self, tenant_id: str, client_id: str, client_secret: str) -> bool:
        """Authenticate using client credentials (app-only auth)."""
        authority = f"https://login.microsoftonline.com/{tenant_id}"

        self._msal_app = ConfidentialClientApplication(
            client_id=client_id,
            client_credential=client_secret,
            authority=authority,
        )
        self._scopes = GRAPH_SCOPES

        result = self._msal_app.acquire_token_for_client(scopes=self._scopes)

        if "access_token" in result:
            self.access_token = result["access_token"]
            self.auth_method = "client_credentials"
            self.token_expiry = time.time() + result.get("expires_in", 3600)
            console.print("[green][+] Client credentials authentication successful[/green]")
            console.print("[dim]    Token refresh: enabled (automatic)[/dim]")
            return True

        error = result.get("error_description", "Unknown error")
        console.print(f"[red][-] Client credentials authentication failed: {error}[/red]")
        return False

    def get_headers(self) -> dict:
        """Return authorization headers, refreshing the token if needed."""
        if self.auth_method == "cookies":
            return {
                "Cookie": self.cookies,
                "Accept": "application/json;odata=nometadata",
            }
        self._ensure_valid_token()
        return {
            "Authorization": f"Bearer {self.access_token}",
            "Content-Type": "application/json",
        }

    def _ensure_valid_token(self):
        """Check token expiry and refresh if within the buffer window."""
        if not self.token_expiry:
            return

        remaining = self.token_expiry - time.time()

        if remaining > TOKEN_REFRESH_BUFFER:
            return  # Token is still healthy

        # Direct tokens can't be refreshed
        if self.auth_method == "direct_token":
            if remaining > 0:
                mins = int(remaining / 60)
                console.print(f"[yellow][!] WARNING: Token expires in ~{mins} min and cannot be refreshed[/yellow]")
            else:
                console.print("[red][!] Token has expired. Re-run with a new token.[/red]")
            return

        # Attempt silent refresh via MSAL
        self._refresh_token()

    def _refresh_token(self):
        """Silently acquire a new access token using MSAL's cached refresh token."""
        if not self._msal_app:
            return

        result = None

        if self.auth_method == "device_code" and self._msal_account:
            # Delegated flow — use cached account + refresh token
            result = self._msal_app.acquire_token_silent(
                scopes=self._scopes,
                account=self._msal_account,
            )
        elif self.auth_method == "client_credentials":
            # App-only flow — just request a new token (MSAL caches internally)
            result = self._msal_app.acquire_token_for_client(scopes=self._scopes)

        if result and "access_token" in result:
            self.access_token = result["access_token"]
            self.token_expiry = time.time() + result.get("expires_in", 3600)
            self._refresh_count += 1
            console.print(f"[green][+] Token refreshed successfully (refresh #{self._refresh_count})[/green]")
        else:
            error = result.get("error_description", "Unknown error") if result else "No MSAL app"
            console.print(f"[red][-] Token refresh failed: {error}[/red]")
            console.print("[yellow][!] Continuing with current token — requests may start failing[/yellow]")

    @staticmethod
    def _parse_jwt_expiry(token: str) -> float:
        """Extract the 'exp' claim from a JWT access token without verifying it."""
        try:
            parts = token.split(".")
            if len(parts) != 3:
                return None
            # Decode the payload (part 2), add padding
            payload = parts[1]
            payload += "=" * (4 - len(payload) % 4)
            decoded = base64.urlsafe_b64decode(payload)
            claims = json.loads(decoded)
            return float(claims.get("exp", 0)) or None
        except (ValueError, KeyError, json.JSONDecodeError):
            return None

    def _validate_token(self) -> bool:
        """Validate the token by making a simple Graph API call."""
        try:
            response = requests.get(
                f"{GRAPH_BASE_URL}/me",
                headers={
                    "Authorization": f"Bearer {self.access_token}",
                    "Content-Type": "application/json",
                },
                timeout=10,
            )
            if response.status_code == 200:
                user_info = response.json()
                display = user_info.get("displayName", user_info.get("userPrincipalName", "Unknown"))
                console.print(f"[cyan][*] Authenticated as: {display}[/cyan]")
                return True

            # Try organization endpoint for app-only tokens
            response = requests.get(
                f"{GRAPH_BASE_URL}/organization",
                headers={
                    "Authorization": f"Bearer {self.access_token}",
                    "Content-Type": "application/json",
                },
                timeout=10,
            )
            if response.status_code == 200:
                orgs = response.json().get("value", [])
                if orgs:
                    org_name = orgs[0].get("displayName", "Unknown")
                    console.print(f"[cyan][*] Authenticated to tenant: {org_name}[/cyan]")
                return True

            return False

        except requests.RequestException as e:
            console.print(f"[red][-] Token validation request failed: {e}[/red]")
            return False

    def get_user_context(self) -> dict:
        """Get information about the current authentication context."""
        info = {"auth_method": self.auth_method}

        # Cookie auth can't call Graph API — return what we know
        if self.auth_method == "cookies":
            info["user"] = "cookie-based session"
            info["display_name"] = "cookie-based session"
            return info

        try:
            response = requests.get(
                f"{GRAPH_BASE_URL}/me",
                headers=self.get_headers(),
                timeout=10,
            )
            if response.status_code == 200:
                data = response.json()
                info["user"] = data.get("userPrincipalName", "Unknown")
                info["display_name"] = data.get("displayName", "Unknown")
            else:
                info["user"] = "unknown (Graph API unavailable)"
        except requests.RequestException:
            info["user"] = "app-only (no user context)"

        return info
