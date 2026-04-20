"""
SPHunter Enumeration Module

Discovers SharePoint sites, subsites, document libraries, and drives
using the Microsoft Graph API.
"""

import time
import requests
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn

console = Console()

GRAPH_BASE_URL = "https://graph.microsoft.com/v1.0"


class SharePointEnumerator:
    """Enumerates SharePoint Online sites, drives, and document libraries."""

    def __init__(self, auth_handler):
        self.auth = auth_handler
        self.sites = []
        self.drives = []
        self.request_delay = 0.2  # Throttle to avoid rate limiting

    def enumerate_all(self, target_sites: list = None) -> dict:
        """
        Run full enumeration: sites → subsites → drives/libraries.

        Args:
            target_sites: Optional list of site name filters. If None, enumerates all.

        Returns:
            dict with 'sites' and 'drives' lists.
        """
        console.print("\n[yellow][*] Starting SharePoint enumeration...[/yellow]\n")

        # Phase 1: Discover sites
        self._enumerate_sites()

        # Filter to target sites if specified
        if target_sites:
            target_lower = [t.lower() for t in target_sites]
            self.sites = [
                s for s in self.sites
                if any(t in s["displayName"].lower() for t in target_lower)
            ]
            console.print(f"[cyan][*] Filtered to {len(self.sites)} sites matching targets[/cyan]")

        # Phase 2: Discover subsites for each site
        self._enumerate_subsites()

        # Phase 3: Discover drives/libraries for each site
        self._enumerate_drives()

        console.print(f"\n[green][+] Enumeration complete: {len(self.sites)} sites, {len(self.drives)} document libraries[/green]\n")

        return {
            "sites": self.sites,
            "drives": self.drives,
        }

    def _enumerate_sites(self):
        """Discover all accessible SharePoint sites."""
        console.print("[cyan][*] Enumerating SharePoint sites...[/cyan]")

        # Method 1: Search for all sites
        url = f"{GRAPH_BASE_URL}/sites?search=*&$top=999"
        sites = self._paginated_get(url, "sites (search)")

        # Method 2: Also try listing from root site
        root_url = f"{GRAPH_BASE_URL}/sites?$top=999"
        root_sites = self._paginated_get(root_url, "sites (root)")

        # Merge and deduplicate by site ID
        seen_ids = set()
        for site in sites + root_sites:
            site_id = site.get("id")
            if site_id and site_id not in seen_ids:
                seen_ids.add(site_id)
                self.sites.append({
                    "id": site_id,
                    "displayName": site.get("displayName", "Unknown"),
                    "webUrl": site.get("webUrl", ""),
                    "description": site.get("description", ""),
                    "createdDateTime": site.get("createdDateTime", ""),
                    "lastModifiedDateTime": site.get("lastModifiedDateTime", ""),
                })

        console.print(f"[green]    [+] Found {len(self.sites)} sites[/green]")

        for site in self.sites:
            console.print(f"[dim]        - {site['displayName']} ({site['webUrl']})[/dim]")

    def _enumerate_subsites(self):
        """Discover subsites for each discovered site."""
        console.print("[cyan][*] Enumerating subsites...[/cyan]")

        new_subsites = []
        for site in self.sites:
            url = f"{GRAPH_BASE_URL}/sites/{site['id']}/sites?$top=999"
            subsites = self._paginated_get(url, f"subsites of {site['displayName']}")

            for sub in subsites:
                sub_id = sub.get("id")
                if sub_id and not any(s["id"] == sub_id for s in self.sites):
                    new_subsites.append({
                        "id": sub_id,
                        "displayName": sub.get("displayName", "Unknown"),
                        "webUrl": sub.get("webUrl", ""),
                        "description": sub.get("description", ""),
                        "parentSite": site["displayName"],
                        "createdDateTime": sub.get("createdDateTime", ""),
                        "lastModifiedDateTime": sub.get("lastModifiedDateTime", ""),
                    })

            time.sleep(self.request_delay)

        self.sites.extend(new_subsites)
        if new_subsites:
            console.print(f"[green]    [+] Found {len(new_subsites)} additional subsites[/green]")

    def _enumerate_drives(self):
        """Discover all drives (document libraries) for each site."""
        console.print("[cyan][*] Enumerating document libraries...[/cyan]")

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
        ) as progress:
            task = progress.add_task("Enumerating drives...", total=len(self.sites))

            for site in self.sites:
                progress.update(task, description=f"Scanning: {site['displayName']}")

                url = f"{GRAPH_BASE_URL}/sites/{site['id']}/drives"
                try:
                    response = requests.get(
                        url,
                        headers=self.auth.get_headers(),
                        timeout=15,
                    )

                    if response.status_code == 200:
                        drives_data = response.json().get("value", [])
                        for drive in drives_data:
                            self.drives.append({
                                "id": drive.get("id"),
                                "name": drive.get("name", "Unknown"),
                                "driveType": drive.get("driveType", ""),
                                "webUrl": drive.get("webUrl", ""),
                                "siteId": site["id"],
                                "siteName": site["displayName"],
                                "quota_total": drive.get("quota", {}).get("total", 0),
                                "quota_used": drive.get("quota", {}).get("used", 0),
                                "itemCount": drive.get("quota", {}).get("fileCount", 0),
                            })
                    elif response.status_code == 403:
                        console.print(f"[dim]    [!] Access denied to drives in: {site['displayName']}[/dim]")
                    elif response.status_code == 429:
                        retry_after = int(response.headers.get("Retry-After", 30))
                        console.print(f"[yellow]    [!] Rate limited. Waiting {retry_after}s...[/yellow]")
                        time.sleep(retry_after)

                except requests.RequestException as e:
                    console.print(f"[red]    [-] Error enumerating drives for {site['displayName']}: {e}[/red]")

                progress.advance(task)
                time.sleep(self.request_delay)

        console.print(f"[green]    [+] Found {len(self.drives)} document libraries[/green]")

    def _paginated_get(self, url: str, label: str) -> list:
        """Handle paginated Graph API responses."""
        all_items = []

        while url:
            try:
                response = requests.get(
                    url,
                    headers=self.auth.get_headers(),
                    timeout=15,
                )

                if response.status_code == 200:
                    data = response.json()
                    items = data.get("value", [])
                    all_items.extend(items)

                    # Check for next page
                    url = data.get("@odata.nextLink")
                    if url:
                        time.sleep(self.request_delay)
                elif response.status_code == 429:
                    retry_after = int(response.headers.get("Retry-After", 30))
                    console.print(f"[yellow][!] Rate limited on {label}. Waiting {retry_after}s...[/yellow]")
                    time.sleep(retry_after)
                    continue
                else:
                    break

            except requests.RequestException as e:
                console.print(f"[red][-] Request failed for {label}: {e}[/red]")
                break

        return all_items

    def enumerate_onedrive_users(self) -> list:
        """Enumerate OneDrive drives for all users (requires admin/app permissions)."""
        console.print("[cyan][*] Enumerating user OneDrive accounts...[/cyan]")

        url = f"{GRAPH_BASE_URL}/users?$select=id,displayName,userPrincipalName&$top=999"
        users = self._paginated_get(url, "users")

        onedrive_drives = []
        for user in users:
            user_id = user.get("id")
            upn = user.get("userPrincipalName", "Unknown")

            try:
                drive_url = f"{GRAPH_BASE_URL}/users/{user_id}/drive"
                response = requests.get(
                    drive_url,
                    headers=self.auth.get_headers(),
                    timeout=10,
                )

                if response.status_code == 200:
                    drive = response.json()
                    onedrive_drives.append({
                        "id": drive.get("id"),
                        "name": f"OneDrive - {upn}",
                        "driveType": "onedrive",
                        "webUrl": drive.get("webUrl", ""),
                        "siteId": None,
                        "siteName": f"OneDrive ({upn})",
                        "owner": upn,
                    })

                time.sleep(self.request_delay)

            except requests.RequestException:
                continue

        console.print(f"[green]    [+] Found {len(onedrive_drives)} OneDrive accounts[/green]")
        self.drives.extend(onedrive_drives)
        return onedrive_drives
