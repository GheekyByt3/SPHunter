"""
SPHunter SharePoint REST API Enumerator (Fallback)

Used when the Graph API token lacks Sites.Read.All / Files.Read.All scopes.
Talks directly to SharePoint's REST API at https://{tenant}.sharepoint.com/_api/

This is the fallback path when device code flow yields a SharePoint-scoped
token instead of a Graph-scoped token.
"""

import time
import requests
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn

console = Console()


class SharePointRESTEnumerator:
    """Enumerates SharePoint sites and libraries via SharePoint REST API."""

    def __init__(self, auth_handler):
        self.auth = auth_handler
        self.sp_base_url = auth_handler.sp_base_url  # e.g., https://contoso.sharepoint.com
        self.sites = []
        self.drives = []
        self.request_delay = 0.2

    def _sp_headers(self):
        """Headers for SharePoint REST API calls."""
        if self.auth.auth_method == "cookies":
            return {
                "Cookie": self.auth.cookies,
                "Accept": "application/json;odata=nometadata",
            }
        return {
            "Authorization": f"Bearer {self.auth.access_token}",
            "Accept": "application/json;odata=verbose",
        }

    def enumerate_all(self, target_sites: list = None, site_url: str = None) -> dict:
        """Run full enumeration via SharePoint REST API."""
        console.print("\n[yellow][*] Starting SharePoint enumeration (REST API mode)...[/yellow]")

        if site_url:
            # Direct site URL provided — skip discovery entirely
            console.print(f"[cyan][*] Using direct site URL: {site_url}[/cyan]")
            site_info = self._get_site_info(site_url)
            if site_info:
                self.sites.append(site_info)
                console.print(f"[green]    [+] Site accessible: {site_info['displayName']}[/green]")

                # Also check for subsites
                self._enumerate_subsites(site_url)
            else:
                console.print(f"[red][-] Could not access site at {site_url}[/red]")
                console.print("[yellow]    Check the URL and ensure you have access[/yellow]")
        else:
            # Phase 1: Search for sites
            self._enumerate_sites_via_search()

            # Phase 2: Try direct site enumeration as fallback
            if not self.sites:
                self._enumerate_sites_direct()

            # Filter to target sites if specified
            if target_sites:
                target_lower = [t.lower() for t in target_sites]
                self.sites = [
                    s for s in self.sites
                    if any(t in s["displayName"].lower() for t in target_lower)
                ]
                console.print(f"[cyan][*] Filtered to {len(self.sites)} sites matching targets[/cyan]")

        # Phase 3: Enumerate document libraries per site
        self._enumerate_libraries()

        console.print(f"\n[green][+] Enumeration complete: {len(self.sites)} sites, {len(self.drives)} document libraries[/green]\n")

        return {
            "sites": self.sites,
            "drives": self.drives,
        }

    def _enumerate_sites_via_search(self):
        """Use SharePoint search API to find all sites."""
        console.print("[cyan][*] Searching for SharePoint sites...[/cyan]")

        search_url = f"{self.sp_base_url}/_api/search/query"
        params = {
            "querytext": "'contentclass:STS_Site'",
            "selectproperties": "'Title,Path,Description,LastModifiedTime'",
            "rowlimit": "500",
            "trimduplicates": "'false'",
        }

        try:
            response = requests.get(
                search_url,
                headers=self._sp_headers(),
                params=params,
                timeout=15,
            )

            if response.status_code == 200:
                data = response.json()
                rows = (data.get("d", {})
                        .get("query", {})
                        .get("PrimaryQueryResult", {})
                        .get("RelevantResults", {})
                        .get("Table", {})
                        .get("Rows", {})
                        .get("results", []))

                for row in rows:
                    cells = {c["Key"]: c["Value"] for c in row.get("Cells", {}).get("results", [])}
                    site_url = cells.get("Path", "")
                    title = cells.get("Title", "Unknown")

                    if site_url:
                        self.sites.append({
                            "id": site_url,
                            "displayName": title,
                            "webUrl": site_url,
                            "description": cells.get("Description", ""),
                            "lastModifiedDateTime": cells.get("LastModifiedTime", ""),
                            "createdDateTime": "",
                        })

                console.print(f"[green]    [+] Search found {len(self.sites)} site(s)[/green]")
                for site in self.sites:
                    console.print(f"[dim]        - {site['displayName']} ({site['webUrl']})[/dim]")

            elif response.status_code == 403:
                console.print("[dim]    Search API access denied — trying direct enumeration[/dim]")
            else:
                console.print(f"[dim]    Search returned {response.status_code} — trying direct enumeration[/dim]")

        except requests.RequestException as e:
            console.print(f"[dim]    Search failed: {e}[/dim]")

    def _enumerate_sites_direct(self):
        """Try to list subsites from root site."""
        console.print("[cyan][*] Trying direct site enumeration...[/cyan]")

        # Try root site subsites
        url = f"{self.sp_base_url}/_api/web/webs?$select=Title,Url,Description,Created,LastItemModifiedDate"

        try:
            response = requests.get(
                url,
                headers=self._sp_headers(),
                timeout=15,
            )

            if response.status_code == 200:
                data = response.json()
                results = data.get("d", {}).get("results", [])

                # Add root site itself
                root_info = self._get_site_info(self.sp_base_url)
                if root_info:
                    self.sites.append(root_info)

                for web in results:
                    self.sites.append({
                        "id": web.get("Url", ""),
                        "displayName": web.get("Title", "Unknown"),
                        "webUrl": web.get("Url", ""),
                        "description": web.get("Description", ""),
                        "createdDateTime": web.get("Created", ""),
                        "lastModifiedDateTime": web.get("LastItemModifiedDate", ""),
                    })

                console.print(f"[green]    [+] Found {len(self.sites)} site(s)[/green]")

            elif response.status_code == 403:
                console.print("[yellow]    [!] Direct enumeration also denied[/yellow]")
                # Last resort: try just the root site
                root_info = self._get_site_info(self.sp_base_url)
                if root_info:
                    self.sites.append(root_info)
                    console.print(f"[green]    [+] Root site accessible: {root_info['displayName']}[/green]")

        except requests.RequestException as e:
            console.print(f"[red]    [-] Direct enumeration failed: {e}[/red]")

    def _enumerate_subsites(self, site_url):
        """Find subsites under a given site URL."""
        url = f"{site_url}/_api/web/webs?$select=Title,Url,Description,Created,LastItemModifiedDate"
        try:
            response = requests.get(url, headers=self._sp_headers(), timeout=15)
            if response.status_code == 200:
                data = response.json()
                if "d" in data:
                    results = data["d"].get("results", [])
                else:
                    results = data.get("value", [])
                for web in results:
                    self.sites.append({
                        "id": web.get("Url", ""),
                        "displayName": web.get("Title", "Unknown"),
                        "webUrl": web.get("Url", ""),
                        "description": web.get("Description", ""),
                        "createdDateTime": web.get("Created", ""),
                        "lastModifiedDateTime": web.get("LastItemModifiedDate", ""),
                    })
                if results:
                    console.print(f"[green]    [+] Found {len(results)} subsite(s)[/green]")
        except requests.RequestException:
            pass

    def _get_site_info(self, site_url):
        """Get info for a specific site."""
        url = f"{site_url}/_api/web?$select=Title,Url,Description,Created,LastItemModifiedDate"

        try:
            response = requests.get(url, headers=self._sp_headers(), timeout=10)

            if response.status_code == 200:
                data = response.json()
                if "d" in data:
                    data = data["d"]

                return {
                    "id": data.get("Url", site_url),
                    "displayName": data.get("Title", "Root Site"),
                    "webUrl": data.get("Url", site_url),
                    "description": data.get("Description", ""),
                    "createdDateTime": data.get("Created", ""),
                    "lastModifiedDateTime": data.get("LastItemModifiedDate", ""),
                }
            else:
                console.print(f"[dim]    Site info returned {response.status_code}: {response.text[:150]}[/dim]")

        except requests.RequestException as e:
            console.print(f"[dim]    Site info request failed: {e}[/dim]")

        return None

    def _enumerate_libraries(self):
        """Enumerate document libraries for each site."""
        console.print("[cyan][*] Enumerating document libraries...[/cyan]")

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
        ) as progress:
            task = progress.add_task("Enumerating...", total=len(self.sites))

            for site in self.sites:
                site_url = site["webUrl"]
                progress.update(task, description=f"Scanning: {site['displayName']}")

                url = (f"{site_url}/_api/web/lists"
                       f"?$filter=BaseTemplate eq 101 and Hidden eq false"
                       f"&$select=Title,Id,ItemCount,RootFolder/ServerRelativeUrl"
                       f"&$expand=RootFolder")

                try:
                    response = requests.get(
                        url,
                        headers=self._sp_headers(),
                        timeout=15,
                    )

                    if response.status_code == 200:
                        data = response.json()
                        # Handle both odata=verbose ("d" → "results") and nometadata ("value")
                        if "d" in data:
                            lists = data["d"].get("results", [])
                        else:
                            lists = data.get("value", [])

                        for lib in lists:
                            root_folder = lib.get("RootFolder", {})
                            self.drives.append({
                                "id": lib.get("Id", ""),
                                "name": lib.get("Title", "Unknown"),
                                "driveType": "documentLibrary",
                                "webUrl": f"{self.sp_base_url}{root_folder.get('ServerRelativeUrl', '')}",
                                "siteId": site["id"],
                                "siteName": site["displayName"],
                                "siteUrl": site_url,
                                "serverRelativeUrl": root_folder.get("ServerRelativeUrl", ""),
                                "itemCount": lib.get("ItemCount", 0),
                                "api_type": "sharepoint",
                            })

                    elif response.status_code == 403:
                        console.print(f"[dim]    [!] Access denied: {site['displayName']}[/dim]")

                except requests.RequestException as e:
                    console.print(f"[red]    [-] Error on {site['displayName']}: {e}[/red]")

                progress.advance(task)
                time.sleep(self.request_delay)

        console.print(f"[green]    [+] Found {len(self.drives)} document libraries[/green]")
