"""
SPHunter Site Discovery Module

Discovers accessible SharePoint site collections by probing common
site names against the tenant. No special permissions needed — just
valid cookies or a token that can hit the SharePoint REST API.
"""

import os
import time
import requests
from rich.console import Console
from rich.progress import Progress, BarColumn, TextColumn, TaskProgressColumn, SpinnerColumn

console = Console()

DEFAULT_WORDLIST_PATH = os.path.join(os.path.dirname(__file__), "..", "..", "config", "site_wordlist.txt")


class SiteDiscovery:
    """Discovers accessible SharePoint sites by brute-forcing common names."""

    def __init__(self, auth_handler, wordlist_path: str = None):
        self.auth = auth_handler
        self.sp_base_url = auth_handler.sp_base_url  # e.g., https://contoso.sharepoint.com
        self.wordlist_path = wordlist_path or DEFAULT_WORDLIST_PATH
        self.request_delay = 0.1
        self.found_sites = []
        self.stats = {
            "total_probed": 0,
            "accessible": 0,
            "denied": 0,
            "not_found": 0,
            "errors": 0,
        }

    def _sp_headers(self):
        """Headers for SharePoint REST API calls."""
        if self.auth.auth_method == "cookies":
            return {
                "Cookie": self.auth.cookies,
                "Accept": "application/json;odata=nometadata",
            }
        return {
            "Authorization": f"Bearer {self.auth.access_token}",
            "Accept": "application/json;odata=nometadata",
        }

    def discover(self) -> list:
        """Probe all site names from wordlist and return accessible sites."""
        console.print(f"\n[yellow][*] Discovering SharePoint sites via brute-force...[/yellow]")
        console.print(f"[dim]    Target: {self.sp_base_url}[/dim]")

        # Load wordlist
        site_names = self._load_wordlist()
        if not site_names:
            return []

        # Build URLs to probe — both /sites/ and /teams/ prefixes
        probe_urls = []
        for name in site_names:
            probe_urls.append((f"{self.sp_base_url}/sites/{name}", name, "sites"))
            probe_urls.append((f"{self.sp_base_url}/teams/{name}", name, "teams"))

        console.print(f"[cyan][*] Probing {len(probe_urls)} URLs ({len(site_names)} names x 2 prefixes)...[/cyan]\n")

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TaskProgressColumn(),
            console=console,
        ) as progress:
            task = progress.add_task("Discovering...", total=len(probe_urls))

            for url, name, prefix in probe_urls:
                progress.update(task, description=f"[dim]{prefix}/{name}[/dim]")
                self._probe_site(url, name, prefix)
                progress.advance(task)
                time.sleep(self.request_delay)

        # Summary
        console.print(f"\n[green][+] Discovery complete[/green]")
        console.print(f"    Probed: {self.stats['total_probed']}")
        console.print(f"    [green]Accessible: {self.stats['accessible']}[/green]")
        console.print(f"    [yellow]Denied: {self.stats['denied']}[/yellow]")
        console.print(f"    [dim]Not found: {self.stats['not_found']}[/dim]")

        if self.found_sites:
            console.print(f"\n[green][+] Found {len(self.found_sites)} accessible site(s):[/green]")
            for site in self.found_sites:
                console.print(f"    [green][+][/green] {site['displayName']} — {site['webUrl']}")

        return self.found_sites

    def _probe_site(self, url: str, name: str, prefix: str):
        """Probe a single site URL and check if accessible."""
        self.stats["total_probed"] += 1

        try:
            response = requests.get(
                f"{url}/_api/web?$select=Title,Url",
                headers=self._sp_headers(),
                timeout=8,
                allow_redirects=False,
            )

            if response.status_code == 200:
                self.stats["accessible"] += 1
                data = response.json()
                if "d" in data:
                    data = data["d"]

                site_info = {
                    "id": data.get("Url", url),
                    "displayName": data.get("Title", name),
                    "webUrl": data.get("Url", url),
                    "description": "",
                    "createdDateTime": "",
                    "lastModifiedDateTime": "",
                }
                self.found_sites.append(site_info)
                console.print(f"    [green][+][/green] [green]{prefix}/{name}[/green] — {data.get('Title', 'Unknown')}")

            elif response.status_code == 403:
                self.stats["denied"] += 1
                console.print(f"    [yellow][!][/yellow] [dim]{prefix}/{name} — access denied[/dim]")

            elif response.status_code in (404, 400):
                self.stats["not_found"] += 1
                # Don't print 404s — too noisy

            elif response.status_code == 429:
                retry_after = int(response.headers.get("Retry-After", 10))
                console.print(f"    [yellow][!] Rate limited — waiting {retry_after}s[/yellow]")
                time.sleep(retry_after)
                # Retry once
                self._probe_site(url, name, prefix)
                return

            else:
                self.stats["errors"] += 1

        except requests.RequestException:
            self.stats["errors"] += 1

    def _load_wordlist(self) -> list:
        """Load site names from wordlist file."""
        try:
            with open(self.wordlist_path, "r") as f:
                names = [line.strip() for line in f if line.strip() and not line.startswith("#")]
            console.print(f"[green][+] Loaded {len(names)} site names from wordlist[/green]")
            return names
        except FileNotFoundError:
            console.print(f"[red][-] Wordlist not found: {self.wordlist_path}[/red]")
            return []
