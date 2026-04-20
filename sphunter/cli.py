"""
SPHunter - SharePoint Sensitive File Hunter
CLI Entry Point
"""

import argparse
import sys
import os
import time
from datetime import datetime
from rich.console import Console
from rich.panel import Panel

from sphunter.modules.auth import AuthHandler
from sphunter.modules.enumerator import SharePointEnumerator
from sphunter.modules.sp_enumerator import SharePointRESTEnumerator
from sphunter.modules.sp_crawler import SharePointRESTCrawler
from sphunter.modules.crawler import SharePointCrawler
from sphunter.modules.searcher import SharePointSearcher
from sphunter.modules.discovery import SiteDiscovery
from sphunter.modules.detector import SensitiveFileDetector
from sphunter.modules.reporter import ReportGenerator

console = Console()

BANNER = """[bold cyan]
  _____ _____  _    _             _
 / ____|  __ \\| |  | |           | |
| (___ | |__) | |__| |_   _ _ __ | |_ ___ _ __
 \\___ \\|  ___/|  __  | | | | '_ \\| __/ _ \\ '__|
 ____) | |    | |  | | |_| | | | | ||  __/ |
|_____/|_|    |_|  |_|\\__,_|_| |_|\\__\\___|_|
[/bold cyan]
  [cyan]v1.0.0[/cyan] [dim]|[/dim] [yellow]For authorized penetration testing only[/yellow]
  [dim]Created with <3 by Prithvi Chintha[/dim]
"""


def print_help():
    """Print a simple colored help screen."""
    console.print(BANNER)

    console.print("[bold yellow]Usage:[/bold yellow]")
    console.print("  python3 sphunter.py [cyan]<auth>[/cyan] [cyan]--mode[/cyan] [white]<search|crawl|both>[/white] [options]\n")

    console.print("[bold yellow]Authentication[/bold yellow] [dim](choose one)[/dim]")
    console.print("  [cyan]-t, --token[/cyan] [white]<TOKEN>[/white]       Microsoft Graph API access token")
    console.print("  [cyan]--device-code[/cyan]             Device code flow (MFA-compatible)")
    console.print("  [cyan]--client-id[/cyan] [white]<ID>[/white]          Azure AD application client ID")
    console.print("  [cyan]--client-secret[/cyan] [white]<SECRET>[/white]  Azure AD client secret")
    console.print("  [cyan]--tenant-id[/cyan] [white]<TID>[/white]         Tenant ID (for client credentials)")
    console.print("  [cyan]--tenant[/cyan] [white]<DOMAIN>[/white]         Tenant domain (for device code / cookies)")
    console.print("  [cyan]--cookie-file[/cyan] [white]<FILE>[/white]      File containing browser cookies")

    console.print("\n[bold yellow]Scope[/bold yellow]")
    console.print("  [cyan]--site-url[/cyan] [white]<URL>[/white]          SharePoint site URL to scan")
    console.print("  [cyan]--discover[/cyan]                Auto-discover accessible sites via wordlist")
    console.print("  [cyan]-s, --sites[/cyan] [white]<NAMES>[/white]       Comma-separated site name filters [dim](default: all)[/dim]")
    console.print("  [cyan]--include-onedrive[/cyan]        Enumerate user OneDrive accounts")
    console.print("  [cyan]--max-file-size[/cyan] [white]<MB>[/white]      Max file size to download [dim](default: 5)[/dim]")

    console.print("\n[bold yellow]Mode[/bold yellow] [red](required)[/red]")
    console.print("  [cyan]-m, --mode[/cyan] [white]<MODE>[/white]         search, crawl, or both")

    console.print("\n[bold yellow]Search Options[/bold yellow]")
    console.print("  [cyan]--search-queries[/cyan] [white]<FILE>[/white]   Custom KQL queries YAML [dim](default: config/search_queries.yaml)[/dim]")
    console.print("  [cyan]--search-limit[/cyan] [white]<N>[/white]        Max results per search query [dim](default: 500)[/dim]")

    console.print("\n[bold yellow]Detection[/bold yellow]")
    console.print("  [cyan]--download[/cyan]                Download files for content inspection [dim](off by default)[/dim]")
    console.print("  [cyan]-r, --rules[/cyan] [white]<FILE>[/white]        Custom YAML rules file [dim](default: config/rules.yaml)[/dim]")

    console.print("\n[bold yellow]Output[/bold yellow]")
    console.print("  [cyan]-o, --output[/cyan] [white]<DIR>[/white]        Output directory [dim](default: sphunter_output)[/dim]")
    console.print("  [cyan]--delay[/cyan] [white]<SECS>[/white]            Delay between requests [dim](default: 0.2)[/dim]")

    console.print("\n[bold yellow]Examples[/bold yellow]")
    console.print("  [dim]# Search scan with cookies[/dim]")
    console.print("  python3 sphunter.py [cyan]--cookie-file[/cyan] cookies.txt [cyan]--site-url[/cyan] https://... [cyan]--mode search[/cyan]\n")
    console.print("  [dim]# Deep crawl with file downloads[/dim]")
    console.print("  python3 sphunter.py [cyan]--cookie-file[/cyan] cookies.txt [cyan]--site-url[/cyan] https://... [cyan]--mode crawl --download[/cyan]\n")
    console.print("  [dim]# Device code flow[/dim]")
    console.print("  python3 sphunter.py [cyan]--device-code --tenant[/cyan] contoso.onmicrosoft.com [cyan]--site-url[/cyan] https://... [cyan]--mode both[/cyan]\n")
    console.print("  [dim]# Client credentials (compromised app registration)[/dim]")
    console.print("  python3 sphunter.py [cyan]--client-id[/cyan] [white]<id>[/white] [cyan]--client-secret[/cyan] [white]<secret>[/white] [cyan]--tenant-id[/cyan] [white]<tid>[/white] [cyan]--mode search[/cyan]\n")


def parse_args():
    parser = argparse.ArgumentParser(add_help=False)

    parser.add_argument("--help", "-h", action="store_true")

    # Authentication
    parser.add_argument("--token", "-t", default=None)
    parser.add_argument("--device-code", action="store_true")
    parser.add_argument("--client-id", default=None)
    parser.add_argument("--client-secret", default=None)
    parser.add_argument("--tenant-id", default=None)
    parser.add_argument("--tenant", default=None)
    parser.add_argument("--cookies", default=None)
    parser.add_argument("--cookie-file", default=None)

    # Scope
    parser.add_argument("--sites", "-s", default=None)
    parser.add_argument("--site-url", default=None)
    parser.add_argument("--discover", action="store_true")
    parser.add_argument("--include-onedrive", action="store_true")
    parser.add_argument("--max-file-size", type=int, default=5)

    # Mode
    parser.add_argument("--mode", "-m", default=None, choices=["search", "crawl", "both"])
    parser.add_argument("--search-queries", default=None)
    parser.add_argument("--search-limit", type=int, default=500)

    # Detection
    parser.add_argument("--download", action="store_true")
    parser.add_argument("--rules", "-r", default=None)

    # Output
    parser.add_argument("--output", "-o", default="./sphunter_output")

    # Performance
    parser.add_argument("--delay", type=float, default=0.2)

    return parser.parse_args()


def main():
    args = parse_args()

    if args.help or len(sys.argv) == 1:
        print_help()
        sys.exit(0)

    console.print(BANNER)

    # Validate auth arguments
    has_token = bool(args.token)
    has_device_code = args.device_code
    has_client_creds = all([args.client_id, args.client_secret, args.tenant_id])
    has_cookies = bool(args.cookies or args.cookie_file)

    auth_methods = sum([has_token, has_device_code, has_client_creds, has_cookies])

    if auth_methods == 0:
        console.print("[red][-] No authentication method specified. Use --token, --device-code, --cookies, or --client-id/--client-secret/--tenant-id[/red]")
        sys.exit(1)

    if auth_methods > 1:
        console.print("[red][-] Multiple authentication methods specified. Choose only one.[/red]")
        sys.exit(1)

    if has_device_code and not args.tenant:
        console.print("[red][-] --tenant is required for device code flow[/red]")
        sys.exit(1)

    if not args.mode:
        console.print("[red][-] --mode is required. Choose: search, crawl, or both[/red]")
        console.print("[dim]    --mode search   Fast KQL queries against SharePoint search index[/dim]")
        console.print("[dim]    --mode crawl    Deep recursive folder walking + content inspection[/dim]")
        console.print("[dim]    --mode both     Search + crawl combined, deduplicated[/dim]")
        sys.exit(1)

    # Timestamp the output directory
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_dir = os.path.join(args.output, f"run_{timestamp}")

    console.print(Panel(
        f"[cyan]Output:[/cyan] {output_dir}\n"
        f"[cyan]Mode:[/cyan] {args.mode}\n"
        f"[cyan]Content inspection:[/cyan] {'Enabled (--download)' if args.download else 'Disabled (filename matching only)'}\n"
        f"[cyan]Max file size:[/cyan] {args.max_file_size}MB\n"
        f"[cyan]OneDrive:[/cyan] {'Included' if args.include_onedrive else 'Excluded'}\n"
        f"[cyan]Target:[/cyan] {args.site_url or args.sites or 'All sites'}",
        title="[bold]SPHunter Configuration[/bold]",
        border_style="blue",
    ))

    start_time = time.time()

    if args.download:
        console.print("")
        console.print(Panel(
            "[bold yellow]WARNING: --download is enabled[/bold yellow]\n\n"
            "Files will be downloaded to your machine for inspection.\n"
            "This is NOISY — downloads are logged in SharePoint audit\n"
            "logs and may trigger DLP/CASB alerts.\n\n"
            "Ensure:\n"
            "  - You have authorization for file downloads\n"
            "  - Downloaded files are stored on an encrypted drive\n"
            "  - Files are wiped after the engagement",
            border_style="yellow",
        ))
        console.print("")

    # ── Step 1: Authenticate ──
    console.print("\n[bold]Phase 1: Authentication[/bold]")
    auth = AuthHandler()

    if has_cookies:
        # Need either --site-url or --tenant to know the SharePoint host
        if not args.site_url and not args.tenant:
            console.print("[red][-] --site-url or --tenant is required when using --cookies[/red]")
            console.print("[dim]    --site-url to scan a specific site, --tenant to discover all accessible sites[/dim]")
            sys.exit(1)
        # Load cookies from file or direct string
        if args.cookie_file:
            try:
                cookie_string = open(args.cookie_file).read().strip()
            except IOError as e:
                console.print(f"[red][-] Could not read cookie file: {e}[/red]")
                sys.exit(1)
        else:
            cookie_string = args.cookies
        # Use site_url if provided, otherwise build root URL from tenant
        if args.site_url:
            target_url = args.site_url
        else:
            sp_host = args.tenant.replace(".onmicrosoft.com", "").replace(".com", "")
            target_url = f"https://{sp_host}.sharepoint.com"
        if not auth.auth_with_cookies(cookie_string, target_url):
            sys.exit(1)
    elif has_token:
        if not auth.auth_with_token(args.token):
            sys.exit(1)
        if args.tenant:
            sp_host = args.tenant.replace(".onmicrosoft.com", "").replace(".com", "")
            auth.sp_base_url = f"https://{sp_host}.sharepoint.com"
    elif has_device_code:
        if not auth.auth_with_device_code(args.tenant, args.client_id):
            sys.exit(1)
    elif has_client_creds:
        if not auth.auth_with_client_credentials(args.tenant_id, args.client_id, args.client_secret):
            sys.exit(1)
        if args.tenant:
            sp_host = args.tenant.replace(".onmicrosoft.com", "").replace(".com", "")
            auth.sp_base_url = f"https://{sp_host}.sharepoint.com"

    auth_info = auth.get_user_context()

    # ── Step 1.5: Site Discovery (if --discover) ──
    target_sites = args.sites.split(",") if args.sites else None
    site_url = args.site_url
    mode = args.mode

    if args.discover:
        if not auth.sp_base_url:
            console.print("[red][-] --discover requires --tenant to know the SharePoint host[/red]")
            sys.exit(1)
        console.print("\n[bold]Phase 1.5: Site Discovery[/bold]")
        discovery = SiteDiscovery(auth)
        discovery.request_delay = args.delay
        discovered_sites = discovery.discover()

        if not discovered_sites and not site_url:
            console.print("[yellow][!] No accessible sites discovered.[/yellow]")
            sys.exit(0)

    # ── Step 2: Enumerate ──
    if mode == "search" and not args.discover:
        console.print("\n[bold]Phase 2: Enumeration[/bold] [dim](skipped — search-only mode)[/dim]")
        enum_results = {"sites": [], "drives": []}
    elif args.discover:
        # Enumerate every discovered site
        console.print("\n[bold]Phase 2: Enumeration[/bold]")
        all_sites = []
        all_drives = []

        # Include --site-url if provided alongside --discover
        sites_to_enum = list(discovered_sites)
        if site_url:
            # Add site_url if not already in discovered list
            if not any(s["webUrl"] == site_url for s in sites_to_enum):
                sites_to_enum.insert(0, {"webUrl": site_url, "displayName": "Target Site"})

        console.print(f"[cyan][*] Enumerating {len(sites_to_enum)} discovered site(s)...[/cyan]")

        for site in sites_to_enum:
            enumerator = SharePointRESTEnumerator(auth)
            enumerator.request_delay = args.delay
            result = enumerator.enumerate_all(site_url=site["webUrl"])
            all_sites.extend(result["sites"])
            all_drives.extend(result["drives"])

        enum_results = {"sites": all_sites, "drives": all_drives}
        console.print(f"[green][+] Total: {len(all_sites)} site(s), {len(all_drives)} document libraries[/green]")
    elif auth.api_type == "sharepoint" or auth.api_type == "cookies" or site_url:
        console.print("\n[bold]Phase 2: Enumeration[/bold]")
        console.print("[cyan][*] Using SharePoint REST API mode[/cyan]")
        enumerator = SharePointRESTEnumerator(auth)
        enumerator.request_delay = args.delay
        enum_results = enumerator.enumerate_all(target_sites=target_sites, site_url=site_url)
    else:
        console.print("\n[bold]Phase 2: Enumeration[/bold]")
        console.print("[cyan][*] Using Microsoft Graph API mode[/cyan]")
        enumerator = SharePointEnumerator(auth)
        enumerator.request_delay = args.delay
        enum_results = enumerator.enumerate_all(target_sites=target_sites)

        # If Graph found 0 sites and we have a tenant, try REST API fallback
        if not enum_results["drives"] and auth.sp_base_url:
            console.print("[yellow][!] Graph API found nothing — falling back to SharePoint REST API...[/yellow]")
            enumerator = SharePointRESTEnumerator(auth)
            enumerator.request_delay = args.delay
            enum_results = enumerator.enumerate_all(target_sites=target_sites, site_url=site_url)

        if args.include_onedrive and hasattr(enumerator, 'enumerate_onedrive_users'):
            enumerator.enumerate_onedrive_users()

    sites = enum_results["sites"]
    drives = enum_results["drives"]

    mode = args.mode
    content_inspection = args.download
    download_dir = os.path.join(output_dir, "downloads") if content_inspection else None
    all_files = []
    crawl_stats = {"total_files": 0, "total_folders": 0, "total_size_bytes": 0, "access_denied": 0, "drives_crawled": 0}

    # ── Step 3a: Search (if mode is 'search' or 'both') ──
    if mode in ("search", "both"):
        console.print("\n[bold]Phase 3a: Search (KQL queries)[/bold]")
        searcher = SharePointSearcher(
            auth_handler=auth,
            queries_path=args.search_queries,
            max_results=args.search_limit,
        )
        searcher.request_delay = args.delay

        search_results = searcher.search_all(site_url=site_url)
        all_files.extend(search_results)
        console.print(f"[cyan][*] Search found {len(search_results)} files[/cyan]")

    # ── Step 3b: Crawl (if mode is 'crawl' or 'both') ──
    if mode in ("crawl", "both"):
        if not drives:
            if mode == "both":
                console.print("[yellow][!] No document libraries for crawling — search results only[/yellow]")
            else:
                console.print("[yellow][!] No document libraries found. Check permissions or site filters.[/yellow]")
                if not all_files:
                    sys.exit(0)
        else:
            console.print(f"\n[bold]Phase 3b: Crawl (recursive folder walk)[/bold]")

            use_sp_crawler = any(d.get("api_type") == "sharepoint" for d in drives)

            if use_sp_crawler:
                crawler = SharePointRESTCrawler(
                    auth_handler=auth,
                    max_file_size_mb=args.max_file_size,
                    download_dir=download_dir,
                )
            else:
                crawler = SharePointCrawler(
                    auth_handler=auth,
                    max_file_size_mb=args.max_file_size,
                    download_dir=download_dir,
                )
            crawler.request_delay = args.delay

            crawl_files = crawler.crawl_drives(drives, content_inspection=content_inspection)
            crawl_stats = crawler.stats
            all_files.extend(crawl_files)
            console.print(f"[cyan][*] Crawl found {len(crawl_files)} files[/cyan]")

    # ── Deduplicate (when running both modes) ──
    # Search results have DispForm URLs, crawl results have real paths.
    # Deduplicate by filename only, preferring crawl results
    # (they have real paths, downloaded content, and better metadata).
    if mode == "both" and all_files:
        # Process crawl results first (they come last in all_files)
        all_files.reverse()

        seen_names = set()
        unique_files = []
        for f in all_files:
            # Deduplicate by just the filename — same file across search/crawl
            name = f.get("name", "").lower()
            if not name:
                unique_files.append(f)
                continue

            if name not in seen_names:
                seen_names.add(name)
                unique_files.append(f)

        unique_files.reverse()
        dupes_removed = len(all_files) - len(unique_files)
        all_files = unique_files
        if dupes_removed > 0:
            console.print(f"[dim]    Deduplicated: {dupes_removed} duplicates removed, {len(all_files)} unique files[/dim]")

    if not all_files:
        console.print("[yellow][!] No files found.[/yellow]")
        sys.exit(0)

    # Update crawl_stats to reflect total files across all modes
    if crawl_stats["total_files"] == 0:
        crawl_stats["total_files"] = len(all_files)
        crawl_stats["total_size_bytes"] = sum(f.get("size", 0) for f in all_files)

    console.print(f"\n[green][+] Total unique files to analyze: {len(all_files)}[/green]")

    # ── Step 4: Detect ──
    console.print("\n[bold]Phase 4: Detection[/bold]")
    detector = SensitiveFileDetector(rules_path=args.rules)
    findings = detector.analyze_files(all_files, content_inspection=content_inspection)

    # ── Step 5: Report ──
    console.print("\n[bold]Phase 5: Reporting[/bold]")
    reporter = ReportGenerator(output_dir)
    reporter.generate_all(
        findings=findings,
        sites=sites,
        drives=drives,
        crawl_stats=crawl_stats,
        auth_info=auth_info,
        all_files=all_files,
    )

    elapsed = time.time() - start_time
    console.print(f"\n[bold green]Done![/bold green] Completed in {elapsed:.1f}s")


if __name__ == "__main__":
    main()
