"""
SPHunter Search Module

Performs SharePoint Search API queries using KQL
(Keyword Query Language) to quickly find sensitive files across
the tenant without crawling every folder.

This is fast but incomplete — it only finds files that SharePoint
has indexed and that match the query patterns.
"""

import time
import yaml
import os
import requests
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn

console = Console()

DEFAULT_QUERIES_PATH = os.path.join(os.path.dirname(__file__), "..", "..", "config", "search_queries.yaml")


class SharePointSearcher:
    """Searches SharePoint using KQL queries via the Search REST API."""

    def __init__(self, auth_handler, queries_path: str = None, max_results: int = 500):
        self.auth = auth_handler
        self.sp_base_url = auth_handler.sp_base_url
        self.queries_path = queries_path or DEFAULT_QUERIES_PATH
        self.max_results = max_results
        self.request_delay = 0.3
        self.results = []
        self.queries = []
        self._load_queries()

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

    def _load_queries(self):
        """Load KQL search queries from YAML config."""
        try:
            with open(self.queries_path, "r") as f:
                data = yaml.safe_load(f)
            self.queries = data.get("queries", [])
            console.print(f"[green][+] Loaded {len(self.queries)} search queries[/green]")
        except FileNotFoundError:
            console.print(f"[red][-] Search queries file not found: {self.queries_path}[/red]")
            console.print("[yellow][*] Running with empty query set[/yellow]")
        except yaml.YAMLError as e:
            console.print(f"[red][-] Error parsing search queries YAML: {e}[/red]")

    def search_all(self, site_url: str = None) -> list:
        """
        Execute all search queries and return combined results.

        Args:
            site_url: Optional — scope search to a specific site.

        Returns:
            List of file metadata dicts (same format as crawler output).
        """
        console.print(f"\n[yellow][*] Running SharePoint search queries...[/yellow]")

        if site_url:
            console.print(f"[cyan][*] Scoped to: {site_url}[/cyan]")

        if not self.queries:
            console.print("[yellow][!] No search queries loaded — skipping search phase[/yellow]")
            return []

        seen_urls = set()

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
        ) as progress:
            task = progress.add_task("Searching...", total=len(self.queries))

            for query_def in self.queries:
                query_name = query_def.get("name", "Unknown")
                kql = query_def.get("kql", "")
                severity = query_def.get("severity", "medium")
                description = query_def.get("description", "")

                if not kql:
                    progress.advance(task)
                    continue

                progress.update(task, description=f"[cyan]{query_name}[/cyan]")

                # Scope to site if provided
                if site_url:
                    scoped_kql = f"path:\"{site_url}\" AND ({kql})"
                else:
                    scoped_kql = kql

                hits = self._execute_search(scoped_kql, query_name)

                for hit in hits:
                    url = hit.get("Path", "")
                    if url and url not in seen_urls:
                        seen_urls.add(url)

                        # Resolve real filename if search only returned a DispForm URL
                        hit = self._resolve_filename(hit, site_url)

                        file_info = self._hit_to_file_info(hit, query_name, severity, description)
                        self.results.append(file_info)

                        # Live output — show resolved filename
                        console.print(
                            f"  [yellow][SEARCH][/yellow] "
                            f"[dim]{query_name}[/dim] → {file_info['name']} "
                            f"[dim]({file_info['webUrl']})[/dim]"
                        )

                progress.advance(task)
                time.sleep(self.request_delay)

        console.print(f"\n[green][+] Search complete: {len(self.results)} unique files found across {len(self.queries)} queries[/green]")
        return self.results

    def _resolve_filename(self, hit: dict, site_url: str = None) -> dict:
        """
        Resolve the real filename for search results that returned DispForm URLs.

        SharePoint search often returns Title without extension (e.g., 'web' instead
        of 'web.config'). If we detect a DispForm URL with an item ID, we call the
        list item API to get the real FileLeafRef (actual filename with extension).
        """
        path = hit.get("Path", "")
        file_ext = hit.get("FileExtension", "") or hit.get("FileType", "")

        # If we already have a good filename with extension, skip
        filename = hit.get("FileName") or hit.get("Filename") or ""
        if filename and "." in filename:
            return hit

        # If there's already a file extension, skip (the _hit_to_file_info will handle it)
        if file_ext:
            return hit

        # Check if Path is a DispForm URL with an item ID
        if "DispForm.aspx" not in path or "ID=" not in path:
            return hit

        # Extract the item ID
        try:
            item_id = path.split("ID=")[1].split("&")[0]
        except (IndexError, ValueError):
            return hit

        # We need a site URL to make the API call
        target_site = site_url
        if not target_site:
            # Try to extract from the Path
            if "/sites/" in path:
                parts = path.split("/sites/")
                site_name = parts[1].split("/")[0]
                target_site = f"{self.sp_base_url}/sites/{site_name}"
            elif "/teams/" in path:
                parts = path.split("/teams/")
                site_name = parts[1].split("/")[0]
                target_site = f"{self.sp_base_url}/teams/{site_name}"
            else:
                return hit

        # Extract the list name from the Path (e.g., "Shared Documents")
        # DispForm URL looks like: .../Shared Documents/Forms/DispForm.aspx?ID=2
        # URL may have encoded spaces (%20) or literal spaces
        from urllib.parse import unquote
        list_name = None
        try:
            decoded_path = unquote(path)
            decoded_site = unquote(target_site)
            relative = decoded_path.split(decoded_site)[1] if decoded_site in decoded_path else ""
            if "/Forms/DispForm" in relative:
                list_name = relative.split("/Forms/DispForm")[0].strip("/")
        except (IndexError, ValueError):
            pass

        if not list_name:
            return hit

        # Call the list item API to get the real filename
        api_url = f"{target_site}/_api/web/lists/getbytitle('{list_name}')/items({item_id})?$select=FileLeafRef,FileRef"

        try:
            response = requests.get(api_url, headers=self._sp_headers(), timeout=8)
            if response.status_code == 200:
                data = response.json()
                if "d" in data:
                    data = data["d"]

                real_filename = data.get("FileLeafRef", "")
                file_ref = data.get("FileRef", "")

                if real_filename:
                    hit["FileName"] = real_filename
                    # Extract extension
                    if "." in real_filename:
                        hit["FileExtension"] = real_filename.rsplit(".", 1)[1]
                if file_ref:
                    hit["ServerRelativeUrl"] = file_ref
                    hit["OriginalPath"] = f"{self.sp_base_url}{file_ref}"

        except requests.RequestException:
            pass

        return hit

    def _execute_search(self, kql: str, query_name: str) -> list:
        """Execute a single KQL search query with pagination."""
        all_hits = []
        start_row = 0
        rows_per_page = min(self.max_results, 500)  # SharePoint caps at 500 per request

        while start_row < self.max_results:
            search_url = f"{self.sp_base_url}/_api/search/query"
            params = {
                "querytext": f"'{kql}'",
                "selectproperties": "'Title,Path,Filename,FileName,Size,LastModifiedTime,Author,FileExtension,FileType,ServerRelativeUrl,OriginalPath,SiteName,ContentClass,SPWebUrl'",
                "rowlimit": str(rows_per_page),
                "startrow": str(start_row),
                "trimduplicates": "'false'",
                "sortlist": "'LastModifiedTime:descending'",
            }

            try:
                response = requests.get(
                    search_url,
                    headers=self._sp_headers(),
                    params=params,
                    timeout=20,
                )

                if response.status_code == 200:
                    data = response.json()

                    # Handle both odata formats
                    if "d" in data:
                        query_result = data["d"].get("query", {})
                    else:
                        query_result = data.get("PrimaryQueryResult", data)

                    relevant = (query_result
                                .get("PrimaryQueryResult", query_result)
                                .get("RelevantResults", {}))

                    total_rows = relevant.get("TotalRows", 0)
                    table = relevant.get("Table", {})
                    rows = table.get("Rows", {})

                    # Handle both formats
                    if isinstance(rows, dict):
                        row_list = rows.get("results", [])
                    elif isinstance(rows, list):
                        row_list = rows
                    else:
                        row_list = []

                    if not row_list:
                        break

                    for row in row_list:
                        # Extract cells into a dict
                        cells = row.get("Cells", {})
                        if isinstance(cells, dict):
                            cell_list = cells.get("results", [])
                        elif isinstance(cells, list):
                            cell_list = cells
                        else:
                            cell_list = []

                        hit = {}
                        for cell in cell_list:
                            key = cell.get("Key", "")
                            value = cell.get("Value", "")
                            if key and value:
                                hit[key] = value

                        # Only include actual files (not sites/folders)
                        content_class = hit.get("ContentClass", "")
                        if content_class and "STS_ListItem_DocumentLibrary" in content_class:
                            all_hits.append(hit)
                        elif not content_class:
                            # If no ContentClass, check if it has a file extension
                            if hit.get("FileExtension", ""):
                                all_hits.append(hit)

                    # Check if there are more pages
                    start_row += rows_per_page
                    if start_row >= total_rows:
                        break

                elif response.status_code == 429:
                    retry_after = int(response.headers.get("Retry-After", 30))
                    console.print(f"[yellow][!] Rate limited. Waiting {retry_after}s...[/yellow]")
                    time.sleep(retry_after)
                    continue
                elif response.status_code in (401, 403):
                    console.print(f"[dim]    Search denied for: {query_name} ({response.status_code})[/dim]")
                    break
                else:
                    console.print(f"[dim]    Search returned {response.status_code} for: {query_name}[/dim]")
                    break

            except requests.RequestException as e:
                console.print(f"[dim]    Search request failed for {query_name}: {e}[/dim]")
                break

        return all_hits

    def _hit_to_file_info(self, hit: dict, query_name: str, severity: str, description: str) -> dict:
        """Convert a search result hit to SPHunter's standard file info format."""
        path = hit.get("Path", "")
        original_path = hit.get("OriginalPath", "")
        file_extension = hit.get("FileExtension", "") or hit.get("FileType", "")
        size = int(hit.get("Size", 0))

        # Ignore bogus extensions from DispForm URLs
        if file_extension.lower() in ("aspx", "asp", "html", "htm"):
            file_extension = ""

        # Reconstruct the real filename with extension
        # Priority: FileName > Title > extract from OriginalPath/ServerRelativeUrl
        filename = hit.get("FileName") or hit.get("Filename") or hit.get("Title", "Unknown")

        # If filename is missing the extension, add it back
        if file_extension and not filename.lower().endswith(f".{file_extension.lower()}"):
            filename = f"{filename}.{file_extension}"

        # If still no good filename, try to extract from OriginalPath or ServerRelativeUrl
        server_rel = hit.get("ServerRelativeUrl", "")
        if filename == "Unknown" or not file_extension:
            for url in [server_rel, original_path, path]:
                if url and "/" in url:
                    candidate = url.rstrip("/").split("/")[-1]
                    if "." in candidate and "DispForm" not in candidate:
                        filename = candidate
                        break

        # Extract site name from path
        site_name = hit.get("SiteName", "")
        if not site_name and "/sites/" in path:
            site_name = path.split("/sites/")[1].split("/")[0]
        elif not site_name and "/teams/" in path:
            site_name = path.split("/teams/")[1].split("/")[0]

        # Build folder path from ServerRelativeUrl
        if server_rel and "/" in server_rel:
            folder_path = "/".join(server_rel.split("/")[:-1]) + "/"
        else:
            folder_path = "/"

        # Use OriginalPath for webUrl if Path points to DispForm.aspx
        web_url = path
        if "DispForm.aspx" in path and original_path:
            web_url = original_path

        return {
            "id": server_rel or path,
            "name": filename,
            "size": size,
            "mimeType": "",
            "webUrl": web_url,
            "folderPath": folder_path,
            "fullPath": server_rel or path,
            "driveId": "",
            "driveName": "",
            "siteName": site_name,
            "createdBy": hit.get("Author", "Unknown"),
            "modifiedBy": hit.get("Author", "Unknown"),
            "createdDateTime": "",
            "lastModifiedDateTime": hit.get("LastModifiedTime", ""),
            "serverRelativeUrl": server_rel,
            "siteUrl": "",
            "local_path": None,
            "findings": [],
            "api_type": "search",
            "search_match": {
                "query_name": query_name,
                "severity": severity,
                "description": description,
            },
        }
