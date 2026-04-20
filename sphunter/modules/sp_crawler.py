"""
SPHunter SharePoint REST API Crawler (Fallback)

Recursively crawls document libraries using SharePoint REST API
when Graph API isn't available.
"""

import os
import time
import tempfile
import requests
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn

console = Console()


class SharePointRESTCrawler:
    """Recursively crawls SharePoint libraries via REST API."""

    def __init__(self, auth_handler, max_file_size_mb: int = 5, download_dir: str = None):
        self.auth = auth_handler
        self.sp_base_url = auth_handler.sp_base_url
        self.max_file_size = max_file_size_mb * 1024 * 1024
        self.download_dir = download_dir or tempfile.mkdtemp(prefix="sphunter_")
        os.makedirs(self.download_dir, exist_ok=True)
        self.request_delay = 0.15
        self.files_found = []
        self.errors = []
        self.stats = {
            "total_files": 0,
            "total_folders": 0,
            "total_size_bytes": 0,
            "access_denied": 0,
            "drives_crawled": 0,
        }

    def _sp_headers(self):
        """Headers for SharePoint REST API."""
        if self.auth.auth_method == "cookies":
            return {
                "Cookie": self.auth.cookies,
                "Accept": "application/json;odata=nometadata",
            }
        return {
            "Authorization": f"Bearer {self.auth.access_token}",
            "Accept": "application/json;odata=verbose",
        }

    def crawl_drives(self, drives: list, content_inspection: bool = True) -> list:
        """Crawl all drives via SharePoint REST API."""
        console.print(f"\n[yellow][*] Crawling {len(drives)} document libraries (REST API)...[/yellow]")

        if content_inspection:
            console.print(f"[dim]    Download dir: {self.download_dir}[/dim]")
            console.print(f"[dim]    Max file size for download: {self.max_file_size // (1024*1024)}MB[/dim]")

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TaskProgressColumn(),
            console=console,
        ) as progress:
            task = progress.add_task("Crawling...", total=len(drives))

            for drive in drives:
                drive_name = drive.get("name", "Unknown")
                site_name = drive.get("siteName", "Unknown")
                progress.update(task, description=f"[cyan]{site_name}[/cyan] / {drive_name}")

                self._crawl_library(drive, content_inspection)
                self.stats["drives_crawled"] += 1
                progress.advance(task)

        console.print(f"\n[green][+] Crawl complete![/green]")
        console.print(f"    Files found: {self.stats['total_files']}")
        console.print(f"    Folders traversed: {self.stats['total_folders']}")
        console.print(f"    Total data size: {self._format_size(self.stats['total_size_bytes'])}")
        console.print(f"    Access denied: {self.stats['access_denied']}")

        return self.files_found

    def _crawl_library(self, drive: dict, content_inspection: bool):
        """Crawl a single document library."""
        server_rel_url = drive.get("serverRelativeUrl", "")
        site_url = drive.get("siteUrl", self.sp_base_url)

        if not server_rel_url:
            return

        self._crawl_folder_recursive(
            site_url=site_url,
            folder_url=server_rel_url,
            drive=drive,
            folder_path="/",
            content_inspection=content_inspection,
            depth=0,
        )

    def _crawl_folder_recursive(self, site_url: str, folder_url: str, drive: dict,
                                 folder_path: str, content_inspection: bool, depth: int):
        """Recursively crawl a folder."""
        if depth > 50:
            return

        # Get files in this folder
        files_url = (f"{site_url}/_api/web/GetFolderByServerRelativeUrl('{folder_url}')/Files"
                     f"?$select=Name,ServerRelativeUrl,Length,TimeCreated,TimeLastModified,"
                     f"Author/Title,ModifiedBy/Title"
                     f"&$expand=Author,ModifiedBy")

        try:
            response = requests.get(files_url, headers=self._sp_headers(), timeout=15)

            if response.status_code == 200:
                data = response.json()
                if "d" in data:
                    files = data["d"].get("results", [])
                else:
                    files = data.get("value", [])

                for item in files:
                    # Author/ModifiedBy can be nested differently depending on odata format
                    author = item.get("Author", {})
                    modified_by = item.get("ModifiedBy", {})
                    if isinstance(author, dict):
                        author_name = author.get("Title", "Unknown")
                    else:
                        author_name = "Unknown"
                    if isinstance(modified_by, dict):
                        modified_name = modified_by.get("Title", "Unknown")
                    else:
                        modified_name = "Unknown"

                    file_info = {
                        "id": item.get("ServerRelativeUrl", ""),
                        "name": item.get("Name", ""),
                        "size": int(item.get("Length", 0)),
                        "mimeType": "",
                        "webUrl": f"{self.sp_base_url}{item.get('ServerRelativeUrl', '')}",
                        "folderPath": folder_path,
                        "fullPath": f"{folder_path}{item.get('Name', '')}",
                        "driveId": drive.get("id", ""),
                        "driveName": drive.get("name", "Unknown"),
                        "siteName": drive.get("siteName", "Unknown"),
                        "createdBy": author_name,
                        "modifiedBy": modified_name,
                        "createdDateTime": item.get("TimeCreated", ""),
                        "lastModifiedDateTime": item.get("TimeLastModified", ""),
                        "serverRelativeUrl": item.get("ServerRelativeUrl", ""),
                        "siteUrl": site_url,
                        "local_path": None,
                        "findings": [],
                        "api_type": "sharepoint",
                    }

                    self.files_found.append(file_info)
                    self.stats["total_files"] += 1
                    self.stats["total_size_bytes"] += file_info["size"]

                    # Download for content inspection
                    if content_inspection and self._should_download(item):
                        local_path = self._download_file(site_url, item)
                        if local_path:
                            file_info["local_path"] = local_path

            elif response.status_code == 403:
                self.stats["access_denied"] += 1
            elif response.status_code == 429:
                retry_after = int(response.headers.get("Retry-After", 30))
                time.sleep(retry_after)

        except requests.RequestException as e:
            self.errors.append({"folder": folder_path, "error": str(e)})

        time.sleep(self.request_delay)

        # Get subfolders
        folders_url = (f"{site_url}/_api/web/GetFolderByServerRelativeUrl('{folder_url}')/Folders"
                       f"?$select=Name,ServerRelativeUrl,ItemCount")

        try:
            response = requests.get(folders_url, headers=self._sp_headers(), timeout=15)

            if response.status_code == 200:
                data = response.json()
                if "d" in data:
                    folders = data["d"].get("results", [])
                else:
                    folders = data.get("value", [])

                for folder in folders:
                    folder_name = folder.get("Name", "")
                    # Skip system folders
                    if folder_name in ("Forms", "_private", "_catalogs", "_cts"):
                        continue

                    self.stats["total_folders"] += 1
                    sub_url = folder.get("ServerRelativeUrl", "")
                    sub_path = f"{folder_path}{folder_name}/"

                    self._crawl_folder_recursive(
                        site_url=site_url,
                        folder_url=sub_url,
                        drive=drive,
                        folder_path=sub_path,
                        content_inspection=content_inspection,
                        depth=depth + 1,
                    )

        except requests.RequestException:
            pass

    def _should_download(self, item: dict) -> bool:
        """Check if file should be downloaded for content inspection."""
        size = int(item.get("Length", 0))
        if size > self.max_file_size or size == 0:
            return False

        name = item.get("Name", "").lower()

        inspectable_extensions = {
            ".txt", ".csv", ".json", ".xml", ".yaml", ".yml", ".ini", ".cfg",
            ".conf", ".config", ".env", ".properties", ".toml",
            ".ps1", ".bat", ".cmd", ".sh", ".bash", ".py", ".rb", ".pl",
            ".sql", ".bak", ".log", ".md", ".rst",
            ".asp", ".aspx", ".php", ".jsp", ".js", ".ts",
            ".htaccess", ".htpasswd", ".gitconfig",
            ".rdp", ".reg", ".inf",
            ".pem", ".key", ".crt", ".cer", ".csr",
            ".kdbx", ".kdb", ".pfx", ".p12", ".ppk", ".ovpn",
            ".docx", ".xlsx", ".pptx",
        }

        for ext in inspectable_extensions:
            if name.endswith(ext):
                return True

        return False

    def _download_file(self, site_url: str, item: dict) -> str:
        """Download a file via SharePoint REST API."""
        server_rel_url = item.get("ServerRelativeUrl", "")
        name = item.get("Name", "unknown")

        url = f"{site_url}/_api/web/GetFileByServerRelativeUrl('{server_rel_url}')/$value"

        try:
            if self.auth.auth_method == "cookies":
                dl_headers = {"Cookie": self.auth.cookies}
            else:
                dl_headers = {"Authorization": f"Bearer {self.auth.access_token}"}

            response = requests.get(
                url,
                headers=dl_headers,
                timeout=30,
                stream=True,
            )

            if response.status_code == 200:
                safe_name = "".join(c if c.isalnum() or c in "._-" else "_" for c in name)
                local_path = os.path.join(self.download_dir, f"sp_{safe_name}")

                with open(local_path, "wb") as f:
                    for chunk in response.iter_content(chunk_size=8192):
                        f.write(chunk)

                return local_path

            elif response.status_code == 429:
                retry_after = int(response.headers.get("Retry-After", 30))
                time.sleep(retry_after)

        except requests.RequestException:
            pass

        return None

    @staticmethod
    def _format_size(size_bytes: int) -> str:
        for unit in ["B", "KB", "MB", "GB", "TB"]:
            if size_bytes < 1024:
                return f"{size_bytes:.1f} {unit}"
            size_bytes /= 1024
        return f"{size_bytes:.1f} PB"
