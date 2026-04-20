"""
SPHunter Crawler Module

Recursively walks SharePoint document libraries and OneDrive folders,
collecting file metadata and optionally downloading files for content inspection.
"""

import os
import time
import tempfile
import requests
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn

console = Console()

GRAPH_BASE_URL = "https://graph.microsoft.com/v1.0"


class SharePointCrawler:
    """Recursively crawls SharePoint document libraries via Graph API."""

    def __init__(self, auth_handler, max_file_size_mb: int = 5, download_dir: str = None):
        self.auth = auth_handler
        self.max_file_size = max_file_size_mb * 1024 * 1024  # Convert to bytes
        self.download_dir = download_dir or tempfile.mkdtemp(prefix="sphunter_")
        os.makedirs(self.download_dir, exist_ok=True)
        self.request_delay = 0.15
        self.files_found = []
        self.folders_crawled = 0
        self.errors = []
        self.stats = {
            "total_files": 0,
            "total_folders": 0,
            "total_size_bytes": 0,
            "access_denied": 0,
            "drives_crawled": 0,
        }

    def crawl_drives(self, drives: list, content_inspection: bool = True) -> list:
        """
        Crawl all provided drives recursively.

        Args:
            drives: List of drive dicts from the enumerator.
            content_inspection: If True, download text-based files for content scanning.

        Returns:
            List of file metadata dicts.
        """
        console.print(f"\n[yellow][*] Crawling {len(drives)} document libraries...[/yellow]")

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

                self._crawl_drive(drive, content_inspection)
                self.stats["drives_crawled"] += 1
                progress.advance(task)

        console.print(f"\n[green][+] Crawl complete![/green]")
        console.print(f"    Files found: {self.stats['total_files']}")
        console.print(f"    Folders traversed: {self.stats['total_folders']}")
        console.print(f"    Total data size: {self._format_size(self.stats['total_size_bytes'])}")
        console.print(f"    Access denied: {self.stats['access_denied']}")

        return self.files_found

    def _crawl_drive(self, drive: dict, content_inspection: bool):
        """Crawl a single drive starting from root."""
        drive_id = drive.get("id")
        if not drive_id:
            return

        url = f"{GRAPH_BASE_URL}/drives/{drive_id}/root/children?$top=200"
        url += "&$select=id,name,size,file,folder,webUrl,lastModifiedDateTime,createdDateTime,createdBy,lastModifiedBy,parentReference"

        self._crawl_folder(
            url=url,
            drive=drive,
            folder_path="/",
            content_inspection=content_inspection,
        )

    def _crawl_folder(self, url: str, drive: dict, folder_path: str, content_inspection: bool, depth: int = 0):
        """Recursively crawl a folder and its subfolders."""
        if depth > 50:  # Safety limit
            return

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

                    for item in items:
                        if "folder" in item:
                            # It's a folder — recurse into it
                            self.stats["total_folders"] += 1
                            child_count = item.get("folder", {}).get("childCount", 0)

                            if child_count > 0:
                                subfolder_url = f"{GRAPH_BASE_URL}/drives/{drive['id']}/items/{item['id']}/children?$top=200"
                                subfolder_url += "&$select=id,name,size,file,folder,webUrl,lastModifiedDateTime,createdDateTime,createdBy,lastModifiedBy,parentReference"
                                subfolder_path = f"{folder_path}{item['name']}/"

                                self._crawl_folder(
                                    url=subfolder_url,
                                    drive=drive,
                                    folder_path=subfolder_path,
                                    content_inspection=content_inspection,
                                    depth=depth + 1,
                                )

                        elif "file" in item:
                            # It's a file — collect metadata
                            file_info = self._extract_file_info(item, drive, folder_path)
                            self.files_found.append(file_info)
                            self.stats["total_files"] += 1
                            self.stats["total_size_bytes"] += item.get("size", 0)

                            # Download for content inspection if applicable
                            if content_inspection and self._should_download(item):
                                local_path = self._download_file(item, drive)
                                if local_path:
                                    file_info["local_path"] = local_path

                    # Handle pagination
                    url = data.get("@odata.nextLink")
                    if url:
                        time.sleep(self.request_delay)
                    else:
                        break

                elif response.status_code == 403:
                    self.stats["access_denied"] += 1
                    break
                elif response.status_code == 429:
                    retry_after = int(response.headers.get("Retry-After", 30))
                    console.print(f"[yellow][!] Rate limited. Waiting {retry_after}s...[/yellow]")
                    time.sleep(retry_after)
                    continue
                else:
                    break

            except requests.RequestException as e:
                self.errors.append({"folder": folder_path, "error": str(e)})
                break

            time.sleep(self.request_delay)

    def _extract_file_info(self, item: dict, drive: dict, folder_path: str) -> dict:
        """Extract relevant metadata from a Graph API file item."""
        created_by = item.get("createdBy", {}).get("user", {}).get("displayName", "Unknown")
        modified_by = item.get("lastModifiedBy", {}).get("user", {}).get("displayName", "Unknown")
        mime_type = item.get("file", {}).get("mimeType", "")

        return {
            "id": item.get("id"),
            "name": item.get("name", ""),
            "size": item.get("size", 0),
            "mimeType": mime_type,
            "webUrl": item.get("webUrl", ""),
            "folderPath": folder_path,
            "fullPath": f"{folder_path}{item.get('name', '')}",
            "driveId": drive.get("id"),
            "driveName": drive.get("name", "Unknown"),
            "siteName": drive.get("siteName", "Unknown"),
            "createdBy": created_by,
            "modifiedBy": modified_by,
            "createdDateTime": item.get("createdDateTime", ""),
            "lastModifiedDateTime": item.get("lastModifiedDateTime", ""),
            "local_path": None,
            "findings": [],
        }

    def _should_download(self, item: dict) -> bool:
        """Determine if a file should be downloaded for content inspection."""
        size = item.get("size", 0)
        if size > self.max_file_size or size == 0:
            return False

        name = item.get("name", "").lower()
        mime = item.get("file", {}).get("mimeType", "")

        # Text-based file extensions worth inspecting
        inspectable_extensions = {
            ".txt", ".csv", ".json", ".xml", ".yaml", ".yml", ".ini", ".cfg",
            ".conf", ".config", ".env", ".properties", ".toml",
            ".ps1", ".bat", ".cmd", ".sh", ".bash", ".py", ".rb", ".pl",
            ".sql", ".bak", ".log", ".md", ".rst",
            ".asp", ".aspx", ".php", ".jsp", ".js", ".ts",
            ".htaccess", ".htpasswd", ".gitconfig",
            ".rdp", ".reg", ".inf",
            ".pem", ".key", ".crt", ".cer", ".csr",
            ".kdbx", ".kdb",  # KeePass databases
            ".pfx", ".p12",  # Certificate stores
            ".ppk",  # PuTTY keys
            ".ovpn",  # OpenVPN configs
        }

        # Check by extension
        for ext in inspectable_extensions:
            if name.endswith(ext):
                return True

        # Check by MIME type
        text_mimes = {"text/", "application/json", "application/xml", "application/javascript"}
        for text_mime in text_mimes:
            if mime.startswith(text_mime):
                return True

        # Also download Office docs for metadata (docx, xlsx are zips)
        office_extensions = {".docx", ".xlsx", ".pptx"}
        for ext in office_extensions:
            if name.endswith(ext):
                return True

        return False

    def _download_file(self, item: dict, drive: dict) -> str:
        """Download a file from SharePoint/OneDrive for content inspection."""
        drive_id = drive.get("id")
        item_id = item.get("id")
        name = item.get("name", "unknown")

        url = f"{GRAPH_BASE_URL}/drives/{drive_id}/items/{item_id}/content"

        try:
            response = requests.get(
                url,
                headers=self.auth.get_headers(),
                timeout=30,
                stream=True,
            )

            if response.status_code == 200:
                # Create safe filename with drive context
                safe_name = f"{drive_id[:8]}_{item_id[:8]}_{name}"
                safe_name = "".join(c if c.isalnum() or c in "._-" else "_" for c in safe_name)
                local_path = os.path.join(self.download_dir, safe_name)

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
        """Format bytes to human-readable size."""
        for unit in ["B", "KB", "MB", "GB", "TB"]:
            if size_bytes < 1024:
                return f"{size_bytes:.1f} {unit}"
            size_bytes /= 1024
        return f"{size_bytes:.1f} PB"
