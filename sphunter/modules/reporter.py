"""
SPHunter Reporting Module

Generates output in multiple formats:
- Console (live, already handled by detector)
- CSV (for filtering/analysis)
- HTML (for pentest reports)
- JSON (for programmatic use)
"""

import os
import csv
import json
from datetime import datetime
from jinja2 import Template
from rich.console import Console
from rich.table import Table

console = Console()

HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SPHunter Report - {{ timestamp }}</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #0d1117; color: #c9d1d9; padding: 20px; }
        .header { background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 24px; margin-bottom: 20px; }
        .header h1 { color: #58a6ff; font-size: 24px; margin-bottom: 8px; }
        .header .subtitle { color: #8b949e; font-size: 14px; }
        .stats { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 12px; margin: 20px 0; }
        .stat-card { background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 16px; text-align: center; }
        .stat-card .number { font-size: 28px; font-weight: bold; }
        .stat-card .label { font-size: 12px; color: #8b949e; margin-top: 4px; }
        .black .number { color: #e6edf3; }
        .red .number { color: #f85149; }
        .yellow .number { color: #d29922; }
        .green .number { color: #3fb950; }
        .findings-table { width: 100%; border-collapse: collapse; margin-top: 20px; }
        .findings-table th { background: #161b22; color: #58a6ff; padding: 12px; text-align: left; border-bottom: 2px solid #30363d; font-size: 12px; text-transform: uppercase; position: sticky; top: 0; cursor: pointer; }
        .findings-table td { padding: 10px 12px; border-bottom: 1px solid #21262d; font-size: 13px; vertical-align: top; }
        .findings-table tr:hover { background: #161b22; }
        .sev-badge { padding: 2px 8px; border-radius: 12px; font-size: 11px; font-weight: bold; text-transform: uppercase; }
        .sev-black { background: #e6edf322; color: #e6edf3; border: 1px solid #e6edf3; }
        .sev-red { background: #f8514922; color: #f85149; }
        .sev-yellow { background: #d2992222; color: #d29922; }
        .sev-green { background: #3fb95022; color: #3fb950; }
        a { color: #58a6ff; text-decoration: none; }
        a:hover { text-decoration: underline; }
        .file-path { font-family: 'Cascadia Code', 'Fira Code', monospace; font-size: 12px; color: #e6edf3; }
        .match-info { font-size: 11px; color: #8b949e; }
        .section-title { color: #58a6ff; font-size: 18px; margin: 24px 0 12px 0; padding-bottom: 8px; border-bottom: 1px solid #30363d; }
        .filter-bar { background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 12px; margin-bottom: 12px; }
        .filter-bar input { background: #0d1117; border: 1px solid #30363d; color: #c9d1d9; padding: 6px 12px; border-radius: 4px; width: 300px; }
        .footer { margin-top: 30px; padding-top: 15px; border-top: 1px solid #30363d; color: #8b949e; font-size: 12px; text-align: center; }
    </style>
</head>
<body>
    <div class="header">
        <h1>SPHunter Report</h1>
        <div class="subtitle">SharePoint Sensitive File Assessment | Generated: {{ timestamp }} | Auth: {{ auth_method }}</div>
    </div>

    <div class="stats">
        <div class="stat-card"><div class="number">{{ total_files }}</div><div class="label">Files Scanned</div></div>
        <div class="stat-card"><div class="number">{{ total_findings }}</div><div class="label">Findings</div></div>
        <div class="stat-card black"><div class="number">{{ severity_counts.get('black', 0) }}</div><div class="label">Black</div></div>
        <div class="stat-card red"><div class="number">{{ severity_counts.get('red', 0) }}</div><div class="label">Red</div></div>
        <div class="stat-card yellow"><div class="number">{{ severity_counts.get('yellow', 0) }}</div><div class="label">Yellow</div></div>
        <div class="stat-card green"><div class="number">{{ severity_counts.get('green', 0) }}</div><div class="label">Green</div></div>
    </div>

    <h2 class="section-title">Sites Enumerated ({{ sites|length }})</h2>
    <table class="findings-table">
        <thead><tr><th>Site Name</th><th>URL</th><th>Libraries</th></tr></thead>
        <tbody>
        {% for site in sites %}
        <tr>
            <td>{{ site.displayName }}</td>
            <td><a href="{{ site.webUrl }}" target="_blank">{{ site.webUrl }}</a></td>
            <td>{{ site.get('drive_count', 0) }}</td>
        </tr>
        {% endfor %}
        </tbody>
    </table>

    <h2 class="section-title">Findings ({{ total_findings }})</h2>
    <div class="filter-bar">
        <input type="text" id="filterInput" placeholder="Filter findings..." onkeyup="filterTable()">
    </div>
    <table class="findings-table" id="findingsTable">
        <thead>
            <tr>
                <th onclick="sortTable(0)">Severity</th>
                <th onclick="sortTable(1)">Site</th>
                <th onclick="sortTable(2)">File Path</th>
                <th onclick="sortTable(3)">Rule(s)</th>
                <th onclick="sortTable(4)">Details</th>
                <th>Link</th>
            </tr>
        </thead>
        <tbody>
        {% for finding in findings %}
        <tr>
            <td><span class="sev-badge sev-{{ finding.highest_severity }}">{{ finding.highest_severity }}</span></td>
            <td>{{ finding.file.siteName }}</td>
            <td class="file-path">{{ finding.file.fullPath }}</td>
            <td>{% for f in finding.findings %}{{ f.rule_name }}{% if not loop.last %}, {% endif %}{% endfor %}</td>
            <td class="match-info">
                {% for f in finding.findings %}
                {{ f.match_type }}: {{ f.description }}
                {% if f.get('match_count') %}({{ f.match_count }} matches){% endif %}
                {% if not loop.last %}<br>{% endif %}
                {% endfor %}
            </td>
            <td><a href="{{ finding.file.webUrl }}" target="_blank">Open</a></td>
        </tr>
        {% endfor %}
        </tbody>
    </table>

    <div class="footer">
        Generated by SPHunter v1.0.0 | For authorized penetration testing only
    </div>

    <script>
    function filterTable() {
        const filter = document.getElementById('filterInput').value.toLowerCase();
        const rows = document.querySelectorAll('#findingsTable tbody tr');
        rows.forEach(row => {
            const text = row.textContent.toLowerCase();
            row.style.display = text.includes(filter) ? '' : 'none';
        });
    }
    function sortTable(col) {
        const table = document.getElementById('findingsTable');
        const rows = Array.from(table.querySelectorAll('tbody tr'));
        const ascending = table.dataset.sortCol == col ? !(table.dataset.sortAsc === 'true') : true;
        table.dataset.sortCol = col;
        table.dataset.sortAsc = ascending;
        rows.sort((a, b) => {
            const aText = a.cells[col].textContent.trim();
            const bText = b.cells[col].textContent.trim();
            return ascending ? aText.localeCompare(bText) : bText.localeCompare(aText);
        });
        const tbody = table.querySelector('tbody');
        rows.forEach(row => tbody.appendChild(row));
    }
    </script>
</body>
</html>"""


class ReportGenerator:
    """Generates SPHunter reports in multiple formats."""

    def __init__(self, output_dir: str):
        self.output_dir = output_dir
        os.makedirs(output_dir, exist_ok=True)

    def generate_all(self, findings: list, sites: list, drives: list, crawl_stats: dict, auth_info: dict, all_files: list = None):
        """Generate reports in all formats."""
        console.print(f"\n[yellow][*] Generating reports in: {self.output_dir}[/yellow]")

        self._generate_csv(findings)
        self._generate_json(findings, sites, drives, crawl_stats, auth_info)
        self._generate_html(findings, sites, drives, crawl_stats, auth_info)
        if all_files:
            self._generate_all_files_csv(all_files)
        self._print_console_summary(findings, sites, drives, crawl_stats)

    def _generate_all_files_csv(self, all_files: list):
        """Generate a CSV listing every crawled file regardless of findings."""
        csv_path = os.path.join(self.output_dir, "sphunter_all_files.csv")

        with open(csv_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow([
                "Site", "Library", "File Path", "File Name", "Extension",
                "Size (bytes)", "Last Modified", "Modified By", "Downloaded", "SharePoint URL",
            ])
            for file_info in all_files:
                name = file_info.get("name", "")
                ext = os.path.splitext(name)[1] if "." in name else "(none)"
                writer.writerow([
                    file_info.get("siteName", ""),
                    file_info.get("driveName", ""),
                    file_info.get("fullPath", ""),
                    name,
                    ext,
                    file_info.get("size", 0),
                    file_info.get("lastModifiedDateTime", ""),
                    file_info.get("modifiedBy", ""),
                    "Yes" if file_info.get("local_path") else "No",
                    file_info.get("webUrl", ""),
                ])

        console.print(f"    [+] All files: {csv_path}")

    def _generate_csv(self, findings: list):
        """Generate CSV report."""
        csv_path = os.path.join(self.output_dir, "sphunter_findings.csv")

        with open(csv_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow([
                "Severity", "Site", "Drive", "File Path", "File Name",
                "Size (bytes)", "Rule Name", "Match Type", "Description",
                "Created By", "Modified By", "Last Modified", "SharePoint URL",
            ])

            for finding in findings:
                file_info = finding["file"]
                for hit in finding["findings"]:
                    writer.writerow([
                        hit["severity"],
                        file_info["siteName"],
                        file_info["driveName"],
                        file_info["fullPath"],
                        file_info["name"],
                        file_info["size"],
                        hit["rule_name"],
                        hit["match_type"],
                        hit["description"],
                        file_info["createdBy"],
                        file_info["modifiedBy"],
                        file_info["lastModifiedDateTime"],
                        file_info["webUrl"],
                    ])

        console.print(f"    [+] CSV: {csv_path}")

    def _generate_json(self, findings: list, sites: list, drives: list, crawl_stats: dict, auth_info: dict):
        """Generate JSON report."""
        json_path = os.path.join(self.output_dir, "sphunter_findings.json")

        report = {
            "metadata": {
                "tool": "SPHunter",
                "version": "1.0.0",
                "timestamp": datetime.now().isoformat(),
                "auth_method": auth_info.get("auth_method", "unknown"),
                "user_context": auth_info.get("user", "unknown"),
            },
            "summary": {
                "sites_enumerated": len(sites),
                "drives_enumerated": len(drives),
                "files_scanned": crawl_stats.get("total_files", 0),
                "findings_count": len(findings),
                "severity_breakdown": self._count_severities(findings),
            },
            "sites": sites,
            "findings": [
                {
                    "severity": f["highest_severity"],
                    "file_name": f["file"]["name"],
                    "file_path": f["file"]["fullPath"],
                    "site": f["file"]["siteName"],
                    "drive": f["file"]["driveName"],
                    "size": f["file"]["size"],
                    "web_url": f["file"]["webUrl"],
                    "created_by": f["file"]["createdBy"],
                    "modified_by": f["file"]["modifiedBy"],
                    "last_modified": f["file"]["lastModifiedDateTime"],
                    "rules_matched": [
                        {
                            "name": hit["rule_name"],
                            "type": hit["match_type"],
                            "severity": hit["severity"],
                            "description": hit["description"],
                        }
                        for hit in f["findings"]
                    ],
                }
                for f in findings
            ],
        }

        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2, default=str)

        console.print(f"    [+] JSON: {json_path}")

    def _generate_html(self, findings: list, sites: list, drives: list, crawl_stats: dict, auth_info: dict):
        """Generate HTML report."""
        html_path = os.path.join(self.output_dir, "sphunter_report.html")

        # Count drives per site
        drive_counts = {}
        for drive in drives:
            site_name = drive.get("siteName", "Unknown")
            drive_counts[site_name] = drive_counts.get(site_name, 0) + 1

        for site in sites:
            site["drive_count"] = drive_counts.get(site["displayName"], 0)

        template = Template(HTML_TEMPLATE)
        html_content = template.render(
            timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            auth_method=auth_info.get("auth_method", "unknown"),
            total_files=crawl_stats.get("total_files", 0),
            total_findings=len(findings),
            severity_counts=self._count_severities(findings),
            sites=sites,
            findings=findings,
        )

        with open(html_path, "w", encoding="utf-8") as f:
            f.write(html_content)

        console.print(f"    [+] HTML: {html_path}")

    def _print_console_summary(self, findings: list, sites: list, drives: list, crawl_stats: dict):
        """Print a rich console summary table."""
        console.print()

        table = Table(title="SPHunter Results Summary", border_style="blue")
        table.add_column("Metric", style="cyan")
        table.add_column("Value", style="white")

        table.add_row("Sites Enumerated", str(len(sites)))
        table.add_row("Document Libraries", str(len(drives)))
        table.add_row("Files Scanned", str(crawl_stats.get("total_files", 0)))
        table.add_row("Folders Traversed", str(crawl_stats.get("total_folders", 0)))
        table.add_row("Total Findings", str(len(findings)))

        severity_counts = self._count_severities(findings)
        table.add_row("[bold white on black]Black[/bold white on black]", str(severity_counts.get("black", 0)))
        table.add_row("[bold red]Red[/bold red]", str(severity_counts.get("red", 0)))
        table.add_row("[yellow]Yellow[/yellow]", str(severity_counts.get("yellow", 0)))
        table.add_row("[green]Green[/green]", str(severity_counts.get("green", 0)))

        console.print(table)

        # Top affected sites
        if findings:
            console.print("\n[bold]Top Affected Sites:[/bold]")
            site_counts = {}
            for f in findings:
                site = f["file"]["siteName"]
                # Normalize: extract short name from full URL
                if "/sites/" in site:
                    site = site.split("/sites/")[-1].split("/")[0]
                elif "/teams/" in site:
                    site = site.split("/teams/")[-1].split("/")[0]
                site_counts[site] = site_counts.get(site, 0) + 1

            for site, count in sorted(site_counts.items(), key=lambda x: x[1], reverse=True)[:10]:
                console.print(f"    {site}: {count} findings")

    @staticmethod
    def _count_severities(findings: list) -> dict:
        """Count findings by severity level."""
        counts = {}
        for f in findings:
            sev = f["highest_severity"]
            counts[sev] = counts.get(sev, 0) + 1
        return counts
