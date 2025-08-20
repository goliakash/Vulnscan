# output/formatter.py
from rich.console import Console
from rich.table import Table
from pathlib import Path
import json
from datetime import datetime

console = Console()


class ConsoleReporter:
    def report(self, data: dict):
        """Pretty-print scan results to the console."""
        target = data.get("target")
        rows = data.get("results", [])

        console.print(f"[bold magenta]VulnScan results for: {target}[/bold magenta]")

        table = Table(show_header=True, header_style="bold cyan")
        table.add_column("Port", justify="right")
        table.add_column("Status")
        table.add_column("Service")
        table.add_column("Banner", overflow="fold")
        table.add_column("#CVEs")

        total_vulns, open_ports = 0, 0
        for r in rows:
            cv_count = sum(len(v.get("cves", [])) for v in r.get("vulnerabilities", []))
            total_vulns += cv_count
            if r.get("status") == "OPEN":
                open_ports += 1
            banner_snip = (r.get("banner", {}) or {}).get("raw") if isinstance(r.get("banner"), dict) else r.get("banner")
            if banner_snip and len(str(banner_snip)) > 60:
                banner_snip = str(banner_snip)[:57] + "..."
            table.add_row(str(r["port"]), r["status"], str(r.get("service") or "-"), str(banner_snip or ""), str(cv_count))

        console.print(table)
        console.print(f"Total open ports: {open_ports} | Total CVEs found: {total_vulns}")


class JSONReporter:
    def save(self, data: dict, target: str = "target") -> str:
        """Save scan results to a JSON file."""
        now = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        fname = Path(f"vulnscan_{target}_{now}.json")
        with open(fname, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        return str(fname)
