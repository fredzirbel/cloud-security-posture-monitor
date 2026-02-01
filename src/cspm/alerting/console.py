"""Rich console output for scan results."""

from __future__ import annotations

from rich.console import Console
from rich.table import Table
from rich.panel import Panel

from cspm.models import ScanResult, Status, Severity

SEVERITY_COLORS = {
    Severity.CRITICAL: "bold red",
    Severity.HIGH: "red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "cyan",
    Severity.INFO: "white",
}

console = Console()


def print_findings(result: ScanResult, show_remediation: bool = False) -> None:
    failures = [f for f in result.findings if f.status == Status.FAIL]
    passes = [f for f in result.findings if f.status == Status.PASS]

    console.print(Panel(
        f"[bold]Scan ID:[/bold] {result.scan_id}\n"
        f"[bold]Timestamp:[/bold] {result.timestamp.isoformat()}\n"
        f"[bold]Region(s):[/bold] {result.region}\n"
        f"[bold]Total checks:[/bold] {len(result.findings)}  |  "
        f"[green]PASS: {len(passes)}[/green]  |  "
        f"[red]FAIL: {len(failures)}[/red]",
        title="CSPM Scan Summary",
        border_style="blue",
    ))

    if not failures:
        console.print("\n[green bold]All checks passed.[/green bold]\n")
        return

    table = Table(title="Failed Checks", show_lines=True, expand=True)
    table.add_column("Severity", style="bold", width=10, no_wrap=True)
    table.add_column("CIS", width=6, no_wrap=True)
    table.add_column("Check", ratio=2)
    table.add_column("Resource", ratio=3)
    table.add_column("Description", ratio=3)

    sorted_failures = sorted(failures, key=lambda f: f.severity)

    for f in sorted_failures:
        color = SEVERITY_COLORS.get(f.severity, "white")
        table.add_row(
            f"[{color}]{f.severity.value}[/{color}]",
            f.cis_id,
            f.title,
            f.resource_arn,
            f.description,
        )

    console.print(table)

    if show_remediation:
        console.print("\n[bold]Remediation Commands:[/bold]\n")
        for f in sorted_failures:
            color = SEVERITY_COLORS.get(f.severity, "white")
            console.print(f"  [{color}][{f.severity.value}][/{color}] {f.check_id} — {f.resource_arn}")
            console.print(f"    $ {f.remediation}\n")
