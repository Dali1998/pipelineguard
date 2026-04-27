"""
Rich-formatted console reporter.
Falls back to plain ANSI codes if `rich` is not installed.
"""

from __future__ import annotations

from pipelineguard.core.scanner import ScanResult
from pipelineguard.models.issue import Severity

try:
    from rich import box
    from rich.console import Console
    from rich.table import Table
    from rich.text import Text

    _RICH = True
except ImportError:
    _RICH = False


_SEVERITY_COLOR = {
    Severity.CRITICAL: "bold red",
    Severity.HIGH: "red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "cyan",
    Severity.INFO: "dim",
}

_ANSI_SEVERITY = {
    Severity.CRITICAL: "\033[1;31m",  # bold red
    Severity.HIGH: "\033[31m",  # red
    Severity.MEDIUM: "\033[33m",  # yellow
    Severity.LOW: "\033[36m",  # cyan
    Severity.INFO: "\033[2m",  # dim
}
_ANSI_RESET = "\033[0m"


def print_report(result: ScanResult, show_remediation: bool = True) -> None:
    if _RICH:
        _rich_report(result, show_remediation)
    else:
        _plain_report(result, show_remediation)


# ---------------------------------------------------------------------------
# Rich renderer
# ---------------------------------------------------------------------------


def _rich_report(result: ScanResult, show_remediation: bool) -> None:
    console = Console()
    summary = result.summary()

    console.rule("[bold]PipelineGuard Scan Report[/bold]")
    console.print(
        f"\n[bold]Scanned:[/bold] {summary['scanned_files']} file(s)  "
        f"[bold]Skipped:[/bold] {summary['skipped_files']} file(s)  "
        f"[bold]Total issues:[/bold] {summary['total_issues']}\n"
    )

    if not result.issues:
        console.print("[green]✔  No issues found.[/green]\n")
        return

    table = Table(box=box.ROUNDED, show_lines=True, expand=True)
    table.add_column("Severity", style="bold", width=10)
    table.add_column("Rule", width=10)
    table.add_column("Title", width=30)
    table.add_column("File / Job")
    if show_remediation:
        table.add_column("Remediation")

    # Sort: critical → high → medium → low → info
    _ORDER = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]
    sorted_issues = sorted(result.issues, key=lambda i: _ORDER.index(i.severity))

    for issue in sorted_issues:
        color = _SEVERITY_COLOR.get(issue.severity, "white")
        sev_text = Text(issue.severity.value.upper(), style=color)
        location = f"{issue.source_file}"
        if issue.job_name:
            location += f"\n[dim]job: {issue.job_name}[/dim]"
        row = [sev_text, issue.rule_id, issue.title, location]
        if show_remediation:
            row.append(issue.remediation or "—")
        table.add_row(*row)

    console.print(table)
    _print_severity_summary(console, summary["by_severity"])


def _print_severity_summary(console, counts: dict) -> None:
    parts = []
    for sev in ("critical", "high", "medium", "low", "info"):
        n = counts.get(sev, 0)
        if n:
            color = _SEVERITY_COLOR.get(Severity(sev), "white")
            parts.append(f"[{color}]{n} {sev}[/{color}]")
    console.print("\n" + "  ".join(parts) + "\n")


# ---------------------------------------------------------------------------
# Plain fallback renderer
# ---------------------------------------------------------------------------


def _plain_report(result: ScanResult, show_remediation: bool) -> None:
    summary = result.summary()
    print("=" * 60)
    print("PipelineGuard Scan Report")
    print("=" * 60)
    print(
        f"Scanned: {summary['scanned_files']} file(s) | "
        f"Skipped: {summary['skipped_files']} | "
        f"Issues: {summary['total_issues']}"
    )
    print()

    if not result.issues:
        print("✔  No issues found.")
        return

    for issue in result.issues:
        color = _ANSI_SEVERITY.get(issue.severity, "")
        print(
            f"{color}[{issue.severity.value.upper()}]{_ANSI_RESET} {issue.rule_id} – {issue.title}"
        )
        print(f"  File : {issue.source_file}")
        if issue.job_name:
            print(f"  Job  : {issue.job_name}")
        if issue.evidence:
            print(f"  Found: {issue.evidence}")
        if show_remediation and issue.remediation:
            print(f"  Fix  : {issue.remediation}")
        print()
