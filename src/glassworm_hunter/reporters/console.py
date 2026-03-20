"""Terminal output reporter using rich."""

from __future__ import annotations

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from ..engine.models import Finding, Report, Severity

_SEVERITY_COLORS = {
    Severity.CRITICAL: "bold red",
    Severity.HIGH: "red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "blue",
}

_SEVERITY_ICONS = {
    Severity.CRITICAL: "[bold red]CRIT[/]",
    Severity.HIGH: "[red]HIGH[/]",
    Severity.MEDIUM: "[yellow]MED [/]",
    Severity.LOW: "[blue]LOW [/]",
}


def print_report(report: Report, console: Console | None = None) -> None:
    """Print scan report to terminal."""
    if console is None:
        console = Console()

    if not report.has_findings:
        console.print()
        console.print(
            Panel(
                "[bold green]No GlassWorm indicators detected[/]",
                title="glassworm-hunter",
                border_style="green",
            )
        )
        _print_summary(report, console)
        return

    console.print()

    # Group findings by severity
    sorted_findings = sorted(
        report.all_findings,
        key=lambda f: [
            Severity.CRITICAL,
            Severity.HIGH,
            Severity.MEDIUM,
            Severity.LOW,
        ].index(f.severity),
    )

    for finding in sorted_findings:
        _print_finding(finding, console)

    _print_summary(report, console)


def _print_finding(finding: Finding, console: Console) -> None:
    """Print a single finding."""
    severity_str = _SEVERITY_ICONS[finding.severity]
    color = _SEVERITY_COLORS[finding.severity]

    location = str(finding.file_path)
    if finding.line_number is not None:
        location += f":{finding.line_number}"
        if finding.column is not None:
            location += f":{finding.column}"

    console.print(f"  {severity_str}  [{color}]{finding.title}[/]")
    console.print(f"         [dim]{location}[/]")

    evidence = finding.evidence
    if len(evidence) > 200:
        evidence = evidence[:200] + "..."
    console.print(f"         {evidence}")
    console.print()


def _print_summary(report: Report, console: Console) -> None:
    """Print scan summary."""
    console.print()

    table = Table(show_header=False, box=None, padding=(0, 2))
    table.add_column("label", style="dim")
    table.add_column("value")

    table.add_row("Files scanned", str(report.total_files_scanned))
    table.add_row("Total findings", str(report.total_findings))

    if report.has_findings:
        crit = report.count_by_severity(Severity.CRITICAL)
        high = report.count_by_severity(Severity.HIGH)
        med = report.count_by_severity(Severity.MEDIUM)
        low = report.count_by_severity(Severity.LOW)

        breakdown = []
        if crit:
            breakdown.append(f"[bold red]{crit} critical[/]")
        if high:
            breakdown.append(f"[red]{high} high[/]")
        if med:
            breakdown.append(f"[yellow]{med} medium[/]")
        if low:
            breakdown.append(f"[blue]{low} low[/]")
        table.add_row("Breakdown", ", ".join(breakdown))

    # Scanner durations
    for result in report.results:
        if result.scan_duration_seconds > 0:
            table.add_row(
                f"Scanner: {result.scanner_name}",
                f"{result.scan_duration_seconds:.1f}s ({result.files_scanned} files)",
            )

    if report.results:
        errors = []
        for r in report.results:
            errors.extend(r.errors)
        if errors:
            table.add_row("Errors", str(len(errors)))

    console.print(table)
    console.print()
