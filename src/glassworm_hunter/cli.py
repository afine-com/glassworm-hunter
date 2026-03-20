"""CLI entry point for glassworm-hunter."""

from __future__ import annotations

import json
import logging
import sys
from pathlib import Path

import click
from rich.console import Console
from rich.progress import BarColumn, MofNCompleteColumn, Progress, SpinnerColumn, TextColumn
from rich.table import Table

from . import __version__
from .engine.models import DetectionType, Report, Severity
from .reporters import console as console_reporter
from .reporters import json_report, sarif
from .scanners import directory, git_repos, npm, pip_packages, vscode


@click.group(invoke_without_command=True)
@click.pass_context
def main(ctx: click.Context) -> None:
    """GlassWorm Scanner - detect supply chain attack payloads."""
    if ctx.invoked_subcommand is None:
        click.echo(ctx.get_help())


@main.command()
def version() -> None:
    """Print version and exit."""
    click.echo(f"glassworm-hunter {__version__}")


@main.command()
@click.argument("paths", nargs=-1, type=click.Path(exists=True, path_type=Path))
@click.option("--extensions/--no-extensions", default=True, help="Scan VS Code/Cursor extensions")
@click.option("--npm-scan/--no-npm-scan", "scan_npm", default=True, help="Scan node_modules")
@click.option("--pip-scan/--no-pip-scan", "scan_pip", default=False, help="Scan Python packages")
@click.option("--git/--no-git", "scan_git", default=True, help="Scan git repos")
@click.option(
    "--format",
    "output_format",
    type=click.Choice(["console", "json", "sarif"]),
    default="console",
    help="Output format",
)
@click.option(
    "--output",
    "output_file",
    type=click.Path(path_type=Path),
    help="Write report to file",
)
@click.option(
    "--severity",
    "min_severity",
    type=click.Choice(["critical", "high", "medium", "low"]),
    default="low",
    help="Minimum severity to report",
)
@click.option("--max-file-size", type=int, default=10 * 1024 * 1024, help="Max file size in bytes")
@click.option("--include-hidden", is_flag=True, help="Scan hidden files/directories")
@click.option("--quiet", is_flag=True, help="Only output findings")
@click.option("--verbose", is_flag=True, help="Show every file being scanned")
@click.option(
    "--exclude",
    "excludes",
    multiple=True,
    help="Glob patterns to exclude from scanning (can be repeated)",
)
@click.option(
    "--disable-rule",
    "disabled_rules",
    multiple=True,
    help="Disable specific detection rules by ID (can be repeated). "
    "Use 'glassworm-hunter rules' to list.",
)
@click.option(
    "--ioc-file",
    "ioc_file",
    type=click.Path(exists=True, dir_okay=False, path_type=Path),
    help="Load additional IoC indicators from a JSON file (merged on top of all other layers).",
)
def scan(
    paths: tuple[Path, ...],
    extensions: bool,
    scan_npm: bool,
    scan_pip: bool,
    scan_git: bool,
    output_format: str,
    output_file: Path | None,
    min_severity: str,
    max_file_size: int,
    include_hidden: bool,
    quiet: bool,
    verbose: bool,
    excludes: tuple[str, ...],
    disabled_rules: tuple[str, ...],
    ioc_file: Path | None,
) -> None:
    """Scan for GlassWorm indicators.

    If no PATHS given, scans the current directory.
    """
    if verbose:
        logging.basicConfig(level=logging.INFO, format="%(message)s")
    elif not quiet:
        logging.basicConfig(level=logging.WARNING, format="%(message)s")

    # Load extra IoC file if provided
    if ioc_file is not None:
        from .engine.ioc import set_extra_ioc_path

        set_extra_ioc_path(ioc_file)

    # Split comma-separated values so both --disable-rule a,b
    # and --disable-rule a --disable-rule b work
    disabled_rules = tuple(
        part.strip() for raw in disabled_rules for part in raw.split(",") if part.strip()
    )
    excludes = tuple(part.strip() for raw in excludes for part in raw.split(",") if part.strip())

    # Validate disabled rules
    valid_rule_ids = {dt.value for dt in DetectionType}
    for rule_id in disabled_rules:
        if rule_id not in valid_rule_ids:
            click.echo(
                f"Warning: unknown rule ID '{rule_id}'. "
                f"Use 'glassworm-hunter rules' to list valid IDs.",
                err=True,
            )

    # Load .glassworm.yml config if present
    scan_paths = list(paths) if paths else [Path.cwd()]
    config_excludes, config_disabled, config_severity = _load_config(scan_paths[0])

    # CLI flags override config file
    effective_excludes = excludes if excludes else config_excludes
    effective_disabled = disabled_rules if disabled_rules else config_disabled
    if min_severity == "low" and config_severity:
        min_severity = config_severity

    stderr_console = Console(stderr=True)
    console = stderr_console if output_format != "console" else Console()

    # Structured data going to stdout must not be polluted with messages
    structured_to_stdout = output_format in ("json", "sarif") and not output_file
    show_progress = not quiet and not verbose and not structured_to_stdout
    show_messages = not quiet and not structured_to_stdout

    if show_messages:
        stderr_console.print(f"[dim]glassworm-hunter v{__version__}[/]")
        if ioc_file:
            stderr_console.print(f"[dim]Extra IoC file: {ioc_file}[/]")
        stderr_console.print()

    results = []

    if show_progress:
        progress = Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            MofNCompleteColumn(),
            console=stderr_console,
            transient=True,
        )
    else:
        progress = None  # type: ignore[assignment]

    # --- Scanning with optional progress bar ---

    if progress:
        progress.start()

    try:
        # Scan VS Code/Cursor extensions
        if extensions:
            if progress:
                task = progress.add_task("Scanning editor extensions...", total=None)
            elif show_messages:
                stderr_console.print("[dim]Scanning editor extensions...[/]")
            ext_results = vscode.scan_extensions(verbose=verbose, max_file_size=max_file_size)
            results.extend(ext_results)
            if progress:
                progress.remove_task(task)

        for scan_path in scan_paths:
            # Scan as directory
            if progress:
                dir_task = progress.add_task(f"Scanning {scan_path.name}/...", total=None)

                def _on_progress(fp: Path, idx: int, total: int, _task: object = dir_task) -> None:
                    progress.update(
                        _task,
                        total=total,
                        completed=idx,
                        description=f"Scanning [cyan]{fp.name}[/]",
                    )
            elif show_messages:
                stderr_console.print(f"[dim]Scanning directory: {scan_path}[/]")
                _on_progress = None  # type: ignore[assignment]
            else:
                _on_progress = None  # type: ignore[assignment]

            dir_result = directory.scan_directory(
                scan_path,
                max_file_size=max_file_size,
                include_hidden=include_hidden,
                verbose=verbose,
                excludes=effective_excludes,
                on_progress=_on_progress,
            )
            results.append(dir_result)
            if progress:
                progress.remove_task(dir_task)

            # Scan git repos
            if scan_git:
                if progress:
                    task = progress.add_task(
                        f"Scanning git repos under {scan_path.name}/...", total=None
                    )
                elif show_messages:
                    stderr_console.print(f"[dim]Scanning git repos under: {scan_path}[/]")
                git_result = git_repos.scan_git_repos(
                    scan_path,
                    verbose=verbose,
                    max_file_size=max_file_size,
                )
                if git_result.files_scanned > 0:
                    results.append(git_result)
                if progress:
                    progress.remove_task(task)

            # Scan node_modules
            if scan_npm:
                if progress:
                    task = progress.add_task(
                        f"Scanning node_modules under {scan_path.name}/...", total=None
                    )
                elif show_messages:
                    stderr_console.print(f"[dim]Scanning node_modules under: {scan_path}[/]")
                npm_result = npm.scan_node_modules(
                    scan_path,
                    verbose=verbose,
                    max_file_size=max_file_size,
                )
                if npm_result.files_scanned > 0 or npm_result.findings:
                    results.append(npm_result)
                if progress:
                    progress.remove_task(task)

        # Scan pip packages
        if scan_pip:
            if progress:
                task = progress.add_task("Scanning Python packages...", total=None)
            elif show_messages:
                stderr_console.print("[dim]Scanning Python packages...[/]")
            pip_result = pip_packages.scan_pip_packages(
                verbose=verbose,
                max_file_size=max_file_size,
            )
            if pip_result.files_scanned > 0:
                results.append(pip_result)
            if progress:
                progress.remove_task(task)

    finally:
        if progress:
            progress.stop()

    # Cross-scanner severity escalation
    _escalate_findings(results)

    # Build report
    severity_filter = Severity(min_severity)
    severity_order = [Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]
    min_index = severity_order.index(severity_filter)

    # Filter findings by minimum severity and disabled rules
    for result in results:
        result.findings = [
            f
            for f in result.findings
            if severity_order.index(f.severity) >= min_index
            and f.detection_type.value not in effective_disabled
        ]

    report = Report(results=results, scanner_version=__version__)

    # Auto-detect format from output file extension when format is console (default)
    if output_file and output_format == "console":
        suffix = output_file.suffix.lower()
        if suffix == ".sarif":
            output_format = "sarif"
        elif suffix == ".json":
            output_format = "json"

    # Output
    if output_format == "json":
        output_text = json_report.generate_json(report)
        if output_file:
            output_file.write_text(output_text, encoding="utf-8")
        else:
            click.echo(output_text)

    elif output_format == "sarif":
        output_text = sarif.generate_sarif(report)
        if output_file:
            output_file.write_text(output_text, encoding="utf-8")
        else:
            click.echo(output_text)

    else:
        # Console format — also support writing to file
        if output_file:
            fh = output_file.open("w", encoding="utf-8")
            file_console = Console(file=fh, force_terminal=False)
            console_reporter.print_report(report, file_console)
        else:
            console_reporter.print_report(report, console)

    # Summary on stderr
    if show_messages:
        total_files = sum(r.files_scanned for r in results)
        total_findings = sum(len(r.findings) for r in results)
        finding_style = "bold red" if total_findings else "green"
        parts = [f"[bold]\u2713[/] Scanned {total_files} files"]
        plural = "s" if total_findings != 1 else ""
        parts.append(f"[{finding_style}]{total_findings} finding{plural}[/]")
        if output_file:
            parts.append(f"report written to [cyan]{output_file}[/]")
        stderr_console.print(", ".join(parts) + ".")

    # Exit code
    if report.has_findings:
        sys.exit(1)
    sys.exit(0)


@main.command()
@click.option("--force", is_flag=True, help="Overwrite existing local IoC database")
@click.option(
    "--source",
    "source_url",
    default=None,
    help="Custom URL to fetch IoC database from (defaults to GitHub main branch).",
)
def update(force: bool, source_url: str | None) -> None:
    """Update local IoC database from GitHub."""
    import urllib.error
    import urllib.request

    user_dir = Path.home() / ".glassworm"
    user_ioc = user_dir / "ioc.json"

    url = source_url or (
        "https://raw.githubusercontent.com/afine-com/glassworm-hunter/main/data/ioc.json"
    )

    console = Console()

    existing = None
    if user_ioc.exists() and not force:
        try:
            with open(user_ioc, encoding="utf-8") as f:
                existing = json.load(f)
            existing_updated = existing.get("last_updated", "unknown")
            console.print(f"[dim]Current local database: {existing_updated}[/]")
        except (json.JSONDecodeError, OSError):
            existing = None

    console.print("[dim]Fetching latest IoC database...[/]")

    try:
        req = urllib.request.Request(
            url, headers={"User-Agent": f"glassworm-hunter/{__version__}"}
        )
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read().decode("utf-8"))
    except (urllib.error.URLError, json.JSONDecodeError, OSError) as e:
        console.print(f"[red]Failed to fetch IoC database: {e}[/]")
        console.print("[dim]Your existing local database (if any) is unchanged.[/]")
        sys.exit(2)

    # Validate
    required_keys = {"schema_version", "extensions", "npm_packages", "c2_ips", "c2_wallets"}
    if not required_keys.issubset(data.keys()):
        console.print("[red]Downloaded file has invalid schema. Aborting.[/]")
        sys.exit(2)

    # Merge with existing if present
    if existing:
        from .engine.ioc import _merge_ioc_dbs

        data = _merge_ioc_dbs(existing, data)

    # Write
    user_dir.mkdir(parents=True, exist_ok=True)
    with open(user_ioc, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)

    # Summary
    ext_count = len(data.get("extensions", []))
    ip_count = len(data.get("c2_ips", []))
    npm_count = len(data.get("npm_packages", []))
    wallet_count = len(data.get("c2_wallets", []))

    console.print(
        f"[green]Updated:[/] {ext_count} extensions, {ip_count} IPs, "
        f"{npm_count} npm packages, {wallet_count} wallets"
    )
    console.print(f"[dim]Saved to {user_ioc}[/]")


@main.command()
def rules() -> None:
    """List all detection rules and their IDs."""
    console = Console()
    table = Table(title="Detection Rules")
    table.add_column("Rule ID", style="cyan")
    table.add_column("Name")

    for dt in DetectionType:
        table.add_row(dt.value, dt.name.replace("_", " ").title())

    console.print(table)


def _escalate_findings(results: list) -> None:
    """Escalate severity when multiple detection types hit the same file."""
    from .engine.models import Finding as _Finding

    # Group findings by file across all results
    by_file: dict[Path, list[tuple[int, int, _Finding]]] = {}
    for ri, result in enumerate(results):
        for fi, finding in enumerate(result.findings):
            by_file.setdefault(finding.file_path, []).append((ri, fi, finding))

    critical_types = {
        DetectionType.INVISIBLE_UNICODE,
        DetectionType.DECODER_PATTERN,
        DetectionType.KNOWN_MALICIOUS_EXTENSION,
        DetectionType.KNOWN_MALICIOUS_PACKAGE,
    }

    for _file_path, entries in by_file.items():
        if len(entries) < 2:
            continue

        types = {f.detection_type for _, _, f in entries}
        has_critical_indicator = bool(types & critical_types)

        if has_critical_indicator:
            for ri, fi, finding in entries:
                if finding.severity in (Severity.LOW, Severity.MEDIUM):
                    # Rebuild with escalated severity (Finding is frozen)
                    results[ri].findings[fi] = _Finding(
                        severity=Severity.HIGH,
                        detection_type=finding.detection_type,
                        file_path=finding.file_path,
                        title=finding.title,
                        description=finding.description,
                        evidence=finding.evidence,
                        recommendation=finding.recommendation,
                        line_number=finding.line_number,
                        column=finding.column,
                        metadata=finding.metadata,
                    )


def _load_config(
    scan_root: Path,
) -> tuple[tuple[str, ...], tuple[str, ...], str]:
    """Load .glassworm.yml config from scan root. Returns (excludes, disabled_rules, severity)."""
    config_path = scan_root / ".glassworm.yml"
    if not config_path.is_file():
        return (), (), ""

    try:
        # Simple YAML parser - no external dependency
        text = config_path.read_text(encoding="utf-8")
        excludes: list[str] = []
        disabled: list[str] = []
        severity = ""
        section = ""

        for line in text.splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            if stripped.startswith("exclude:"):
                section = "exclude"
                continue
            if stripped.startswith("disable_rules:"):
                section = "disable_rules"
                continue
            if stripped.startswith("severity:"):
                severity = stripped.split(":", 1)[1].strip().strip("'\"")
                section = ""
                continue
            if stripped.startswith("- ") and section == "exclude":
                excludes.append(stripped[2:].strip().strip("'\""))
            elif stripped.startswith("- ") and section == "disable_rules":
                disabled.append(stripped[2:].strip().strip("'\""))
            elif not stripped.startswith("-"):
                section = ""

        return tuple(excludes), tuple(disabled), severity
    except OSError:
        return (), (), ""
