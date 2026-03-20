"""Generic directory scanner."""

from __future__ import annotations

import logging
import time
from collections.abc import Callable
from fnmatch import fnmatch
from pathlib import Path

from ..engine import behavioral, ioc, unicode
from ..engine.models import Finding, ScanResult
from ..engine.unicode import ALL_CODE_EXTS, BINARY_EXTS

logger = logging.getLogger(__name__)

SKIP_DIRS = frozenset(
    {
        "node_modules",
        ".git",
        ".hg",
        ".svn",
        "__pycache__",
        ".mypy_cache",
        ".pytest_cache",
        ".ruff_cache",
        ".tox",
        ".nox",
        ".venv",
        "venv",
        "env",
        ".env",
        "vendor",
        "dist",
        "build",
        ".next",
        ".nuxt",
        "target",
        "out",
        "coverage",
        ".cache",
    }
)


def _should_exclude(path: Path, root: Path, excludes: tuple[str, ...]) -> bool:
    """Check if a path matches any exclude pattern."""
    if not excludes:
        return False
    try:
        rel = str(path.relative_to(root))
    except ValueError:
        rel = path.name
    return any(fnmatch(rel, pat) or fnmatch(path.name, pat) for pat in excludes)


def scan_directory(
    path: Path,
    max_file_size: int = 10 * 1024 * 1024,
    include_hidden: bool = False,
    verbose: bool = False,
    excludes: tuple[str, ...] = (),
    on_progress: Callable[[Path, int, int], None] | None = None,
) -> ScanResult:
    """Scan a directory recursively for GlassWorm indicators."""
    start = time.monotonic()
    result = ScanResult(scanner_name="directory", scan_target=str(path))

    if not path.is_dir():
        result.errors.append(f"Not a directory: {path}")
        return result

    all_files = [
        fp
        for fp in _walk_files(path, include_hidden, excludes, path)
        if fp.suffix.lower() not in BINARY_EXTS and fp.suffix.lower() in ALL_CODE_EXTS
    ]
    total = len(all_files)

    for idx, file_path in enumerate(all_files, 1):
        if verbose:
            logger.info("Scanning: %s", file_path)

        if on_progress is not None:
            on_progress(file_path, idx, total)

        result.files_scanned += 1
        findings = _scan_single_file(file_path, max_file_size)
        result.findings.extend(findings)

    result.scan_duration_seconds = time.monotonic() - start
    return result


def _walk_files(
    root: Path,
    include_hidden: bool,
    excludes: tuple[str, ...] = (),
    scan_root: Path | None = None,
) -> list[Path]:
    """Walk directory tree, respecting skip rules."""
    files: list[Path] = []
    if scan_root is None:
        scan_root = root

    try:
        entries = sorted(root.iterdir())
    except PermissionError:
        return files

    for entry in entries:
        # Never follow symlinks - they can point outside the scan target
        if entry.is_symlink():
            continue

        if not include_hidden and entry.name.startswith(".") and entry.name not in (".github",):
            continue

        if entry.is_dir():
            if entry.name in SKIP_DIRS:
                continue
            if _should_exclude(entry, scan_root, excludes):
                continue
            files.extend(_walk_files(entry, include_hidden, excludes, scan_root))
        elif entry.is_file():
            if _should_exclude(entry, scan_root, excludes):
                continue
            files.append(entry)

    return files


def _scan_single_file(file_path: Path, max_file_size: int) -> list[Finding]:
    """Run all detection engines on a single file."""
    findings: list[Finding] = []

    # Never follow symlinks
    if file_path.is_symlink():
        return findings

    # Unicode detection (works on bytes)
    findings.extend(unicode.scan_file_bytes(file_path, max_file_size))

    # Content-based detection (needs text)
    try:
        file_size = file_path.stat().st_size
        if file_size == 0 or file_size > max_file_size:
            return findings
        content = file_path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return findings

    # Behavioral patterns
    findings.extend(behavioral.scan_file_content(content, file_path))

    # IOC matching
    findings.extend(ioc.search_file_content_for_iocs(content, file_path))

    return findings
