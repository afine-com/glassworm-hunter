"""Python site-packages scanner."""

from __future__ import annotations

import logging
import site
import sys
import time
from pathlib import Path

from ..engine import behavioral, ioc, unicode
from ..engine.models import ScanResult

logger = logging.getLogger(__name__)

_SCAN_EXTS = frozenset({".py", ".js", ".sh", ".bash"})


def scan_pip_packages(
    verbose: bool = False,
    max_file_size: int = 10 * 1024 * 1024,
) -> ScanResult:
    """Scan Python site-packages for suspicious content."""
    start = time.monotonic()
    result = ScanResult(scanner_name="pip", scan_target="python-packages")

    sp_dirs = _find_site_packages()
    if not sp_dirs:
        logger.info("No site-packages directories found")
        return result

    for sp_dir in sp_dirs:
        if verbose:
            logger.info("Scanning site-packages: %s", sp_dir)
        _scan_site_packages(sp_dir, result, verbose, max_file_size)

    result.scan_duration_seconds = time.monotonic() - start
    return result


def _find_site_packages() -> list[Path]:
    """Find all site-packages directories."""
    dirs: list[Path] = []

    # System site-packages
    for sp in site.getsitepackages():
        p = Path(sp)
        if p.is_dir():
            dirs.append(p)

    # User site-packages
    user_sp = site.getusersitepackages()
    if isinstance(user_sp, str):
        p = Path(user_sp)
        if p.is_dir():
            dirs.append(p)

    # Current virtualenv
    if hasattr(sys, "real_prefix") or (
        hasattr(sys, "base_prefix") and sys.base_prefix != sys.prefix
    ):
        venv_sp = Path(sys.prefix) / "lib"
        if venv_sp.is_dir():
            # Find the pythonX.Y/site-packages dir
            for pydir in venv_sp.iterdir():
                if pydir.name.startswith("python") and pydir.is_dir():
                    sp = pydir / "site-packages"
                    if sp.is_dir():
                        dirs.append(sp)

    return list(set(dirs))


def _scan_site_packages(
    sp_dir: Path,
    result: ScanResult,
    verbose: bool,
    max_file_size: int,
) -> None:
    """Scan packages in a site-packages directory."""
    try:
        entries = sorted(sp_dir.iterdir())
    except PermissionError:
        result.errors.append(f"Permission denied: {sp_dir}")
        return

    for entry in entries:
        if entry.is_symlink():
            continue
        if not entry.is_dir():
            continue
        if entry.name.startswith("_") or entry.name.endswith(".dist-info"):
            continue
        if entry.name.endswith(".egg-info"):
            continue

        # Check setup.py in the package
        setup_py = entry / "setup.py"
        if setup_py.is_file():
            _scan_setup_py(setup_py, result, max_file_size)

        # Scan Python files for suspicious patterns
        for file_path in _walk_package_files(entry):
            result.files_scanned += 1

            result.findings.extend(unicode.scan_file_bytes(file_path, max_file_size))

            # Content-based detection (respect max_file_size)
            try:
                file_size = file_path.stat().st_size
                if file_size == 0 or file_size > max_file_size:
                    continue
                content = file_path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue

            result.findings.extend(behavioral.scan_file_content(content, file_path))
            result.findings.extend(ioc.search_file_content_for_iocs(content, file_path))


def _scan_setup_py(
    setup_py: Path,
    result: ScanResult,
    max_file_size: int,
) -> None:
    """Scan a setup.py for suspicious install commands."""
    result.findings.extend(unicode.scan_file_bytes(setup_py, max_file_size))
    try:
        file_size = setup_py.stat().st_size
        if file_size == 0 or file_size > max_file_size:
            return
        content = setup_py.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return
    result.findings.extend(behavioral.scan_file_content(content, setup_py))
    result.findings.extend(ioc.search_file_content_for_iocs(content, setup_py))


def _walk_package_files(pkg_dir: Path, max_depth: int = 2) -> list[Path]:
    """Walk a Python package for scannable files."""
    files: list[Path] = []

    def _walk(path: Path, depth: int) -> None:
        if depth > max_depth:
            return
        try:
            for entry in sorted(path.iterdir()):
                if entry.is_symlink():
                    continue
                if entry.is_file() and entry.suffix.lower() in _SCAN_EXTS:
                    files.append(entry)
                elif entry.is_dir() and not entry.name.startswith((".", "_")):
                    _walk(entry, depth + 1)
        except PermissionError:
            pass

    _walk(pkg_dir, 0)
    return files
