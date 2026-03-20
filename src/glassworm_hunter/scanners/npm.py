"""npm/yarn/pnpm node_modules scanner."""

from __future__ import annotations

import json
import logging
import time
from pathlib import Path

from ..engine import behavioral, ioc, unicode
from ..engine.models import DetectionType, Finding, ScanResult, Severity
from ..engine.unicode import has_variation_selector_bytes

logger = logging.getLogger(__name__)

_SCAN_EXTS = frozenset({".js", ".mjs", ".cjs", ".ts", ".jsx", ".tsx"})

# Install scripts that could execute malicious code
_SUSPICIOUS_SCRIPTS = frozenset(
    {
        "preinstall",
        "postinstall",
        "preuninstall",
        "install",
    }
)


def scan_node_modules(
    root: Path,
    verbose: bool = False,
    max_file_size: int = 10 * 1024 * 1024,
) -> ScanResult:
    """Find and scan node_modules directories under root."""
    start = time.monotonic()
    result = ScanResult(scanner_name="npm", scan_target=str(root))

    nm_dirs = _find_node_modules(root)
    if not nm_dirs:
        return result

    for nm_dir in nm_dirs:
        _scan_node_modules_dir(nm_dir, result, verbose, max_file_size)

    result.scan_duration_seconds = time.monotonic() - start
    return result


def _find_node_modules(root: Path, max_depth: int = 5) -> list[Path]:
    """Find node_modules directories, stopping at the first level found per subtree."""
    found: list[Path] = []

    def _walk(path: Path, depth: int) -> None:
        if depth > max_depth:
            return
        try:
            for entry in path.iterdir():
                if entry.is_symlink():
                    continue
                if not entry.is_dir():
                    continue
                if entry.name == "node_modules":
                    found.append(entry)
                    # Don't recurse into node_modules looking for nested ones
                elif entry.name not in (".git", ".hg", "dist", "build", ".next"):
                    _walk(entry, depth + 1)
        except PermissionError:
            pass

    _walk(root, 0)
    return found


def _scan_node_modules_dir(
    nm_dir: Path,
    result: ScanResult,
    verbose: bool,
    max_file_size: int,
) -> None:
    """Scan packages in a node_modules directory."""
    try:
        entries = sorted(nm_dir.iterdir())
    except PermissionError:
        result.errors.append(f"Permission denied: {nm_dir}")
        return

    for entry in entries:
        if entry.is_symlink():
            continue
        if entry.name.startswith("."):
            continue

        # Handle scoped packages (@org/pkg)
        if entry.name.startswith("@") and entry.is_dir():
            try:
                for scoped_pkg in sorted(entry.iterdir()):
                    if scoped_pkg.is_symlink():
                        continue
                    if scoped_pkg.is_dir():
                        _scan_package(scoped_pkg, result, verbose, max_file_size)
            except PermissionError:
                pass
        elif entry.is_dir():
            _scan_package(entry, result, verbose, max_file_size)


def _scan_package(
    pkg_dir: Path,
    result: ScanResult,
    verbose: bool,
    max_file_size: int,
) -> None:
    """Scan a single npm package."""
    pkg_json_path = pkg_dir / "package.json"
    if not pkg_json_path.is_file():
        return

    try:
        pkg_data = json.loads(pkg_json_path.read_text(encoding="utf-8", errors="replace"))
    except (json.JSONDecodeError, OSError):
        return

    pkg_name = pkg_data.get("name", pkg_dir.name)
    pkg_version = pkg_data.get("version", "unknown")

    # Check against known malicious packages
    malicious = ioc.check_npm_package(pkg_name, pkg_version)
    if malicious:
        result.findings.append(
            Finding(
                severity=malicious.severity,
                detection_type=malicious.detection_type,
                file_path=pkg_json_path,
                title=malicious.title,
                description=malicious.description,
                evidence=malicious.evidence,
                recommendation=malicious.recommendation,
                metadata=malicious.metadata,
            )
        )

    # Check for suspicious install scripts
    scripts = pkg_data.get("scripts", {})
    has_suspicious_script = False
    if isinstance(scripts, dict):
        for script_name in _SUSPICIOUS_SCRIPTS:
            if script_name in scripts:
                script_cmd = scripts[script_name]
                # Only flag if it runs a JS file (not just standard build tools)
                if isinstance(script_cmd, str) and _is_suspicious_script_cmd(script_cmd):
                    has_suspicious_script = True
                    result.findings.append(
                        Finding(
                            severity=Severity.LOW,
                            detection_type=DetectionType.SUSPICIOUS_INSTALL_SCRIPT,
                            file_path=pkg_json_path,
                            title=f"Suspicious {script_name} script in {pkg_name}",
                            description=(
                                f"Package '{pkg_name}' has a {script_name} script "
                                f"that executes code. GlassWorm uses install scripts "
                                f"as an execution vector."
                            ),
                            evidence=f"{script_name}: {script_cmd}",
                            recommendation=(
                                "Review the install script and the code it executes. "
                                "Verify this is expected behavior for this package."
                            ),
                        )
                    )

    # Byte-level pre-screen: check entry point files for variation selector
    # bytes. This is cheap (substring search on raw bytes) and catches unknown
    # GlassWorm variants that aren't on any blocklist and don't use install
    # scripts. Without this, the scanner only deep-scans packages that are
    # already flagged by IOC or script heuristics — defeating the
    # "detect the technique, not the identifier" promise.
    has_invisible_payload = _prescreen_entry_points(pkg_dir, pkg_data, max_file_size)

    # Deep scan if ANY signal fires: known IOC, suspicious script, or byte hit
    should_deep_scan = malicious is not None or has_suspicious_script or has_invisible_payload

    if should_deep_scan:
        _deep_scan_package(pkg_dir, result, max_file_size)

    if verbose:
        logger.info("Scanned package: %s@%s", pkg_name, pkg_version)


def _is_suspicious_script_cmd(cmd: str) -> bool:
    """Check if an install script command looks suspicious."""
    # Normal build tool commands are fine
    safe_prefixes = (
        "node-gyp",
        "prebuild",
        "cmake",
        "make",
        "tsc",
        "npx",
        "rimraf",
        "mkdirp",
        "napi",
    )
    cmd_lower = cmd.strip().lower()
    if any(cmd_lower.startswith(p) for p in safe_prefixes):
        return False
    # Flag if it directly runs a JS file
    return "node " in cmd_lower or cmd_lower.endswith(".js")


def _prescreen_entry_points(
    pkg_dir: Path,
    pkg_data: dict[str, object],
    max_file_size: int,
) -> bool:
    """Byte-level check of package entry points for variation selector sequences.

    This reads raw bytes of a small number of files (typically 1-3) and checks
    for the byte prefixes of variation selector characters. No UTF-8 decoding,
    no regex — just ``bytes.__contains__``. Cost per package: 1-3 stat+read
    calls on files that are usually <100 KB.

    Returns True if any entry point file contains variation selector bytes.
    """
    candidates: list[Path] = []

    # 1. "main" field — the most common entry point
    main = pkg_data.get("main")
    if isinstance(main, str) and main:
        candidates.append(pkg_dir / main)

    # 2. "exports"."." — modern Node entry point
    exports = pkg_data.get("exports")
    if isinstance(exports, dict):
        dot = exports.get(".")
        if isinstance(dot, str):
            candidates.append(pkg_dir / dot)
        elif isinstance(dot, dict):
            for key in ("import", "require", "default"):
                val = dot.get(key)
                if isinstance(val, str):
                    candidates.append(pkg_dir / val)
                    break  # one is enough

    # 3. Fallback: index.js / index.mjs / index.cjs
    if not candidates:
        for name in ("index.js", "index.mjs", "index.cjs"):
            p = pkg_dir / name
            if p.is_file():
                candidates.append(p)
                break

    # Read bytes and check
    for path in candidates:
        if not path.is_file() or path.is_symlink():
            continue
        try:
            size = path.stat().st_size
            if size == 0 or size > max_file_size:
                continue
            data = path.read_bytes()
        except OSError:
            continue
        if has_variation_selector_bytes(data):
            return True

    return False


def _deep_scan_package(
    pkg_dir: Path,
    result: ScanResult,
    max_file_size: int,
) -> None:
    """Deep scan all code files in a flagged package."""
    for file_path in _walk_package_files(pkg_dir):
        result.files_scanned += 1

        # Unicode detection
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


def _walk_package_files(pkg_dir: Path, max_depth: int = 3) -> list[Path]:
    """Walk package directory for scannable files."""
    files: list[Path] = []
    skip = {"node_modules", ".git", "test", "tests", "__tests__", "docs"}

    def _walk(path: Path, depth: int) -> None:
        if depth > max_depth:
            return
        try:
            for entry in sorted(path.iterdir()):
                if entry.is_symlink():
                    continue
                if entry.is_file() and entry.suffix.lower() in _SCAN_EXTS:
                    files.append(entry)
                elif entry.is_dir() and entry.name not in skip:
                    _walk(entry, depth + 1)
        except PermissionError:
            pass

    _walk(pkg_dir, 0)
    return files
