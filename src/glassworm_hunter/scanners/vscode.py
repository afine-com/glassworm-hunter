"""VS Code / Cursor / Codium extension scanner."""

from __future__ import annotations

import json
import logging
import time
from pathlib import Path

from ..engine import behavioral, ioc, unicode
from ..engine.models import DetectionType, Finding, ScanResult, Severity
from ..engine.unicode import BINARY_EXTS

logger = logging.getLogger(__name__)

# Extension directories per editor
_EDITOR_DIRS: tuple[tuple[str, str], ...] = (
    ("VS Code", ".vscode/extensions"),
    ("VS Code Insiders", ".vscode-insiders/extensions"),
    ("Cursor", ".cursor/extensions"),
    ("VSCodium", ".vscode-oss/extensions"),
    ("VSCodium (alt)", ".vscodium/extensions"),
)

# File extensions to scan within extensions
_SCAN_EXTS = frozenset(
    {
        ".js",
        ".ts",
        ".mjs",
        ".cjs",
        ".jsx",
        ".tsx",
        ".json",
    }
)


def find_extension_dirs() -> list[tuple[str, Path]]:
    """Find all installed editor extension directories."""
    home = Path.home()
    found: list[tuple[str, Path]] = []

    for editor_name, rel_path in _EDITOR_DIRS:
        ext_dir = home / rel_path
        if ext_dir.is_dir():
            found.append((editor_name, ext_dir))

    return found


def scan_extensions(
    verbose: bool = False,
    max_file_size: int = 10 * 1024 * 1024,
) -> list[ScanResult]:
    """Scan all installed VS Code/Cursor/Codium extensions."""
    results: list[ScanResult] = []
    editor_dirs = find_extension_dirs()

    if not editor_dirs:
        logger.info("No VS Code/Cursor/Codium extension directories found")
        return results

    for editor_name, ext_dir in editor_dirs:
        result = _scan_editor_extensions(editor_name, ext_dir, verbose, max_file_size)
        results.append(result)

    return results


def _scan_editor_extensions(
    editor_name: str,
    ext_dir: Path,
    verbose: bool,
    max_file_size: int,
) -> ScanResult:
    """Scan extensions for a single editor."""
    start = time.monotonic()
    result = ScanResult(
        scanner_name=f"vscode-{editor_name.lower().replace(' ', '-')}",
        scan_target=str(ext_dir),
    )

    try:
        ext_folders = [d for d in ext_dir.iterdir() if d.is_dir() and not d.is_symlink()]
    except PermissionError as e:
        result.errors.append(f"Permission denied: {ext_dir}: {e}")
        return result

    extensions_scanned = 0

    for ext_folder in sorted(ext_folders):
        pkg_json = ext_folder / "package.json"
        if not pkg_json.is_file():
            continue

        extensions_scanned += 1
        findings, files_count = _scan_single_extension(
            ext_folder,
            pkg_json,
            verbose,
            max_file_size,
        )
        result.files_scanned += files_count

        for f in findings:
            # Update file_path to include extension context
            result.findings.append(f)

        if verbose:
            logger.info(
                "[%s] Scanned: %s (%d findings)",
                editor_name,
                ext_folder.name,
                len(findings),
            )

    result.scan_duration_seconds = time.monotonic() - start
    logger.info(
        "[%s] Scanned %d extensions in %.1fs",
        editor_name,
        extensions_scanned,
        result.scan_duration_seconds,
    )
    return result


def _scan_single_extension(
    ext_folder: Path,
    pkg_json_path: Path,
    verbose: bool,
    max_file_size: int,
) -> tuple[list[Finding], int]:
    """Scan a single extension directory. Returns (findings, files_scanned)."""
    findings: list[Finding] = []
    files_scanned = 0

    # Parse package.json
    try:
        pkg_data = json.loads(pkg_json_path.read_text(encoding="utf-8", errors="replace"))
    except (json.JSONDecodeError, OSError) as e:
        logger.debug("Cannot parse %s: %s", pkg_json_path, e)
        return findings, 0

    publisher = pkg_data.get("publisher", "")
    name = pkg_data.get("name", "")
    ext_id = f"{publisher}.{name}" if publisher and name else ext_folder.name

    # Check against known malicious extensions
    matched_known_id = False
    if publisher and name:
        malicious = ioc.check_extension_id(publisher, name)
        if malicious:
            matched_known_id = True
            # Update the file path to the actual extension location
            findings.append(
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

    # Even when the full ID is not on the known-bad list, the publisher itself
    # may be a compromised account — flag the extension as suspect.  Skip if
    # we already reported the stronger known-bad finding above.
    if publisher and not matched_known_id:
        pub_finding = ioc.check_extension_publisher(publisher, name)
        if pub_finding:
            findings.append(
                Finding(
                    severity=pub_finding.severity,
                    detection_type=pub_finding.detection_type,
                    file_path=pkg_json_path,
                    title=pub_finding.title,
                    description=pub_finding.description,
                    evidence=pub_finding.evidence,
                    recommendation=pub_finding.recommendation,
                    metadata=pub_finding.metadata,
                )
            )

    # Check extensionDependencies and extensionPack for known malicious refs
    for dep_field in ("extensionDependencies", "extensionPack"):
        deps = pkg_data.get(dep_field, [])
        if isinstance(deps, list):
            for dep in deps:
                if isinstance(dep, str) and "." in dep:
                    dep_parts = dep.split(".", 1)
                    dep_check = ioc.check_extension_id(dep_parts[0], dep_parts[1])
                    if dep_check:
                        findings.append(
                            Finding(
                                severity=Severity.HIGH,
                                detection_type=DetectionType.SUSPICIOUS_EXTENSION_DEPENDENCY,
                                file_path=pkg_json_path,
                                title=f"Extension depends on known malicious extension: {dep}",
                                description=(
                                    f"Extension '{ext_id}' has '{dep}' in its "
                                    f"{dep_field}, which is a known GlassWorm "
                                    f"distribution vector. This is a Wave 5 "
                                    f"transitive infection technique."
                                ),
                                evidence=f"{dep_field}: {deps}",
                                recommendation=(
                                    "Uninstall both this extension and the referenced "
                                    "dependency. This is likely a transitive infection."
                                ),
                            )
                        )

    # Scan JavaScript/TypeScript files in the extension
    for file_path in _walk_extension_files(ext_folder):
        if file_path.suffix.lower() in BINARY_EXTS:
            continue
        if file_path.suffix.lower() not in _SCAN_EXTS:
            continue

        files_scanned += 1

        # Unicode detection
        unicode_findings = unicode.scan_file_bytes(file_path, max_file_size)
        findings.extend(unicode_findings)

        # Content-based detection (respect max_file_size)
        try:
            file_size = file_path.stat().st_size
            if file_size == 0 or file_size > max_file_size:
                continue
            content = file_path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue

        findings.extend(behavioral.scan_file_content(content, file_path))
        findings.extend(ioc.search_file_content_for_iocs(content, file_path))

    return findings, files_scanned


def _walk_extension_files(ext_folder: Path) -> list[Path]:
    """Walk extension directory for scannable files."""
    files: list[Path] = []
    skip = {"node_modules", ".git", "test", "tests", "__tests__"}

    try:
        for entry in sorted(ext_folder.iterdir()):
            if entry.is_symlink():
                continue
            if entry.is_file():
                files.append(entry)
            elif entry.is_dir() and entry.name not in skip:
                # Only go 2 levels deep in extensions
                try:
                    for sub in sorted(entry.iterdir()):
                        if sub.is_symlink():
                            continue
                        if sub.is_file():
                            files.append(sub)
                        elif sub.is_dir() and sub.name not in skip:
                            try:
                                for subsub in sorted(sub.iterdir()):
                                    if subsub.is_symlink():
                                        continue
                                    if subsub.is_file():
                                        files.append(subsub)
                            except PermissionError:
                                pass
                except PermissionError:
                    pass
    except PermissionError:
        pass

    return files
