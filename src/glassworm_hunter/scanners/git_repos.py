"""Local git repository scanner."""

from __future__ import annotations

import logging
import time
from pathlib import Path

from ..engine.models import ScanResult
from ..engine.unicode import ALL_CODE_EXTS, BINARY_EXTS
from .directory import SKIP_DIRS, _scan_single_file

logger = logging.getLogger(__name__)


def scan_git_repos(
    root: Path,
    verbose: bool = False,
    max_file_size: int = 10 * 1024 * 1024,
) -> ScanResult:
    """Find and scan git repositories under root."""
    start = time.monotonic()
    result = ScanResult(scanner_name="git", scan_target=str(root))

    repos = _find_git_repos(root)
    if not repos:
        return result

    for repo_dir in repos:
        if verbose:
            logger.info("Scanning git repo: %s", repo_dir)
        _scan_repo(repo_dir, result, max_file_size, verbose)

    result.scan_duration_seconds = time.monotonic() - start
    return result


def _find_git_repos(root: Path, max_depth: int = 5) -> list[Path]:
    """Find directories containing .git."""
    repos: list[Path] = []

    def _walk(path: Path, depth: int) -> None:
        if depth > max_depth:
            return
        git_dir = path / ".git"
        if git_dir.is_dir():
            repos.append(path)
            return  # Don't look for nested repos
        try:
            for entry in sorted(path.iterdir()):
                if entry.is_symlink():
                    continue
                if (
                    entry.is_dir()
                    and entry.name not in SKIP_DIRS
                    and not entry.name.startswith(".")
                ):
                    _walk(entry, depth + 1)
        except PermissionError:
            pass

    if (root / ".git").is_dir():
        repos.append(root)
    else:
        _walk(root, 0)

    return repos


def _scan_repo(
    repo_dir: Path,
    result: ScanResult,
    max_file_size: int,
    verbose: bool,
) -> None:
    """Scan all tracked files in a git repository."""
    for file_path in _walk_repo_files(repo_dir):
        if file_path.suffix.lower() in BINARY_EXTS:
            continue
        if file_path.suffix.lower() not in ALL_CODE_EXTS:
            continue

        result.files_scanned += 1
        findings = _scan_single_file(file_path, max_file_size)
        result.findings.extend(findings)

        if verbose and findings:
            logger.info("  Found %d issues in %s", len(findings), file_path)


def _walk_repo_files(repo_dir: Path) -> list[Path]:
    """Walk a git repository, skipping .git and common non-source dirs."""
    files: list[Path] = []
    skip = SKIP_DIRS | {".git"}

    def _walk(path: Path) -> None:
        try:
            for entry in sorted(path.iterdir()):
                if entry.is_symlink():
                    continue
                if entry.name.startswith(".") and entry.name != ".github":
                    continue
                if entry.is_file():
                    files.append(entry)
                elif entry.is_dir() and entry.name not in skip:
                    _walk(entry)
        except PermissionError:
            pass

    _walk(repo_dir)
    return files
