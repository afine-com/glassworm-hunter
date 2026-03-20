"""Invisible Unicode character detection - core GlassWorm detection engine."""

from __future__ import annotations

import logging
from pathlib import Path

from .models import DetectionType, Finding, Severity

logger = logging.getLogger(__name__)

# --- Byte-level pre-screening patterns ---
# U+FE00-U+FE0F encode as 0xEF 0xB8 0x80 through 0xEF 0xB8 0x8F
VS_BYTE_PREFIX = b"\xef\xb8"
# U+E0100-U+E01EF encode as 0xF3 0xA0 0x84 0x80 through 0xF3 0xA0 0x87 0xAF
SVS_BYTE_PREFIX = b"\xf3\xa0"

# --- Unicode ranges ---
VS_START = 0xFE00
VS_END = 0xFE0F
SVS_START = 0xE0100
SVS_END = 0xE01EF

# Bidirectional override characters (Trojan Source)
BIDI_CHARS = frozenset(range(0x202A, 0x202F)) | frozenset(range(0x2066, 0x206A))

# Zero-width characters
ZW_CHARS = frozenset({0x200B, 0x200C, 0x200D, 0xFEFF})

# Hangul filler (invisible valid JS identifier)
HANGUL_FILLER = 0x3164

# Code file extensions (weighted by concern)
HIGH_CONCERN_EXTS = frozenset(
    {
        ".js",
        ".ts",
        ".mjs",
        ".cjs",
        ".jsx",
        ".tsx",
    }
)
MEDIUM_CONCERN_EXTS = frozenset(
    {
        ".py",
        ".rb",
        ".go",
        ".rs",
        ".java",
        ".cs",
        ".php",
        ".sh",
        ".bash",
        ".zsh",
        ".ps1",
        ".psm1",
    }
)
LOW_CONCERN_EXTS = frozenset(
    {
        ".md",
        ".txt",
        ".rst",
        ".html",
        ".css",
        ".scss",
        ".less",
        ".svg",
        ".xml",
        ".yaml",
        ".yml",
        ".toml",
        ".json",
        ".ini",
        ".cfg",
    }
)
ALL_CODE_EXTS = HIGH_CONCERN_EXTS | MEDIUM_CONCERN_EXTS | LOW_CONCERN_EXTS

# Binary extensions to always skip
BINARY_EXTS = frozenset(
    {
        ".png",
        ".jpg",
        ".jpeg",
        ".gif",
        ".bmp",
        ".ico",
        ".webp",
        ".avif",
        ".woff",
        ".woff2",
        ".ttf",
        ".otf",
        ".eot",
        ".zip",
        ".tar",
        ".gz",
        ".bz2",
        ".xz",
        ".7z",
        ".rar",
        ".exe",
        ".dll",
        ".so",
        ".dylib",
        ".o",
        ".a",
        ".lib",
        ".wasm",
        ".node",
        ".pyc",
        ".pyo",
        ".class",
        ".pdf",
        ".doc",
        ".docx",
        ".xls",
        ".xlsx",
        ".mp3",
        ".mp4",
        ".wav",
        ".avi",
        ".mov",
        ".mkv",
        ".sqlite",
        ".db",
    }
)

# Thresholds
SUSPICIOUS_VS_CLUSTER = 3
CRITICAL_VS_CLUSTER = 10
SUSPICIOUS_ZW_DENSITY = 10  # per 1000 chars


def _is_variation_selector(cp: int) -> bool:
    """Check if a codepoint is a variation selector."""
    return (VS_START <= cp <= VS_END) or (SVS_START <= cp <= SVS_END)


def _decode_variation_selectors(chars: list[str]) -> bytes:
    """Decode a sequence of variation selector characters to bytes."""
    result = []
    for ch in chars:
        cp = ord(ch)
        if VS_START <= cp <= VS_END:
            result.append(cp - VS_START)
        elif SVS_START <= cp <= SVS_END:
            result.append(cp - SVS_START + 16)
    return bytes(result)


def has_variation_selector_bytes(data: bytes) -> bool:
    """Fast byte-level pre-screen for variation selector sequences."""
    return VS_BYTE_PREFIX in data or SVS_BYTE_PREFIX in data


def scan_file_bytes(file_path: Path, max_size: int = 10 * 1024 * 1024) -> list[Finding]:
    """Scan a file for invisible Unicode patterns."""
    findings: list[Finding] = []

    if file_path.suffix.lower() in BINARY_EXTS:
        return findings

    # Never follow symlinks - they can point outside the scan target
    if file_path.is_symlink():
        return findings

    try:
        file_size = file_path.stat().st_size
    except OSError as e:
        logger.debug("Cannot stat %s: %s", file_path, e)
        return findings

    if file_size == 0 or file_size > max_size:
        return findings

    try:
        data = file_path.read_bytes()
    except OSError as e:
        logger.debug("Cannot read %s: %s", file_path, e)
        return findings

    # Fast pre-screen
    has_vs = has_variation_selector_bytes(data)
    has_potential_bidi = b"\xe2\x80" in data
    has_potential_zw = has_potential_bidi or b"\xef\xbb\xbf" in data
    has_potential_hangul = b"\xe3\x85\xa4" in data

    if not (has_vs or has_potential_bidi or has_potential_zw or has_potential_hangul):
        return findings

    # Full Unicode decode
    try:
        text = data.decode("utf-8", errors="replace")
    except Exception:
        return findings

    lines = text.splitlines(keepends=True)

    for line_num, line in enumerate(lines, start=1):
        findings.extend(_scan_line_variation_selectors(line, line_num, file_path))
        findings.extend(_scan_line_bidi(line, line_num, file_path))
        findings.extend(_scan_line_hangul(line, line_num, file_path))

    # Check zero-width density across the whole file
    findings.extend(_scan_zw_density(text, file_path))

    return findings


def _scan_line_variation_selectors(line: str, line_num: int, file_path: Path) -> list[Finding]:
    """Detect clusters of variation selector characters in a line."""
    findings: list[Finding] = []
    cluster_start: int | None = None
    cluster_chars: list[str] = []

    for col, ch in enumerate(line):
        cp = ord(ch)
        if _is_variation_selector(cp):
            if cluster_start is None:
                cluster_start = col
            cluster_chars.append(ch)
        else:
            if cluster_chars and len(cluster_chars) >= SUSPICIOUS_VS_CLUSTER:
                findings.append(_make_vs_finding(cluster_chars, cluster_start, line_num, file_path))
            cluster_start = None
            cluster_chars = []

    # Handle cluster at end of line
    if cluster_chars and len(cluster_chars) >= SUSPICIOUS_VS_CLUSTER:
        findings.append(_make_vs_finding(cluster_chars, cluster_start, line_num, file_path))

    return findings


def _make_vs_finding(
    chars: list[str],
    col: int | None,
    line_num: int,
    file_path: Path,
) -> Finding:
    """Create a finding for a variation selector cluster."""
    count = len(chars)
    severity = Severity.CRITICAL if count >= CRITICAL_VS_CLUSTER else Severity.MEDIUM

    # Decode to show what the invisible payload contains
    decoded = _decode_variation_selectors(chars)
    try:
        decoded_preview = decoded[:200].decode("utf-8", errors="replace")
    except Exception:
        decoded_preview = repr(decoded[:200])

    is_code_file = file_path.suffix.lower() in HIGH_CONCERN_EXTS
    if is_code_file and count >= CRITICAL_VS_CLUSTER:
        severity = Severity.CRITICAL
    elif is_code_file:
        severity = Severity.HIGH

    return Finding(
        severity=severity,
        detection_type=DetectionType.INVISIBLE_UNICODE,
        file_path=file_path,
        line_number=line_num,
        column=col,
        title=f"Invisible Unicode payload: {count} variation selectors",
        description=(
            f"Found {count} consecutive Unicode variation selector characters "
            f"(U+FE00-FE0F / U+E0100-E01EF) that encode hidden data. "
            f"Legitimate uses are 1-2 characters for emoji rendering. "
            f"Sequences of {count} characters indicate an encoded payload, "
            f"consistent with the GlassWorm attack technique."
        ),
        evidence=f"Decoded payload preview: {decoded_preview}",
        recommendation=(
            "This file contains an invisible encoded payload. "
            "Do NOT execute it. Remove the file or the affected extension/package. "
            "If this is in an installed extension or npm package, uninstall it immediately. "
            "Check your NPM tokens, GitHub credentials, and SSH keys for compromise."
        ),
        metadata={
            "selector_count": count,
            "decoded_size_bytes": len(decoded),
        },
    )


def _scan_line_bidi(line: str, line_num: int, file_path: Path) -> list[Finding]:
    """Detect bidirectional override characters (Trojan Source)."""
    findings: list[Finding] = []

    for col, ch in enumerate(line):
        if ord(ch) in BIDI_CHARS:
            char_name = f"U+{ord(ch):04X}"
            findings.append(
                Finding(
                    severity=Severity.MEDIUM,
                    detection_type=DetectionType.BIDI_OVERRIDE,
                    file_path=file_path,
                    line_number=line_num,
                    column=col,
                    title=f"Bidirectional override character ({char_name})",
                    description=(
                        f"Found Unicode bidirectional override character {char_name}. "
                        f"These characters can make source code appear differently "
                        f"to humans vs compilers (Trojan Source attack, CVE-2021-42574)."
                    ),
                    evidence=repr(line.strip()[:200]),
                    recommendation=(
                        "Review this line carefully. The visible code may not match "
                        "what the compiler/interpreter executes. Remove bidirectional "
                        "override characters unless they serve a legitimate purpose."
                    ),
                )
            )

    return findings


def _scan_line_hangul(line: str, line_num: int, file_path: Path) -> list[Finding]:
    """Detect Hangul filler character in code files."""
    if file_path.suffix.lower() not in HIGH_CONCERN_EXTS:
        return []

    findings: list[Finding] = []
    for col, ch in enumerate(line):
        if ord(ch) == HANGUL_FILLER:
            findings.append(
                Finding(
                    severity=Severity.MEDIUM,
                    detection_type=DetectionType.HANGUL_FILLER,
                    file_path=file_path,
                    line_number=line_num,
                    column=col,
                    title="Hangul filler character (U+3164) in code file",
                    description=(
                        "Found Hangul filler character U+3164, which is invisible but "
                        "constitutes a valid JavaScript identifier. This can be used "
                        "to create invisible variable names for backdoor code."
                    ),
                    evidence=repr(line.strip()[:200]),
                    recommendation=(
                        "Remove the Hangul filler character. If it appears as a "
                        "variable name in destructuring or assignments, the code "
                        "may contain a hidden backdoor."
                    ),
                )
            )

    return findings


def _scan_zw_density(text: str, file_path: Path) -> list[Finding]:
    """Detect suspicious density of zero-width characters."""
    if file_path.suffix.lower() not in (HIGH_CONCERN_EXTS | MEDIUM_CONCERN_EXTS):
        return []

    zw_count = sum(1 for ch in text if ord(ch) in ZW_CHARS)
    text_len = max(len(text), 1)
    density = (zw_count / text_len) * 1000

    if zw_count >= SUSPICIOUS_ZW_DENSITY and density > 1.0:
        return [
            Finding(
                severity=Severity.LOW,
                detection_type=DetectionType.ZERO_WIDTH_CHARS,
                file_path=file_path,
                line_number=None,
                column=None,
                title=f"Unusual zero-width character density: {zw_count} characters",
                description=(
                    f"Found {zw_count} zero-width characters (ZWSP, ZWNJ, ZWJ, BOM) "
                    f"in a code file. While individually legitimate, high density of "
                    f"these characters in source code may indicate data hiding."
                ),
                evidence=f"Density: {density:.2f} per 1000 chars, total: {zw_count}",
                recommendation=(
                    "Review the file for hidden content. Zero-width characters "
                    "can be used to encode data invisibly in source code."
                ),
                metadata={"zw_count": zw_count, "density_per_1000": round(density, 2)},
            )
        ]

    return []
