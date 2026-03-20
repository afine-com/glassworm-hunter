"""Behavioral pattern detection for GlassWorm attack techniques."""

from __future__ import annotations

import re
from pathlib import Path

from .models import DetectionType, Finding, Severity

# --- GlassWorm-specific decoder patterns (CRITICAL) ---
# These must be tight enough to NOT match normal Node.js code like
# Buffer.from(x).toString('utf-8') which appears in every webpack bundle.
_DECODER_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    (
        # codePointAt + variation selector hex constant nearby.
        # Window limited to 500 chars — in a real decoder they are adjacent.
        # No re.DOTALL: `.` won't match newlines, so this spans at most a few
        # lines — not the entire file like the old pattern did.
        re.compile(
            r"codePointAt\s*\(\s*\d*\s*\).{0,500}(?:0xFE00|0xfe00|0xe0100|0xE0100)",
            re.IGNORECASE | re.DOTALL,
        ),
        "Variation selector codepoint mapping (GlassWorm decoder signature)",
    ),
    (
        # Both variation selector ranges AND eval/Function within 500 chars.
        # re.DOTALL with {0,500} lets us match across a few lines (real
        # decoders span 3-5 lines) while preventing false positives on
        # obfuscated bundles (Pylance etc.) where these hex values appear
        # thousands of characters apart as unrelated numeric constants.
        re.compile(
            r"(?:0xFE00|0xfe00).{0,500}(?:0xE0100|0xe0100).{0,500}(?:eval|Function)",
            re.IGNORECASE | re.DOTALL,
        ),
        "Variation selector range constants with eval/Function",
    ),
    # Buffer.from + toString('utf-8') is only suspicious when fed into eval/Function.
    # Plain Buffer.from(...).toString('utf-8') is standard Node.js and appears in
    # virtually every bundled VS Code extension. Flagging it alone is a FP magnet.
    (
        re.compile(
            r"\b(?:eval|Function)\s*\(\s*Buffer\.from\s*\(.*?\)"
            r"\.toString\s*\(\s*['\"]utf-?8['\"]\s*\)",
        ),
        "eval/Function with Buffer.from().toString('utf-8') chain",
    ),
)

# --- eval/Function execution sinks (MEDIUM) ---
# Note: child_process import is NOT included here. It is a standard Node.js
# API used by virtually every VS Code extension (LSP, debugger, git, etc.).
# Flagging it produces hundreds of useless findings. Instead, we flag
# child_process only when combined with decoded/dynamic content (execSync with
# Buffer.from, etc.) which is covered by the last pattern below.
_EVAL_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    (
        re.compile(r"\beval\s*\(\s*(?:Buffer\.from|String\.fromCharCode|atob)\b"),
        "eval() with dynamic content construction",
    ),
    (
        re.compile(r"\beval\s*\(\s*`"),
        "eval() with template literal",
    ),
    (
        re.compile(r"new\s+Function\s*\(\s*(?:Buffer\.from|String\.fromCharCode|atob)\b"),
        "new Function() with dynamic content construction",
    ),
    (
        re.compile(
            r"\b(?:execSync|spawnSync|exec)\s*\(\s*(?:Buffer\.from|atob|String\.fromCharCode)"
        ),
        "Command execution with decoded content",
    ),
)

# --- Credential access patterns (MEDIUM) ---
_CREDENTIAL_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    (
        re.compile(r"""(?:readFile|readFileSync|open|read)\s*\(\s*.*\.npmrc"""),
        "Reading .npmrc (contains NPM auth tokens)",
    ),
    (
        re.compile(r"""(?:readFile|readFileSync|open|read)\s*\(\s*.*\.git-?credentials"""),
        "Reading Git credentials file",
    ),
    (
        re.compile(
            r"""(?:readFile|readFileSync|open|read)\s*\(\s*.*(?:id_rsa|id_ed25519|id_ecdsa)"""
        ),
        "Reading SSH private key",
    ),
    (
        re.compile(
            r"""process\.env\s*\[\s*['"](?:NPM_TOKEN|GITHUB_TOKEN|GH_TOKEN|OPEN_VSX_TOKEN|GITLAB_TOKEN)['"]\s*\]"""
        ),
        "Accessing sensitive token environment variable",
    ),
    (
        # Require path separator before the DB filename to avoid matching bare
        # words in minified bundles. Real credential theft reads a file like:
        #   readFileSync(home + '/Library/Application Support/Google/Chrome/Default/Login Data')
        re.compile(
            r"(?:readFile|readFileSync)\s*\("
            r"[^)]{0,200}"
            r"[\\/](?:Login\s*Data|Cookies|Web\s*Data)",
        ),
        "Reading browser credential/cookie storage",
    ),
)

# --- C2 communication patterns (HIGH) ---
_C2_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    (
        re.compile(r"""(?:getTransaction|getSignaturesForAddress|getAccountInfo)\s*\("""),
        "Solana RPC method call (potential blockchain C2)",
    ),
    (
        re.compile(r"""calendar\.app\.google\.com|calendar\.google\.com/calendar"""),
        "Google Calendar URL (potential backup C2 channel)",
    ),
    (
        re.compile(r"""(?:RTCPeerConnection|RTCDataChannel|createDataChannel)\s*\("""),
        "WebRTC data channel creation (potential P2P C2)",
    ),
    (
        re.compile(r"""(?:dht|DHT).*(?:announce|lookup|findNode)"""),
        "BitTorrent DHT operations (potential decentralized C2)",
    ),
)

# File extensions where behavioral patterns are meaningful
_BEHAVIORAL_EXTS = frozenset(
    {
        ".js",
        ".ts",
        ".mjs",
        ".cjs",
        ".jsx",
        ".tsx",
        ".py",
        ".rb",
        ".sh",
        ".bash",
        ".ps1",
    }
)


def scan_file_content(content: str, file_path: Path) -> list[Finding]:
    """Scan file content for suspicious behavioral patterns."""
    if file_path.suffix.lower() not in _BEHAVIORAL_EXTS:
        return []

    findings: list[Finding] = []

    # Check decoder patterns (CRITICAL)
    for pattern, desc in _DECODER_PATTERNS:
        for match in pattern.finditer(content):
            line_num = content[: match.start()].count("\n") + 1
            findings.append(
                Finding(
                    severity=Severity.CRITICAL,
                    detection_type=DetectionType.DECODER_PATTERN,
                    file_path=file_path,
                    line_number=line_num,
                    title=f"GlassWorm decoder pattern: {desc}",
                    description=(
                        "Detected code pattern matching the GlassWorm invisible "
                        "Unicode decoder. This code extracts byte values from "
                        "variation selector characters and executes the result."
                    ),
                    evidence=_get_evidence(content, match.start(), match.end()),
                    recommendation=(
                        "This is a strong indicator of GlassWorm infection. "
                        "Do not execute this code. Remove the file/package. "
                        "Rotate all credentials on this machine."
                    ),
                )
            )

    # Check eval patterns (MEDIUM)
    for pattern, desc in _EVAL_PATTERNS:
        for match in pattern.finditer(content):
            line_num = content[: match.start()].count("\n") + 1
            findings.append(
                Finding(
                    severity=Severity.MEDIUM,
                    detection_type=DetectionType.EVAL_PATTERN,
                    file_path=file_path,
                    line_number=line_num,
                    title=f"Suspicious execution pattern: {desc}",
                    description=(
                        "Found code that dynamically constructs and executes "
                        "content. While not always malicious, this pattern is "
                        "commonly used in supply chain attacks."
                    ),
                    evidence=_get_evidence(content, match.start(), match.end()),
                    recommendation=(
                        "Review this code carefully. If found in a dependency, "
                        "verify the package source and recent changes."
                    ),
                )
            )

    # Check credential access (MEDIUM)
    for pattern, desc in _CREDENTIAL_PATTERNS:
        for match in pattern.finditer(content):
            line_num = content[: match.start()].count("\n") + 1
            findings.append(
                Finding(
                    severity=Severity.MEDIUM,
                    detection_type=DetectionType.CREDENTIAL_ACCESS,
                    file_path=file_path,
                    line_number=line_num,
                    title=f"Credential access: {desc}",
                    description=(
                        "Found code that accesses sensitive credentials or tokens. "
                        "GlassWorm harvests NPM tokens, GitHub credentials, and "
                        "SSH keys to propagate to victims' packages."
                    ),
                    evidence=_get_evidence(content, match.start(), match.end()),
                    recommendation=(
                        "Verify this credential access is legitimate and expected "
                        "for this package's functionality."
                    ),
                )
            )

    # Check C2 patterns (HIGH)
    for pattern, desc in _C2_PATTERNS:
        for match in pattern.finditer(content):
            line_num = content[: match.start()].count("\n") + 1
            # Lower severity for files that are clearly crypto/calendar related
            file_name = file_path.name.lower()
            is_expected = any(
                kw in file_name
                for kw in ("solana", "web3", "blockchain", "calendar", "webrtc", "torrent")
            )
            severity = Severity.MEDIUM if is_expected else Severity.HIGH

            findings.append(
                Finding(
                    severity=severity,
                    detection_type=DetectionType.C2_INDICATOR,
                    file_path=file_path,
                    line_number=line_num,
                    title=f"Potential C2 channel: {desc}",
                    description=(
                        "Found code pattern associated with GlassWorm's "
                        "command-and-control infrastructure. GlassWorm uses "
                        "Solana blockchain, Google Calendar, and WebRTC P2P "
                        "as C2 channels."
                    ),
                    evidence=_get_evidence(content, match.start(), match.end()),
                    recommendation=(
                        "If this is not a cryptocurrency, calendar, or "
                        "communication application, investigate this code. "
                        "These patterns are used by GlassWorm for C2."
                    ),
                )
            )

    return findings


def _get_evidence(content: str, start: int, end: int) -> str:
    """Extract evidence string with surrounding context."""
    # Expand to full lines
    line_start = content.rfind("\n", 0, start)
    line_start = line_start + 1 if line_start >= 0 else 0
    line_end = content.find("\n", end)
    line_end = line_end if line_end >= 0 else len(content)

    evidence = content[line_start:line_end].strip()
    if len(evidence) > 200:
        evidence = evidence[:200] + "..."
    return evidence
