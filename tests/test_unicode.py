"""Tests for Unicode detection engine."""

from __future__ import annotations

from pathlib import Path

from glassworm_hunter.engine.models import DetectionType, Severity
from glassworm_hunter.engine.unicode import scan_file_bytes


def _encode_vs(payload: str) -> str:
    """Encode string to variation selectors."""
    result = []
    for byte in payload.encode("utf-8"):
        if byte < 16:
            result.append(chr(0xFE00 + byte))
        else:
            result.append(chr(0xE0100 + byte - 16))
    return "".join(result)


class TestVariationSelectorDetection:
    def test_no_findings_on_clean_file(self, tmp_path: Path) -> None:
        f = tmp_path / "clean.js"
        f.write_text("console.log('hello');\n", encoding="utf-8")
        findings = scan_file_bytes(f)
        assert len(findings) == 0

    def test_no_findings_on_single_emoji_vs(self, tmp_path: Path) -> None:
        """Single variation selector for emoji is legitimate."""
        f = tmp_path / "emoji.js"
        # Heart emoji with VS16
        f.write_text("const x = '\u2764\ufe0f';\n", encoding="utf-8")
        findings = scan_file_bytes(f)
        assert len(findings) == 0

    def test_no_findings_on_two_vs(self, tmp_path: Path) -> None:
        """Two consecutive variation selectors - still under threshold."""
        f = tmp_path / "two.js"
        f.write_text("const x = '\ufe00\ufe01';\n", encoding="utf-8")
        findings = scan_file_bytes(f)
        assert len(findings) == 0

    def test_detects_three_vs_as_suspicious(self, tmp_path: Path) -> None:
        """Three consecutive variation selectors cross the threshold."""
        f = tmp_path / "three.js"
        vs = "\ufe00\ufe01\ufe02"
        f.write_text(f"const x = '{vs}';\n", encoding="utf-8")
        findings = scan_file_bytes(f)
        assert len(findings) == 1
        assert findings[0].detection_type == DetectionType.INVISIBLE_UNICODE

    def test_detects_large_cluster_as_critical(self, tmp_path: Path) -> None:
        """Large variation selector cluster is critical in JS files."""
        f = tmp_path / "payload.js"
        payload = _encode_vs('console.log("pwned")')
        f.write_text(f"const x = `{payload}`;\n", encoding="utf-8")
        findings = scan_file_bytes(f)
        assert len(findings) == 1
        assert findings[0].severity == Severity.CRITICAL
        assert findings[0].detection_type == DetectionType.INVISIBLE_UNICODE

    def test_decoded_preview_in_evidence(self, tmp_path: Path) -> None:
        """Evidence should contain decoded payload preview."""
        f = tmp_path / "preview.js"
        original = 'console.log("glassworm-test")'
        payload = _encode_vs(original)
        f.write_text(f"const x = `{payload}`;\n", encoding="utf-8")
        findings = scan_file_bytes(f)
        assert len(findings) == 1
        assert "glassworm-test" in findings[0].evidence

    def test_skips_binary_files(self, tmp_path: Path) -> None:
        f = tmp_path / "image.png"
        f.write_bytes(b"\x89PNG\r\n\x1a\n" + b"\x00" * 100)
        findings = scan_file_bytes(f)
        assert len(findings) == 0

    def test_skips_empty_files(self, tmp_path: Path) -> None:
        f = tmp_path / "empty.js"
        f.write_text("", encoding="utf-8")
        findings = scan_file_bytes(f)
        assert len(findings) == 0

    def test_skips_oversized_files(self, tmp_path: Path) -> None:
        f = tmp_path / "big.js"
        f.write_text("x" * 100, encoding="utf-8")
        findings = scan_file_bytes(f, max_size=50)
        assert len(findings) == 0

    def test_handles_invalid_utf8(self, tmp_path: Path) -> None:
        f = tmp_path / "bad.js"
        f.write_bytes(b"\xff\xfe" + b"normal text" + b"\x80\x81")
        findings = scan_file_bytes(f)
        # Should not crash
        assert isinstance(findings, list)

    def test_supplementary_vs_range(self, tmp_path: Path) -> None:
        """Test detection of supplementary variation selectors (U+E0100+)."""
        f = tmp_path / "supp.js"
        vs = "".join(chr(0xE0100 + i) for i in range(20))
        f.write_text(f"const x = `{vs}`;\n", encoding="utf-8")
        findings = scan_file_bytes(f)
        assert len(findings) == 1
        assert findings[0].severity == Severity.CRITICAL

    def test_multiple_clusters_in_one_file(self, tmp_path: Path) -> None:
        f = tmp_path / "multi.js"
        vs1 = "".join(chr(0xFE00 + i) for i in range(5))
        vs2 = "".join(chr(0xFE00 + i) for i in range(15))
        f.write_text(f"const a = `{vs1}`;\nconst b = `{vs2}`;\n", encoding="utf-8")
        findings = scan_file_bytes(f)
        assert len(findings) == 2


class TestBidiDetection:
    def test_detects_bidi_override(self, tmp_path: Path) -> None:
        f = tmp_path / "bidi.js"
        # U+202E = RIGHT-TO-LEFT OVERRIDE
        f.write_text("const x = '\u202e' + 'normal';\n", encoding="utf-8")
        findings = scan_file_bytes(f)
        bidi_findings = [f for f in findings if f.detection_type == DetectionType.BIDI_OVERRIDE]
        assert len(bidi_findings) == 1
        assert bidi_findings[0].severity == Severity.MEDIUM


class TestHangulFillerDetection:
    def test_detects_hangul_filler_in_js(self, tmp_path: Path) -> None:
        f = tmp_path / "hangul.js"
        f.write_text("const \u3164 = 'hidden';\n", encoding="utf-8")
        findings = scan_file_bytes(f)
        hangul_findings = [f for f in findings if f.detection_type == DetectionType.HANGUL_FILLER]
        assert len(hangul_findings) == 1

    def test_no_hangul_finding_in_markdown(self, tmp_path: Path) -> None:
        f = tmp_path / "text.md"
        f.write_text("Some text \u3164 here\n", encoding="utf-8")
        findings = scan_file_bytes(f)
        hangul_findings = [f for f in findings if f.detection_type == DetectionType.HANGUL_FILLER]
        assert len(hangul_findings) == 0


class TestSymlinkSafety:
    def test_skips_symlink_files(self, tmp_path: Path) -> None:
        """scan_file_bytes must not follow symlinks."""
        real = tmp_path / "real.js"
        payload = _encode_vs('console.log("pwned")')
        real.write_text(f"const x = `{payload}`;\n", encoding="utf-8")
        link = tmp_path / "link.js"
        link.symlink_to(real)
        # Scanning the real file should find the payload
        assert len(scan_file_bytes(real)) > 0
        # Scanning via symlink should find nothing (symlink skipped)
        assert len(scan_file_bytes(link)) == 0


class TestEdgeCases:
    def test_file_with_no_newlines(self, tmp_path: Path) -> None:
        """File with no newlines - single long line with VS payload."""
        f = tmp_path / "noeol.js"
        payload = _encode_vs("alert(1)")
        f.write_text(f"const x = `{payload}`", encoding="utf-8")
        findings = scan_file_bytes(f)
        assert len(findings) == 1

    def test_vs_boundary_fe00(self, tmp_path: Path) -> None:
        """U+FE00 is the first variation selector."""
        f = tmp_path / "boundary.js"
        vs = "\ufe00" * 5
        f.write_text(f"const x = '{vs}';\n", encoding="utf-8")
        findings = scan_file_bytes(f)
        assert len(findings) == 1

    def test_vs_boundary_fe0f(self, tmp_path: Path) -> None:
        """U+FE0F is the last standard variation selector."""
        f = tmp_path / "boundary2.js"
        vs = "\ufe0f" * 5
        f.write_text(f"const x = '{vs}';\n", encoding="utf-8")
        findings = scan_file_bytes(f)
        assert len(findings) == 1

    def test_svs_boundary_e0100(self, tmp_path: Path) -> None:
        """U+E0100 is the first supplementary variation selector."""
        f = tmp_path / "svs_start.js"
        vs = chr(0xE0100) * 5
        f.write_text(f"const x = '{vs}';\n", encoding="utf-8")
        findings = scan_file_bytes(f)
        assert len(findings) == 1

    def test_svs_boundary_e01ef(self, tmp_path: Path) -> None:
        """U+E01EF is the last supplementary variation selector."""
        f = tmp_path / "svs_end.js"
        vs = chr(0xE01EF) * 5
        f.write_text(f"const x = '{vs}';\n", encoding="utf-8")
        findings = scan_file_bytes(f)
        assert len(findings) == 1

    def test_emoji_with_vs16_no_false_positive(self, tmp_path: Path) -> None:
        """Three emojis each with VS16 should NOT false-positive.

        The VS16 chars are not consecutive - they're separated by base emojis.
        """
        f = tmp_path / "emojis.js"
        # heart+VS16, thumbsup+VS16, smile+VS16
        content = "const x = '\u2764\ufe0f\U0001f44d\ufe0f\U0001f604\ufe0f';\n"
        f.write_text(content, encoding="utf-8")
        findings = scan_file_bytes(f)
        vs_findings = [
            finding
            for finding in findings
            if finding.detection_type == DetectionType.INVISIBLE_UNICODE
        ]
        assert len(vs_findings) == 0
