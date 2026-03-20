"""Tests for file system scanners."""

from __future__ import annotations

from pathlib import Path

from glassworm_hunter.engine.models import DetectionType, Severity
from glassworm_hunter.scanners.directory import scan_directory
from glassworm_hunter.scanners.npm import scan_node_modules


class TestDirectoryScanner:
    def test_clean_directory(self, tmp_clean_dir: Path) -> None:
        result = scan_directory(tmp_clean_dir)
        assert result.files_scanned > 0
        assert len(result.findings) == 0
        assert result.scanner_name == "directory"

    def test_infected_directory(self, tmp_infected_dir: Path) -> None:
        result = scan_directory(tmp_infected_dir)
        assert result.files_scanned > 0
        assert len(result.findings) > 0
        assert any(f.severity == Severity.CRITICAL for f in result.findings)

    def test_nonexistent_directory(self, tmp_path: Path) -> None:
        result = scan_directory(tmp_path / "nonexistent")
        assert len(result.errors) > 0

    def test_scans_only_code_files(self, tmp_path: Path) -> None:
        d = tmp_path / "mixed"
        d.mkdir()
        (d / "code.js").write_text("console.log('ok');\n", encoding="utf-8")
        (d / "image.png").write_bytes(b"\x89PNG\r\n\x1a\n")
        (d / "data.dat").write_bytes(b"\x00" * 100)
        result = scan_directory(d)
        assert result.files_scanned == 1  # Only code.js

    def test_skips_node_modules(self, tmp_path: Path) -> None:
        d = tmp_path / "project"
        d.mkdir()
        (d / "index.js").write_text("ok();\n", encoding="utf-8")
        nm = d / "node_modules" / "pkg"
        nm.mkdir(parents=True)
        (nm / "index.js").write_text("ok();\n", encoding="utf-8")
        result = scan_directory(d)
        assert result.files_scanned == 1  # Only top-level index.js

    def test_skips_symlinks_to_files(self, tmp_path: Path) -> None:
        """Symlinks to files must not be followed (security)."""
        d = tmp_path / "project"
        d.mkdir()
        real = d / "real.js"
        real.write_text("console.log('ok');\n", encoding="utf-8")
        link = d / "link.js"
        link.symlink_to(real)
        result = scan_directory(d)
        assert result.files_scanned == 1  # Only real.js, not the symlink

    def test_skips_symlinks_to_directories(self, tmp_path: Path) -> None:
        """Symlinks to directories must not be followed (security)."""
        d = tmp_path / "project"
        d.mkdir()
        (d / "index.js").write_text("ok();\n", encoding="utf-8")
        outside = tmp_path / "outside"
        outside.mkdir()
        (outside / "secret.js").write_text("ok();\n", encoding="utf-8")
        (d / "linked_dir").symlink_to(outside)
        result = scan_directory(d)
        assert result.files_scanned == 1  # Only index.js

    def test_skips_broken_symlinks(self, tmp_path: Path) -> None:
        """Broken symlinks must not cause errors."""
        d = tmp_path / "project"
        d.mkdir()
        (d / "index.js").write_text("ok();\n", encoding="utf-8")
        (d / "broken.js").symlink_to(d / "nonexistent.js")
        result = scan_directory(d)
        assert result.files_scanned == 1
        assert len(result.errors) == 0

    def test_empty_directory(self, tmp_path: Path) -> None:
        """Empty directory should scan zero files with no errors."""
        d = tmp_path / "empty"
        d.mkdir()
        result = scan_directory(d)
        assert result.files_scanned == 0
        assert len(result.findings) == 0
        assert len(result.errors) == 0


class TestNpmScanner:
    def test_detects_malicious_package(self, tmp_npm_dir: Path) -> None:
        result = scan_node_modules(tmp_npm_dir)
        malicious_findings = [
            f for f in result.findings if f.detection_type == DetectionType.KNOWN_MALICIOUS_PACKAGE
        ]
        assert len(malicious_findings) == 1
        assert malicious_findings[0].severity == Severity.CRITICAL

    def test_no_findings_for_clean_packages(self, tmp_path: Path) -> None:
        project = tmp_path / "clean"
        project.mkdir()
        nm = project / "node_modules" / "express"
        nm.mkdir(parents=True)
        (nm / "package.json").write_text(
            '{"name": "express", "version": "4.18.2"}',
            encoding="utf-8",
        )
        (nm / "index.js").write_text("module.exports = {};\n", encoding="utf-8")
        result = scan_node_modules(project)
        assert len(result.findings) == 0

    def test_no_crash_on_empty_dir(self, tmp_path: Path) -> None:
        result = scan_node_modules(tmp_path)
        assert len(result.findings) == 0

    def test_detects_unknown_variant_via_prescreen(self, tmp_path: Path) -> None:
        """A package NOT on the IOC list and WITHOUT an install script, but
        with a variation-selector payload in its entry point, must still be
        caught. This is the core "detect the technique" promise."""
        project = tmp_path / "project"
        project.mkdir()
        nm = project / "node_modules" / "totally-legit-pkg"
        nm.mkdir(parents=True)
        (nm / "package.json").write_text(
            '{"name": "totally-legit-pkg", "version": "1.0.0", "main": "index.js"}',
            encoding="utf-8",
        )
        # Encode a hidden payload using variation selectors
        payload = 'require("child_process").exec("whoami")'
        encoded = []
        for byte in payload.encode("utf-8"):
            if byte < 16:
                encoded.append(chr(0xFE00 + byte))
            else:
                encoded.append(chr(0xE0100 + byte - 16))
        hidden = "".join(encoded)
        (nm / "index.js").write_text(
            f"const x = `{hidden}`;\nmodule.exports = {{}};\n",
            encoding="utf-8",
        )
        result = scan_node_modules(project)
        vs_findings = [
            f for f in result.findings if f.detection_type == DetectionType.INVISIBLE_UNICODE
        ]
        assert len(vs_findings) >= 1
        assert vs_findings[0].severity == Severity.CRITICAL

    def test_prescreen_uses_exports_field(self, tmp_path: Path) -> None:
        """Pre-screen should find payloads via the 'exports' field, not just 'main'."""
        project = tmp_path / "project"
        project.mkdir()
        nm = project / "node_modules" / "esm-pkg"
        nm.mkdir(parents=True)
        (nm / "package.json").write_text(
            '{"name": "esm-pkg", "version": "2.0.0", "exports": {".": "./dist/entry.mjs"}}',
            encoding="utf-8",
        )
        dist = nm / "dist"
        dist.mkdir()
        # Clean index.js (decoy) + infected entry.mjs (real entry point)
        (nm / "index.js").write_text("module.exports = {};\n", encoding="utf-8")
        payload = "alert(1)"
        encoded = []
        for byte in payload.encode("utf-8"):
            if byte < 16:
                encoded.append(chr(0xFE00 + byte))
            else:
                encoded.append(chr(0xE0100 + byte - 16))
        hidden = "".join(encoded)
        (dist / "entry.mjs").write_text(
            f"export const x = `{hidden}`;\n",
            encoding="utf-8",
        )
        result = scan_node_modules(project)
        vs_findings = [
            f for f in result.findings if f.detection_type == DetectionType.INVISIBLE_UNICODE
        ]
        assert len(vs_findings) >= 1
