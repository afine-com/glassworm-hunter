"""Tests for IOC matching."""

from __future__ import annotations

import json
from pathlib import Path

from glassworm_hunter.engine.ioc import (
    _hardcoded_to_dict,
    _merge_ioc_dbs,
    check_extension_id,
    check_filesystem_artifacts,
    check_npm_package,
    get_attacker_artifacts,
    get_c2_ips,
    get_extension_ids,
    get_npm_packages,
    load_ioc_database,
    reset_cache,
    search_file_content_for_iocs,
)
from glassworm_hunter.engine.models import DetectionType, Severity


class TestExtensionIOC:
    def test_matches_known_malicious_extension(self) -> None:
        finding = check_extension_id("codejoy", "codejoy-vscode-extension")
        assert finding is not None
        assert finding.severity == Severity.CRITICAL
        assert finding.detection_type == DetectionType.KNOWN_MALICIOUS_EXTENSION
        assert "wave-1" in str(finding.metadata.get("wave", ""))

    def test_case_insensitive_match(self) -> None:
        finding = check_extension_id("CODEJOY", "CODEJOY-VSCODE-EXTENSION")
        assert finding is not None

    def test_no_match_for_clean_extension(self) -> None:
        finding = check_extension_id("microsoft", "python")
        assert finding is None

    def test_matches_wave5_extension(self) -> None:
        finding = check_extension_id("quartz", "quartz-markdown-editor")
        assert finding is not None
        assert "wave-5" in str(finding.metadata.get("wave", ""))


class TestNpmIOC:
    def test_matches_known_malicious_package(self) -> None:
        finding = check_npm_package("@aifabrix/miso-client", "4.7.2")
        assert finding is not None
        assert finding.severity == Severity.CRITICAL
        assert finding.detection_type == DetectionType.KNOWN_MALICIOUS_PACKAGE

    def test_matches_without_version(self) -> None:
        finding = check_npm_package("react-native-country-select")
        assert finding is not None

    def test_no_match_for_clean_package(self) -> None:
        finding = check_npm_package("lodash", "4.17.21")
        assert finding is None


class TestContentIOC:
    def test_detects_c2_ip(self) -> None:
        content = "const server = '217.69.3.218';\n"
        findings = search_file_content_for_iocs(content, Path("c2.js"))
        ip_findings = [f for f in findings if f.detection_type == DetectionType.KNOWN_C2_IP]
        assert len(ip_findings) == 1
        assert ip_findings[0].severity == Severity.HIGH

    def test_detects_solana_wallet(self) -> None:
        content = 'const wallet = "28PKnu7RzizxBzFPoLp69HLXp9bJL3JFtT2s5QzHsEA2";\n'
        findings = search_file_content_for_iocs(content, Path("wallet.js"))
        wallet_findings = [f for f in findings if f.detection_type == DetectionType.KNOWN_C2_WALLET]
        assert len(wallet_findings) == 1

    def test_detects_attacker_email(self) -> None:
        content = "const email = 'uhjdclolkdn@gmail.com';\n"
        findings = search_file_content_for_iocs(content, Path("config.js"))
        assert len(findings) >= 1
        assert any(f.detection_type == DetectionType.C2_INDICATOR for f in findings)

    def test_detects_attacker_path(self) -> None:
        content = 'path = "/Users/davidioasd/Downloads/rust_implant/payload";\n'
        findings = search_file_content_for_iocs(content, Path("build.rs"))
        assert len(findings) >= 1

    def test_no_findings_on_clean_content(self) -> None:
        content = "const x = '192.168.1.1';\nconst y = 'hello';\n"
        findings = search_file_content_for_iocs(content, Path("clean.js"))
        assert len(findings) == 0

    def test_detects_forcememo_marker(self) -> None:
        """ForceMemo marker variable must be detected."""
        content = "var lzcdrtfxyqiplpd = true;\n"
        findings = search_file_content_for_iocs(content, Path("payload.js"))
        assert len(findings) >= 1
        assert any("marker variable" in f.title.lower() for f in findings)


class TestIoCLoading:
    def test_hardcoded_to_dict(self) -> None:
        db = _hardcoded_to_dict()
        assert len(db["extensions"]) > 0
        assert len(db["npm_packages"]) > 0
        assert len(db["c2_ips"]) > 0
        assert len(db["c2_wallets"]) > 0
        assert len(db["attacker_artifacts"]) == 3  # email + path + marker_variable

    def test_merge_deduplicates(self) -> None:
        base = {
            "extensions": [{"id": "a.b"}],
            "npm_packages": [{"name": "pkg1"}],
            "c2_ips": [{"ip": "1.2.3.4"}],
            "c2_wallets": [{"address": "abc"}],
            "attacker_artifacts": [{"value": "x"}],
        }
        overlay = {
            "extensions": [{"id": "a.b"}, {"id": "c.d"}],
            "npm_packages": [{"name": "pkg1"}, {"name": "pkg2"}],
            "c2_ips": [{"ip": "1.2.3.4"}, {"ip": "5.6.7.8"}],
            "c2_wallets": [{"address": "abc"}, {"address": "def"}],
            "attacker_artifacts": [{"value": "x"}, {"value": "y"}],
        }
        merged = _merge_ioc_dbs(base, overlay)
        assert len(merged["extensions"]) == 2
        assert len(merged["npm_packages"]) == 2
        assert len(merged["c2_ips"]) == 2
        assert len(merged["c2_wallets"]) == 2
        assert len(merged["attacker_artifacts"]) == 2

    def test_load_database_returns_dict(self) -> None:
        db = load_ioc_database()
        assert isinstance(db, dict)
        assert "extensions" in db
        assert "npm_packages" in db

    def test_get_extension_ids_includes_hardcoded(self) -> None:
        ids = get_extension_ids()
        assert "codejoy.codejoy-vscode-extension" in ids
        assert "quartz.quartz-markdown-editor" in ids

    def test_get_npm_packages_includes_hardcoded(self) -> None:
        names = get_npm_packages()
        assert "@aifabrix/miso-client" in names

    def test_get_c2_ips_includes_hardcoded(self) -> None:
        ips = get_c2_ips()
        assert "217.69.3.218" in ips

    def test_get_attacker_artifacts_includes_marker(self) -> None:
        """Merged database should include ForceMemo marker from ioc.json."""
        artifacts = get_attacker_artifacts()
        values = {a["value"] for a in artifacts}
        assert "lzcdrtfxyqiplpd" in values

    def test_user_json_loading(self, tmp_path: Path, monkeypatch: object) -> None:
        """User-local ioc.json gets merged."""
        import glassworm_hunter.engine.ioc as ioc_mod

        user_ioc = tmp_path / "ioc.json"
        user_ioc.write_text(
            json.dumps(
                {
                    "schema_version": "1.0",
                    "extensions": [{"id": "test.user-extension"}],
                    "npm_packages": [],
                    "c2_ips": [],
                    "c2_wallets": [],
                    "attacker_artifacts": [],
                }
            ),
            encoding="utf-8",
        )

        monkeypatch.setattr(ioc_mod, "_USER_IOC_PATH", user_ioc)  # type: ignore[attr-defined]
        ioc_mod.reset_cache()

        ids = ioc_mod.get_extension_ids()
        assert "test.user-extension" in ids
        # Hardcoded still present
        assert "codejoy.codejoy-vscode-extension" in ids


class TestXorKeyMatching:
    """xor_key artifacts must use whole-word + bitwise-context matching.

    The GlassWorm ForceMemo XOR key (value "134") is a short integer that
    appears countless times in legitimate minified JS as array indices,
    ASCII codes, port numbers, etc.  A plain substring match produces
    enormous numbers of false positives.  These tests verify that only
    actual XOR/bitwise usage triggers a finding.
    """

    def _make_artifact_db(self, monkeypatch, ioc_mod) -> None:
        """Inject a minimal IOC database with only the xor_key artifact."""
        import glassworm_hunter.engine.ioc as _ioc

        fake_db = {
            "schema_version": "1.0",
            "extensions": [],
            "npm_packages": [],
            "c2_ips": [],
            "c2_wallets": [],
            "attacker_artifacts": [
                {"type": "xor_key", "value": "134", "source": "test"}
            ],
        }
        monkeypatch.setattr(_ioc, "_merged_db", fake_db)

    def test_xor_key_fires_on_xor_expression(self, monkeypatch) -> None:
        import glassworm_hunter.engine.ioc as ioc_mod
        self._make_artifact_db(monkeypatch, ioc_mod)

        content = "const decoded = charCode ^ 134;\n"
        findings = search_file_content_for_iocs(content, Path("evil.js"))
        assert len(findings) == 1
        assert "XOR key" in findings[0].title

    def test_xor_key_fires_on_key_assignment(self, monkeypatch) -> None:
        import glassworm_hunter.engine.ioc as ioc_mod
        self._make_artifact_db(monkeypatch, ioc_mod)

        content = "var key=134,encoded=payload;\n"
        findings = search_file_content_for_iocs(content, Path("evil.js"))
        assert len(findings) == 1

    def test_xor_key_no_false_positive_array_index(self, monkeypatch) -> None:
        """Array index access should NOT fire."""
        import glassworm_hunter.engine.ioc as ioc_mod
        self._make_artifact_db(monkeypatch, ioc_mod)

        content = "var x = arr[134];\nreturn items.slice(0, 134);\n"
        findings = search_file_content_for_iocs(content, Path("clean.min.js"))
        assert len(findings) == 0

    def test_xor_key_no_false_positive_minified_js(self, monkeypatch) -> None:
        """Minified JS with 134 as a numeric literal must not fire."""
        import glassworm_hunter.engine.ioc as ioc_mod
        self._make_artifact_db(monkeypatch, ioc_mod)

        # Real-world pattern from KaTeX / mermaid / highlight.js
        content = (
            "A(j,P,z,`\\u{E010}`,`\\\\@nleqslant`),A(j,P,z,`\\u{E011}`,"
            "`\\\\@nleqq`),t.push(134),r.splice(0,134),"
            "n.charCodeAt(134)===32&&(o=134);\n"
        )
        findings = search_file_content_for_iocs(content, Path("katex.min.js"))
        assert len(findings) == 0

    def test_xor_key_no_false_positive_string_literal(self, monkeypatch) -> None:
        """String containing '134' as a substring must not fire."""
        import glassworm_hunter.engine.ioc as ioc_mod
        self._make_artifact_db(monkeypatch, ioc_mod)

        content = 'var version = "1.34.0"; var port = 13400;\n'
        findings = search_file_content_for_iocs(content, Path("clean.js"))
        assert len(findings) == 0


class TestSkippedArtifactTypes:
    """openvsx_publisher, github_account, and persistence_file must not
    produce findings from file-content scanning — they are metadata or
    filesystem IOCs."""

    def _make_db_with(self, monkeypatch, artifact_type: str, value: str) -> None:
        import glassworm_hunter.engine.ioc as _ioc
        monkeypatch.setattr(
            _ioc,
            "_merged_db",
            {
                "schema_version": "1.0",
                "extensions": [],
                "npm_packages": [],
                "c2_ips": [],
                "c2_wallets": [],
                "attacker_artifacts": [
                    {"type": artifact_type, "value": value, "source": "test"}
                ],
            },
        )

    def test_openvsx_publisher_skipped_in_content_scan(self, monkeypatch) -> None:
        self._make_db_with(monkeypatch, "openvsx_publisher", "oorzc")
        # Content that literally contains the publisher name
        content = 'publisher: "oorzc", name: "ssh-tools"\n'
        findings = search_file_content_for_iocs(content, Path("package.json"))
        assert len(findings) == 0

    def test_github_account_skipped_in_content_scan(self, monkeypatch) -> None:
        self._make_db_with(monkeypatch, "github_account", "chiara585")
        content = '# Contributed by @chiara585\n'
        findings = search_file_content_for_iocs(content, Path("CHANGELOG.md"))
        assert len(findings) == 0

    def test_persistence_file_skipped_in_content_scan(self, monkeypatch) -> None:
        self._make_db_with(monkeypatch, "persistence_file", "~/init.json")
        content = 'load("~/init.json");\n'
        findings = search_file_content_for_iocs(content, Path("loader.js"))
        assert len(findings) == 0


class TestFilesystemArtifacts:
    """check_filesystem_artifacts() detects persistence files on disk."""

    def test_detects_existing_persistence_file(
        self, monkeypatch, tmp_path: Path
    ) -> None:
        import glassworm_hunter.engine.ioc as ioc_mod

        persist = tmp_path / "init.json"
        persist.write_text("{}", encoding="utf-8")

        monkeypatch.setattr(
            ioc_mod,
            "_merged_db",
            {
                "schema_version": "1.0",
                "extensions": [],
                "npm_packages": [],
                "c2_ips": [],
                "c2_wallets": [],
                "attacker_artifacts": [
                    {
                        "type": "persistence_file",
                        "value": str(persist),
                        "source": "test",
                    }
                ],
            },
        )

        findings = check_filesystem_artifacts()
        assert len(findings) == 1
        assert findings[0].severity == Severity.CRITICAL
        assert "persistence file" in findings[0].title.lower()

    def test_no_finding_when_persistence_file_absent(
        self, monkeypatch, tmp_path: Path
    ) -> None:
        import glassworm_hunter.engine.ioc as ioc_mod

        absent = tmp_path / "init.json"  # not created

        monkeypatch.setattr(
            ioc_mod,
            "_merged_db",
            {
                "schema_version": "1.0",
                "extensions": [],
                "npm_packages": [],
                "c2_ips": [],
                "c2_wallets": [],
                "attacker_artifacts": [
                    {
                        "type": "persistence_file",
                        "value": str(absent),
                        "source": "test",
                    }
                ],
            },
        )

        findings = check_filesystem_artifacts()
        assert len(findings) == 0
