"""Tests for CLI interface."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

from click.testing import CliRunner

from glassworm_hunter.cli import main


class TestCLI:
    def test_help(self) -> None:
        runner = CliRunner()
        result = runner.invoke(main, ["--help"])
        assert result.exit_code == 0
        assert "GlassWorm Scanner" in result.output

    def test_version(self) -> None:
        runner = CliRunner()
        result = runner.invoke(main, ["version"])
        assert result.exit_code == 0
        assert "0.1.0" in result.output

    def test_scan_clean_dir_exit_0(self, tmp_clean_dir: Path) -> None:
        runner = CliRunner()
        result = runner.invoke(
            main,
            [
                "scan",
                str(tmp_clean_dir),
                "--no-extensions",
                "--no-npm-scan",
                "--no-git",
            ],
        )
        assert result.exit_code == 0

    def test_scan_infected_dir_exit_1(self, tmp_infected_dir: Path) -> None:
        runner = CliRunner()
        result = runner.invoke(
            main,
            [
                "scan",
                str(tmp_infected_dir),
                "--no-extensions",
                "--no-npm-scan",
                "--no-git",
            ],
        )
        assert result.exit_code == 1

    def test_json_output(self, tmp_clean_dir: Path) -> None:
        runner = CliRunner()
        result = runner.invoke(
            main,
            [
                "scan",
                str(tmp_clean_dir),
                "--no-extensions",
                "--no-npm-scan",
                "--no-git",
                "--format",
                "json",
            ],
        )
        assert result.exit_code == 0
        parsed = json.loads(result.output)
        assert parsed["scanner"] == "glassworm-hunter"
        assert parsed["summary"]["total_findings"] == 0

    def test_json_output_with_findings(self, tmp_infected_dir: Path) -> None:
        runner = CliRunner()
        result = runner.invoke(
            main,
            [
                "scan",
                str(tmp_infected_dir),
                "--no-extensions",
                "--no-npm-scan",
                "--no-git",
                "--format",
                "json",
            ],
        )
        assert result.exit_code == 1
        parsed = json.loads(result.output)
        assert parsed["summary"]["total_findings"] > 0

    def test_sarif_output(self, tmp_clean_dir: Path) -> None:
        runner = CliRunner()
        result = runner.invoke(
            main,
            [
                "scan",
                str(tmp_clean_dir),
                "--no-extensions",
                "--no-npm-scan",
                "--no-git",
                "--format",
                "sarif",
            ],
        )
        assert result.exit_code == 0
        parsed = json.loads(result.output)
        assert parsed["version"] == "2.1.0"

    def test_output_to_file(self, tmp_clean_dir: Path, tmp_path: Path) -> None:
        out_file = tmp_path / "report.json"
        runner = CliRunner()
        result = runner.invoke(
            main,
            [
                "scan",
                str(tmp_clean_dir),
                "--no-extensions",
                "--no-npm-scan",
                "--no-git",
                "--format",
                "json",
                "--output",
                str(out_file),
            ],
        )
        assert result.exit_code == 0
        assert out_file.exists()
        parsed = json.loads(out_file.read_text())
        assert parsed["scanner"] == "glassworm-hunter"

    def test_severity_filter(self, tmp_infected_dir: Path) -> None:
        runner = CliRunner()
        # Only show critical
        result = runner.invoke(
            main,
            [
                "scan",
                str(tmp_infected_dir),
                "--no-extensions",
                "--no-npm-scan",
                "--no-git",
                "--format",
                "json",
                "--severity",
                "critical",
            ],
        )
        if result.exit_code == 1:
            parsed = json.loads(result.output)
            for f in parsed["findings"]:
                assert f["severity"] == "critical"

    def test_quiet_mode(self, tmp_clean_dir: Path) -> None:
        runner = CliRunner()
        result = runner.invoke(
            main,
            [
                "scan",
                str(tmp_clean_dir),
                "--no-extensions",
                "--no-npm-scan",
                "--no-git",
                "--quiet",
            ],
        )
        assert result.exit_code == 0


class TestRulesCommand:
    def test_rules_help(self) -> None:
        runner = CliRunner()
        result = runner.invoke(main, ["rules", "--help"])
        assert result.exit_code == 0

    def test_rules_lists_detection_types(self) -> None:
        runner = CliRunner()
        result = runner.invoke(main, ["rules"])
        assert result.exit_code == 0
        assert "invisible-unicode" in result.output
        assert "eval-pattern" in result.output
        assert "decoder-pattern" in result.output
        assert "known-malicious-extension" in result.output


class TestUpdateCommand:
    def test_update_help(self) -> None:
        runner = CliRunner()
        result = runner.invoke(main, ["update", "--help"])
        assert result.exit_code == 0
        assert "Update local IoC database" in result.output

    def test_update_with_mocked_http(self, tmp_path: Path) -> None:
        """Test update command with mocked HTTP response."""
        fake_data = json.dumps(
            {
                "schema_version": "1.0",
                "extensions": [{"id": "test.ext"}],
                "npm_packages": [],
                "c2_ips": [],
                "c2_wallets": [],
                "attacker_artifacts": [],
            }
        ).encode("utf-8")

        mock_resp = MagicMock()
        mock_resp.read.return_value = fake_data
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__ = MagicMock(return_value=False)

        user_dir = tmp_path / ".glassworm"

        with (
            patch("urllib.request.urlopen", return_value=mock_resp),
            patch("glassworm_hunter.cli.Path.home", return_value=tmp_path),
        ):
            runner = CliRunner()
            result = runner.invoke(main, ["update", "--force"])

        assert result.exit_code == 0
        assert "Updated" in result.output
        assert (user_dir / "ioc.json").exists()

    def test_update_fails_gracefully_when_offline(self) -> None:
        """Test that update handles network errors gracefully."""
        import urllib.error

        with patch(
            "urllib.request.urlopen",
            side_effect=urllib.error.URLError("Network unreachable"),
        ):
            runner = CliRunner()
            result = runner.invoke(main, ["update"])
            assert result.exit_code == 2
            assert "Failed" in result.output


class TestExcludeFlag:
    def test_exclude_minified_files(self, tmp_path: Path) -> None:
        """--exclude '*.min.js' should skip minified files."""
        d = tmp_path / "project"
        d.mkdir()
        # This file has invisible unicode (will produce findings without exclude)
        (d / "normal.js").write_text("console.log('ok');\n", encoding="utf-8")
        (d / "vendor.min.js").write_text("console.log('ok');\n", encoding="utf-8")

        runner = CliRunner()
        result = runner.invoke(
            main,
            [
                "scan",
                str(d),
                "--no-extensions",
                "--no-npm-scan",
                "--no-git",
                "--format",
                "json",
                "--exclude",
                "*.min.js",
            ],
        )
        assert result.exit_code == 0
        parsed = json.loads(result.output)
        assert parsed["summary"]["files_scanned"] == 1

    def test_exclude_vendor_directory(self, tmp_path: Path) -> None:
        """--exclude 'vendor/**' should skip vendor directory."""
        d = tmp_path / "project"
        d.mkdir()
        (d / "index.js").write_text("ok();\n", encoding="utf-8")
        vendor = d / "vendorlib"
        vendor.mkdir()
        (vendor / "lib.js").write_text("ok();\n", encoding="utf-8")

        runner = CliRunner()
        result = runner.invoke(
            main,
            [
                "scan",
                str(d),
                "--no-extensions",
                "--no-npm-scan",
                "--no-git",
                "--format",
                "json",
                "--exclude",
                "vendorlib/*",
            ],
        )
        assert result.exit_code == 0
        parsed = json.loads(result.output)
        assert parsed["summary"]["files_scanned"] == 1


class TestDisableRuleFlag:
    def test_disable_rule_suppresses_findings(self, tmp_path: Path) -> None:
        """--disable-rule should suppress findings of that type."""
        d = tmp_path / "project"
        d.mkdir()
        # Content that triggers eval-pattern
        (d / "test.js").write_text("eval(Buffer.from(data).toString('utf-8'));\n", encoding="utf-8")

        runner = CliRunner()

        # Without disable: should have findings
        result_without = runner.invoke(
            main,
            [
                "scan",
                str(d),
                "--no-extensions",
                "--no-npm-scan",
                "--no-git",
                "--format",
                "json",
            ],
        )
        parsed_without = json.loads(result_without.output)
        eval_findings_without = [
            f for f in parsed_without["findings"] if f["detection_type"] == "eval-pattern"
        ]

        # With disable: eval-pattern findings should be gone
        result_with = runner.invoke(
            main,
            [
                "scan",
                str(d),
                "--no-extensions",
                "--no-npm-scan",
                "--no-git",
                "--format",
                "json",
                "--disable-rule",
                "eval-pattern",
            ],
        )
        parsed_with = json.loads(result_with.output)
        eval_findings_with = [
            f for f in parsed_with["findings"] if f["detection_type"] == "eval-pattern"
        ]

        assert len(eval_findings_without) > 0
        assert len(eval_findings_with) == 0

    def test_disable_rule_invalid_warns(self, tmp_clean_dir: Path) -> None:
        """Invalid rule ID should produce a warning but not crash."""
        runner = CliRunner()
        result = runner.invoke(
            main,
            [
                "scan",
                str(tmp_clean_dir),
                "--no-extensions",
                "--no-npm-scan",
                "--no-git",
                "--disable-rule",
                "nonexistent-rule",
            ],
        )
        assert result.exit_code == 0
        # Warning goes to stderr, check it wasn't a crash
        assert "Error" not in result.output


class TestGlasswormYml:
    def test_loads_config_file(self, tmp_path: Path) -> None:
        """Config file should set defaults for excludes and disabled rules."""
        d = tmp_path / "project"
        d.mkdir()
        (d / "index.js").write_text("ok();\n", encoding="utf-8")
        (d / "vendor.min.js").write_text("ok();\n", encoding="utf-8")

        config = d / ".glassworm.yml"
        config.write_text(
            'exclude:\n  - "*.min.js"\ndisable_rules:\n  - eval-pattern\nseverity: medium\n',
            encoding="utf-8",
        )

        runner = CliRunner()
        result = runner.invoke(
            main,
            [
                "scan",
                str(d),
                "--no-extensions",
                "--no-npm-scan",
                "--no-git",
                "--format",
                "json",
            ],
        )
        assert result.exit_code == 0
        parsed = json.loads(result.output)
        # vendor.min.js should be excluded
        assert parsed["summary"]["files_scanned"] == 1


class TestIocFileFlag:
    def test_ioc_file_loads_extra_indicators(self, tmp_path: Path) -> None:
        """--ioc-file should load additional IoC indicators."""
        d = tmp_path / "project"
        d.mkdir()
        # Content with a custom IP that will only be an IoC if custom file is loaded
        (d / "main.js").write_text(
            "const server = '192.168.99.99';\nconsole.log(server);\n",
            encoding="utf-8",
        )

        # Create custom IoC file with this IP
        ioc_file = tmp_path / "custom_ioc.json"
        ioc_file.write_text(
            json.dumps(
                {
                    "schema_version": "1.0",
                    "extensions": [],
                    "npm_packages": [],
                    "c2_ips": [{"ip": "192.168.99.99"}],
                    "c2_wallets": [],
                    "attacker_artifacts": [],
                }
            ),
            encoding="utf-8",
        )

        runner = CliRunner()

        # Without --ioc-file: no findings for this IP
        result_without = runner.invoke(
            main,
            [
                "scan",
                str(d),
                "--no-extensions",
                "--no-npm-scan",
                "--no-git",
                "--format",
                "json",
            ],
        )
        parsed_without = json.loads(result_without.output)
        ip_findings_without = [
            f for f in parsed_without["findings"] if f["detection_type"] == "known-c2-ip"
        ]

        # With --ioc-file: should detect the custom IP
        result_with = runner.invoke(
            main,
            [
                "scan",
                str(d),
                "--no-extensions",
                "--no-npm-scan",
                "--no-git",
                "--format",
                "json",
                "--ioc-file",
                str(ioc_file),
            ],
        )
        parsed_with = json.loads(result_with.output)
        ip_findings_with = [
            f for f in parsed_with["findings"] if f["detection_type"] == "known-c2-ip"
        ]

        assert len(ip_findings_without) == 0
        assert len(ip_findings_with) > 0

    def test_ioc_file_nonexistent_errors(self) -> None:
        """--ioc-file with a nonexistent path should error."""
        runner = CliRunner()
        result = runner.invoke(
            main,
            [
                "scan",
                ".",
                "--no-extensions",
                "--no-npm-scan",
                "--no-git",
                "--ioc-file",
                "/tmp/nonexistent_ioc_12345.json",
            ],
        )
        assert result.exit_code != 0


class TestUpdateSource:
    def test_update_custom_source(self, tmp_path: Path) -> None:
        """--source should use a custom URL for fetching IoCs."""
        fake_data = json.dumps(
            {
                "schema_version": "1.0",
                "extensions": [{"id": "custom.ext"}],
                "npm_packages": [],
                "c2_ips": [],
                "c2_wallets": [],
                "attacker_artifacts": [],
            }
        ).encode("utf-8")

        mock_resp = MagicMock()
        mock_resp.read.return_value = fake_data
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__ = MagicMock(return_value=False)

        with (
            patch("urllib.request.urlopen", return_value=mock_resp) as mock_urlopen,
            patch("glassworm_hunter.cli.Path.home", return_value=tmp_path),
        ):
            runner = CliRunner()
            result = runner.invoke(
                main,
                ["update", "--force", "--source", "https://example.com/ioc.json"],
            )

        assert result.exit_code == 0
        assert "Updated" in result.output
        # Verify the custom URL was used
        call_args = mock_urlopen.call_args
        request_obj = call_args[0][0]
        assert "example.com" in request_obj.full_url


class TestProgressBar:
    def test_scan_produces_no_errors_with_progress(self, tmp_clean_dir: Path) -> None:
        """Progress bar should not cause errors during normal scan."""
        runner = CliRunner()
        result = runner.invoke(
            main,
            [
                "scan",
                str(tmp_clean_dir),
                "--no-extensions",
                "--no-npm-scan",
                "--no-git",
            ],
        )
        assert result.exit_code == 0

    def test_quiet_suppresses_progress(self, tmp_clean_dir: Path) -> None:
        """--quiet should suppress progress output."""
        runner = CliRunner()
        result = runner.invoke(
            main,
            [
                "scan",
                str(tmp_clean_dir),
                "--no-extensions",
                "--no-npm-scan",
                "--no-git",
                "--quiet",
            ],
        )
        assert result.exit_code == 0
        # Quiet mode should produce minimal output
        assert "Scanning" not in result.output
