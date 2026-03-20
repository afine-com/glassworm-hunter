"""Tests for behavioral pattern detection."""

from __future__ import annotations

from pathlib import Path

from glassworm_hunter.engine.behavioral import scan_file_content
from glassworm_hunter.engine.models import DetectionType, Severity


class TestDecoderPatterns:
    def test_detects_glassworm_decoder(self) -> None:
        content = (
            "const s = v => [...v].map(w => (\n"
            "  w = w.codePointAt(0),\n"
            "  w >= 0xFE00 && w <= 0xFE0F ? w - 0xFE00 :\n"
            "  w >= 0xE0100 && w <= 0xE01EF ? w - 0xE0100 + 16 : null\n"
            ")).filter(n => n !== null);\n"
        )
        findings = scan_file_content(content, Path("extension.js"))
        decoder_findings = [
            f for f in findings if f.detection_type == DetectionType.DECODER_PATTERN
        ]
        assert len(decoder_findings) >= 1
        assert any(f.severity == Severity.CRITICAL for f in decoder_findings)

    def test_detects_eval_buffer_from_tostring(self) -> None:
        """eval(Buffer.from(...).toString('utf-8')) is a decoder pattern."""
        content = "eval(Buffer.from(data).toString('utf-8'));\n"
        findings = scan_file_content(content, Path("test.js"))
        decoder_findings = [
            f for f in findings if f.detection_type == DetectionType.DECODER_PATTERN
        ]
        assert len(decoder_findings) >= 1

    def test_plain_buffer_from_tostring_is_not_decoder(self) -> None:
        """Buffer.from().toString('utf-8') WITHOUT eval is normal Node.js."""
        content = "const text = Buffer.from(data).toString('utf-8');\n"
        findings = scan_file_content(content, Path("extension.js"))
        decoder_findings = [
            f for f in findings if f.detection_type == DetectionType.DECODER_PATTERN
        ]
        assert len(decoder_findings) == 0

    def test_no_fp_on_webpack_bundle_buffer(self) -> None:
        """Minified webpack bundle with Buffer.from().toString should not CRIT."""
        content = (
            '(()=>{var e={1234:function(e,t,n){"use strict";'
            "var r=Buffer.from(data).toString('utf-8');"
            "console.log(r);}});\n"
        )
        findings = scan_file_content(content, Path("extension.js"))
        decoder_findings = [
            f for f in findings if f.detection_type == DetectionType.DECODER_PATTERN
        ]
        assert len(decoder_findings) == 0

    def test_detects_vs_range_with_eval(self) -> None:
        """0xFE00 + 0xE0100 + eval together is a decoder."""
        content = "const lo = 0xFE00; const hi = 0xE0100;\neval(decode(payload, lo, hi));\n"
        findings = scan_file_content(content, Path("test.js"))
        decoder_findings = [
            f for f in findings if f.detection_type == DetectionType.DECODER_PATTERN
        ]
        assert len(decoder_findings) >= 1

    def test_no_fp_on_obfuscated_bundle(self) -> None:
        """Obfuscated JS (like Pylance) with hex literals far apart should not CRIT.

        Real-world FP: Pylance's obfuscated bundle contains 0xfe00-range values
        as unrelated numeric constants and 'Function' as a standard constructor,
        spread across thousands of characters. The old regex with re.DOTALL
        matched these across the entire file.
        """
        # Simulate: 0xfe00 somewhere, then 1000+ chars of junk, then 0xe0100,
        # then more junk, then Function — all on separate lines.
        content = (
            "var _0x1234 = parseInt(_0x5678(0xfe00)) / 0x1;\n"
            + ("var _0x0000 = _0xaaaa(0x" + "ff" * 2 + ");\n") * 60
            + "var _0x5678 = parseInt(_0xabcd(0xe0100)) / 0x2;\n"
            + ("var _0x1111 = _0xbbbb(0x" + "aa" * 2 + ");\n") * 60
            + "const _0x9999 = new Function('return this')();\n"
        )
        findings = scan_file_content(content, Path("bundle.js"))
        decoder_findings = [
            f for f in findings if f.detection_type == DetectionType.DECODER_PATTERN
        ]
        assert len(decoder_findings) == 0


class TestEvalPatterns:
    def test_detects_eval_with_buffer(self) -> None:
        content = "eval(Buffer.from(encoded).toString('utf8'));\n"
        findings = scan_file_content(content, Path("test.js"))
        eval_findings = [f for f in findings if f.detection_type == DetectionType.EVAL_PATTERN]
        assert len(eval_findings) >= 1

    def test_detects_eval_with_template_literal(self) -> None:
        content = "eval(`${decoded}`);\n"
        findings = scan_file_content(content, Path("test.js"))
        eval_findings = [f for f in findings if f.detection_type == DetectionType.EVAL_PATTERN]
        assert len(eval_findings) == 1

    def test_no_findings_on_clean_code(self) -> None:
        content = "const x = 1 + 2;\nconsole.log(x);\n"
        findings = scan_file_content(content, Path("clean.js"))
        assert len(findings) == 0

    def test_no_findings_on_non_code_file(self) -> None:
        content = "eval(Buffer.from(data).toString('utf-8'));\n"
        findings = scan_file_content(content, Path("test.md"))
        assert len(findings) == 0

    def test_child_process_import_not_flagged(self) -> None:
        """Plain require('child_process') should NOT be flagged.

        This is standard Node.js API used by every LSP, debugger, and build
        tool. Flagging it produces hundreds of useless findings on VS Code
        extensions.
        """
        content = "const cp = require('child_process');\n"
        findings = scan_file_content(content, Path("extension.js"))
        assert len(findings) == 0

    def test_exec_with_decoded_content_is_flagged(self) -> None:
        """execSync with Buffer.from IS suspicious — decoded command execution."""
        content = "execSync(Buffer.from(encoded, 'base64').toString());\n"
        findings = scan_file_content(content, Path("test.js"))
        eval_findings = [f for f in findings if f.detection_type == DetectionType.EVAL_PATTERN]
        assert len(eval_findings) >= 1


class TestCredentialAccessPatterns:
    def test_detects_npmrc_read(self) -> None:
        content = "const data = fs.readFileSync('/home/user/.npmrc', 'utf-8');\n"
        findings = scan_file_content(content, Path("steal.js"))
        cred_findings = [f for f in findings if f.detection_type == DetectionType.CREDENTIAL_ACCESS]
        assert len(cred_findings) == 1

    def test_detects_github_token_env(self) -> None:
        content = "const token = process.env['GITHUB_TOKEN'];\n"
        findings = scan_file_content(content, Path("steal.js"))
        cred_findings = [f for f in findings if f.detection_type == DetectionType.CREDENTIAL_ACCESS]
        assert len(cred_findings) == 1

    def test_detects_ssh_key_read(self) -> None:
        content = "const key = fs.readFileSync(path.join(home, '.ssh/id_rsa'));\n"
        findings = scan_file_content(content, Path("steal.js"))
        cred_findings = [f for f in findings if f.detection_type == DetectionType.CREDENTIAL_ACCESS]
        assert len(cred_findings) == 1

    def test_detects_browser_credential_with_path(self) -> None:
        """readFileSync with full path to Chrome Login Data IS credential theft."""
        content = (
            "const creds = fs.readFileSync("
            "home + '/Library/Application Support/Google/Chrome/Default/Login Data'"
            ");\n"
        )
        findings = scan_file_content(content, Path("steal.js"))
        cred_findings = [f for f in findings if f.detection_type == DetectionType.CREDENTIAL_ACCESS]
        assert len(cred_findings) == 1

    def test_bare_cookies_string_not_flagged(self) -> None:
        """The word 'Cookies' in minified JS should NOT be flagged.

        Telemetry SDKs, HTTP header handling, etc. all contain the word
        'Cookies'. Only file-read calls with a path should trigger.
        """
        content = (
            'var COOKIE_HEADER = "Cookies";\n'
            "function parseCookies(req) { return req.headers.Cookies; }\n"
        )
        findings = scan_file_content(content, Path("extension.js"))
        cred_findings = [f for f in findings if f.detection_type == DetectionType.CREDENTIAL_ACCESS]
        assert len(cred_findings) == 0

    def test_bare_login_data_string_not_flagged(self) -> None:
        """'Login Data' without readFile context should NOT trigger."""
        content = 'const label = "Login Data";\nconsole.log(label);\n'
        findings = scan_file_content(content, Path("extension.js"))
        cred_findings = [f for f in findings if f.detection_type == DetectionType.CREDENTIAL_ACCESS]
        assert len(cred_findings) == 0


class TestC2Patterns:
    def test_detects_solana_rpc(self) -> None:
        content = "const sigs = await connection.getSignaturesForAddress(pubkey);\n"
        findings = scan_file_content(content, Path("c2.js"))
        c2_findings = [f for f in findings if f.detection_type == DetectionType.C2_INDICATOR]
        assert len(c2_findings) == 1
        assert c2_findings[0].severity == Severity.HIGH

    def test_lower_severity_in_crypto_file(self) -> None:
        content = "const sigs = await connection.getSignaturesForAddress(pubkey);\n"
        findings = scan_file_content(content, Path("solana-client.js"))
        c2_findings = [f for f in findings if f.detection_type == DetectionType.C2_INDICATOR]
        assert len(c2_findings) == 1
        assert c2_findings[0].severity == Severity.MEDIUM

    def test_detects_google_calendar_c2(self) -> None:
        content = "const url = 'https://calendar.app.google.com/abc123';\n"
        findings = scan_file_content(content, Path("c2.js"))
        c2_findings = [f for f in findings if f.detection_type == DetectionType.C2_INDICATOR]
        assert len(c2_findings) == 1
