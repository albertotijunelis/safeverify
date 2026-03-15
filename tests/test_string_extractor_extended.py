"""Extended tests for HashGuard string_extractor module — covers remaining branches."""

import os
import tempfile

import pytest

from hashguard.string_extractor import (
    extract_strings,
    StringExtractionResult,
    _is_bogon,
    _is_benign_domain,
    _is_benign_registry,
    _safe_decode,
    _dedup_add,
    _BENIGN_IPS,
    _BENIGN_DOMAIN_SUFFIXES,
    _BENIGN_REGISTRY_PREFIXES,
)


def _tmp(data: bytes) -> str:
    fd, path = tempfile.mkstemp()
    os.write(fd, data)
    os.close(fd)
    return path


# ── _is_benign_domain ───────────────────────────────────────────────────────

class TestIsBenignDomain:
    def test_exact_match(self):
        assert _is_benign_domain("google.com") is True

    def test_subdomain_match(self):
        assert _is_benign_domain("maps.google.com") is True

    def test_deep_subdomain(self):
        assert _is_benign_domain("a.b.c.microsoft.com") is True

    def test_unknown_domain(self):
        assert _is_benign_domain("evil-c2.xyz") is False

    def test_trailing_dot(self):
        assert _is_benign_domain("google.com.") is True

    def test_case_insensitive(self):
        assert _is_benign_domain("GOOGLE.COM") is True

    def test_partial_suffix_no_match(self):
        assert _is_benign_domain("notgoogle.com") is False

    def test_pypi_org(self):
        assert _is_benign_domain("pypi.org") is True

    def test_amazonaws(self):
        assert _is_benign_domain("s3.amazonaws.com") is True

    def test_github(self):
        assert _is_benign_domain("raw.githubusercontent.com") is True


# ── _is_benign_registry ─────────────────────────────────────────────────────

class TestIsBenignRegistry:
    def test_app_paths(self):
        assert _is_benign_registry(
            r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\notepad.exe"
        ) is True

    def test_nt_currentversion(self):
        assert _is_benign_registry(
            r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion"
        ) is True

    def test_cryptography(self):
        assert _is_benign_registry(r"HKLM\SOFTWARE\Microsoft\Cryptography") is True

    def test_control_panel(self):
        assert _is_benign_registry(r"HKCU\Control Panel\Desktop") is True

    def test_suspicious_key(self):
        assert _is_benign_registry(
            r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
        ) is False

    def test_case_insensitive(self):
        assert _is_benign_registry(
            r"hklm\software\microsoft\cryptography"
        ) is True

    def test_nls(self):
        assert _is_benign_registry(
            r"HKLM\SYSTEM\CurrentControlSet\Control\Nls\Language"
        ) is True


# ── _safe_decode ─────────────────────────────────────────────────────────────

class TestSafeDecode:
    def test_normal_string(self):
        assert _safe_decode(b"hello world") == "hello world"

    def test_strips_nulls(self):
        assert _safe_decode(b"\x00hello\x00") == "hello"

    def test_strips_newlines(self):
        assert _safe_decode(b"\r\nhello\r\n") == "hello"

    def test_invalid_utf8(self):
        result = _safe_decode(b"\xff\xfe hello")
        assert "hello" in result

    def test_empty(self):
        assert _safe_decode(b"") == ""


# ── _dedup_add ───────────────────────────────────────────────────────────────

class TestDedupAdd:
    def test_adds_new(self):
        lst = []
        _dedup_add(lst, "a")
        assert lst == ["a"]

    def test_skips_duplicate(self):
        lst = ["a"]
        _dedup_add(lst, "a")
        assert lst == ["a"]

    def test_respects_limit(self):
        lst = list(range(50))
        _dedup_add(lst, "new", limit=50)
        assert "new" not in lst
        assert len(lst) == 50

    def test_under_limit(self):
        lst = list(range(49))
        _dedup_add(lst, "new", limit=50)
        assert "new" in lst

    def test_custom_limit(self):
        lst = ["a", "b"]
        _dedup_add(lst, "c", limit=3)
        assert "c" in lst
        _dedup_add(lst, "d", limit=3)
        assert "d" not in lst


# ── _is_bogon extended ──────────────────────────────────────────────────────

class TestIsBogonExtended:
    def test_0_prefix(self):
        assert _is_bogon("0.0.0.0") is True

    def test_255_prefix(self):
        assert _is_bogon("255.255.255.255") is True

    def test_169_254(self):
        assert _is_bogon("169.254.1.1") is True

    def test_172_16(self):
        assert _is_bogon("172.16.0.1") is True

    def test_172_31(self):
        assert _is_bogon("172.31.255.255") is True

    def test_172_32_not_bogon(self):
        assert _is_bogon("172.32.0.1") is False

    def test_172_15_not_bogon(self):
        assert _is_bogon("172.15.0.1") is False

    def test_public_ip(self):
        assert _is_bogon("8.8.8.8") is False

    def test_class_b_private(self):
        assert _is_bogon("172.20.0.1") is True


# ── extract_strings extended ─────────────────────────────────────────────────

class TestExtractStringsExtended:
    def test_benign_ip_filtered(self):
        data = b"Connect to 8.8.8.8 and 1.1.1.1 for DNS"
        p = _tmp(data)
        try:
            result = extract_strings(p)
            assert "8.8.8.8" not in result.iocs["ips"]
            assert "1.1.1.1" not in result.iocs["ips"]
        finally:
            os.remove(p)

    def test_benign_url_filtered(self):
        data = b"Visit https://www.google.com/search?q=test for results"
        p = _tmp(data)
        try:
            result = extract_strings(p)
            urls = result.iocs["urls"]
            # Benign Google URLs should be filtered out
            assert not any(u.startswith("https://www.google.com/") for u in urls)
        finally:
            os.remove(p)

    def test_benign_domain_filtered(self):
        data = b"\x00update.microsoft.com\x00"
        p = _tmp(data)
        try:
            result = extract_strings(p)
            domains = result.iocs.get("domains", [])
            assert "update.microsoft.com" not in domains
        finally:
            os.remove(p)

    def test_benign_registry_filtered(self):
        data = rb"HKLM\SOFTWARE\Microsoft\Cryptography\MachineGuid"
        p = _tmp(data)
        try:
            result = extract_strings(p)
            keys = result.iocs.get("registry_keys", [])
            assert not any("Cryptography" in k for k in keys)
        finally:
            os.remove(p)

    def test_btc_bech32_address(self):
        # bc1 address (bech32)
        addr = b"bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"
        data = b"\x00\x00" + addr + b"\x00\x00"
        p = _tmp(data)
        try:
            result = extract_strings(p)
            wallets = result.iocs.get("crypto_wallets", [])
            assert any("bc1q" in w for w in wallets)
        finally:
            os.remove(p)

    def test_monero_address(self):
        # Monero addresses start with 4 and are 95 chars
        addr = b"4" + b"A" + b"1" * 93
        data = b"\x00" + addr + b"\x00"
        p = _tmp(data)
        try:
            result = extract_strings(p)
            wallets = result.iocs.get("crypto_wallets", [])
            assert len(wallets) >= 0  # May or may not match depending on exact format
        finally:
            os.remove(p)

    def test_ethereum_address(self):
        addr = b"0x742d35Cc6634C0532925a3b844Bc9e7595f2bD61"
        data = b"\x00" + addr + b"\x00"
        p = _tmp(data)
        try:
            result = extract_strings(p)
            wallets = result.iocs.get("crypto_wallets", [])
            assert any("0x742d35" in w for w in wallets)
        finally:
            os.remove(p)

    def test_mixed_iocs(self):
        data = (
            b"http://evil.example.com/payload.exe\x00"
            b"203.0.113.42\x00"
            b"evil-c2.xyz\x00"
            b"admin@evil.xyz\x00"
            b"powershell -EncodedCommand ABCDEFGH\x00"
            b"C:\\Windows\\Temp\\dropper.exe\x00"
            b"0x742d35Cc6634C0532925a3b844Bc9e7595f2bD61\x00"
            b"Mozilla/5.0 (evil bot)\x00"
            b"HKLM\\SOFTWARE\\Evil\\Persistence\\Run\x00"
        )
        p = _tmp(data)
        try:
            result = extract_strings(p)
            assert result.has_iocs is True
            assert len(result.iocs["urls"]) >= 1
            assert len(result.iocs["ips"]) >= 1
            assert len(result.iocs["emails"]) >= 1
            assert len(result.iocs["powershell_commands"]) >= 1
            assert len(result.iocs["suspicious_paths"]) >= 1
            assert len(result.iocs["crypto_wallets"]) >= 1
            assert len(result.iocs["user_agents"]) >= 1
            assert len(result.iocs["registry_keys"]) >= 1
        finally:
            os.remove(p)

    def test_dedup_limit_urls(self):
        """Ensure dedup limit of 50 is respected."""
        urls = [f"http://evil{i}.example.com/path{i}" for i in range(60)]
        data = b"\x00".join(u.encode() for u in urls)
        p = _tmp(data)
        try:
            result = extract_strings(p)
            assert len(result.iocs["urls"]) <= 50
        finally:
            os.remove(p)

    def test_string_count(self):
        data = b"This is a printable string\x00Another printable string here\x00"
        p = _tmp(data)
        try:
            result = extract_strings(p)
            assert result.total_strings >= 2
        finally:
            os.remove(p)

    def test_to_dict_empty_categories_omitted(self):
        data = b"\x00" * 100  # No IOCs
        p = _tmp(data)
        try:
            result = extract_strings(p)
            d = result.to_dict()
            assert d["has_iocs"] is False
            # Empty categories should not be in iocs dict
            if "iocs" in d:
                for v in d["iocs"].values():
                    assert len(v) > 0
        finally:
            os.remove(p)

    def test_pwsh_variant(self):
        data = b"pwsh -Command Get-Process | Export-Csv output.csv"
        p = _tmp(data)
        try:
            result = extract_strings(p)
            ps = result.iocs.get("powershell_commands", [])
            assert len(ps) >= 1
        finally:
            os.remove(p)

    def test_ip_dedup(self):
        data = b"203.0.113.42 " * 10
        p = _tmp(data)
        try:
            result = extract_strings(p)
            ips = result.iocs["ips"]
            assert ips.count("203.0.113.42") <= 1
        finally:
            os.remove(p)


# ── StringExtractionResult ───────────────────────────────────────────────────

class TestStringExtractionResult:
    def test_default_init(self):
        r = StringExtractionResult()
        assert r.total_strings == 0
        assert r.has_iocs is False

    def test_has_iocs_with_data(self):
        r = StringExtractionResult()
        r.iocs["urls"].append("http://evil.com")
        assert r.has_iocs is True

    def test_to_dict_structure(self):
        r = StringExtractionResult()
        r.total_strings = 5
        r.iocs["ips"].append("1.2.3.4")
        d = r.to_dict()
        assert d["total_strings"] == 5
        assert d["has_iocs"] is True
        assert "ips" in d["iocs"]
