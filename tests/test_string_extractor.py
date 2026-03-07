"""Tests for the string extraction module."""

import os
import tempfile
import pytest

from hashguard.string_extractor import extract_strings, StringExtractionResult


def _make_temp(data: bytes) -> str:
    fd, path = tempfile.mkstemp()
    os.write(fd, data)
    os.close(fd)
    return path


class TestExtractStrings:
    """Tests for extract_strings function."""

    def test_empty_file(self, tmp_path):
        p = tmp_path / "empty.bin"
        p.write_bytes(b"")
        result = extract_strings(str(p))
        assert result.total_strings == 0
        assert not result.has_iocs

    def test_extracts_urls(self):
        data = b"\x00\x00http://malware.example.com/payload.exe\x00\x00"
        p = _make_temp(data)
        try:
            result = extract_strings(p)
            assert "http://malware.example.com/payload.exe" in result.iocs["urls"]
        finally:
            os.remove(p)

    def test_extracts_https_url(self):
        data = b"XXXhttps://evil.example.org/callback?id=123XXX"
        p = _make_temp(data)
        try:
            result = extract_strings(p)
            urls = result.iocs["urls"]
            assert any("evil.example.org" in u for u in urls)
        finally:
            os.remove(p)

    def test_extracts_ip_addresses(self):
        data = b"\x00\x00Connect to 203.0.113.42 on port 443\x00"
        p = _make_temp(data)
        try:
            result = extract_strings(p)
            assert "203.0.113.42" in result.iocs["ips"]
        finally:
            os.remove(p)

    def test_skips_bogon_ips(self):
        data = b"127.0.0.1 192.168.1.1 10.0.0.1"
        p = _make_temp(data)
        try:
            result = extract_strings(p)
            ips = result.iocs["ips"]
            assert "127.0.0.1" not in ips
            assert "192.168.1.1" not in ips
            assert "10.0.0.1" not in ips
        finally:
            os.remove(p)

    def test_extracts_email(self):
        data = b"Contact admin@malware-c2.example.com for info"
        p = _make_temp(data)
        try:
            result = extract_strings(p)
            assert any("admin@malware-c2.example.com" in e for e in result.iocs["emails"])
        finally:
            os.remove(p)

    def test_extracts_powershell_cmd(self):
        data = b"cmd /c powershell -encodedCommand AAABBBCCC"
        p = _make_temp(data)
        try:
            result = extract_strings(p)
            assert len(result.iocs["powershell_commands"]) >= 1
        finally:
            os.remove(p)

    def test_extracts_registry_key(self):
        data = b"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"
        p = _make_temp(data)
        try:
            result = extract_strings(p)
            assert any("CurrentVersion\\Run" in k for k in result.iocs["registry_keys"])
        finally:
            os.remove(p)

    def test_extracts_domain(self):
        data = b"\x00evil-c2-server.xyz\x00more data\x00"
        p = _make_temp(data)
        try:
            result = extract_strings(p)
            domains = result.iocs["domains"]
            assert any("evil-c2-server.xyz" in d for d in domains)
        finally:
            os.remove(p)

    def test_extracts_suspicious_path(self):
        data = b"\x00C:\\Windows\\Temp\\payload.exe\x00"
        p = _make_temp(data)
        try:
            result = extract_strings(p)
            assert len(result.iocs["suspicious_paths"]) >= 1
        finally:
            os.remove(p)

    def test_has_iocs_property(self):
        data = b"http://evil.example.com/bad.exe padding padding"
        p = _make_temp(data)
        try:
            result = extract_strings(p)
            assert result.has_iocs is True
        finally:
            os.remove(p)

    def test_to_dict_flat_structure(self):
        data = b"\x00http://evil.example.com/payload\x00203.0.113.1\x00"
        p = _make_temp(data)
        try:
            result = extract_strings(p)
            d = result.to_dict()
            assert "total_strings" in d
            assert "has_iocs" in d
            # URLs should be at top level (flat), not nested under "iocs"
            if result.iocs["urls"]:
                assert "urls" in d
        finally:
            os.remove(p)

    def test_dedup(self):
        url = b"http://evil.example.com/payload.exe"
        data = url + b"\x00" + url + b"\x00" + url
        p = _make_temp(data)
        try:
            result = extract_strings(p)
            assert result.iocs["urls"].count(url.decode()) <= 1
        finally:
            os.remove(p)

    def test_max_bytes_limit(self, tmp_path):
        """Only first max_bytes are read."""
        p = tmp_path / "big.bin"
        p.write_bytes(
            b"\x00" * 100
            + b"http://early.example.com/x"
            + b"\x00" * 200
            + b"http://late.example.com/yy"
        )
        result = extract_strings(str(p), max_bytes=150)
        urls = result.iocs["urls"]
        assert any("early" in u for u in urls)

    def test_nonexistent_file(self):
        result = extract_strings("/nonexistent/file.bin")
        assert result.total_strings == 0
        assert not result.has_iocs
