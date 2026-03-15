"""Extended tests for HashGuard scanner module — covers remaining branches."""

import hashlib
import json
import os
import tempfile
from unittest.mock import patch, MagicMock

import pytest

from hashguard import scanner
from hashguard.config import HashGuardConfig


def _tmp_file(data: bytes) -> str:
    fd, path = tempfile.mkstemp()
    os.write(fd, data)
    os.close(fd)
    return path


# ── FileAnalysisResult extended ──────────────────────────────────────────────

class TestFileAnalysisResultExtended:
    def test_to_dict_with_anomaly_and_memory(self):
        result = scanner.FileAnalysisResult(
            path="/t.exe",
            hashes={"md5": "a"},
            file_size=100,
            anomaly_detection={"is_anomaly": True, "score": 0.95},
            memory_analysis={"risk_score": 80},
        )
        d = result.to_dict()
        assert d["anomaly_detection"]["is_anomaly"] is True
        assert d["memory_analysis"]["risk_score"] == 80

    def test_to_dict_with_script_deobfuscation(self):
        result = scanner.FileAnalysisResult(
            path="/t.ps1",
            hashes={"md5": "a"},
            file_size=50,
            script_deobfuscation={"layers": 3, "decoded": True},
        )
        d = result.to_dict()
        assert d["script_deobfuscation"]["layers"] == 3

    def test_timestamp_set(self):
        result = scanner.FileAnalysisResult(path="/t", hashes={}, file_size=0)
        assert result.timestamp is not None
        assert "T" in result.timestamp  # ISO format

    def test_to_json_contains_timestamp(self):
        result = scanner.FileAnalysisResult(path="/t", hashes={"md5": "x"}, file_size=0)
        data = json.loads(result.to_json())
        assert "timestamp" in data

    def test_to_dict_excludes_none_optional_fields(self):
        result = scanner.FileAnalysisResult(path="/t", hashes={}, file_size=0)
        d = result.to_dict()
        for field in ("pe_info", "yara_matches", "capabilities", "advanced_pe",
                       "fuzzy_hashes", "ml_classification", "family_detection",
                       "ioc_graph", "timeline", "packer", "shellcode",
                       "script_deobfuscation", "anomaly_detection", "memory_analysis"):
            assert field not in d


# ── SignatureDatabase extended ───────────────────────────────────────────────

class TestSignatureDatabaseExtended:
    def test_empty_signatures(self, tmp_path):
        sig_path = tmp_path / "sigs.json"
        sig_path.write_text("{}")
        config = HashGuardConfig(signatures_file=str(sig_path))
        db = scanner.SignatureDatabase(config)
        assert db.count() == 0
        assert db.get("abc") is None
        assert db.contains("abc") is False

    def test_multiple_lookups(self, tmp_path):
        sig_path = tmp_path / "sigs.json"
        sig_path.write_text('{"aaa": "Trojan.A", "bbb": "Worm.B", "ccc": "Ransom.C"}')
        config = HashGuardConfig(signatures_file=str(sig_path))
        db = scanner.SignatureDatabase(config)
        assert db.count() == 3
        assert db.get("aaa") == "Trojan.A"
        assert db.get("bbb") == "Worm.B"
        assert db.get("ddd") is None

    def test_reload(self, tmp_path):
        sig_path = tmp_path / "sigs.json"
        sig_path.write_text('{"x": "malware"}')
        config = HashGuardConfig(signatures_file=str(sig_path))
        db = scanner.SignatureDatabase(config)
        assert db.count() == 1
        sig_path.write_text('{"x": "malware", "y": "trojan"}')
        db.load()
        assert db.count() == 2


# ── compute_hashes extended ──────────────────────────────────────────────────

class TestComputeHashesExtended:
    def test_sha512(self, tmp_path):
        p = tmp_path / "test.bin"
        p.write_bytes(b"test")
        hashes = scanner.compute_hashes(str(p), ["sha512"])
        assert "sha512" in hashes
        assert len(hashes["sha512"]) == 128

    def test_multiple_chunks(self, tmp_path):
        p = tmp_path / "big.bin"
        data = b"x" * 200000  # Larger than default chunk_size
        p.write_bytes(data)
        hashes = scanner.compute_hashes(str(p))
        expected_md5 = hashlib.md5(data).hexdigest()
        assert hashes["md5"] == expected_md5

    def test_max_file_size_exact(self, tmp_path):
        p = tmp_path / "exact.bin"
        p.write_bytes(b"x" * 100)
        config = HashGuardConfig(max_file_size=100)
        hashes = scanner.compute_hashes(str(p), config=config)
        assert "md5" in hashes

    def test_custom_algorithms(self, tmp_path):
        p = tmp_path / "test.bin"
        p.write_bytes(b"data")
        hashes = scanner.compute_hashes(str(p), ["sha256"])
        assert "sha256" in hashes
        assert "md5" not in hashes


# ── is_malware extended ──────────────────────────────────────────────────────

class TestIsMalwareExtended:
    def test_uses_global_signatures(self, tmp_path, monkeypatch):
        monkeypatch.setattr(scanner, "_global_signatures", None)
        p = _tmp_file(b"hello")
        try:
            result = scanner.is_malware(p)
            assert isinstance(result, bool)
        finally:
            os.remove(p)
            monkeypatch.setattr(scanner, "_global_signatures", None)


# ── query_virustotal extended ────────────────────────────────────────────────

class TestQueryVirusTotalExtended:
    @patch("hashguard.scanner.compute_hashes")
    def test_vt_other_status_code(self, mock_hashes, monkeypatch):
        mock_hashes.return_value = {"sha256": "abc"}
        class FakeResp:
            status_code = 429
        import requests as _req
        monkeypatch.setattr(_req, "get", lambda *a, **kw: FakeResp())
        assert scanner.query_virustotal("x.exe", api_key="key") is None

    @patch("hashguard.scanner.compute_hashes")
    def test_vt_unexpected_exception(self, mock_hashes, monkeypatch):
        mock_hashes.return_value = {"sha256": "abc"}
        import requests as _req
        monkeypatch.setattr(_req, "get", lambda *a, **kw: (_ for _ in ()).throw(RuntimeError("err")))
        assert scanner.query_virustotal("x.exe", api_key="key") is None


# ── query_virustotal_url extended ────────────────────────────────────────────

class TestQueryVTUrlExtended:
    def test_exception_returns_none(self, monkeypatch):
        import requests as _req
        monkeypatch.setattr(_req, "get", lambda *a, **kw: (_ for _ in ()).throw(Exception("err")))
        assert scanner.query_virustotal_url("http://e.com", api_key="key") is None

    def test_no_key_via_direct_param(self):
        assert scanner.query_virustotal_url("http://e.com", api_key="") is None


# ── analyze with batch_mode ──────────────────────────────────────────────────

class TestAnalyzeBatchMode:
    def test_batch_mode_skips_threat_intel(self, tmp_path):
        sig_path = tmp_path / "sigs.json"
        sig_path.write_text("{}")
        config = HashGuardConfig(signatures_file=str(sig_path))
        p = _tmp_file(b"batch test")
        try:
            with patch("hashguard.threat_intel.query_all") as mock_ti:
                result = scanner.analyze(p, config=config, batch_mode=True)
                mock_ti.assert_not_called()
            assert result.path == p
        finally:
            os.remove(p)

    def test_batch_mode_result_has_hashes(self, tmp_path):
        sig_path = tmp_path / "sigs.json"
        sig_path.write_text("{}")
        config = HashGuardConfig(signatures_file=str(sig_path))
        p = _tmp_file(b"data")
        try:
            result = scanner.analyze(p, config=config, batch_mode=True)
            assert "md5" in result.hashes
            assert "sha256" in result.hashes
        finally:
            os.remove(p)


# ── analyze_url extended ────────────────────────────────────────────────────

class TestAnalyzeUrlExtended:
    def test_rejects_empty_hostname(self):
        with pytest.raises(ValueError, match="no hostname"):
            scanner.analyze_url("http:///path")

    def test_rejects_file_scheme(self):
        with pytest.raises(ValueError, match="Unsupported URL scheme"):
            scanner.analyze_url("file:///etc/passwd")

    def test_rejects_data_scheme(self):
        with pytest.raises(ValueError, match="Unsupported URL scheme"):
            scanner.analyze_url("data:text/plain,hello")

    def test_too_many_redirects(self, monkeypatch):
        class RedirectResp:
            status_code = 302
            is_redirect = True
            is_permanent_redirect = False
            headers = {"Location": "http://example.com/next"}
            def raise_for_status(self): pass
        import requests as _req
        import socket as _socket
        monkeypatch.setattr(_req, "get", lambda *a, **kw: RedirectResp())
        monkeypatch.setattr(scanner, "_is_private_ip", lambda _h: False)
        monkeypatch.setattr(_socket, "getaddrinfo", lambda *a, **kw: [(_socket.AF_INET, _socket.SOCK_STREAM, 0, "", ("93.184.216.34", 80))])
        with pytest.raises(ValueError, match="Too many redirects"):
            scanner.analyze_url("http://example.com/start")

    def test_download_exceeds_limit(self, tmp_path, monkeypatch):
        sig_path = tmp_path / "sigs.json"
        sig_path.write_text("{}")
        config = HashGuardConfig(signatures_file=str(sig_path))

        class FakeResp:
            status_code = 200
            is_redirect = False
            is_permanent_redirect = False
            def raise_for_status(self): pass
            def iter_content(self, chunk_size=8192):
                # Generate more than 200MB
                for _ in range(30000):
                    yield b"x" * 8192
        import requests as _req
        import socket as _socket
        monkeypatch.setattr(_req, "get", lambda *a, **kw: FakeResp())
        monkeypatch.setattr(scanner, "_is_private_ip", lambda _h: False)
        monkeypatch.setattr(_socket, "getaddrinfo", lambda *a, **kw: [(_socket.AF_INET, _socket.SOCK_STREAM, 0, "", ("93.184.216.34", 80))])
        with pytest.raises(ValueError, match="200 MB"):
            scanner.analyze_url("http://example.com/huge.bin", config=config)

    def test_redirect_bad_scheme(self, monkeypatch):
        class RedirectResp:
            status_code = 301
            is_redirect = False
            is_permanent_redirect = True
            headers = {"Location": "ftp://evil.com/file"}
            def raise_for_status(self): pass
        import requests as _req
        import socket as _socket
        monkeypatch.setattr(_req, "get", lambda *a, **kw: RedirectResp())
        monkeypatch.setattr(scanner, "_is_private_ip", lambda _h: False)
        monkeypatch.setattr(_socket, "getaddrinfo", lambda *a, **kw: [(_socket.AF_INET, _socket.SOCK_STREAM, 0, "", ("93.184.216.34", 80))])
        with pytest.raises(ValueError, match="unsupported scheme"):
            scanner.analyze_url("http://example.com/redir")

    def test_url_with_vt_both_results(self, tmp_path, monkeypatch):
        sig_path = tmp_path / "sigs.json"
        sig_path.write_text("{}")
        config = HashGuardConfig(signatures_file=str(sig_path), vt_api_key="testkey")

        class FakeResp:
            status_code = 200
            is_redirect = False
            is_permanent_redirect = False
            def raise_for_status(self): pass
            def iter_content(self, chunk_size=8192):
                return [b"content"]
        import requests as _req
        import socket as _socket
        monkeypatch.setattr(_req, "get", lambda *a, **kw: FakeResp())
        monkeypatch.setattr(scanner, "_is_private_ip", lambda _h: False)
        monkeypatch.setattr(_socket, "getaddrinfo", lambda *a, **kw: [(_socket.AF_INET, _socket.SOCK_STREAM, 0, "", ("93.184.216.34", 80))])

        file_vt = {"data": {"id": "file_result"}}
        url_vt = {"data": {"id": "url_result"}}
        with patch("hashguard.scanner.query_virustotal", return_value=file_vt):
            with patch("hashguard.scanner.query_virustotal_url", return_value=url_vt):
                result = scanner.analyze_url("http://example.com/f.exe", vt=True, config=config)
        assert result.vt_result["data"]["id"] == "file_result"
        assert result.vt_result["url_scan"]["data"]["id"] == "url_result"

    def test_url_with_vt_only_url_result(self, tmp_path, monkeypatch):
        sig_path = tmp_path / "sigs.json"
        sig_path.write_text("{}")
        config = HashGuardConfig(signatures_file=str(sig_path), vt_api_key="testkey")

        class FakeResp:
            status_code = 200
            is_redirect = False
            is_permanent_redirect = False
            def raise_for_status(self): pass
            def iter_content(self, chunk_size=8192):
                return [b"content"]
        import requests as _req
        import socket as _socket
        monkeypatch.setattr(_req, "get", lambda *a, **kw: FakeResp())
        monkeypatch.setattr(scanner, "_is_private_ip", lambda _h: False)
        monkeypatch.setattr(_socket, "getaddrinfo", lambda *a, **kw: [(_socket.AF_INET, _socket.SOCK_STREAM, 0, "", ("93.184.216.34", 80))])

        url_vt = {"data": {"id": "url_only"}}
        with patch("hashguard.scanner.query_virustotal", return_value=None):
            with patch("hashguard.scanner.query_virustotal_url", return_value=url_vt):
                result = scanner.analyze_url("http://example.com/f.exe", vt=True, config=config)
        assert result.vt_result["data"]["id"] == "url_only"

    def test_requires_requests(self, monkeypatch):
        import builtins
        orig = builtins.__import__
        def fail_requests(name, *a, **kw):
            if name == "requests":
                raise ImportError("no requests")
            return orig(name, *a, **kw)
        monkeypatch.setattr(builtins, "__import__", fail_requests)
        with pytest.raises(RuntimeError, match="requests"):
            scanner.analyze_url("http://example.com/f.exe")


# ── _is_private_ip extended ─────────────────────────────────────────────────

class TestIsPrivateIPExtended:
    def test_ipv6_loopback(self, monkeypatch):
        import socket
        monkeypatch.setattr(
            socket, "getaddrinfo",
            lambda *a, **kw: [(socket.AF_INET6, 1, 0, "", ("::1", 0, 0, 0))]
        )
        assert scanner._is_private_ip("localhost6") is True

    def test_reserved_ip(self, monkeypatch):
        import socket
        monkeypatch.setattr(
            socket, "getaddrinfo",
            lambda *a, **kw: [(socket.AF_INET, 1, 0, "", ("0.0.0.0", 0))]
        )
        assert scanner._is_private_ip("zero.invalid") is True

    def test_rfc1918_10(self, monkeypatch):
        import socket
        monkeypatch.setattr(
            socket, "getaddrinfo",
            lambda *a, **kw: [(socket.AF_INET, 1, 0, "", ("10.0.0.1", 0))]
        )
        assert scanner._is_private_ip("internal.host") is True

    def test_multiple_results_mixed(self, monkeypatch):
        import socket
        monkeypatch.setattr(
            socket, "getaddrinfo",
            lambda *a, **kw: [
                (socket.AF_INET, 1, 0, "", ("8.8.8.8", 0)),
                (socket.AF_INET, 1, 0, "", ("192.168.1.1", 0)),
            ]
        )
        assert scanner._is_private_ip("mixed.host") is True


# ── _run_extended_analysis extended ──────────────────────────────────────────

class TestRunExtendedAnalysisExtended:
    def test_with_malicious_signature(self, tmp_path):
        p = _tmp_file(b"malware data")
        try:
            hashes = scanner.compute_hashes(p)
            config = HashGuardConfig(signatures_file=str(tmp_path / "empty.json"))
            result = scanner._run_extended_analysis(
                p, hashes, True, "Known.Trojan", config
            )
            is_mal = result[0]
            desc = result[1]
            assert is_mal is True
            assert "Known.Trojan" in desc
        finally:
            os.remove(p)

    def test_batch_mode_skips_fuzzy_and_anomaly(self, tmp_path):
        p = _tmp_file(b"batch data")
        try:
            hashes = scanner.compute_hashes(p)
            config = HashGuardConfig(signatures_file=str(tmp_path / "empty.json"))
            with patch("hashguard.threat_intel.query_all") as mock_ti:
                result = scanner._run_extended_analysis(
                    p, hashes, False, "Clean", config, batch_mode=True
                )
                mock_ti.assert_not_called()
        finally:
            os.remove(p)


# ── analyze file not found ───────────────────────────────────────────────────

class TestAnalyzeErrors:
    def test_file_not_found(self):
        with pytest.raises(FileNotFoundError):
            scanner.analyze("/nonexistent/path.exe")

    def test_analyze_with_vt(self, tmp_path):
        sig_path = tmp_path / "sigs.json"
        sig_path.write_text("{}")
        config = HashGuardConfig(signatures_file=str(sig_path), vt_api_key="testkey")
        p = _tmp_file(b"data")
        try:
            with patch("hashguard.scanner.query_virustotal", return_value={"data": {}}):
                result = scanner.analyze(p, vt=True, config=config)
            assert result.vt_result is not None
        finally:
            os.remove(p)


# ── _get_global_signatures ───────────────────────────────────────────────────

class TestGetGlobalSignaturesExtended:
    def test_returns_same_instance(self, monkeypatch):
        monkeypatch.setattr(scanner, "_global_signatures", None)
        db1 = scanner._get_global_signatures()
        db2 = scanner._get_global_signatures()
        assert db1 is db2
        monkeypatch.setattr(scanner, "_global_signatures", None)

    def test_cached_returns_directly(self, monkeypatch):
        fake = MagicMock()
        monkeypatch.setattr(scanner, "_global_signatures", fake)
        assert scanner._get_global_signatures() is fake
        monkeypatch.setattr(scanner, "_global_signatures", None)
