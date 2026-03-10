"""Comprehensive unit tests for HashGuard scanner."""

import os
import json
import tempfile
import pytest
from unittest.mock import patch

from hashguard import scanner
from hashguard.config import HashGuardConfig


def make_temp_file(contents: bytes) -> str:
    """Create a temporary file with given contents."""
    fd, path = tempfile.mkstemp()
    os.write(fd, contents)
    os.close(fd)
    return path


class TestHashComputation:
    """Tests for hash computation."""

    def test_compute_hashes_matches_known(self):
        """Test that computed hashes match known values."""
        data = b"hello"
        p = make_temp_file(data)
        try:
            hashes = scanner.compute_hashes(p)
            assert hashes["md5"] == "5d41402abc4b2a76b9719d911017c592"
            assert hashes["sha1"] == "aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d"
            assert (
                hashes["sha256"]
                == "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
            )
        finally:
            os.remove(p)

    def test_compute_single_hash(self):
        """Test computing a single hash algorithm."""
        data = b"test"
        p = make_temp_file(data)
        try:
            hashes = scanner.compute_hashes(p, ["md5"])
            assert "md5" in hashes
            assert "sha1" not in hashes
        finally:
            os.remove(p)

    def test_file_not_found(self):
        """Test error handling for non-existent file."""
        with pytest.raises(FileNotFoundError):
            scanner.compute_hashes("/nonexistent/path/file.txt")


class TestMalwareDetection:
    """Tests for malware signature detection."""

    def test_malware_detection_false(self, tmp_path):
        """Test that clean files are not flagged."""
        sig = {"5d41402abc4b2a76b9719d911017c592": "test malware"}
        sig_path = tmp_path / "sigs.json"
        sig_path.write_text(json.dumps(sig))

        config = HashGuardConfig(signatures_file=str(sig_path))
        sig_db = scanner.SignatureDatabase(config)

        # File with different hash
        p = make_temp_file(b"nothello")
        try:
            assert not scanner.is_malware(p, sig_db, config)
        finally:
            os.remove(p)

    def test_malware_detection_true(self, tmp_path):
        """Test that malicious files are correctly identified."""
        sig = {"5d41402abc4b2a76b9719d911017c592": "test malware"}
        sig_path = tmp_path / "sigs.json"
        sig_path.write_text(json.dumps(sig))

        config = HashGuardConfig(signatures_file=str(sig_path))
        sig_db = scanner.SignatureDatabase(config)

        # File matching the signature
        p = make_temp_file(b"hello")
        try:
            assert scanner.is_malware(p, sig_db, config)
        finally:
            os.remove(p)


class TestFileAnalysisResult:
    """Tests for FileAnalysisResult class."""

    def test_result_to_dict(self):
        """Test converting result to dictionary."""
        result = scanner.FileAnalysisResult(
            path="/test/file.exe",
            hashes={"md5": "abc123", "sha256": "def456"},
            malicious=True,
            description="Known malware",
            file_size=1024,
            analysis_time=0.5,
        )

        d = result.to_dict()
        assert d["path"] == "/test/file.exe"
        assert d["malicious"] is True
        assert d["file_size"] == 1024
        assert "analysis_time_ms" in d

    def test_result_to_json(self):
        """Test converting result to JSON."""
        result = scanner.FileAnalysisResult(
            path="/test/file.exe",
            hashes={"md5": "abc123"},
            malicious=False,
            file_size=512,
        )

        json_str = result.to_json()
        data = json.loads(json_str)
        assert data["path"] == "/test/file.exe"
        assert data["malicious"] is False


class TestSignatureDatabase:
    """Tests for SignatureDatabase."""

    def test_load_signatures(self, tmp_path):
        """Test loading signature database."""
        sig = {
            "hash1": "malware1",
            "hash2": "malware2",
        }
        sig_path = tmp_path / "sigs.json"
        sig_path.write_text(json.dumps(sig))

        config = HashGuardConfig(signatures_file=str(sig_path))
        db = scanner.SignatureDatabase(config)

        assert db.count() == 2
        assert db.get("hash1") == "malware1"

    def test_case_insensitive_lookup(self, tmp_path):
        """Test case-insensitive hash lookup."""
        sig = {"ABC123": "test"}
        sig_path = tmp_path / "sigs.json"
        sig_path.write_text(json.dumps(sig))

        config = HashGuardConfig(signatures_file=str(sig_path))
        db = scanner.SignatureDatabase(config)

        assert db.contains("abc123")
        assert db.get("ABC123") == "test"

    def test_missing_signatures_file(self, tmp_path):
        """Test behavior when signatures file doesn't exist."""
        config = HashGuardConfig(signatures_file=str(tmp_path / "missing.json"))
        db = scanner.SignatureDatabase(config)
        assert db.count() == 0


class TestAnalyzeFunction:
    """Tests for main analyze function."""

    def test_analyze_clean_file(self, tmp_path):
        """Test analyzing a clean file."""
        sig_path = tmp_path / "sigs.json"
        sig_path.write_text(json.dumps({}))

        config = HashGuardConfig(signatures_file=str(sig_path))

        # Create test file
        p = make_temp_file(b"hello")
        try:
            with patch("hashguard.threat_intel.query_all") as mock_ti:
                from hashguard.threat_intel import ThreatIntelResult

                mock_ti.return_value = ThreatIntelResult(hits=[], total_sources=0, flagged_count=0)
                result = scanner.analyze(p, config=config)
            assert result.path == p
            assert result.malicious is False
            assert result.file_size > 0
        finally:
            os.remove(p)

    def test_analyze_malicious_file(self, tmp_path):
        """Test analyzing a malicious file."""
        # Known hash for 'hello'
        sig = {"5d41402abc4b2a76b9719d911017c592": "test malware"}
        sig_path = tmp_path / "sigs.json"
        sig_path.write_text(json.dumps(sig))

        config = HashGuardConfig(signatures_file=str(sig_path))

        p = make_temp_file(b"hello")
        try:
            result = scanner.analyze(p, config=config)
            assert result.malicious is True
            assert "test malware" in result.description
        finally:
            os.remove(p)


class TestConfig:
    """Tests for HashGuardConfig."""

    def test_default_config(self):
        """Test default configuration values."""
        config = HashGuardConfig()
        assert config.hash_algorithms == ["md5", "sha1", "sha256"]
        assert config.chunk_size == 65536
        assert config.max_file_size == 0

    def test_config_from_file(self, tmp_path):
        """Test loading config from JSON file."""
        cfg = {"log_level": "DEBUG", "chunk_size": 4096}
        cfg_path = tmp_path / "config.json"
        cfg_path.write_text(json.dumps(cfg))

        config = HashGuardConfig.from_file(str(cfg_path))
        assert config.log_level == "DEBUG"
        assert config.chunk_size == 4096

    def test_config_from_missing_file(self, tmp_path):
        """Test loading config from a non-existent file returns defaults."""
        config = HashGuardConfig.from_file(str(tmp_path / "nope.json"))
        assert config.log_level == "INFO"

    def test_config_to_dict_redacts_key(self):
        """Test that API key is redacted in exported config."""
        config = HashGuardConfig(vt_api_key="secret123")
        d = config.to_dict()
        assert d["vt_api_key"] == "***REDACTED***"

    def test_config_save_and_load(self, tmp_path):
        """Test save then load round-trip."""
        cfg_path = str(tmp_path / "saved.json")
        config = HashGuardConfig(log_level="WARNING")
        config.save(cfg_path)

        loaded = HashGuardConfig.from_file(cfg_path)
        assert loaded.log_level == "WARNING"

    def test_config_save_excludes_api_key(self, tmp_path):
        """Test that save does NOT persist API key to disk (security)."""
        cfg_path = str(tmp_path / "apikey.json")
        config = HashGuardConfig(vt_api_key="mykey123")
        config.save(cfg_path)

        import json

        with open(cfg_path) as f:
            data = json.load(f)
        assert "vt_api_key" not in data


class TestReports:
    """Tests for ReportGenerator and BatchAnalyzer."""

    def test_report_to_json(self):
        """Test JSON report generation."""
        from hashguard.reports import ReportGenerator

        result = scanner.FileAnalysisResult(path="/test.exe", hashes={"md5": "abc"}, file_size=100)
        output = ReportGenerator.to_json([result])
        data = json.loads(output)
        assert isinstance(data, list)
        assert data[0]["path"] == "/test.exe"

    def test_report_to_csv(self):
        """Test CSV report generation."""
        from hashguard.reports import ReportGenerator

        result = scanner.FileAnalysisResult(
            path="/test.exe", hashes={"md5": "abc", "sha256": "def"}, file_size=100
        )
        csv_output = ReportGenerator.to_csv([result])
        assert "/test.exe" in csv_output
        assert "abc" in csv_output

    def test_report_to_html(self):
        """Test HTML report generation."""
        from hashguard.reports import ReportGenerator

        result = scanner.FileAnalysisResult(path="/test.exe", hashes={"md5": "abc"}, file_size=100)
        html = ReportGenerator.to_html([result])
        assert "<html" in html.lower() or "<table" in html.lower()

    def test_batch_analyzer(self, tmp_path):
        """Test BatchAnalyzer on a directory."""
        from hashguard.reports import BatchAnalyzer

        sig_path = tmp_path / "sigs.json"
        sig_path.write_text(json.dumps({}))

        (tmp_path / "a.txt").write_bytes(b"hello")
        (tmp_path / "b.txt").write_bytes(b"world")

        with patch("hashguard.threat_intel.query_all") as mock_ti:
            from hashguard.threat_intel import ThreatIntelResult

            mock_ti.return_value = ThreatIntelResult(hits=[], total_sources=0, flagged_count=0)
            analyzer = BatchAnalyzer()
            results = analyzer.analyze_directory(str(tmp_path), pattern="*.txt")

        assert len(results) >= 2
        summary = analyzer.get_summary()
        assert summary["total_files"] >= 2
        assert summary["clean_count"] >= 2


class TestAnalyzeUrl:
    """Tests for analyze_url with mocked HTTP."""

    def test_analyze_url_clean(self, tmp_path, monkeypatch):
        """Test URL analysis with a mocked download."""
        sig_path = tmp_path / "sigs.json"
        sig_path.write_text(json.dumps({}))
        config = HashGuardConfig(signatures_file=str(sig_path))

        class FakeResp:
            status_code = 200
            is_redirect = False
            is_permanent_redirect = False

            def raise_for_status(self):
                pass

            def iter_content(self, chunk_size=8192):
                return [b"hello world url test"]

        import requests as _req

        monkeypatch.setattr(_req, "get", lambda *a, **kw: FakeResp())
        monkeypatch.setattr(scanner, "_is_private_ip", lambda _h: False)

        result = scanner.analyze_url("http://example.com/test.bin", config=config)
        assert result.hashes.get("sha256")
        assert result.path == "http://example.com/test.bin"

    def test_analyze_url_malicious(self, tmp_path, monkeypatch):
        """Test URL analysis detects a known-bad hash."""
        import hashlib

        payload = b"malicious_payload_data"
        md5 = hashlib.md5(payload).hexdigest()
        sig_path = tmp_path / "sigs.json"
        sig_path.write_text(json.dumps({md5: "Test URL Malware"}))
        config = HashGuardConfig(signatures_file=str(sig_path))

        class FakeResp:
            status_code = 200
            is_redirect = False
            is_permanent_redirect = False

            def raise_for_status(self):
                pass

            def iter_content(self, chunk_size=8192):
                return [payload]

        import requests as _req

        monkeypatch.setattr(_req, "get", lambda *a, **kw: FakeResp())
        monkeypatch.setattr(scanner, "_is_private_ip", lambda _h: False)

        result = scanner.analyze_url("http://example.com/bad.exe", config=config)
        assert result.malicious is True
        assert "Test URL Malware" in result.description

    @pytest.mark.parametrize(
        "url",
        [
            "http://127.0.0.1/secret",
            "http://localhost/secret",
            "http://10.0.0.1/secret",
            "http://172.16.0.1/secret",
            "http://192.168.1.1/secret",
            "http://[::1]/secret",
        ],
    )
    def test_analyze_url_blocks_private_ips(self, url, monkeypatch):
        """SSRF: URLs resolving to private/reserved IPs must be rejected."""
        monkeypatch.setattr(scanner, "_is_private_ip", lambda _h: True)
        with pytest.raises(ValueError, match="local/private"):
            scanner.analyze_url(url)

    def test_analyze_url_rejects_ftp_scheme(self):
        """Only http/https schemes are allowed."""
        with pytest.raises(ValueError, match="Unsupported URL scheme"):
            scanner.analyze_url("ftp://example.com/file")

    def test_analyze_url_blocks_redirect_to_private_ip(self, monkeypatch):
        """SSRF: Redirects to private IPs must be caught."""
        call_count = 0

        class RedirectResp:
            status_code = 302
            is_redirect = True
            is_permanent_redirect = False
            headers = {"Location": "http://169.254.169.254/latest/meta-data/"}

            def raise_for_status(self):
                pass

        import requests as _req

        monkeypatch.setattr(_req, "get", lambda *a, **kw: RedirectResp())
        # First call (original URL) passes, redirect target is private
        original_check = scanner._is_private_ip

        def selective_check(hostname):
            if hostname == "169.254.169.254":
                return True
            return False

        monkeypatch.setattr(scanner, "_is_private_ip", selective_check)

        with pytest.raises(ValueError, match="Redirect points to a local/private"):
            scanner.analyze_url("http://evil.com/redir")


class TestExtendedAnalysis:
    """Tests for _run_extended_analysis helper."""

    def test_returns_clean_when_no_modules(self, tmp_path, monkeypatch):
        """Extended analysis gracefully handles missing PE/YARA/threat_intel."""
        p = make_temp_file(b"clean data")
        try:
            hashes = scanner.compute_hashes(p)
            config = HashGuardConfig(signatures_file=str(tmp_path / "empty.json"))

            # Force import failures
            def fail_import(name, *a, **kw):
                if any(
                    mod in name
                    for mod in (
                        "pe_analyzer",
                        "yara_scanner",
                        "threat_intel",
                        "risk_scorer",
                        "string_extractor",
                    )
                ):
                    raise ImportError("forced")
                return original_import(name, *a, **kw)

            import builtins

            original_import = builtins.__import__
            monkeypatch.setattr(builtins, "__import__", fail_import)

            result = scanner._run_extended_analysis(p, hashes, False, "Clean", config)
            mal = result[0]
            desc = result[1]
            pe = result[2]
            yara = result[3]
            ti = result[4]
            assert mal is False
            assert desc == "Clean"
            assert pe is None
            assert yara is None
            assert ti is None
        finally:
            os.remove(p)


class TestIsPrivateIP:
    """Tests for _is_private_ip SSRF protection."""

    def test_loopback_ipv4(self, monkeypatch):
        import socket

        monkeypatch.setattr(
            socket,
            "getaddrinfo",
            lambda *a, **kw: [(socket.AF_INET, 1, 0, "", ("127.0.0.1", 0))],
        )
        assert scanner._is_private_ip("localhost") is True

    def test_private_rfc1918(self, monkeypatch):
        import socket

        monkeypatch.setattr(
            socket,
            "getaddrinfo",
            lambda *a, **kw: [(socket.AF_INET, 1, 0, "", ("192.168.1.1", 0))],
        )
        assert scanner._is_private_ip("internal.corp") is True

    def test_public_ip(self, monkeypatch):
        import socket

        monkeypatch.setattr(
            socket,
            "getaddrinfo",
            lambda *a, **kw: [(socket.AF_INET, 1, 0, "", ("8.8.8.8", 0))],
        )
        assert scanner._is_private_ip("dns.google") is False

    def test_unresolvable_host(self, monkeypatch):
        import socket

        monkeypatch.setattr(
            socket,
            "getaddrinfo",
            lambda *a, **kw: (_ for _ in ()).throw(socket.gaierror("not found")),
        )
        assert scanner._is_private_ip("nonexistent.invalid") is False

    def test_link_local(self, monkeypatch):
        import socket

        monkeypatch.setattr(
            socket,
            "getaddrinfo",
            lambda *a, **kw: [(socket.AF_INET, 1, 0, "", ("169.254.169.254", 0))],
        )
        assert scanner._is_private_ip("metadata.internal") is True


class TestQueryVirusTotal:
    """Tests for query_virustotal with mocked requests."""

    def test_no_api_key_returns_none(self, tmp_path):
        config = HashGuardConfig(vt_api_key="")
        p = make_temp_file(b"test")
        try:
            assert scanner.query_virustotal(p, config=config) is None
        finally:
            os.remove(p)

    @patch("hashguard.scanner.compute_hashes")
    def test_vt_200_returns_json(self, mock_hashes, monkeypatch):
        mock_hashes.return_value = {"sha256": "abc123"}

        class FakeResp:
            status_code = 200
            def json(self):
                return {"data": {"attributes": {"last_analysis_stats": {"malicious": 5}}}}

        import requests as _req
        monkeypatch.setattr(_req, "get", lambda *a, **kw: FakeResp())

        result = scanner.query_virustotal("dummy.exe", api_key="testkey")
        assert result["data"]["attributes"]["last_analysis_stats"]["malicious"] == 5

    @patch("hashguard.scanner.compute_hashes")
    def test_vt_404_returns_none(self, mock_hashes, monkeypatch):
        mock_hashes.return_value = {"sha256": "abc123"}

        class FakeResp:
            status_code = 404

        import requests as _req
        monkeypatch.setattr(_req, "get", lambda *a, **kw: FakeResp())

        assert scanner.query_virustotal("dummy.exe", api_key="testkey") is None

    @patch("hashguard.scanner.compute_hashes")
    def test_vt_request_exception(self, mock_hashes, monkeypatch):
        mock_hashes.return_value = {"sha256": "abc123"}
        import requests as _req
        monkeypatch.setattr(
            _req, "get", lambda *a, **kw: (_ for _ in ()).throw(_req.RequestException("timeout"))
        )
        assert scanner.query_virustotal("dummy.exe", api_key="testkey") is None


class TestQueryVirustotalUrl:
    """Tests for query_virustotal_url."""

    def test_no_api_key(self):
        assert scanner.query_virustotal_url("http://example.com", config=HashGuardConfig(vt_api_key="")) is None

    def test_success(self, monkeypatch):
        class FakeResp:
            status_code = 200
            def json(self):
                return {"data": {"id": "url123"}}

        import requests as _req
        monkeypatch.setattr(_req, "get", lambda *a, **kw: FakeResp())
        result = scanner.query_virustotal_url("http://example.com", api_key="testkey")
        assert result["data"]["id"] == "url123"

    def test_non_200(self, monkeypatch):
        class FakeResp:
            status_code = 403

        import requests as _req
        monkeypatch.setattr(_req, "get", lambda *a, **kw: FakeResp())
        assert scanner.query_virustotal_url("http://example.com", api_key="testkey") is None


class TestFileAnalysisResultFull:
    """Extended tests for FileAnalysisResult.to_dict with all v2 fields."""

    def test_v2_fields_included(self):
        result = scanner.FileAnalysisResult(
            path="/test.exe",
            hashes={"md5": "abc"},
            file_size=100,
            pe_info={"is_pe": True},
            yara_matches={"matches": []},
            capabilities={"total": 5},
            family_detection={"family": "emotet"},
            shellcode={"detected": True},
        )
        d = result.to_dict()
        assert d["pe_info"] == {"is_pe": True}
        assert d["yara_matches"] == {"matches": []}
        assert d["capabilities"] == {"total": 5}
        assert d["family_detection"] == {"family": "emotet"}
        assert d["shellcode"] == {"detected": True}

    def test_optional_fields_excluded_when_none(self):
        result = scanner.FileAnalysisResult(
            path="/test.exe", hashes={"md5": "abc"}, file_size=100
        )
        d = result.to_dict()
        assert "pe_info" not in d
        assert "yara_matches" not in d
        assert "capabilities" not in d

    def test_to_json_roundtrip(self):
        result = scanner.FileAnalysisResult(
            path="/test.exe",
            hashes={"md5": "abc"},
            file_size=100,
            risk_score={"score": 75, "verdict": "suspicious"},
        )
        data = json.loads(result.to_json())
        assert data["risk_score"]["score"] == 75
        assert data["risk_score"]["verdict"] == "suspicious"


class TestComputeHashesEdgeCases:
    """Edge case tests for compute_hashes."""

    def test_max_file_size_exceeded(self, tmp_path):
        p = tmp_path / "big.bin"
        p.write_bytes(b"x" * 100)
        config = HashGuardConfig(max_file_size=50)
        with pytest.raises(ValueError, match="exceeds maximum size"):
            scanner.compute_hashes(str(p), config=config)

    def test_empty_file(self, tmp_path):
        p = tmp_path / "empty.bin"
        p.write_bytes(b"")
        hashes = scanner.compute_hashes(str(p))
        # MD5 of empty string is well-known
        assert hashes["md5"] == "d41d8cd98f00b204e9800998ecf8427e"

    def test_permission_error(self, tmp_path, monkeypatch):
        p = make_temp_file(b"data")
        try:
            import builtins
            real_open = builtins.open
            def fail_open(path, *a, **kw):
                if str(path) == p:
                    raise PermissionError("denied")
                return real_open(path, *a, **kw)
            monkeypatch.setattr(builtins, "open", fail_open)
            with pytest.raises(PermissionError):
                scanner.compute_hashes(p)
        finally:
            os.remove(p)
