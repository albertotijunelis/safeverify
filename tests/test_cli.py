"""Tests for HashGuard CLI module."""

import sys
from unittest.mock import patch, MagicMock

import pytest

from hashguard import cli


class TestCLIImport:
    def test_module_imports(self):
        assert hasattr(cli, "main")
        assert hasattr(cli, "analyze_single")
        assert hasattr(cli, "analyze_url_single")
        assert hasattr(cli, "analyze_batch")


class TestPrintResult:
    """Test the _print_result helper produces output to stdout."""

    def _make_result(self, **overrides):
        r = MagicMock()
        r.path = "/tmp/test.exe"
        r.file_size = 1024
        r.hashes = {"md5": "a" * 32, "sha1": "b" * 40, "sha256": "c" * 64}
        r.malicious = False
        r.description = ""
        r.risk_score = {"score": 10, "verdict": "clean", "factors": []}
        r.vt_result = None
        r.threat_intel = None
        r.pe_info = None
        r.yara_matches = None
        r.strings_info = None
        r.analysis_time = 0.05
        for k, v in overrides.items():
            setattr(r, k, v)
        return r

    def test_prints_clean_file(self, capsys):
        result = self._make_result()
        cli._print_result(result)
        captured = capsys.readouterr()
        assert "CLEAN" in captured.out
        assert "c" * 64 in captured.out

    def test_prints_malicious_file(self, capsys):
        result = self._make_result(malicious=True, description="Trojan detected")
        cli._print_result(result)
        captured = capsys.readouterr()
        assert "MALICIOUS" in captured.out
        assert "Trojan detected" in captured.out

    def test_prints_risk_score_bar(self, capsys):
        result = self._make_result(
            risk_score={
                "score": 80,
                "verdict": "high",
                "factors": [{"name": "packed", "points": 20, "detail": "UPX"}],
            }
        )
        cli._print_result(result)
        captured = capsys.readouterr()
        assert "80/100" in captured.out
        assert "packed" in captured.out

    def test_prints_pe_info(self, capsys):
        pe = {
            "is_pe": True,
            "machine": "AMD64",
            "compile_time": "2024-01-01",
            "entry_point": "0x1000",
            "overall_entropy": 6.5,
            "packed": False,
            "sections": [{"name": ".text", "entropy": 6.0, "raw_size": 4096}],
            "warnings": ["Suspicious entropy"],
            "suspicious_imports": ["VirtualAlloc"],
        }
        result = self._make_result(pe_info=pe)
        cli._print_result(result)
        captured = capsys.readouterr()
        assert "AMD64" in captured.out
        assert ".text" in captured.out

    def test_prints_yara_matches(self, capsys):
        yara = {
            "matches": [
                {
                    "rule": "Suspicious_Packer",
                    "meta": {"description": "Packed binary", "severity": "high"},
                }
            ]
        }
        result = self._make_result(yara_matches=yara)
        cli._print_result(result)
        captured = capsys.readouterr()
        assert "Suspicious_Packer" in captured.out

    def test_prints_iocs(self, capsys):
        strings = {
            "has_iocs": True,
            "urls": ["http://evil.com"],
            "ips": [],
            "domains": [],
            "emails": [],
            "powershell_commands": [],
            "suspicious_paths": [],
            "crypto_wallets": [],
            "user_agents": [],
            "registry_keys": [],
        }
        result = self._make_result(strings_info=strings)
        cli._print_result(result)
        captured = capsys.readouterr()
        assert "http://evil.com" in captured.out

    def test_prints_vt_result(self, capsys):
        vt = {
            "data": {
                "attributes": {
                    "last_analysis_stats": {
                        "malicious": 30,
                        "undetected": 40,
                    }
                }
            }
        }
        result = self._make_result(vt_result=vt)
        cli._print_result(result)
        captured = capsys.readouterr()
        assert "30/70" in captured.out

    def test_prints_threat_intel(self, capsys):
        ti = {
            "hits": [
                {"source": "MalwareBazaar", "found": True, "malware_family": "Emotet"},
                {"source": "URLhaus", "found": False},
            ]
        }
        result = self._make_result(threat_intel=ti)
        cli._print_result(result)
        captured = capsys.readouterr()
        assert "MalwareBazaar" in captured.out
        assert "Emotet" in captured.out


class TestMainParser:
    def test_version_flag(self, capsys):
        with pytest.raises(SystemExit) as exc:
            with patch("sys.argv", ["hashguard", "--version"]):
                cli.main()
        assert exc.value.code == 0

    def test_web_mode(self):
        with patch("sys.argv", ["hashguard", "--web"]):
            with patch("hashguard.web.api.start_server") as mock:
                cli.main()
                mock.assert_called_once()

    @patch("hashguard.cli.analyze")
    def test_single_file(self, mock_analyze, tmp_path, capsys):
        f = tmp_path / "test.txt"
        f.write_text("hello")
        mock_result = MagicMock()
        mock_result.path = str(f)
        mock_result.file_size = 5
        mock_result.hashes = {"md5": "a" * 32, "sha1": "b" * 40, "sha256": "c" * 64}
        mock_result.malicious = False
        mock_result.description = ""
        mock_result.risk_score = {"score": 0, "verdict": "clean", "factors": []}
        mock_result.vt_result = None
        mock_result.threat_intel = None
        mock_result.pe_info = None
        mock_result.yara_matches = None
        mock_result.strings_info = None
        mock_result.analysis_time = 0.01
        mock_analyze.return_value = mock_result

        with patch("sys.argv", ["hashguard", str(f)]):
            with pytest.raises(SystemExit) as exc:
                cli.main()
            assert exc.value.code == 0

    @patch("hashguard.cli.analyze")
    def test_single_file_json(self, mock_analyze, tmp_path, capsys):
        f = tmp_path / "test.txt"
        f.write_text("hello")
        mock_result = MagicMock()
        mock_result.to_json.return_value = '{"test": true}'
        mock_analyze.return_value = mock_result

        with patch("sys.argv", ["hashguard", str(f), "--json"]):
            with pytest.raises(SystemExit) as exc:
                cli.main()
            assert exc.value.code == 0

    def test_file_not_found(self, capsys):
        with patch("sys.argv", ["hashguard", "/nonexistent/file.exe"]):
            with patch("hashguard.cli.analyze", side_effect=FileNotFoundError("not found")):
                with pytest.raises(SystemExit) as exc:
                    cli.main()
                assert exc.value.code == 1


class TestAnalyzeSingle:
    @patch("hashguard.cli.analyze")
    def test_success(self, mock_analyze):
        mock_result = MagicMock()
        mock_result.path = "/test"
        mock_result.file_size = 0
        mock_result.hashes = {}
        mock_result.malicious = False
        mock_result.description = ""
        mock_result.risk_score = {}
        mock_result.vt_result = None
        mock_result.threat_intel = None
        mock_result.pe_info = None
        mock_result.yara_matches = None
        mock_result.strings_info = None
        mock_result.analysis_time = 0
        mock_analyze.return_value = mock_result

        args = MagicMock()
        args.path = "/test"
        args.vt = False
        args.json = False
        assert cli.analyze_single(args) == 0

    def test_file_not_found(self):
        args = MagicMock()
        args.path = "/nonexistent"
        args.vt = False
        args.json = False
        with patch("hashguard.cli.analyze", side_effect=FileNotFoundError):
            assert cli.analyze_single(args) == 1


class TestAnalyzeURLSingle:
    @patch("hashguard.cli.analyze_url")
    def test_success(self, mock_analyze):
        mock_result = MagicMock()
        mock_result.path = "http://example.com/file"
        mock_result.file_size = 100
        mock_result.hashes = {}
        mock_result.malicious = False
        mock_result.description = ""
        mock_result.risk_score = {}
        mock_result.vt_result = None
        mock_result.threat_intel = None
        mock_result.pe_info = None
        mock_result.yara_matches = None
        mock_result.strings_info = None
        mock_result.analysis_time = 0
        mock_analyze.return_value = mock_result

        args = MagicMock()
        args.url = "http://example.com/file"
        args.vt = False
        args.json = False
        assert cli.analyze_url_single(args) == 0

    @patch("hashguard.cli.analyze_url", side_effect=Exception("timeout"))
    def test_error(self, mock_analyze):
        args = MagicMock()
        args.url = "http://example.com/file"
        args.vt = False
        args.json = False
        assert cli.analyze_url_single(args) == 1
