"""Extended tests for HashGuard CLI module — covers remaining branches."""

import sys
from unittest.mock import patch, MagicMock, PropertyMock

import pytest

from hashguard import cli


# ── Helper ───────────────────────────────────────────────────────────────────

def _make_result(**overrides):
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


# ── _ensure_utf8_stdout edge cases ──────────────────────────────────────────

class TestEnsureUTF8Extended:
    def test_windows_reconfigure_error(self, monkeypatch):
        monkeypatch.setattr("sys.platform", "win32")
        mock_stdout = MagicMock()
        mock_stdout.reconfigure.side_effect = Exception("unsupported")
        monkeypatch.setattr("sys.stdout", mock_stdout)
        cli._ensure_utf8_stdout()  # Should not raise

    def test_windows_no_reconfigure(self, monkeypatch):
        monkeypatch.setattr("sys.platform", "win32")
        mock_stdout = MagicMock(spec=[])  # No reconfigure attribute
        monkeypatch.setattr("sys.stdout", mock_stdout)
        cli._ensure_utf8_stdout()

    def test_windows_success(self, monkeypatch):
        monkeypatch.setattr("sys.platform", "win32")
        mock_stdout = MagicMock()
        monkeypatch.setattr("sys.stdout", mock_stdout)
        cli._ensure_utf8_stdout()
        mock_stdout.reconfigure.assert_called_once()


# ── _print_result additional branches ────────────────────────────────────────

class TestPrintResultBranches:
    def test_risk_score_empty(self, capsys):
        result = _make_result(risk_score={})
        cli._print_result(result)
        out = capsys.readouterr().out
        assert "CLEAN" in out

    def test_risk_score_none(self, capsys):
        result = _make_result(risk_score=None)
        cli._print_result(result)
        out = capsys.readouterr().out
        assert "CLEAN" in out

    def test_risk_factors_with_no_detail(self, capsys):
        result = _make_result(risk_score={
            "score": 40,
            "verdict": "suspicious",
            "factors": [{"name": "entropy", "points": 10}],
        })
        cli._print_result(result)
        out = capsys.readouterr().out
        assert "entropy" in out

    def test_iocs_many_items_truncated(self, capsys):
        strings = {
            "has_iocs": True,
            "urls": [f"http://evil{i}.example.com/path" for i in range(8)],
            "ips": [],
            "domains": [],
            "emails": [],
            "powershell_commands": [],
            "suspicious_paths": [],
            "crypto_wallets": [],
            "user_agents": [],
            "registry_keys": [],
        }
        result = _make_result(strings_info=strings)
        cli._print_result(result)
        out = capsys.readouterr().out
        assert "... and 3 more" in out

    def test_vt_result_with_data(self, capsys):
        vt = {"data": {"attributes": {"last_analysis_stats": {
            "malicious": 10, "undetected": 50, "harmless": 5
        }}}}
        result = _make_result(vt_result=vt)
        cli._print_result(result)
        out = capsys.readouterr().out
        assert "10/65" in out

    def test_threat_intel_not_found(self, capsys):
        ti = {"hits": [{"source": "URLhaus", "found": False}]}
        result = _make_result(threat_intel=ti)
        cli._print_result(result)
        out = capsys.readouterr().out
        assert "Not found" in out

    def test_pe_with_no_sections(self, capsys):
        pe = {
            "is_pe": True,
            "machine": "x86",
            "compile_time": "2024-01-01",
            "entry_point": "0x1000",
            "overall_entropy": 5.0,
            "packed": False,
            "sections": [],
            "warnings": [],
            "suspicious_imports": [],
        }
        result = _make_result(pe_info=pe)
        cli._print_result(result)
        out = capsys.readouterr().out
        assert "x86" in out

    def test_yara_empty_matches(self, capsys):
        yara = {"matches": []}
        result = _make_result(yara_matches=yara)
        cli._print_result(result)
        out = capsys.readouterr().out
        assert "YARA" not in out

    def test_yara_no_meta(self, capsys):
        yara = {"matches": [{"rule": "GenericRule", "meta": {}}]}
        result = _make_result(yara_matches=yara)
        cli._print_result(result)
        out = capsys.readouterr().out
        assert "GenericRule" in out

    def test_risk_score_max_bar(self, capsys):
        result = _make_result(risk_score={
            "score": 100,
            "verdict": "malicious",
            "factors": [],
        })
        cli._print_result(result)
        out = capsys.readouterr().out
        assert "100/100" in out

    def test_risk_score_zero_bar(self, capsys):
        result = _make_result(risk_score={
            "score": 0,
            "verdict": "clean",
            "factors": [],
        })
        cli._print_result(result)
        out = capsys.readouterr().out
        assert "0/100" in out

    def test_custom_title(self, capsys):
        result = _make_result()
        cli._print_result(result, title="CUSTOM REPORT")
        out = capsys.readouterr().out
        assert "CUSTOM REPORT" in out

    def test_multiple_ioc_categories(self, capsys):
        strings = {
            "has_iocs": True,
            "urls": [],
            "ips": ["203.0.113.1"],
            "domains": ["evil.xyz"],
            "emails": ["bad@evil.xyz"],
            "powershell_commands": ["powershell -enc AAAA"],
            "suspicious_paths": [r"C:\Windows\Temp\x.exe"],
            "crypto_wallets": ["1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"],
            "user_agents": ["Mozilla/5.0 evil"],
            "registry_keys": [r"HKLM\SOFTWARE\Evil\Run"],
        }
        result = _make_result(strings_info=strings)
        cli._print_result(result)
        out = capsys.readouterr().out
        assert "IPs" in out
        assert "Domains" in out
        assert "Emails" in out
        assert "PowerShell" in out
        assert "Crypto Wallets" in out


# ── main() argument combinations ─────────────────────────────────────────────

class TestMainModes:
    def test_url_mode(self):
        mock_result = _make_result()
        with patch("sys.argv", ["hashguard", "--url", "http://example.com/f.exe"]):
            with patch("hashguard.cli.analyze_url", return_value=mock_result):
                with pytest.raises(SystemExit) as exc:
                    cli.main()
                assert exc.value.code == 0

    def test_url_mode_json(self):
        mock_result = MagicMock()
        mock_result.to_json.return_value = '{"url": true}'
        with patch("sys.argv", ["hashguard", "--url", "http://example.com/f.exe", "--json"]):
            with patch("hashguard.cli.analyze_url", return_value=mock_result):
                with pytest.raises(SystemExit) as exc:
                    cli.main()
                assert exc.value.code == 0

    def test_url_mode_error(self):
        with patch("sys.argv", ["hashguard", "--url", "http://evil.com/f"]):
            with patch("hashguard.cli.analyze_url", side_effect=Exception("fail")):
                with pytest.raises(SystemExit) as exc:
                    cli.main()
                assert exc.value.code == 1

    def test_batch_mode_via_main(self):
        with patch("sys.argv", ["hashguard", "--batch", "/tmp/dir"]):
            with patch("hashguard.cli.BatchAnalyzer") as mock_ba_cls:
                mock_ba = MagicMock()
                mock_ba.analyze_directory.return_value = []
                mock_ba.get_summary.return_value = {
                    "total_files": 0, "malicious_count": 0, "clean_count": 0,
                    "malicious_percentage": 0, "total_size_bytes": 0,
                    "total_analysis_time_seconds": 0,
                }
                mock_ba_cls.return_value = mock_ba
                with pytest.raises(SystemExit) as exc:
                    cli.main()
                assert exc.value.code == 0

    def test_config_flag(self, tmp_path):
        cfg = tmp_path / "cfg.json"
        cfg.write_text('{"log_level": "DEBUG"}')
        mock_result = _make_result()
        test_file = tmp_path / "test.txt"
        test_file.write_text("hello")
        with patch("sys.argv", ["hashguard", str(test_file), "--config", str(cfg)]):
            with patch("hashguard.cli.analyze", return_value=mock_result):
                with pytest.raises(SystemExit) as exc:
                    cli.main()
                assert exc.value.code == 0

    def test_web_with_port(self):
        with patch("sys.argv", ["hashguard", "--web", "--port", "9090"]):
            with patch("hashguard.web.api.start_server") as mock:
                cli.main()
                mock.assert_called_once_with(port=9090)

    def test_default_no_args_tty(self, monkeypatch):
        monkeypatch.setattr("sys.stdin", MagicMock(isatty=lambda: True))
        with patch("sys.argv", ["hashguard"]):
            with patch("hashguard.web.api.start_server") as mock:
                cli.main()
                mock.assert_called_once()

    def test_no_path_no_url_no_dir_no_tty(self, monkeypatch):
        """When stdin has data but no flags, it should print help."""
        mock_stdin = MagicMock()
        mock_stdin.isatty.return_value = False
        monkeypatch.setattr("sys.stdin", mock_stdin)
        with patch("sys.argv", ["hashguard"]):
            with pytest.raises(SystemExit) as exc:
                cli.main()
            # No path, stdin not tty, no --batch → print_help → exit 0
            assert exc.value.code == 0

    def test_vt_flag(self, tmp_path):
        f = tmp_path / "test.txt"
        f.write_text("hello")
        mock_result = _make_result()
        with patch("sys.argv", ["hashguard", str(f), "--vt"]):
            with patch("hashguard.cli.analyze", return_value=mock_result) as mock_analyze:
                with pytest.raises(SystemExit) as exc:
                    cli.main()
                assert exc.value.code == 0
                mock_analyze.assert_called_once()
                call_kwargs = mock_analyze.call_args
                assert call_kwargs[1].get("vt") is True or call_kwargs[0][1] is True


# ── analyze_single edge cases ────────────────────────────────────────────────

class TestAnalyzeSingleEdge:
    @patch("hashguard.cli.analyze", side_effect=RuntimeError("disk"))
    def test_generic_error(self, mock_analyze, capsys):
        args = MagicMock()
        args.path = "/test"
        args.vt = False
        args.json = False
        assert cli.analyze_single(args) == 1

    @patch("hashguard.cli.analyze")
    def test_json_output_calls_to_json(self, mock_analyze, capsys):
        mock_result = MagicMock()
        mock_result.to_json.return_value = '{"x": 1}'
        mock_analyze.return_value = mock_result
        args = MagicMock()
        args.path = "/test"
        args.vt = True
        args.json = True
        assert cli.analyze_single(args) == 0
        mock_result.to_json.assert_called_once()


# ── analyze_url_single edge cases ────────────────────────────────────────────

class TestAnalyzeUrlSingleEdge:
    @patch("hashguard.cli.analyze_url")
    def test_json_output(self, mock_analyze):
        mock_result = MagicMock()
        mock_result.to_json.return_value = '{"url": true}'
        mock_analyze.return_value = mock_result
        args = MagicMock()
        args.url = "http://example.com/f"
        args.vt = False
        args.json = True
        assert cli.analyze_url_single(args) == 0


# ── analyze_batch extended ───────────────────────────────────────────────────

class TestAnalyzeBatchExtended:
    @patch("hashguard.cli.BatchAnalyzer")
    def test_output_default_format(self, mock_ba_cls, tmp_path):
        """Output file without known extension defaults to JSON."""
        mock_ba = MagicMock()
        mock_ba.analyze_directory.return_value = []
        mock_ba_cls.return_value = mock_ba
        out = str(tmp_path / "report.dat")
        args = MagicMock()
        args.directory = "/tmp/test"
        args.no_recursive = False
        args.pattern = "*"
        args.vt = False
        args.output = out
        with patch("hashguard.cli.ReportGenerator") as mock_rg:
            mock_rg.to_json.return_value = '[]'
            assert cli.analyze_batch(args) == 0

    @patch("hashguard.cli.BatchAnalyzer")
    def test_batch_no_recursive(self, mock_ba_cls):
        mock_ba = MagicMock()
        mock_ba.analyze_directory.return_value = []
        mock_ba.get_summary.return_value = {
            "total_files": 0, "malicious_count": 0, "clean_count": 0,
            "malicious_percentage": 0, "total_size_bytes": 0,
            "total_analysis_time_seconds": 0,
        }
        mock_ba_cls.return_value = mock_ba
        args = MagicMock()
        args.directory = "/tmp/test"
        args.no_recursive = True
        args.pattern = "*.exe"
        args.vt = True
        args.output = None
        assert cli.analyze_batch(args) == 0
        call_kw = mock_ba.analyze_directory.call_args
        assert call_kw[1]["recursive"] is False
        assert call_kw[1]["pattern"] == "*.exe"

    @patch("hashguard.cli.BatchAnalyzer")
    def test_batch_stdin_no_files(self, mock_ba_cls, monkeypatch):
        """Batch with no directory and no stdin data → error."""
        mock_ba = MagicMock()
        mock_ba_cls.return_value = mock_ba
        mock_stdin = MagicMock()
        mock_stdin.isatty.return_value = True
        monkeypatch.setattr("sys.stdin", mock_stdin)
        args = MagicMock()
        args.directory = None
        args.output = None
        assert cli.analyze_batch(args) == 1

    @patch("hashguard.cli.BatchAnalyzer")
    def test_batch_stdin_with_files(self, mock_ba_cls, monkeypatch):
        """Batch reads file list from stdin."""
        mock_ba = MagicMock()
        mock_ba.analyze_files.return_value = []
        mock_ba.get_summary.return_value = {
            "total_files": 0, "malicious_count": 0, "clean_count": 0,
            "malicious_percentage": 0, "total_size_bytes": 0,
            "total_analysis_time_seconds": 0,
        }
        mock_ba_cls.return_value = mock_ba
        mock_stdin = MagicMock()
        mock_stdin.isatty.return_value = False
        mock_stdin.__iter__ = lambda self: iter(["/tmp/a.exe\n", "/tmp/b.exe\n"])
        monkeypatch.setattr("sys.stdin", mock_stdin)
        args = MagicMock()
        args.directory = None
        args.output = None
        assert cli.analyze_batch(args) == 0
        mock_ba.analyze_files.assert_called_once()
