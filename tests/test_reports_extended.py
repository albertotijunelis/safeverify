"""Extended tests for HashGuard reports module — covers remaining branches."""

import csv
import io
import json
from unittest.mock import MagicMock, patch

import pytest

from hashguard.reports import BatchAnalyzer, ReportGenerator


def _make_result(**overrides):
    r = MagicMock()
    r.path = "/tmp/test.exe"
    r.file_size = 2048
    r.hashes = {"md5": "a" * 32, "sha1": "b" * 40, "sha256": "c" * 64}
    r.malicious = False
    r.description = "Clean"
    r.analysis_time = 0.05
    r.to_dict.return_value = {
        "path": r.path,
        "file_size": r.file_size,
        "hashes": r.hashes,
        "malicious": r.malicious,
    }
    for k, v in overrides.items():
        setattr(r, k, v)
        if k in ("path", "file_size", "malicious"):
            r.to_dict.return_value[k] = v
    return r


# ── BatchAnalyzer extended ───────────────────────────────────────────────────

class TestBatchAnalyzerExtended:
    def test_get_summary_average_time(self):
        ba = BatchAnalyzer()
        ba.results = [
            _make_result(file_size=100, analysis_time=0.2),
            _make_result(file_size=200, analysis_time=0.4),
        ]
        s = ba.get_summary()
        assert s["average_time_per_file"] == 0.3
        assert "timestamp" in s

    def test_get_summary_percentage(self):
        ba = BatchAnalyzer()
        ba.results = [
            _make_result(malicious=True, file_size=100, analysis_time=0.1),
            _make_result(malicious=True, file_size=100, analysis_time=0.1),
            _make_result(malicious=False, file_size=100, analysis_time=0.1),
            _make_result(malicious=False, file_size=100, analysis_time=0.1),
        ]
        s = ba.get_summary()
        assert s["malicious_percentage"] == 50.0

    @patch("hashguard.reports.analyze")
    def test_analyze_directory_pattern(self, mock_analyze, tmp_path):
        (tmp_path / "a.exe").write_bytes(b"hello")
        (tmp_path / "b.txt").write_text("world")
        mock_analyze.return_value = _make_result()
        ba = BatchAnalyzer()
        results = ba.analyze_directory(str(tmp_path), pattern="*.exe")
        assert len(results) == 1

    @patch("hashguard.reports.analyze")
    def test_analyze_directory_skips_symlinks(self, mock_analyze, tmp_path):
        (tmp_path / "real.txt").write_text("data")
        try:
            (tmp_path / "link.txt").symlink_to(tmp_path / "real.txt")
        except OSError:
            pytest.skip("symlinks not supported")
        mock_analyze.return_value = _make_result()
        ba = BatchAnalyzer()
        results = ba.analyze_directory(str(tmp_path))
        # Only real.txt should be analyzed, not the symlink
        assert len(results) == 1

    @patch("hashguard.reports.analyze", side_effect=Exception("fail"))
    def test_analyze_directory_handles_errors(self, mock_analyze, tmp_path):
        (tmp_path / "a.txt").write_text("data")
        ba = BatchAnalyzer()
        results = ba.analyze_directory(str(tmp_path))
        assert results == []

    @patch("hashguard.reports.analyze")
    def test_analyze_directory_skips_dirs(self, mock_analyze, tmp_path):
        sub = tmp_path / "subdir"
        sub.mkdir()
        (tmp_path / "a.txt").write_text("data")
        mock_analyze.return_value = _make_result()
        ba = BatchAnalyzer()
        results = ba.analyze_directory(str(tmp_path), recursive=False)
        assert len(results) == 1

    @patch("hashguard.reports.analyze")
    def test_analyze_files_with_vt(self, mock_analyze):
        mock_analyze.return_value = _make_result()
        ba = BatchAnalyzer()
        results = ba.analyze_files(["/tmp/a.exe"], vt=True)
        assert len(results) == 1
        call_kwargs = mock_analyze.call_args
        assert call_kwargs[1]["vt"] is True

    def test_init_with_custom_config(self):
        from hashguard.config import HashGuardConfig
        config = HashGuardConfig(log_level="DEBUG")
        ba = BatchAnalyzer(config=config)
        assert ba.config.log_level == "DEBUG"


# ── ReportGenerator extended ─────────────────────────────────────────────────

class TestReportGeneratorJSONExtended:
    def test_json_not_pretty(self):
        results = [_make_result()]
        output = ReportGenerator.to_json(results, pretty=False)
        assert "\n" not in output
        data = json.loads(output)
        assert len(data) == 1

    def test_json_single_result(self):
        output = ReportGenerator.to_json([_make_result()])
        data = json.loads(output)
        assert len(data) == 1
        assert data[0]["path"] == "/tmp/test.exe"


class TestReportGeneratorCSVExtended:
    def test_csv_malicious_flag(self):
        results = [
            _make_result(malicious=True, description="Trojan.Win32"),
        ]
        output = ReportGenerator.to_csv(results)
        reader = csv.reader(io.StringIO(output))
        rows = list(reader)
        assert rows[1][5] == "YES"

    def test_csv_multiple_rows(self):
        results = [_make_result() for _ in range(5)]
        output = ReportGenerator.to_csv(results)
        reader = csv.reader(io.StringIO(output))
        rows = list(reader)
        assert len(rows) == 6  # header + 5

    def test_csv_special_characters(self):
        r = _make_result(path='/tmp/"special,file".exe', description='Has "quotes" and, commas')
        output = ReportGenerator.to_csv([r])
        reader = csv.reader(io.StringIO(output))
        rows = list(reader)
        assert '"special,file"' in rows[1][0]


class TestReportGeneratorHTMLExtended:
    def test_html_malicious_badge(self):
        results = [_make_result(malicious=True, description="Trojan")]
        output = ReportGenerator.to_html(results)
        assert "MALICIOUS" in output
        assert "malicious" in output  # CSS class

    def test_html_clean_badge(self):
        results = [_make_result(malicious=False)]
        output = ReportGenerator.to_html(results)
        assert "CLEAN" in output

    def test_html_empty_results(self):
        output = ReportGenerator.to_html([])
        assert "<!DOCTYPE html>" in output

    def test_html_custom_title(self):
        results = [_make_result()]
        output = ReportGenerator.to_html(results, title="Custom Title")
        assert "Custom Title" in output

    def test_html_escapes_path(self):
        r = _make_result(path="/tmp/<script>alert(1)</script>.exe")
        output = ReportGenerator.to_html([r])
        assert "<script>" not in output
        assert "&lt;script&gt;" in output

    def test_html_multiple_results(self):
        results = [
            _make_result(malicious=True, path="/a.exe"),
            _make_result(malicious=False, path="/b.txt"),
        ]
        output = ReportGenerator.to_html(results)
        assert "MALICIOUS" in output
        assert "CLEAN" in output

    def test_html_contains_version(self):
        results = [_make_result()]
        output = ReportGenerator.to_html(results)
        from hashguard import __version__
        assert __version__ in output

    def test_html_sha256_truncated(self):
        results = [_make_result()]
        output = ReportGenerator.to_html(results)
        # SHA256 is truncated to first 16 chars + "..."
        assert "c" * 16 in output
