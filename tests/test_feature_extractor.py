"""Tests for the feature extractor module."""

import math
import os
import tempfile

import pytest

from hashguard.feature_extractor import (
    FEATURE_COLUMNS,
    _byte_histogram,
    _histogram_stats,
    _safe_get,
    _SEVERITY_MAP,
    extract_features,
)


def _make_temp_file(data: bytes) -> str:
    fd, path = tempfile.mkstemp()
    os.write(fd, data)
    os.close(fd)
    return path


# ── _safe_get ───────────────────────────────────────────────────────────────


class TestSafeGet:
    def test_nested_keys(self):
        d = {"a": {"b": {"c": 42}}}
        assert _safe_get(d, "a", "b", "c") == 42

    def test_missing_key(self):
        d = {"a": {"b": 1}}
        assert _safe_get(d, "a", "x", default=99) == 99

    def test_none_value(self):
        d = {"a": None}
        assert _safe_get(d, "a", "b", default=5) == 5

    def test_empty_dict(self):
        assert _safe_get({}, "a", default=0) == 0

    def test_none_input(self):
        assert _safe_get(None, "a", default=-1) == -1


# ── _byte_histogram ────────────────────────────────────────────────────────


class TestByteHistogram:
    def test_all_zeros(self):
        path = _make_temp_file(b"\x00" * 100)
        try:
            hist = _byte_histogram(path)
            assert len(hist) == 256
            assert hist[0] == 100
            assert sum(hist) == 100
        finally:
            os.remove(path)

    def test_mixed_bytes(self):
        data = bytes([0, 1, 2, 3, 0, 1])
        path = _make_temp_file(data)
        try:
            hist = _byte_histogram(path)
            assert hist[0] == 2
            assert hist[1] == 2
            assert hist[2] == 1
            assert hist[3] == 1
            assert sum(hist) == 6
        finally:
            os.remove(path)

    def test_empty_file(self):
        path = _make_temp_file(b"")
        try:
            hist = _byte_histogram(path)
            assert sum(hist) == 0
        finally:
            os.remove(path)

    def test_nonexistent_file(self):
        hist = _byte_histogram("/nonexistent/path/file.bin")
        assert sum(hist) == 0


# ── _histogram_stats ───────────────────────────────────────────────────────


class TestHistogramStats:
    def test_zero_histogram(self):
        hist = [0] * 256
        stats = _histogram_stats(hist)
        assert stats["byte_entropy"] == 0.0
        assert stats["byte_mean"] == 0.0
        assert stats["byte_std"] == 0.0

    def test_uniform_distribution(self):
        hist = [100] * 256
        stats = _histogram_stats(hist)
        assert stats["byte_entropy"] == pytest.approx(8.0, abs=0.01)

    def test_single_byte_value(self):
        hist = [0] * 256
        hist[65] = 1000  # all 'A'
        stats = _histogram_stats(hist)
        assert stats["byte_entropy"] == 0.0
        assert stats["byte_mean"] == pytest.approx(65.0, abs=0.01)
        assert stats["byte_zero_ratio"] == 0.0

    def test_printable_ratio(self):
        hist = [0] * 256
        for i in range(32, 127):
            hist[i] = 1
        stats = _histogram_stats(hist)
        assert stats["byte_printable_ratio"] == pytest.approx(1.0, abs=0.01)

    def test_high_ratio(self):
        hist = [0] * 256
        for i in range(128, 256):
            hist[i] = 1
        stats = _histogram_stats(hist)
        assert stats["byte_high_ratio"] == pytest.approx(1.0, abs=0.01)


# ── extract_features ───────────────────────────────────────────────────────


def _minimal_result() -> dict:
    """Return a minimal analysis result dict."""
    return {
        "file_size": 1024,
        "hashes": {"sha256": "abc123"},
        "pe_info": None,
        "strings_info": None,
        "yara_matches": None,
        "threat_intel": None,
        "capabilities": None,
        "packer": None,
        "shellcode": None,
        "risk_score": {"score": 0, "verdict": "clean", "factors": []},
        "malicious": False,
        "family_detection": None,
    }


def _rich_result() -> dict:
    """Return a realistic result dict with all sections populated."""
    return {
        "file_size": 65536,
        "path": "/tmp/sample.exe",
        "hashes": {"sha256": "deadbeef"},
        "pe_info": {
            "is_pe": True,
            "sections": [
                {"name": ".text", "entropy": 6.8, "raw_size": 32768},
                {"name": ".data", "entropy": 3.2, "raw_size": 8192},
                {"name": ".rsrc", "entropy": 7.1, "raw_size": 4096},
            ],
            "imports": {
                "kernel32.dll": ["CreateFileA", "WriteFile"],
                "advapi32.dll": ["RegSetValueExA"],
            },
            "suspicious_imports": ["CreateRemoteThread", "VirtualAllocEx"],
            "packed": False,
            "overall_entropy": 5.9,
        },
        "advanced_pe": {
            "tls": {"has_tls": True},
            "anti_analysis": {"total_detections": 3},
        },
        "strings_info": {
            "total_strings": 450,
            "has_iocs": True,
            "urls": ["http://evil.com/c2"],
            "ips": ["10.0.0.1", "192.168.1.1"],
            "domains": ["evil.com"],
            "emails": ["hacker@evil.com"],
            "crypto_wallets": [],
            "registry_keys": ["HKLM\\Software\\Evil"],
            "powershell_commands": ["Invoke-Expression"],
            "user_agents": [],
            "suspicious_paths": ["C:\\Windows\\Temp\\evil.exe"],
        },
        "yara_matches": {
            "rules_loaded": 160,
            "matches": [
                {
                    "rule": "trojan_generic",
                    "meta": {"severity": "high", "category": "trojan"},
                    "strings": ["$s1", "$s2"],
                },
                {
                    "rule": "ransomware_v1",
                    "meta": {"severity": "critical", "category": "ransomware"},
                    "strings": ["$r1"],
                },
            ],
        },
        "threat_intel": {
            "total_sources": 6,
            "flagged_count": 2,
            "successful_sources": 5,
            "hits": [
                {"source": "MalwareBazaar", "tags": ["trojan", "rat"], "malware_family": "AgentTesla"},
                {"source": "OTX", "tags": ["stealer"], "malware_family": ""},
            ],
        },
        "capabilities": {
            "total_detected": 4,
            "max_severity": "high",
            "risk_categories": {
                "ransomware": 0,
                "reverse_shell": 1,
                "credential_stealing": 2,
                "persistence": 1,
                "evasion": 0,
                "keylogger": 0,
                "data_exfil": 0,
            },
            "capabilities": [
                {"name": "Remote Shell", "category": "reverse_shell", "confidence": 85, "severity": "high"},
                {"name": "Credential Theft", "category": "credential_stealing", "confidence": 70, "severity": "medium"},
            ],
        },
        "packer": {"detected": True},
        "shellcode": {"detected": True, "confidence": "high"},
        "risk_score": {
            "score": 85,
            "verdict": "malicious",
            "factors": [
                {"description": "YARA match", "points": 25},
                {"description": "Suspicious imports", "points": 15},
                {"description": "TI hit", "points": 30},
            ],
        },
        "malicious": True,
        "family_detection": {"family": "AgentTesla", "confidence": 0.85},
    }


class TestExtractFeatures:
    def test_minimal_result_file_features(self):
        path = _make_temp_file(b"\x00" * 1024)
        try:
            feats = extract_features(path, _minimal_result())
            assert feats["file_size"] == 1024
            assert feats["file_size_log"] == pytest.approx(math.log2(1025), abs=0.01)
            assert feats["byte_entropy"] == 0.0
        finally:
            os.remove(path)

    def test_minimal_result_pe_defaults(self):
        path = _make_temp_file(b"\x00")
        try:
            feats = extract_features(path, _minimal_result())
            assert feats["pe_is_pe"] == 0
            assert feats["pe_section_count"] == 0
            assert feats["pe_entropy_mean"] == 0.0
            assert feats["pe_import_dll_count"] == 0
        finally:
            os.remove(path)

    def test_minimal_result_label_fields(self):
        path = _make_temp_file(b"\x00")
        try:
            feats = extract_features(path, _minimal_result())
            assert feats["label_verdict"] == "clean"
            assert feats["label_is_malicious"] == 0
            assert feats["label_family"] == ""
        finally:
            os.remove(path)

    def test_rich_result_pe_features(self):
        path = _make_temp_file(b"\x41" * 65536)
        try:
            feats = extract_features(path, _rich_result())
            assert feats["pe_is_pe"] == 1
            assert feats["pe_section_count"] == 3
            assert feats["pe_entropy_max"] == pytest.approx(7.1, abs=0.01)
            assert feats["pe_entropy_min"] == pytest.approx(3.2, abs=0.01)
            assert feats["pe_import_dll_count"] == 2
            assert feats["pe_import_func_count"] == 3
            assert feats["pe_suspicious_import_count"] == 2
            assert feats["pe_has_tls"] == 1
            assert feats["pe_anti_analysis_count"] == 3
        finally:
            os.remove(path)

    def test_rich_result_string_features(self):
        path = _make_temp_file(b"\x00")
        try:
            feats = extract_features(path, _rich_result())
            assert feats["str_total_count"] == 450
            assert feats["str_has_iocs"] == 1
            assert feats["str_url_count"] == 1
            assert feats["str_ip_count"] == 2
            assert feats["str_domain_count"] == 1
            assert feats["str_email_count"] == 1
            assert feats["str_registry_key_count"] == 1
            assert feats["str_powershell_count"] == 1
            assert feats["str_suspicious_path_count"] == 1
        finally:
            os.remove(path)

    def test_rich_result_yara_features(self):
        path = _make_temp_file(b"\x00")
        try:
            feats = extract_features(path, _rich_result())
            assert feats["yara_rules_loaded"] == 160
            assert feats["yara_match_count"] == 2
            assert feats["yara_max_severity"] == 4  # critical
            assert feats["yara_total_severity"] == 7  # high(3) + critical(4)
            assert feats["yara_string_hit_count"] == 3
            assert feats["yara_unique_categories"] == 2
        finally:
            os.remove(path)

    def test_rich_result_ti_features(self):
        path = _make_temp_file(b"\x00")
        try:
            feats = extract_features(path, _rich_result())
            assert feats["ti_total_sources"] == 6
            assert feats["ti_flagged_count"] == 2
            assert feats["ti_successful_sources"] == 5
            assert feats["ti_total_tags"] == 3
            assert feats["ti_has_family"] == 1
        finally:
            os.remove(path)

    def test_rich_result_capability_features(self):
        path = _make_temp_file(b"\x00")
        try:
            feats = extract_features(path, _rich_result())
            assert feats["cap_total_detected"] == 4
            assert feats["cap_reverse_shell"] == 1
            assert feats["cap_credential_stealing"] == 2
            assert feats["cap_max_severity"] == 3  # high
            assert feats["cap_avg_confidence"] == pytest.approx(77.5, abs=0.5)
            assert feats["cap_max_confidence"] == pytest.approx(85.0, abs=0.1)
        finally:
            os.remove(path)

    def test_rich_result_packer_shellcode(self):
        path = _make_temp_file(b"\x00")
        try:
            feats = extract_features(path, _rich_result())
            assert feats["packer_detected"] == 1
            assert feats["shellcode_detected"] == 1
            assert feats["shellcode_confidence"] == 3  # high
        finally:
            os.remove(path)

    def test_rich_result_risk_features(self):
        path = _make_temp_file(b"\x00")
        try:
            feats = extract_features(path, _rich_result())
            assert feats["risk_score"] == 85
            assert feats["risk_factor_count"] == 3
            assert feats["risk_max_factor"] == 30
            assert feats["risk_total_points"] == 70  # 25+15+30
        finally:
            os.remove(path)

    def test_rich_result_labels(self):
        path = _make_temp_file(b"\x00")
        try:
            feats = extract_features(path, _rich_result())
            assert feats["label_verdict"] == "malicious"
            assert feats["label_is_malicious"] == 1
            assert feats["label_family"] == "AgentTesla"
            assert feats["label_family_confidence"] == pytest.approx(0.85, abs=0.01)
        finally:
            os.remove(path)

    def test_nonexistent_file_path(self):
        """Feature extraction should still work with a non-existent file path (byte features zeroed)."""
        feats = extract_features("/nonexistent/path.bin", _minimal_result())
        assert feats["byte_entropy"] == 0.0
        assert feats["file_size"] == 1024

    def test_all_feature_columns_present(self):
        """Every key from FEATURE_COLUMNS should be present in extracted features."""
        path = _make_temp_file(b"\x00")
        try:
            feats = extract_features(path, _rich_result())
            for col in FEATURE_COLUMNS:
                assert col in feats, f"Missing feature column: {col}"
        finally:
            os.remove(path)

    def test_feature_types(self):
        """Numeric features should be int or float, label fields str or float."""
        path = _make_temp_file(b"\x41" * 100)
        try:
            feats = extract_features(path, _rich_result())
            for col, sql_type in FEATURE_COLUMNS.items():
                val = feats[col]
                if sql_type == "TEXT":
                    assert isinstance(val, str), f"{col} should be str, got {type(val)}"
                elif sql_type == "INTEGER":
                    assert isinstance(val, int), f"{col} should be int, got {type(val)}"
                elif sql_type == "REAL":
                    assert isinstance(val, (int, float)), f"{col} should be numeric, got {type(val)}"
        finally:
            os.remove(path)


# ── FEATURE_COLUMNS consistency ────────────────────────────────────────────


class TestFeatureColumns:
    def test_column_count(self):
        """Should have ~80 columns (± some)."""
        assert 60 <= len(FEATURE_COLUMNS) <= 100

    def test_all_sql_types_valid(self):
        for col, sql_type in FEATURE_COLUMNS.items():
            assert sql_type in ("INTEGER", "REAL", "TEXT"), f"Invalid type for {col}: {sql_type}"

    def test_label_columns_exist(self):
        assert "label_verdict" in FEATURE_COLUMNS
        assert "label_is_malicious" in FEATURE_COLUMNS
        assert "label_family" in FEATURE_COLUMNS
        assert "label_family_confidence" in FEATURE_COLUMNS
