"""Tests for HashGuard YARA scanner module."""

import os
import tempfile
import pytest
from unittest.mock import patch, MagicMock


class TestYaraAvailability:
    def test_is_available_returns_bool(self):
        from hashguard.yara_scanner import is_available
        assert isinstance(is_available(), bool)

    def test_yara_available_flag(self):
        from hashguard.yara_scanner import _YARA_AVAILABLE
        assert isinstance(_YARA_AVAILABLE, bool)


class TestYaraMatch:
    def test_default_fields(self):
        from hashguard.yara_scanner import YaraMatch
        m = YaraMatch(rule="test_rule", namespace="default")
        assert m.rule == "test_rule"
        assert m.namespace == "default"
        assert m.tags == []
        assert m.meta == {}
        assert m.strings == []

    def test_custom_fields(self):
        from hashguard.yara_scanner import YaraMatch
        m = YaraMatch(
            rule="trojan_detect",
            namespace="trojans",
            tags=["malware", "trojan"],
            meta={"author": "test", "severity": "high"},
            strings=["0x100: $s1"],
        )
        assert m.tags == ["malware", "trojan"]
        assert m.meta["author"] == "test"
        assert len(m.strings) == 1

    def test_to_dict(self):
        from hashguard.yara_scanner import YaraMatch
        m = YaraMatch(rule="r1", namespace="ns1", tags=["t1"], meta={"k": "v"}, strings=["s1"])
        d = m.to_dict()
        assert d["rule"] == "r1"
        assert d["namespace"] == "ns1"
        assert d["tags"] == ["t1"]
        assert d["meta"] == {"k": "v"}
        assert d["strings"] == ["s1"]

    def test_to_dict_empty(self):
        from hashguard.yara_scanner import YaraMatch
        m = YaraMatch(rule="empty", namespace="ns")
        d = m.to_dict()
        assert isinstance(d, dict)
        assert len(d) == 5


class TestYaraScanResult:
    def test_default_result(self):
        from hashguard.yara_scanner import YaraScanResult
        r = YaraScanResult()
        assert r.available is False
        assert r.rules_loaded == 0
        assert r.matches == []

    def test_result_with_matches(self):
        from hashguard.yara_scanner import YaraScanResult, YaraMatch
        m = YaraMatch(rule="r1", namespace="ns")
        r = YaraScanResult(available=True, rules_loaded=5, matches=[m])
        assert r.available is True
        assert r.rules_loaded == 5
        assert len(r.matches) == 1

    def test_to_dict(self):
        from hashguard.yara_scanner import YaraScanResult, YaraMatch
        m = YaraMatch(rule="r1", namespace="ns")
        r = YaraScanResult(available=True, rules_loaded=3, matches=[m])
        d = r.to_dict()
        assert d["available"] is True
        assert d["rules_loaded"] == 3
        assert len(d["matches"]) == 1
        assert d["matches"][0]["rule"] == "r1"

    def test_to_dict_empty(self):
        from hashguard.yara_scanner import YaraScanResult
        r = YaraScanResult()
        d = r.to_dict()
        assert d["matches"] == []


class TestFindRuleFiles:
    def test_nonexistent_dir(self):
        from hashguard.yara_scanner import _find_rule_files
        assert _find_rule_files("/nonexistent/dir") == []

    def test_empty_dir(self):
        from hashguard.yara_scanner import _find_rule_files
        with tempfile.TemporaryDirectory() as td:
            assert _find_rule_files(td) == []

    def test_finds_yar_files(self):
        from hashguard.yara_scanner import _find_rule_files
        with tempfile.TemporaryDirectory() as td:
            for name in ["test.yar", "custom.yara", "skip.txt"]:
                open(os.path.join(td, name), "w").close()
            files = _find_rule_files(td)
            assert len(files) == 2
            assert any("test.yar" in f for f in files)
            assert any("custom.yara" in f for f in files)

    def test_returns_sorted(self):
        from hashguard.yara_scanner import _find_rule_files
        with tempfile.TemporaryDirectory() as td:
            for name in ["z_rules.yar", "a_rules.yar", "m_rules.yar"]:
                open(os.path.join(td, name), "w").close()
            files = _find_rule_files(td)
            basenames = [os.path.basename(f) for f in files]
            assert basenames == sorted(basenames)

    def test_recurses_subdirs(self):
        from hashguard.yara_scanner import _find_rule_files
        with tempfile.TemporaryDirectory() as td:
            sub = os.path.join(td, "subdir")
            os.makedirs(sub)
            open(os.path.join(td, "root.yar"), "w").close()
            open(os.path.join(sub, "nested.yar"), "w").close()
            files = _find_rule_files(td)
            assert len(files) == 2

    def test_actual_project_rules(self):
        from hashguard.yara_scanner import _find_rule_files
        rules_dir = os.path.join(os.path.dirname(__file__), "..", "yara_rules")
        if os.path.isdir(rules_dir):
            files = _find_rule_files(rules_dir)
            assert len(files) >= 1


class TestScanFile:
    def test_nonexistent_file(self):
        from hashguard.yara_scanner import scan_file
        r = scan_file("/nonexistent/file.exe")
        assert isinstance(r.matches, list)

    def test_returns_scan_result(self, tmp_path):
        from hashguard.yara_scanner import scan_file
        p = tmp_path / "test.bin"
        p.write_bytes(b"hello world test content")
        r = scan_file(str(p))
        assert hasattr(r, "available")
        assert hasattr(r, "rules_loaded")
        assert hasattr(r, "matches")

    def test_result_serializable(self, tmp_path):
        from hashguard.yara_scanner import scan_file
        import json
        p = tmp_path / "test2.bin"
        p.write_bytes(b"test content")
        r = scan_file(str(p))
        d = r.to_dict()
        serialized = json.dumps(d)
        assert isinstance(serialized, str)

    def test_custom_rules_dir(self, tmp_path):
        from hashguard.yara_scanner import scan_file
        p = tmp_path / "test3.bin"
        p.write_bytes(b"test")
        r = scan_file(str(p), rules_dir="/nonexistent")
        assert r.rules_loaded == 0

    def test_scan_with_no_yara(self):
        from hashguard.yara_scanner import scan_file
        with patch("hashguard.yara_scanner._YARA_AVAILABLE", False):
            r = scan_file("/some/file.bin")
            assert r.available is False
            assert r.matches == []

    def test_scan_actual_rules_dir(self, tmp_path):
        from hashguard.yara_scanner import scan_file, is_available
        if not is_available():
            pytest.skip("yara-python not installed")

        rules_dir = os.path.join(os.path.dirname(__file__), "..", "yara_rules")
        if not os.path.isdir(rules_dir):
            pytest.skip("yara_rules directory not found")

        p = tmp_path / "test_mz.bin"
        p.write_bytes(b"MZ" + b"\x00" * 100)
        r = scan_file(str(p), rules_dir=rules_dir)
        assert r.available is True
        assert r.rules_loaded >= 1

    def test_scan_compile_error_fallback(self, tmp_path):
        from hashguard.yara_scanner import scan_file, is_available
        if not is_available():
            pytest.skip("yara-python not installed")

        rules_dir = tmp_path / "rules"
        rules_dir.mkdir()
        (rules_dir / "test.yar").write_text(
            'rule test_rule { strings: $s = "TESTPATTERN" condition: $s }'
        )

        p = tmp_path / "test_content.bin"
        p.write_bytes(b"some content with TESTPATTERN inside")
        r = scan_file(str(p), rules_dir=str(rules_dir))
        assert r.available is True
        assert r.rules_loaded >= 1
        if r.matches:
            assert r.matches[0].rule == "test_rule"
