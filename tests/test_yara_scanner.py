"""Tests for HashGuard YARA scanner module."""

import os
import tempfile

import pytest

from hashguard.yara_scanner import (
    YaraMatch,
    YaraScanResult,
    _find_rule_files,
    is_available,
    scan_file,
)


class TestYaraMatch:
    """Tests for YaraMatch dataclass."""

    def test_to_dict(self):
        m = YaraMatch(
            rule="Suspicious_Test",
            namespace="default",
            tags=["malware"],
            meta={"description": "test rule", "severity": "high"},
            strings=["0x00: $s1"],
        )
        d = m.to_dict()
        assert d["rule"] == "Suspicious_Test"
        assert d["namespace"] == "default"
        assert d["tags"] == ["malware"]
        assert d["meta"]["severity"] == "high"


class TestYaraScanResult:
    """Tests for YaraScanResult dataclass."""

    def test_default(self):
        r = YaraScanResult()
        assert r.available is False
        assert r.rules_loaded == 0
        assert r.matches == []

    def test_to_dict(self):
        m = YaraMatch(rule="Test", namespace="ns")
        r = YaraScanResult(available=True, rules_loaded=3, matches=[m])
        d = r.to_dict()
        assert d["available"] is True
        assert d["rules_loaded"] == 3
        assert len(d["matches"]) == 1


class TestFindRuleFiles:
    """Tests for rule file discovery."""

    def test_empty_dir(self, tmp_path):
        assert _find_rule_files(str(tmp_path)) == []

    def test_finds_yar_files(self, tmp_path):
        (tmp_path / "rule1.yar").write_text("rule test { condition: true }")
        (tmp_path / "rule2.yara").write_text("rule test2 { condition: true }")
        (tmp_path / "readme.txt").write_text("not a rule")
        found = _find_rule_files(str(tmp_path))
        assert len(found) == 2
        assert all(f.endswith((".yar", ".yara")) for f in found)

    def test_nonexistent_dir(self):
        assert _find_rule_files("/nonexistent/path") == []

    def test_nested_rules(self, tmp_path):
        sub = tmp_path / "subdir"
        sub.mkdir()
        (sub / "nested.yar").write_text("rule nested { condition: true }")
        found = _find_rule_files(str(tmp_path))
        assert len(found) == 1


class TestScanFile:
    """Tests for the scan_file function."""

    def test_scan_nonexistent_file(self, tmp_path):
        result = scan_file("/nonexistent/file.exe", rules_dir=str(tmp_path))
        assert isinstance(result, YaraScanResult)

    def test_scan_no_rules(self, tmp_path):
        target = tmp_path / "test.txt"
        target.write_text("hello")
        empty_rules = tmp_path / "rules"
        empty_rules.mkdir()
        result = scan_file(str(target), rules_dir=str(empty_rules))
        assert result.rules_loaded == 0
        assert result.matches == []


class TestIsAvailable:
    """Tests for yara availability check."""

    def test_returns_bool(self):
        assert isinstance(is_available(), bool)
