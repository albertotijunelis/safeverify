"""Tests for HashGuard family detector module."""

import os
import tempfile

import pytest

from hashguard.family_detector import (
    FamilyDetection,
    _detect_compiler,
    detect_family,
    FAMILY_SIGNATURES,
    COMPILER_SIGNATURES,
)


def _make_temp(data: bytes) -> str:
    fd, path = tempfile.mkstemp()
    os.write(fd, data)
    os.close(fd)
    return path


class TestFamilyDetection:
    """Tests for FamilyDetection dataclass."""

    def test_default(self):
        d = FamilyDetection()
        assert d.family == ""
        assert d.confidence == 0.0
        assert d.source == ""
        assert d.all_matches == []

    def test_to_dict(self):
        d = FamilyDetection(
            family="Emotet",
            confidence=0.92,
            source="strings",
            description="Banking trojan",
            compiler="Delphi",
            all_matches=[
                {"family": "Emotet", "confidence": 0.92, "source": "strings"},
                {"family": "Trickbot", "confidence": 0.5, "source": "ml"},
            ],
        )
        result = d.to_dict()
        assert result["family"] == "Emotet"
        assert result["confidence"] == 92.0
        assert result["compiler"] == "Delphi"
        assert len(result["all_matches"]) == 2

    def test_to_dict_no_compiler(self):
        d = FamilyDetection(family="Test", confidence=0.5)
        result = d.to_dict()
        assert "compiler" not in result


class TestDetectCompiler:
    """Tests for compiler detection."""

    def test_detects_autoit(self):
        data = b"\x00" * 100 + b"AutoIt v3" + b"\x00" * 100
        p = _make_temp(data)
        try:
            result = _detect_compiler(p)
            assert result is not None
            assert "AutoIt" in result
        finally:
            os.remove(p)

    def test_detects_pyinstaller(self):
        data = b"\x00" * 100 + b"PyInstaller" + b"\x00" * 100
        p = _make_temp(data)
        try:
            result = _detect_compiler(p)
            assert result is not None
            assert "PyInstaller" in result
        finally:
            os.remove(p)

    def test_detects_golang(self):
        data = b"\x00" * 100 + b"Go build ID:" + b"\x00" * 100
        p = _make_temp(data)
        try:
            result = _detect_compiler(p)
            assert result is not None
            assert "Go" in result
        finally:
            os.remove(p)

    def test_no_compiler_detected(self):
        data = b"\x00" * 200
        p = _make_temp(data)
        try:
            result = _detect_compiler(p)
            assert result is None
        finally:
            os.remove(p)

    def test_nonexistent_file(self):
        result = _detect_compiler("/nonexistent/path/file.exe")
        assert result is None


class TestDetectFamilyStrings:
    """Tests for string-based family detection."""

    def test_detects_xmrig(self):
        data = b"xmrig miner v6.18 stratum+tcp://pool.example.com randomx hashrate"
        p = _make_temp(data)
        try:
            result = detect_family(p)
            assert result.family == "XMRig"
            assert result.confidence > 0.0
            assert result.source == "strings"
        finally:
            os.remove(p)

    def test_detects_lockbit(self):
        data = b"LockBit ransomware .lockbit Restore-My-Files.txt"
        p = _make_temp(data)
        try:
            result = detect_family(p)
            assert result.family == "LockBit"
            assert result.confidence > 0.0
        finally:
            os.remove(p)

    def test_detects_mirai(self):
        data = b"mirai /bin/busybox scanner_init killer_init"
        p = _make_temp(data)
        try:
            result = detect_family(p)
            assert result.family == "Mirai"
        finally:
            os.remove(p)

    def test_clean_file_no_family(self):
        data = b"This is a perfectly normal file with nothing suspicious in it."
        p = _make_temp(data)
        try:
            result = detect_family(p)
            assert result.family == ""
            assert result.confidence == 0.0
        finally:
            os.remove(p)


class TestDetectFamilyYara:
    """Tests for YARA-based family detection."""

    def test_yara_family_detection(self):
        data = b"clean content"
        p = _make_temp(data)
        try:
            yara_matches = {
                "matches": [
                    {
                        "rule": "APT28_Backdoor",
                        "meta": {
                            "malware_family": "APT28",
                            "description": "APT28 Fancy Bear backdoor",
                        },
                    }
                ]
            }
            result = detect_family(p, yara_matches=yara_matches)
            assert result.family == "APT28"
            assert result.source == "yara"
        finally:
            os.remove(p)


class TestDetectFamilyThreatIntel:
    """Tests for threat intel-based family detection."""

    def test_threat_intel_family(self):
        data = b"clean content"
        p = _make_temp(data)
        try:
            ti = {
                "hits": [
                    {
                        "source": "MalwareBazaar",
                        "found": True,
                        "malware_family": "Emotet",
                    }
                ]
            }
            result = detect_family(p, threat_intel=ti)
            assert result.family == "Emotet"
            assert result.source == "threat_intel"
        finally:
            os.remove(p)

    def test_threat_intel_no_family(self):
        data = b"clean content"
        p = _make_temp(data)
        try:
            ti = {"hits": [{"source": "MalwareBazaar", "found": False}]}
            result = detect_family(p, threat_intel=ti)
            assert result.family == ""
        finally:
            os.remove(p)


class TestDetectFamilyML:
    """Tests for ML-based family detection."""

    def test_ml_generic_classification(self):
        data = b"clean content"
        p = _make_temp(data)
        try:
            ml = {"predicted_class": "trojan", "confidence": 0.85}
            result = detect_family(p, ml_result=ml)
            assert result.family == "Generic.Trojan"
            assert result.source == "ml"
        finally:
            os.remove(p)

    def test_ml_benign_ignored(self):
        data = b"clean content"
        p = _make_temp(data)
        try:
            ml = {"predicted_class": "benign", "confidence": 0.95}
            result = detect_family(p, ml_result=ml)
            assert result.family == ""
        finally:
            os.remove(p)

    def test_ml_low_confidence_ignored(self):
        data = b"clean content"
        p = _make_temp(data)
        try:
            ml = {"predicted_class": "trojan", "confidence": 0.3}
            result = detect_family(p, ml_result=ml)
            assert result.family == ""
        finally:
            os.remove(p)

    def test_ml_confidence_as_percentage(self):
        data = b"clean content"
        p = _make_temp(data)
        try:
            ml = {"predicted_class": "ransomware", "confidence": 85}
            result = detect_family(p, ml_result=ml)
            assert result.family == "Generic.Ransomware"
        finally:
            os.remove(p)


class TestDetectFamilyPriority:
    """Tests that higher-confidence sources win."""

    def test_yara_beats_ml(self):
        data = b"clean content"
        p = _make_temp(data)
        try:
            yara_matches = {
                "matches": [
                    {"rule": "LockBit", "meta": {"malware_family": "LockBit"}}
                ]
            }
            ml = {"predicted_class": "trojan", "confidence": 0.85}
            result = detect_family(p, yara_matches=yara_matches, ml_result=ml)
            assert result.family == "LockBit"
        finally:
            os.remove(p)
