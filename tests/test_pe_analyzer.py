"""Tests for HashGuard PE analyzer module."""

import os
import struct
import tempfile

import pytest

from hashguard.pe_analyzer import (
    PEAnalysisResult,
    PESection,
    _entropy,
    analyze_pe,
    is_pe_file,
)


class TestEntropy:
    """Tests for Shannon entropy calculation."""

    def test_empty_data(self):
        assert _entropy(b"") == 0.0

    def test_uniform_data(self):
        # All same byte → entropy = 0
        assert _entropy(b"\x00" * 100) == 0.0

    def test_two_symbols_equal(self):
        # Two equal-frequency symbols → entropy ≈ 1.0
        data = b"\x00\x01" * 50
        ent = _entropy(data)
        assert abs(ent - 1.0) < 0.01

    def test_high_entropy(self):
        # Random-ish data should be high entropy
        data = bytes(range(256)) * 4
        ent = _entropy(data)
        assert ent > 7.9

    def test_low_entropy(self):
        data = b"AAAA" * 100
        ent = _entropy(data)
        assert ent == 0.0


class TestIsPEFile:
    """Tests for PE file detection."""

    def test_pe_by_extension(self, tmp_path):
        for ext in [".exe", ".dll", ".sys", ".scr"]:
            p = tmp_path / f"test{ext}"
            p.write_bytes(b"not a real PE")
            assert is_pe_file(str(p))

    def test_pe_by_mz_header(self, tmp_path):
        p = tmp_path / "test.bin"
        p.write_bytes(b"MZ" + b"\x00" * 100)
        assert is_pe_file(str(p))

    def test_non_pe_file(self, tmp_path):
        p = tmp_path / "test.txt"
        p.write_text("hello world")
        assert not is_pe_file(str(p))

    def test_nonexistent_file(self):
        assert not is_pe_file("/nonexistent/file.bin")


class TestPEAnalysisResult:
    """Tests for PEAnalysisResult dataclass."""

    def test_default_values(self):
        r = PEAnalysisResult()
        assert r.is_pe is False
        assert r.sections == []
        assert r.imports == {}
        assert r.suspicious_imports == []
        assert r.warnings == []
        assert r.packed is False

    def test_to_dict(self):
        sec = PESection(
            name=".text",
            virtual_size=4096,
            raw_size=4096,
            entropy=6.5,
            characteristics="EXEC | READ",
        )
        r = PEAnalysisResult(
            is_pe=True,
            machine="x86 (32-bit)",
            sections=[sec],
            imports={"kernel32.dll": ["CreateFileA"]},
            suspicious_imports=["kernel32.dll:VirtualAlloc"],
            packed=True,
            packer_hint="UPX",
            overall_entropy=7.2,
        )
        d = r.to_dict()
        assert d["is_pe"] is True
        assert d["machine"] == "x86 (32-bit)"
        assert len(d["sections"]) == 1
        assert d["sections"][0]["name"] == ".text"
        assert d["packed"] is True
        assert d["packer_hint"] == "UPX"


class TestAnalyzePE:
    """Tests for the analyze_pe function."""

    def test_non_pe_file(self, tmp_path):
        p = tmp_path / "test.txt"
        p.write_text("just text")
        result = analyze_pe(str(p))
        assert result.is_pe is False

    def test_invalid_pe_format(self, tmp_path):
        """File with MZ header but not a valid PE."""
        p = tmp_path / "fake.exe"
        p.write_bytes(b"MZ" + b"\x00" * 200)
        result = analyze_pe(str(p))
        # Should return without crashing, is_pe might be False
        assert isinstance(result, PEAnalysisResult)

    def test_nonexistent_file(self):
        result = analyze_pe("/nonexistent/file.exe")
        assert result.is_pe is False
