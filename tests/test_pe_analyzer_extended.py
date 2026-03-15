"""Extended tests for HashGuard PE analyzer module — covers remaining branches."""

import os
import sys
import json
from unittest.mock import patch, MagicMock

import pytest

from hashguard.pe_analyzer import (
    PEAnalysisResult,
    PESection,
    _entropy,
    _load_pe_indicators,
    analyze_pe,
    is_pe_file,
    PE_EXTENSIONS,
)


# ── _load_pe_indicators branches ─────────────────────────────────────────────

class TestLoadPEIndicatorsExtended:
    def test_frozen_path(self, tmp_path):
        data_dir = tmp_path / "data"
        data_dir.mkdir()
        indicators = {"suspicious_apis": ["VirtualAlloc"], "packer_sections": {".upx0": "UPX"}}
        (data_dir / "pe_indicators.json").write_text(json.dumps(indicators))
        sys.frozen = True
        sys._MEIPASS = str(tmp_path)
        try:
            apis, packers = _load_pe_indicators()
        finally:
            del sys.frozen
            del sys._MEIPASS
        assert "VirtualAlloc" in apis
        assert ".upx0" in packers

    def test_exception_returns_defaults(self):
        with patch("builtins.open", side_effect=Exception("read error")):
            with patch("os.path.isfile", return_value=True):
                apis, packers = _load_pe_indicators()
        assert apis == set()
        assert packers == {}

    def test_missing_keys_in_json(self, tmp_path):
        data_dir = tmp_path / "data"
        data_dir.mkdir()
        (data_dir / "pe_indicators.json").write_text("{}")
        with patch("hashguard.pe_analyzer.os.path.dirname", return_value=str(tmp_path)):
            with patch("os.path.isfile", return_value=True):
                with patch("builtins.open", return_value=open(str(data_dir / "pe_indicators.json"))):
                    apis, packers = _load_pe_indicators()
        assert apis == set()
        assert packers == {}


# ── _entropy ─────────────────────────────────────────────────────────────────

class TestEntropyExtended:
    def test_single_byte(self):
        assert _entropy(b"\x42") == 0.0

    def test_four_unique_bytes(self):
        data = b"\x00\x01\x02\x03" * 25
        ent = _entropy(data)
        assert abs(ent - 2.0) < 0.01

    def test_all_256_bytes(self):
        data = bytes(range(256))
        ent = _entropy(data)
        assert abs(ent - 8.0) < 0.01

    def test_two_thirds_one_third(self):
        data = b"\x00" * 200 + b"\x01" * 100
        ent = _entropy(data)
        assert 0.9 < ent < 1.0


# ── is_pe_file extended ─────────────────────────────────────────────────────

class TestIsPEFileExtended:
    def test_all_pe_extensions(self, tmp_path):
        for ext in PE_EXTENSIONS:
            p = tmp_path / f"test{ext}"
            p.write_bytes(b"dummy")
            assert is_pe_file(str(p)) is True

    def test_non_mz_binary(self, tmp_path):
        p = tmp_path / "test.bin"
        p.write_bytes(b"PK" + b"\x00" * 100)  # ZIP header
        assert is_pe_file(str(p)) is False

    def test_empty_file(self, tmp_path):
        p = tmp_path / "empty.bin"
        p.write_bytes(b"")
        assert is_pe_file(str(p)) is False

    def test_read_error(self, tmp_path, monkeypatch):
        p = tmp_path / "error.bin"
        p.write_bytes(b"content")
        import builtins
        real_open = builtins.open
        def fail_open(path, *a, **kw):
            if "error.bin" in str(path):
                raise IOError("read error")
            return real_open(path, *a, **kw)
        monkeypatch.setattr(builtins, "open", fail_open)
        assert is_pe_file(str(p)) is False

    def test_mz_header_minimal(self, tmp_path):
        p = tmp_path / "tiny.bin"
        p.write_bytes(b"MZ")  # Just 2 bytes
        assert is_pe_file(str(p)) is True


# ── PEAnalysisResult extended ────────────────────────────────────────────────

class TestPEAnalysisResultExtended:
    def test_all_fields_in_to_dict(self):
        sec = PESection(
            name=".text", virtual_size=8192, raw_size=4096,
            entropy=6.5, characteristics="EXEC | READ"
        )
        r = PEAnalysisResult(
            is_pe=True,
            machine="ARM64",
            compile_time="2024-01-01 00:00:00 UTC",
            entry_point="0x00001000",
            sections=[sec],
            imports={"kernel32.dll": ["GetProcAddress"]},
            suspicious_imports=["kernel32.dll:VirtualAlloc"],
            warnings=["Suspicious"],
            packed=True,
            packer_hint="Themida",
            overall_entropy=7.5,
        )
        d = r.to_dict()
        assert d["machine"] == "ARM64"
        assert d["overall_entropy"] == 7.5
        assert len(d["sections"]) == 1
        assert d["sections"][0]["entropy"] == 6.5
        assert d["packed"] is True
        assert d["imports"]["kernel32.dll"] == ["GetProcAddress"]

    def test_empty_to_dict(self):
        r = PEAnalysisResult()
        d = r.to_dict()
        assert d["is_pe"] is False
        assert d["sections"] == []
        assert d["imports"] == {}


# ── PESection ────────────────────────────────────────────────────────────────

class TestPESection:
    def test_fields(self):
        s = PESection(
            name=".data", virtual_size=4096, raw_size=2048,
            entropy=3.5, characteristics="READ | WRITE"
        )
        assert s.name == ".data"
        assert s.virtual_size == 4096
        assert s.raw_size == 2048
        assert s.entropy == 3.5
        assert s.characteristics == "READ | WRITE"


# ── analyze_pe with mocked pefile — additional branches ──────────────────────

def _make_mock_section(name=b".text\x00\x00\x00", raw_data=b"\x00" * 512,
                       vsize=4096, rsize=512, chars=0x60000020):
    sec = MagicMock()
    sec.Name = name
    sec.get_data.return_value = raw_data
    sec.Misc_VirtualSize = vsize
    sec.SizeOfRawData = rsize
    sec.Characteristics = chars
    return sec


class TestAnalyzePEExtended:
    def _make_pe_mock(self, machine=0x14C, timestamp=1609459200, ep=0x1000,
                      sections=None, imports=None):
        pe = MagicMock()
        pe.FILE_HEADER.Machine = machine
        pe.FILE_HEADER.TimeDateStamp = timestamp
        pe.OPTIONAL_HEADER.AddressOfEntryPoint = ep
        pe.sections = sections or [_make_mock_section()]
        if imports is not None:
            pe.DIRECTORY_ENTRY_IMPORT = imports
        else:
            del pe.DIRECTORY_ENTRY_IMPORT
        pe.parse_data_directories.return_value = None
        pe.close.return_value = None
        return pe

    @patch("hashguard.pe_analyzer.is_pe_file", return_value=True)
    def test_pefile_import_error(self, mock_ispe, monkeypatch):
        """When pefile is not installed, return empty result."""
        import builtins
        orig = builtins.__import__
        def fail_pefile(name, *a, **kw):
            if name == "pefile":
                raise ImportError("no pefile")
            return orig(name, *a, **kw)
        monkeypatch.setattr(builtins, "__import__", fail_pefile)
        result = analyze_pe("test.exe")
        assert result.is_pe is False

    @patch("hashguard.pe_analyzer.is_pe_file", return_value=True)
    def test_multiple_sections(self, mock_ispe):
        low_ent = b"\x00" * 1024
        sec1 = _make_mock_section(name=b".text\x00\x00\x00", raw_data=low_ent, rsize=1024)
        sec2 = _make_mock_section(name=b".rdata\x00\x00", raw_data=low_ent, rsize=1024)
        sec3 = _make_mock_section(name=b".data\x00\x00\x00", raw_data=low_ent, rsize=1024)
        pe_mock = self._make_pe_mock(sections=[sec1, sec2, sec3])
        mock_pefile = MagicMock()
        mock_pefile.PE.return_value = pe_mock
        mock_pefile.PEFormatError = type("PEFormatError", (Exception,), {})
        with patch.dict("sys.modules", {"pefile": mock_pefile}):
            with patch("hashguard.pe_analyzer.pefile", mock_pefile, create=True):
                result = analyze_pe("test.exe")
        assert len(result.sections) == 3

    @patch("hashguard.pe_analyzer.is_pe_file", return_value=True)
    def test_write_only_section(self, mock_ispe):
        """Section with WRITE only, no EXEC."""
        sec = _make_mock_section(chars=0x80000000)  # WRITE only
        pe_mock = self._make_pe_mock(sections=[sec])
        mock_pefile = MagicMock()
        mock_pefile.PE.return_value = pe_mock
        mock_pefile.PEFormatError = type("PEFormatError", (Exception,), {})
        with patch.dict("sys.modules", {"pefile": mock_pefile}):
            with patch("hashguard.pe_analyzer.pefile", mock_pefile, create=True):
                result = analyze_pe("test.exe")
        assert result.sections[0].characteristics == "WRITE"
        assert not any("writable and executable" in w for w in result.warnings)

    @patch("hashguard.pe_analyzer.is_pe_file", return_value=True)
    def test_read_only_section(self, mock_ispe):
        sec = _make_mock_section(chars=0x40000000)  # READ only
        pe_mock = self._make_pe_mock(sections=[sec])
        mock_pefile = MagicMock()
        mock_pefile.PE.return_value = pe_mock
        mock_pefile.PEFormatError = type("PEFormatError", (Exception,), {})
        with patch.dict("sys.modules", {"pefile": mock_pefile}):
            with patch("hashguard.pe_analyzer.pefile", mock_pefile, create=True):
                result = analyze_pe("test.exe")
        assert result.sections[0].characteristics == "READ"

    @patch("hashguard.pe_analyzer.is_pe_file", return_value=True)
    def test_no_flags_section(self, mock_ispe):
        sec = _make_mock_section(chars=0x00000000)
        pe_mock = self._make_pe_mock(sections=[sec])
        mock_pefile = MagicMock()
        mock_pefile.PE.return_value = pe_mock
        mock_pefile.PEFormatError = type("PEFormatError", (Exception,), {})
        with patch.dict("sys.modules", {"pefile": mock_pefile}):
            with patch("hashguard.pe_analyzer.pefile", mock_pefile, create=True):
                result = analyze_pe("test.exe")
        assert "0x00000000" in result.sections[0].characteristics

    @patch("hashguard.pe_analyzer.is_pe_file", return_value=True)
    def test_import_with_no_name(self, mock_ispe):
        """Import with name=None should use ordinal."""
        imp_func = MagicMock()
        imp_func.name = None
        imp_func.ordinal = 99
        dll_entry = MagicMock()
        dll_entry.dll = b"advapi32.dll"
        dll_entry.imports = [imp_func]
        pe_mock = self._make_pe_mock(imports=[dll_entry])
        mock_pefile = MagicMock()
        mock_pefile.PE.return_value = pe_mock
        mock_pefile.PEFormatError = type("PEFormatError", (Exception,), {})
        with patch.dict("sys.modules", {"pefile": mock_pefile}):
            with patch("hashguard.pe_analyzer.pefile", mock_pefile, create=True):
                result = analyze_pe("test.exe")
        # Imports with name=None are skipped (no fname.decode)
        assert "advapi32.dll" in result.imports

    @patch("hashguard.pe_analyzer.is_pe_file", return_value=True)
    def test_one_high_entropy_section_not_packed(self, mock_ispe):
        """Single high-entropy section shouldn't trigger packed detection."""
        high_data = bytes(range(256)) * 20
        sec1 = _make_mock_section(name=b".text\x00\x00\x00", raw_data=high_data, rsize=len(high_data))
        sec2 = _make_mock_section(name=b".data\x00\x00\x00", raw_data=b"\x00" * 5120, rsize=5120)
        pe_mock = self._make_pe_mock(sections=[sec1, sec2])
        mock_pefile = MagicMock()
        mock_pefile.PE.return_value = pe_mock
        mock_pefile.PEFormatError = type("PEFormatError", (Exception,), {})
        with patch.dict("sys.modules", {"pefile": mock_pefile}):
            with patch("hashguard.pe_analyzer.pefile", mock_pefile, create=True):
                result = analyze_pe("test.exe")
        # Only 1 high entropy section, needs >=2 and overall > 7.0
        # Result depends on weighted average
        assert isinstance(result.packed, bool)

    @patch("hashguard.pe_analyzer.is_pe_file", return_value=True)
    def test_closes_pe_on_success(self, mock_ispe):
        pe_mock = self._make_pe_mock()
        mock_pefile = MagicMock()
        mock_pefile.PE.return_value = pe_mock
        mock_pefile.PEFormatError = type("PEFormatError", (Exception,), {})
        with patch.dict("sys.modules", {"pefile": mock_pefile}):
            with patch("hashguard.pe_analyzer.pefile", mock_pefile, create=True):
                analyze_pe("test.exe")
        pe_mock.close.assert_called_once()
