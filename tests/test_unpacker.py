"""Tests for unpacker module — packer detection and shellcode detection."""

import os
import subprocess
import tempfile
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest

from hashguard.unpacker import (
    UnpackResult,
    ShellcodeInfo,
    EmulationUnpackResult,
    detect_packer,
    detect_shellcode,
    unpack_upx,
    emulate_unpack,
    _find_api_hashes,
    _get_non_code_regions,
    _section_entropy,
    _SHELLCODE_STRONG,
    _SHELLCODE_WEAK,
    _API_HASH_PATTERNS,
    PACKER_SIGNATURES,
)


# ── Dataclass tests ──────────────────────────────────────────────────────────


class TestUnpackResult:
    def test_defaults(self):
        r = UnpackResult()
        assert r.was_packed is False
        assert r.packer == ""
        assert r.unpacked is False
        assert r.error == ""

    def test_to_dict(self):
        r = UnpackResult(
            was_packed=True,
            packer="UPX",
            unpacked=True,
            original_size=1000,
            unpacked_size=5000,
        )
        d = r.to_dict()
        assert d["packer"] == "UPX"
        assert d["size_ratio"] == 5.0


class TestShellcodeInfo:
    def test_defaults(self):
        s = ShellcodeInfo()
        assert s.detected is False
        assert s.confidence == "low"
        assert s.indicators == []

    def test_to_dict(self):
        s = ShellcodeInfo(detected=True, confidence="high", indicators=["PEB access"])
        d = s.to_dict()
        assert d["detected"] is True
        assert d["confidence"] == "high"


# ── Packer detection tests ───────────────────────────────────────────────────


class TestDetectPacker:
    def test_upx_magic(self, tmp_path):
        p = tmp_path / "test.exe"
        p.write_bytes(b"\x00" * 100 + b"UPX!" + b"\x00" * 100)
        packed, name = detect_packer(str(p))
        assert packed is True
        assert name == "UPX"

    def test_upx_section_name(self, tmp_path):
        p = tmp_path / "test.exe"
        p.write_bytes(b"\x00" * 50 + b"UPX0" + b"\x00" * 50)
        packed, name = detect_packer(str(p))
        assert packed is True
        assert name == "UPX"

    def test_mpress(self, tmp_path):
        p = tmp_path / "test.exe"
        p.write_bytes(b"\x00" * 50 + b".MPRESS1" + b"\x00" * 50)
        packed, name = detect_packer(str(p))
        assert packed is True
        assert name == "MPRESS"

    def test_themida_string(self, tmp_path):
        p = tmp_path / "test.exe"
        p.write_bytes(b"\x00" * 50 + b"Themida" + b"\x00" * 50)
        packed, name = detect_packer(str(p))
        assert packed is True
        assert name == "Themida"

    def test_vmprotect(self, tmp_path):
        p = tmp_path / "test.exe"
        p.write_bytes(b"\x00" * 50 + b"VMProtect" + b"\x00" * 50)
        packed, name = detect_packer(str(p))
        assert packed is True
        assert name == "VMProtect"

    def test_aspack(self, tmp_path):
        p = tmp_path / "test.exe"
        p.write_bytes(b"\x00" * 50 + b".aspack" + b"\x00" * 50)
        packed, name = detect_packer(str(p))
        assert packed is True
        assert name == "ASPack"

    def test_clean_file(self, tmp_path):
        p = tmp_path / "test.exe"
        p.write_bytes(b"MZ" + b"\x00" * 200)
        packed, name = detect_packer(str(p))
        assert packed is False
        assert name == ""

    def test_nonexistent_file(self):
        packed, name = detect_packer("/no/such/file")
        assert packed is False
        assert name == ""

    def test_all_signatures_have_section_names(self):
        """Every packer signature must have at least one detection method."""
        for packer, sigs in PACKER_SIGNATURES.items():
            has_method = (
                sigs.get("magic")
                or sigs.get("section_names")
                or sigs.get("strings")
            )
            assert has_method, f"{packer} has no detection method"


# ── Shellcode detection tests ────────────────────────────────────────────────


class TestDetectShellcode:
    def test_clean_file(self, tmp_path):
        p = tmp_path / "clean.bin"
        p.write_bytes(b"This is a completely normal text file " * 10)
        info = detect_shellcode(str(p))
        assert info.detected is False

    def test_peb_access_pattern(self, tmp_path):
        p = tmp_path / "shellcode.bin"
        # Two strong indicators => high confidence
        payload = (
            b"\x00" * 100
            + b"\x64\xa1\x30\x00\x00\x00"  # PEB access
            + b"\x00" * 50
            + b"\xe8\x00\x00\x00\x00"  # call $+5
            + b"\x00" * 100
        )
        p.write_bytes(payload)
        info = detect_shellcode(str(p))
        assert info.detected is True
        assert info.confidence == "high"
        assert any("PEB" in i for i in info.indicators)

    def test_ror13_pattern(self, tmp_path):
        p = tmp_path / "shellcode.bin"
        payload = (
            b"\x00" * 100
            + b"\xc1\xcf\x0d"  # ROR13
            + b"\x00" * 200
        )
        p.write_bytes(payload)
        info = detect_shellcode(str(p))
        assert info.detected is True
        assert any("ROR13" in i for i in info.indicators)

    def test_small_file_skipped(self, tmp_path):
        p = tmp_path / "tiny.bin"
        p.write_bytes(b"\x90" * 10)
        info = detect_shellcode(str(p))
        assert info.detected is False

    def test_nonexistent_file(self):
        info = detect_shellcode("/no/such/file")
        assert info.detected is False


# ── Helper function tests ────────────────────────────────────────────────────


class TestSectionEntropy:
    def test_empty(self):
        assert _section_entropy(b"") == 0.0

    def test_uniform(self):
        data = bytes(range(256)) * 10
        assert _section_entropy(data) > 7.9

    def test_low(self):
        data = b"\x00" * 100
        assert _section_entropy(data) == 0.0


class TestFindApiHashes:
    def test_no_hashes_found(self):
        result = _find_api_hashes(b"\x00" * 100)
        assert result == []

    def test_known_hash_found(self):
        # Embed a known API hash (LoadLibraryA ROR13)
        from hashguard.unpacker import _KNOWN_API_HASHES_ROR13

        if _KNOWN_API_HASHES_ROR13:
            hash_val = list(_KNOWN_API_HASHES_ROR13.keys())[0]
            needle = hash_val.to_bytes(4, "little")
            content = b"\x00" * 50 + needle + b"\x00" * 50
            result = _find_api_hashes(content)
            assert len(result) >= 1


# ── UPX unpacking tests ─────────────────────────────────────────────────────


class TestUnpackUPX:
    def test_not_packed(self, tmp_path):
        p = tmp_path / "clean.exe"
        p.write_bytes(b"MZ" + b"\x00" * 200)
        result = unpack_upx(str(p))
        assert result.was_packed is False
        assert result.unpacked is False

    def test_non_upx_packer(self, tmp_path):
        p = tmp_path / "packed.exe"
        p.write_bytes(b"\x00" * 50 + b"VMProtect" + b"\x00" * 50)
        result = unpack_upx(str(p))
        assert result.was_packed is True
        assert result.packer == "VMProtect"
        assert result.unpacked is False
        assert "only supported for UPX" in result.error

    @patch("hashguard.unpacker.shutil.which", return_value=None)
    @patch("hashguard.unpacker.os.path.isfile", return_value=False)
    def test_upx_binary_not_found(self, mock_isfile, mock_which, tmp_path):
        p = tmp_path / "packed.exe"
        p.write_bytes(b"\x00" * 50 + b"UPX!" + b"\x00" * 50)
        result = unpack_upx(str(p))
        assert "UPX binary not found" in result.error

    @patch("hashguard.unpacker.subprocess.run")
    @patch("hashguard.unpacker.shutil.which", return_value="/usr/bin/upx")
    def test_upx_unpack_success(self, mock_which, mock_run, tmp_path):
        p = tmp_path / "packed.exe"
        p.write_bytes(b"\x00" * 50 + b"UPX!" + b"\x00" * 50)
        mock_run.return_value = MagicMock(returncode=0)
        result = unpack_upx(str(p), output_dir=str(tmp_path))
        assert result.unpacked is True
        assert result.unpacked_path != ""

    @patch("hashguard.unpacker.subprocess.run")
    @patch("hashguard.unpacker.shutil.which", return_value="/usr/bin/upx")
    def test_upx_unpack_failure(self, mock_which, mock_run, tmp_path):
        p = tmp_path / "packed.exe"
        p.write_bytes(b"\x00" * 50 + b"UPX!" + b"\x00" * 50)
        mock_run.return_value = MagicMock(returncode=1, stderr=b"CantUnpackException")
        result = unpack_upx(str(p), output_dir=str(tmp_path))
        assert result.unpacked is False
        assert "CantUnpackException" in result.error

    @patch("hashguard.unpacker.subprocess.run", side_effect=subprocess.TimeoutExpired("upx", 30))
    @patch("hashguard.unpacker.shutil.which", return_value="/usr/bin/upx")
    def test_upx_timeout(self, mock_which, mock_run, tmp_path):
        p = tmp_path / "packed.exe"
        p.write_bytes(b"\x00" * 50 + b"UPX!" + b"\x00" * 50)
        result = unpack_upx(str(p), output_dir=str(tmp_path))
        assert "timed out" in result.error.lower()


# ── _get_non_code_regions tests ──────────────────────────────────────────────


class TestGetNonCodeRegions:
    @patch("hashguard.unpacker.HAS_PEFILE", False)
    def test_no_pefile_returns_empty(self):
        result = _get_non_code_regions("dummy.exe")
        assert result == []

    @patch("hashguard.unpacker.HAS_PEFILE", True)
    def test_returns_data_sections(self):
        sec_data = MagicMock()
        sec_data.Characteristics = 0x40000000  # MEM_READ only
        sec_data.PointerToRawData = 0x400
        sec_data.SizeOfRawData = 0x200

        sec_code = MagicMock()
        sec_code.Characteristics = 0x60000020  # MEM_EXECUTE | MEM_READ | CODE
        sec_code.PointerToRawData = 0x200
        sec_code.SizeOfRawData = 0x200

        mock_pe = MagicMock()
        mock_pe.sections = [sec_code, sec_data]

        with patch("hashguard.unpacker.pefile") as mock_pf:
            mock_pf.PE.return_value = mock_pe
            result = _get_non_code_regions("test.exe")

        assert len(result) == 1
        assert result[0] == (0x400, 0x200)

    @patch("hashguard.unpacker.HAS_PEFILE", True)
    def test_skips_zero_size_sections(self):
        sec = MagicMock()
        sec.Characteristics = 0x40000000
        sec.PointerToRawData = 0
        sec.SizeOfRawData = 0

        mock_pe = MagicMock()
        mock_pe.sections = [sec]

        with patch("hashguard.unpacker.pefile") as mock_pf:
            mock_pf.PE.return_value = mock_pe
            result = _get_non_code_regions("test.exe")
        assert result == []


# ── EmulationUnpackResult tests ──────────────────────────────────────────────


class TestEmulationUnpackResult:
    def test_defaults(self):
        r = EmulationUnpackResult()
        assert r.attempted is False
        assert r.success is False
        assert r.oep_found is False
        assert r.error == ""

    def test_to_dict(self):
        r = EmulationUnpackResult(
            attempted=True,
            success=True,
            oep_found=True,
            oep_address=0x401000,
            instructions_executed=12345,
        )
        d = r.to_dict()
        assert d["attempted"] is True
        assert d["oep_address"] == "0x401000"
        assert d["instructions_executed"] == 12345

    def test_to_dict_no_oep(self):
        r = EmulationUnpackResult(attempted=True)
        d = r.to_dict()
        assert d["oep_address"] == ""


# ── emulate_unpack tests ─────────────────────────────────────────────────────


class TestEmulateUnpack:
    @patch("hashguard.unpacker.HAS_UNICORN", False)
    def test_no_unicorn(self, tmp_path):
        result = emulate_unpack(str(tmp_path / "test.exe"))
        assert "unicorn" in result.error.lower()

    @patch("hashguard.unpacker.HAS_UNICORN", True)
    @patch("hashguard.unpacker.HAS_PEFILE", False)
    def test_no_pefile(self, tmp_path):
        result = emulate_unpack(str(tmp_path / "test.exe"))
        assert "pefile" in result.error.lower()

    @patch("hashguard.unpacker.HAS_UNICORN", True)
    @patch("hashguard.unpacker.HAS_PEFILE", True)
    def test_pe_parse_failure(self, tmp_path):
        f = tmp_path / "bad.exe"
        f.write_bytes(b"not a PE")
        with patch("hashguard.unpacker.pefile") as mock_pf:
            mock_pf.PE.side_effect = Exception("invalid PE")
            result = emulate_unpack(str(f))
        assert result.attempted is True
        assert "Failed to parse PE" in result.error


# ── Shellcode weak indicator tests ───────────────────────────────────────────


class TestShellcodeWeakIndicators:
    def test_nop_sled_in_data_section(self, tmp_path):
        """NOP sled in a non-code section should be detected as weak indicator."""
        p = tmp_path / "test.bin"
        # Build content: some filler, then NOP sled, then strong indicator for detection
        nop_sled = b"\x90" * 40
        strong = b"\xe8\x00\x00\x00\x00"  # call $+5
        content = b"\x00" * 200 + nop_sled + b"\x00" * 50 + strong + b"\x00" * 100
        p.write_bytes(content)

        # Mock _get_non_code_regions to include the NOP sled area
        with patch("hashguard.unpacker._get_non_code_regions", return_value=[(190, 100)]):
            info = detect_shellcode(str(p))
        assert info.detected is True
        assert any("NOP sled" in i for i in info.indicators)

    def test_multiple_weak_indicators_trigger_detection(self, tmp_path):
        """Three or more weak indicators in data sections trigger low confidence."""
        p = tmp_path / "test.bin"
        nop_sled = b"\x90" * 40
        int3_sled = b"\xcc" * 20
        inf_loop = b"\xeb\xfe"
        content = (
            b"\x00" * 100 + nop_sled
            + b"\x00" * 100 + int3_sled
            + b"\x00" * 100 + inf_loop
            + b"\x00" * 100
        )
        p.write_bytes(content)

        # Mark the entire content as a data section
        with patch("hashguard.unpacker._get_non_code_regions", return_value=[(0, len(content))]):
            info = detect_shellcode(str(p))
        assert info.detected is True
        assert info.confidence == "low"
