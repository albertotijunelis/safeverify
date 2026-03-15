"""Tests for hashguard.memory_analyzer module."""

import sys
from dataclasses import dataclass, field
from typing import List
from unittest.mock import MagicMock, patch, PropertyMock

import pytest

from hashguard.memory_analyzer import (
    IMAGE_SCN_CNT_CODE,
    IMAGE_SCN_CNT_INITIALIZED_DATA,
    IMAGE_SCN_MEM_EXECUTE,
    IMAGE_SCN_MEM_READ,
    IMAGE_SCN_MEM_WRITE,
    DYNAMIC_RESOLVE_APIS,
    INJECTION_TECHNIQUES,
    SUSPICIOUS_MEMORY_APIS,
    EntryPointAnomaly,
    InjectionTechnique,
    MemoryAnalysisResult,
    SectionPermission,
    _analyze_entry_point,
    _analyze_sections,
    _build_summary,
    _compute_risk,
    _detect_injection_techniques,
    _flags_string,
    _get_imported_apis,
    _section_entropy,
    analyze_memory,
)


# ── Helpers ─────────────────────────────────────────────────────────────────

def _make_import_entry(api_names: list[str]):
    """Build a mock DIRECTORY_ENTRY_IMPORT entry with given API names."""
    entry = MagicMock()
    imports = []
    for name in api_names:
        imp = MagicMock()
        imp.name = name.encode("ascii")
        imports.append(imp)
    entry.imports = imports
    return entry


def _make_section(
    name: str = ".text",
    va: int = 0x1000,
    vsize: int = 0x1000,
    raw_size: int = 0x1000,
    characteristics: int = IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_CNT_CODE,
    data: bytes = b"\x00" * 64,
):
    """Build a mock PE section."""
    sec = MagicMock()
    sec.Name = name.encode("ascii").ljust(8, b"\x00")
    sec.VirtualAddress = va
    sec.Misc_VirtualSize = vsize
    sec.SizeOfRawData = raw_size
    sec.Characteristics = characteristics
    sec.get_data.return_value = data
    return sec


def _make_pe(sections=None, imports=None, ep_rva=0x1000):
    """Build a mock pefile.PE."""
    pe = MagicMock()
    pe.sections = sections or []
    pe.OPTIONAL_HEADER = MagicMock()
    pe.OPTIONAL_HEADER.AddressOfEntryPoint = ep_rva

    if imports is not None:
        pe.DIRECTORY_ENTRY_IMPORT = imports
    else:
        # Remove the attribute so hasattr returns False
        if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
            del pe.DIRECTORY_ENTRY_IMPORT

    return pe


# ═══════════════════════════════════════════════════════════════════════════
# TestInjectionTechniqueDataclass
# ═══════════════════════════════════════════════════════════════════════════

class TestInjectionTechniqueDataclass:
    def test_defaults(self):
        t = InjectionTechnique(name="test", description="desc")
        assert t.matched_apis == []
        assert t.missing_apis == []
        assert t.confidence == 0.0
        assert t.severity == "medium"

    def test_to_dict(self):
        t = InjectionTechnique(
            name="classic",
            description="Classic injection",
            matched_apis=["VirtualAllocEx"],
            missing_apis=["WriteProcessMemory"],
            confidence=0.7123,
            mitre="T1055.001",
            severity="critical",
        )
        d = t.to_dict()
        assert d["name"] == "classic"
        assert d["confidence"] == 0.71  # rounded to 2 decimal
        assert d["mitre"] == "T1055.001"
        assert "VirtualAllocEx" in d["matched_apis"]


# ═══════════════════════════════════════════════════════════════════════════
# TestSectionPermissionDataclass
# ═══════════════════════════════════════════════════════════════════════════

class TestSectionPermissionDataclass:
    def test_defaults(self):
        s = SectionPermission(name=".text")
        assert s.virtual_address == 0
        assert s.is_rwx is False

    def test_to_dict_hex_address(self):
        s = SectionPermission(name=".data", virtual_address=0x4000, entropy=7.12345)
        d = s.to_dict()
        assert d["virtual_address"] == "0x4000"
        assert d["entropy"] == 7.123  # rounded to 3


# ═══════════════════════════════════════════════════════════════════════════
# TestEntryPointAnomaly
# ═══════════════════════════════════════════════════════════════════════════

class TestEntryPointAnomaly:
    def test_defaults(self):
        e = EntryPointAnomaly()
        assert e.ep_section == ""
        assert e.is_outside_code is False

    def test_to_dict(self):
        e = EntryPointAnomaly(ep_section=".upx", ep_rva=0xDEAD, is_writable=True)
        d = e.to_dict()
        assert d["ep_rva"] == "0xdead"
        assert d["is_writable"] is True


# ═══════════════════════════════════════════════════════════════════════════
# TestMemoryAnalysisResult
# ═══════════════════════════════════════════════════════════════════════════

class TestMemoryAnalysisResult:
    def test_empty_result(self):
        r = MemoryAnalysisResult()
        d = r.to_dict()
        assert d["injection_techniques"] == []
        assert d["risk_score"] == 0
        assert d["max_severity"] == "none"
        assert "entry_point" not in d

    def test_with_entry_point(self):
        ep = EntryPointAnomaly(ep_section=".text", ep_rva=0x1000, is_writable=True)
        r = MemoryAnalysisResult(entry_point=ep)
        d = r.to_dict()
        assert "entry_point" in d
        assert d["entry_point"]["is_writable"] is True

    def test_with_techniques(self):
        t = InjectionTechnique(name="test", description="d", confidence=0.8)
        r = MemoryAnalysisResult(injection_techniques=[t], total_techniques_detected=1)
        d = r.to_dict()
        assert len(d["injection_techniques"]) == 1


# ═══════════════════════════════════════════════════════════════════════════
# TestGetImportedApis
# ═══════════════════════════════════════════════════════════════════════════

class TestGetImportedApis:
    def test_no_imports(self):
        pe = MagicMock(spec=[])  # no DIRECTORY_ENTRY_IMPORT attribute
        assert _get_imported_apis(pe) == set()

    def test_with_imports(self):
        entry = _make_import_entry(["VirtualAlloc", "WriteProcessMemory"])
        pe = MagicMock()
        pe.DIRECTORY_ENTRY_IMPORT = [entry]
        apis = _get_imported_apis(pe)
        assert "VirtualAlloc" in apis
        assert "WriteProcessMemory" in apis

    def test_null_import_name(self):
        entry = MagicMock()
        imp = MagicMock()
        imp.name = None
        entry.imports = [imp]
        pe = MagicMock()
        pe.DIRECTORY_ENTRY_IMPORT = [entry]
        apis = _get_imported_apis(pe)
        assert len(apis) == 0

    def test_multiple_dlls(self):
        e1 = _make_import_entry(["CreateFileA"])
        e2 = _make_import_entry(["VirtualAllocEx", "CreateRemoteThread"])
        pe = MagicMock()
        pe.DIRECTORY_ENTRY_IMPORT = [e1, e2]
        apis = _get_imported_apis(pe)
        assert len(apis) == 3


# ═══════════════════════════════════════════════════════════════════════════
# TestSectionEntropy
# ═══════════════════════════════════════════════════════════════════════════

class TestSectionEntropy:
    def test_empty_data(self):
        assert _section_entropy(b"") == 0.0

    def test_uniform_data(self):
        """All same byte → entropy = 0."""
        assert _section_entropy(b"\x00" * 100) == 0.0

    def test_two_values(self):
        """Two equally distributed bytes → entropy = 1.0."""
        data = b"\x00\x01" * 50
        entropy = _section_entropy(data)
        assert abs(entropy - 1.0) < 0.01

    def test_high_entropy(self):
        """All 256 byte values → entropy close to 8.0."""
        data = bytes(range(256))
        entropy = _section_entropy(data)
        assert entropy == 8.0


# ═══════════════════════════════════════════════════════════════════════════
# TestFlagsString
# ═══════════════════════════════════════════════════════════════════════════

class TestFlagsString:
    def test_read_only(self):
        assert _flags_string(IMAGE_SCN_MEM_READ) == "R"

    def test_rwx(self):
        flags = IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE | IMAGE_SCN_MEM_EXECUTE
        assert _flags_string(flags) == "RWX"

    def test_write_execute(self):
        flags = IMAGE_SCN_MEM_WRITE | IMAGE_SCN_MEM_EXECUTE
        assert _flags_string(flags) == "WX"

    def test_no_flags(self):
        assert _flags_string(0) == ""


# ═══════════════════════════════════════════════════════════════════════════
# TestDetectInjectionTechniques
# ═══════════════════════════════════════════════════════════════════════════

class TestDetectInjectionTechniques:
    def test_no_apis_no_techniques(self):
        assert _detect_injection_techniques(set()) == []

    def test_classic_injection_full(self):
        apis = {"VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread", "OpenProcess"}
        techs = _detect_injection_techniques(apis)
        names = [t.name for t in techs]
        assert "classic_injection" in names
        classic = next(t for t in techs if t.name == "classic_injection")
        assert classic.confidence >= 0.7
        assert classic.severity == "critical"

    def test_process_hollowing(self):
        apis = {"CreateProcessA", "NtUnmapViewOfSection", "WriteProcessMemory", "SetThreadContext", "ResumeThread"}
        techs = _detect_injection_techniques(apis)
        names = [t.name for t in techs]
        assert "process_hollowing" in names

    def test_partial_match_below_threshold(self):
        """Only 1 of 3 required APIs → below 50% threshold → no detection."""
        apis = {"VirtualAllocEx"}  # 1/3 required for classic_injection
        techs = _detect_injection_techniques(apis)
        classic_matches = [t for t in techs if t.name == "classic_injection"]
        assert len(classic_matches) == 0

    def test_partial_match_above_threshold(self):
        """2 of 3 required APIs → 67% → above 50% → detected with lower confidence."""
        apis = {"VirtualAllocEx", "WriteProcessMemory"}
        techs = _detect_injection_techniques(apis)
        classic_matches = [t for t in techs if t.name == "classic_injection"]
        assert len(classic_matches) == 1
        assert classic_matches[0].confidence < 0.7  # partial
        assert "CreateRemoteThread" in classic_matches[0].missing_apis

    def test_case_insensitive(self):
        apis = {"virtualallocex", "writeprocessmemory", "createremotethread"}
        techs = _detect_injection_techniques(apis)
        names = [t.name for t in techs]
        assert "classic_injection" in names

    def test_heap_spray(self):
        apis = {"HeapCreate", "HeapAlloc", "VirtualAlloc"}
        techs = _detect_injection_techniques(apis)
        names = [t.name for t in techs]
        assert "heap_spray" in names

    def test_memory_guard_change(self):
        apis = {"VirtualProtect", "VirtualAlloc", "VirtualAllocEx"}
        techs = _detect_injection_techniques(apis)
        names = [t.name for t in techs]
        assert "memory_guard_change" in names

    def test_sorted_by_confidence(self):
        """Multiple techniques detected → sorted by confidence descending."""
        apis = {
            "VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread",  # classic
            "QueueUserAPC", "ResumeThread",  # early_bird
            "VirtualProtect",  # memory_guard_change
        }
        techs = _detect_injection_techniques(apis)
        confidences = [t.confidence for t in techs]
        assert confidences == sorted(confidences, reverse=True)

    def test_dll_injection(self):
        apis = {"CreateRemoteThread", "LoadLibraryA", "VirtualAllocEx", "GetProcAddress"}
        techs = _detect_injection_techniques(apis)
        names = [t.name for t in techs]
        assert "dll_injection" in names

    def test_apc_injection(self):
        apis = {"QueueUserAPC", "OpenThread", "VirtualAllocEx", "WriteProcessMemory"}
        techs = _detect_injection_techniques(apis)
        names = [t.name for t in techs]
        assert "apc_injection" in names

    def test_map_view_injection(self):
        apis = {"NtCreateSection", "NtMapViewOfSection", "NtUnmapViewOfSection"}
        techs = _detect_injection_techniques(apis)
        names = [t.name for t in techs]
        assert "map_view_injection" in names

    def test_thread_hijack(self):
        apis = {"SuspendThread", "SetThreadContext", "GetThreadContext", "ResumeThread"}
        techs = _detect_injection_techniques(apis)
        names = [t.name for t in techs]
        assert "thread_hijack" in names


# ═══════════════════════════════════════════════════════════════════════════
# TestAnalyzeSections
# ═══════════════════════════════════════════════════════════════════════════

class TestAnalyzeSections:
    def test_normal_sections_no_findings(self):
        """Read+Execute code section → not suspicious."""
        pe = _make_pe(sections=[
            _make_section(".text", characteristics=IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_CNT_CODE),
            _make_section(".data", characteristics=IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE | IMAGE_SCN_CNT_INITIALIZED_DATA),
        ])
        result = _analyze_sections(pe)
        assert len(result) == 0

    def test_rwx_section(self):
        """RWX section is flagged."""
        pe = _make_pe(sections=[
            _make_section(".rwx", characteristics=IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE | IMAGE_SCN_MEM_EXECUTE),
        ])
        result = _analyze_sections(pe)
        assert len(result) == 1
        assert result[0].is_rwx is True
        assert result[0].flags == "RWX"

    def test_writable_code(self):
        """Code section with WRITE flag → writable code."""
        pe = _make_pe(sections=[
            _make_section(".text",
                          characteristics=IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE | IMAGE_SCN_CNT_CODE),
        ])
        result = _analyze_sections(pe)
        assert len(result) == 1
        assert result[0].is_writable_code is True

    def test_executable_data(self):
        """Data section with EXECUTE flag (no CODE flag) → executable data."""
        pe = _make_pe(sections=[
            _make_section(".edata",
                          characteristics=IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_CNT_INITIALIZED_DATA),
        ])
        result = _analyze_sections(pe)
        assert len(result) == 1
        assert result[0].is_executable_data is True

    def test_entropy_computed(self):
        """Shannon entropy is calculated for suspicious sections."""
        data = bytes(range(256)) * 4  # high entropy
        pe = _make_pe(sections=[
            _make_section(".rwx",
                          characteristics=IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE | IMAGE_SCN_MEM_EXECUTE,
                          data=data),
        ])
        result = _analyze_sections(pe)
        assert result[0].entropy > 7.0

    def test_mixed_sections(self):
        """Only suspicious sections are returned."""
        pe = _make_pe(sections=[
            _make_section(".text", characteristics=IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_CNT_CODE),
            _make_section(".rdata", characteristics=IMAGE_SCN_MEM_READ | IMAGE_SCN_CNT_INITIALIZED_DATA),
            _make_section(".sus", characteristics=IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE | IMAGE_SCN_MEM_EXECUTE),
        ])
        result = _analyze_sections(pe)
        assert len(result) == 1
        assert result[0].name == ".sus"


# ═══════════════════════════════════════════════════════════════════════════
# TestAnalyzeEntryPoint
# ═══════════════════════════════════════════════════════════════════════════

class TestAnalyzeEntryPoint:
    def test_ep_zero_returns_none(self):
        pe = _make_pe(sections=[_make_section()], ep_rva=0)
        assert _analyze_entry_point(pe) is None

    def test_no_sections_returns_none(self):
        pe = _make_pe(sections=[], ep_rva=0x1000)
        assert _analyze_entry_point(pe) is None

    def test_normal_ep_returns_none(self):
        """EP in first read-only code section → no anomaly."""
        pe = _make_pe(sections=[
            _make_section(".text", va=0x1000, vsize=0x2000,
                          characteristics=IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_CNT_CODE),
        ], ep_rva=0x1000)
        assert _analyze_entry_point(pe) is None

    def test_ep_outside_all_sections(self):
        pe = _make_pe(sections=[
            _make_section(".text", va=0x1000, vsize=0x1000),
        ], ep_rva=0xFFFF)
        result = _analyze_entry_point(pe)
        assert result is not None
        assert result.is_outside_code is True
        assert "outside" in result.description.lower()

    def test_ep_in_writable_section(self):
        pe = _make_pe(sections=[
            _make_section(".text", va=0x1000, vsize=0x2000,
                          characteristics=IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE | IMAGE_SCN_MEM_EXECUTE),
        ], ep_rva=0x1000)
        result = _analyze_entry_point(pe)
        assert result is not None
        assert result.is_writable is True

    def test_ep_in_last_section(self):
        """EP in last section with 2+ sections → common in packed binaries."""
        pe = _make_pe(sections=[
            _make_section(".text", va=0x1000, vsize=0x1000,
                          characteristics=IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_EXECUTE),
            _make_section(".upx2", va=0x3000, vsize=0x2000,
                          characteristics=IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE | IMAGE_SCN_MEM_EXECUTE),
        ], ep_rva=0x3000)
        result = _analyze_entry_point(pe)
        assert result is not None
        assert result.is_last_section is True
        assert result.is_writable is True

    def test_ep_in_last_section_single_section(self):
        """EP in only section → is_last_section should be False (single section doesn't count)."""
        pe = _make_pe(sections=[
            _make_section(".text", va=0x1000, vsize=0x2000,
                          characteristics=IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE),
        ], ep_rva=0x1000)
        result = _analyze_entry_point(pe)
        assert result is not None
        assert result.is_last_section is False
        assert result.is_writable is True


# ═══════════════════════════════════════════════════════════════════════════
# TestComputeRisk
# ═══════════════════════════════════════════════════════════════════════════

class TestComputeRisk:
    def test_empty_result_zero(self):
        r = MemoryAnalysisResult()
        score, sev = _compute_risk(r)
        assert score == 0
        assert sev == "none"

    def test_critical_technique_high_confidence(self):
        t = InjectionTechnique(name="classic", description="d", confidence=0.8, severity="critical")
        r = MemoryAnalysisResult(injection_techniques=[t])
        score, sev = _compute_risk(r)
        assert score >= 30
        assert sev == "critical"

    def test_medium_technique_lower_score(self):
        t = InjectionTechnique(name="guard", description="d", confidence=0.8, severity="medium")
        r = MemoryAnalysisResult(injection_techniques=[t])
        score, sev = _compute_risk(r)
        assert score >= 10
        assert score < 30

    def test_technique_low_confidence(self):
        t = InjectionTechnique(name="classic", description="d", confidence=0.55, severity="critical")
        r = MemoryAnalysisResult(injection_techniques=[t])
        score, sev = _compute_risk(r)
        assert score == 15  # critical at 0.5-0.7 confidence

    def test_rwx_sections(self):
        r = MemoryAnalysisResult(
            rwx_section_count=2,
            suspicious_sections=[
                SectionPermission(name=".s1", is_rwx=True),
                SectionPermission(name=".s2", is_rwx=True),
            ]
        )
        score, sev = _compute_risk(r)
        assert score == 30  # 2 * 15
        assert sev == "high"

    def test_writable_code_sections(self):
        r = MemoryAnalysisResult(
            suspicious_sections=[
                SectionPermission(name=".text", is_writable_code=True),
            ]
        )
        score, sev = _compute_risk(r)
        assert score == 8
        assert sev == "medium"

    def test_suspicious_apis(self):
        r = MemoryAnalysisResult(suspicious_api_count=5)
        score, sev = _compute_risk(r)
        assert score == 15  # 5 * 3 = 15

    def test_suspicious_apis_capped(self):
        """API score capped at 20."""
        r = MemoryAnalysisResult(suspicious_api_count=10)
        score, sev = _compute_risk(r)
        assert score == 20

    def test_dynamic_resolve(self):
        r = MemoryAnalysisResult(has_dynamic_resolve=True)
        score, sev = _compute_risk(r)
        assert score == 5

    def test_ep_outside_code(self):
        ep = EntryPointAnomaly(is_outside_code=True)
        r = MemoryAnalysisResult(entry_point=ep)
        score, sev = _compute_risk(r)
        assert score == 15
        assert sev == "high"

    def test_ep_writable_and_last(self):
        ep = EntryPointAnomaly(is_writable=True, is_last_section=True)
        r = MemoryAnalysisResult(entry_point=ep)
        score, sev = _compute_risk(r)
        assert score == 15  # 10 + 5

    def test_capped_at_100(self):
        """Score never exceeds 100."""
        t1 = InjectionTechnique(name="a", description="d", confidence=0.9, severity="critical")
        t2 = InjectionTechnique(name="b", description="d", confidence=0.9, severity="critical")
        t3 = InjectionTechnique(name="c", description="d", confidence=0.9, severity="critical")
        t4 = InjectionTechnique(name="d", description="d", confidence=0.9, severity="critical")
        ep = EntryPointAnomaly(is_outside_code=True, is_writable=True, is_last_section=True)
        r = MemoryAnalysisResult(
            injection_techniques=[t1, t2, t3, t4],
            rwx_section_count=3,
            suspicious_sections=[SectionPermission(name=".s", is_rwx=True)] * 3,
            suspicious_api_count=10,
            has_dynamic_resolve=True,
            entry_point=ep,
        )
        score, sev = _compute_risk(r)
        assert score == 100

    def test_combined_score(self):
        """Multiple signals combine correctly."""
        t = InjectionTechnique(name="test", description="d", confidence=0.8, severity="high")
        ep = EntryPointAnomaly(is_writable=True)
        r = MemoryAnalysisResult(
            injection_techniques=[t],
            rwx_section_count=1,
            suspicious_sections=[SectionPermission(name=".s", is_rwx=True)],
            suspicious_api_count=2,
            has_dynamic_resolve=True,
            entry_point=ep,
        )
        score, sev = _compute_risk(r)
        # 20 (high@0.8) + 15 (1 RWX) + 6 (2 APIs*3) + 5 (dynamic) + 10 (ep writable) = 56
        assert score == 56


# ═══════════════════════════════════════════════════════════════════════════
# TestBuildSummary
# ═══════════════════════════════════════════════════════════════════════════

class TestBuildSummary:
    def test_no_findings(self):
        r = MemoryAnalysisResult()
        assert _build_summary(r) == "No memory-related threats detected"

    def test_injection_techniques(self):
        t = InjectionTechnique(name="classic_injection", description="d")
        r = MemoryAnalysisResult(
            injection_techniques=[t],
            total_techniques_detected=1,
        )
        summary = _build_summary(r)
        assert "1 injection technique(s)" in summary
        assert "classic injection" in summary  # underscore replaced

    def test_rwx_sections(self):
        r = MemoryAnalysisResult(rwx_section_count=2)
        summary = _build_summary(r)
        assert "2 RWX section(s)" in summary

    def test_section_anomalies(self):
        r = MemoryAnalysisResult(
            suspicious_sections=[
                SectionPermission(name=".text", is_writable_code=True),
                SectionPermission(name=".edata", is_executable_data=True),
            ]
        )
        summary = _build_summary(r)
        assert "writable code" in summary
        assert "executable data" in summary

    def test_entry_point(self):
        ep = EntryPointAnomaly(description="EP in writable section")
        r = MemoryAnalysisResult(entry_point=ep)
        summary = _build_summary(r)
        assert "EP anomaly" in summary

    def test_dynamic_resolve(self):
        r = MemoryAnalysisResult(has_dynamic_resolve=True)
        summary = _build_summary(r)
        assert "Dynamic API resolution" in summary

    def test_suspicious_apis_without_techniques(self):
        r = MemoryAnalysisResult(suspicious_api_count=3)
        summary = _build_summary(r)
        assert "3 suspicious memory API(s)" in summary

    def test_suspicious_apis_hidden_when_techniques_present(self):
        """When techniques are detected, don't also list raw API count."""
        t = InjectionTechnique(name="test", description="d")
        r = MemoryAnalysisResult(
            injection_techniques=[t],
            total_techniques_detected=1,
            suspicious_api_count=5,
        )
        summary = _build_summary(r)
        assert "suspicious memory API" not in summary

    def test_max_three_techniques_in_summary(self):
        techs = [InjectionTechnique(name=f"tech_{i}", description="d") for i in range(5)]
        r = MemoryAnalysisResult(
            injection_techniques=techs,
            total_techniques_detected=5,
        )
        summary = _build_summary(r)
        assert "5 injection technique(s)" in summary
        # only first 3 names shown
        assert "tech 0" in summary
        assert "tech 2" in summary


# ═══════════════════════════════════════════════════════════════════════════
# TestAnalyzeMemory (integration with mocked pefile)
# ═══════════════════════════════════════════════════════════════════════════

class TestAnalyzeMemory:
    @patch("hashguard.memory_analyzer.HAS_PEFILE", False)
    def test_no_pefile(self):
        result = analyze_memory("fake.exe")
        assert result.summary == "pefile not available"
        assert result.risk_score == 0

    @patch("hashguard.memory_analyzer.HAS_PEFILE", True)
    @patch("hashguard.memory_analyzer.pefile")
    def test_invalid_pe(self, mock_pefile):
        mock_pefile.PE.side_effect = Exception("Invalid PE")
        result = analyze_memory("not_a_pe.txt")
        assert result.summary == "Not a valid PE file"

    @patch("hashguard.memory_analyzer.HAS_PEFILE", True)
    @patch("hashguard.memory_analyzer.pefile")
    def test_clean_pe(self, mock_pefile):
        """PE with no suspicious imports or sections → clean result."""
        pe = _make_pe(
            sections=[
                _make_section(".text", va=0x1000, vsize=0x2000,
                              characteristics=IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_CNT_CODE),
                _make_section(".data", va=0x3000, vsize=0x1000,
                              characteristics=IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE | IMAGE_SCN_CNT_INITIALIZED_DATA),
            ],
            imports=[_make_import_entry(["CreateFileA", "ReadFile", "CloseHandle"])],
            ep_rva=0x1000,
        )
        mock_pefile.PE.return_value = pe
        result = analyze_memory("clean.exe")
        assert result.risk_score == 0
        assert result.total_techniques_detected == 0
        assert result.summary == "No memory-related threats detected"
        pe.close.assert_called_once()

    @patch("hashguard.memory_analyzer.HAS_PEFILE", True)
    @patch("hashguard.memory_analyzer.pefile")
    def test_injection_detection(self, mock_pefile):
        """PE with classic injection APIs → detected."""
        pe = _make_pe(
            sections=[_make_section(".text", va=0x1000, vsize=0x2000,
                                    characteristics=IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_CNT_CODE)],
            imports=[_make_import_entry([
                "VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread", "OpenProcess",
            ])],
            ep_rva=0x1000,
        )
        mock_pefile.PE.return_value = pe
        result = analyze_memory("injector.exe")
        assert result.total_techniques_detected >= 1
        assert result.risk_score > 0
        assert result.max_severity == "critical"
        assert any(t.name == "classic_injection" for t in result.injection_techniques)

    @patch("hashguard.memory_analyzer.HAS_PEFILE", True)
    @patch("hashguard.memory_analyzer.pefile")
    def test_rwx_section_detection(self, mock_pefile):
        """PE with RWX section → flagged."""
        pe = _make_pe(
            sections=[
                _make_section(".text", va=0x1000, vsize=0x2000,
                              characteristics=IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_CNT_CODE),
                _make_section(".packed", va=0x3000, vsize=0x1000,
                              characteristics=IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE | IMAGE_SCN_MEM_EXECUTE),
            ],
            imports=[_make_import_entry(["CreateFileA"])],
            ep_rva=0x1000,
        )
        mock_pefile.PE.return_value = pe
        result = analyze_memory("packed.exe")
        assert result.rwx_section_count == 1
        assert result.risk_score >= 15

    @patch("hashguard.memory_analyzer.HAS_PEFILE", True)
    @patch("hashguard.memory_analyzer.pefile")
    def test_dynamic_resolve_detection(self, mock_pefile):
        pe = _make_pe(
            sections=[_make_section()],
            imports=[_make_import_entry(["GetProcAddress", "LdrLoadDll"])],
            ep_rva=0x1000,
        )
        mock_pefile.PE.return_value = pe
        result = analyze_memory("resolver.exe")
        assert result.has_dynamic_resolve is True
        assert "GetProcAddress" in result.dynamic_resolve_apis

    @patch("hashguard.memory_analyzer.HAS_PEFILE", True)
    @patch("hashguard.memory_analyzer.pefile")
    def test_ep_anomaly_detection(self, mock_pefile):
        """EP outside all sections → detected."""
        pe = _make_pe(
            sections=[
                _make_section(".text", va=0x1000, vsize=0x1000,
                              characteristics=IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_CNT_CODE),
            ],
            imports=[_make_import_entry(["ExitProcess"])],
            ep_rva=0xFFFF,  # outside .text
        )
        mock_pefile.PE.return_value = pe
        result = analyze_memory("weird_ep.exe")
        assert result.entry_point is not None
        assert result.entry_point.is_outside_code is True
        assert result.risk_score >= 15

    @patch("hashguard.memory_analyzer.HAS_PEFILE", True)
    @patch("hashguard.memory_analyzer.pefile")
    def test_full_malicious_pe(self, mock_pefile):
        """PE with injection APIs + RWX section + dynamic resolve → high score."""
        pe = _make_pe(
            sections=[
                _make_section(".text", va=0x1000, vsize=0x2000,
                              characteristics=IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_CNT_CODE),
                _make_section(".packed", va=0x4000, vsize=0x3000,
                              characteristics=IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE | IMAGE_SCN_MEM_EXECUTE),
            ],
            imports=[_make_import_entry([
                "VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread",
                "OpenProcess", "GetProcAddress", "NtUnmapViewOfSection",
            ])],
            ep_rva=0x4000,  # in last section (packed)
        )
        mock_pefile.PE.return_value = pe
        result = analyze_memory("evil.exe")
        assert result.risk_score >= 50
        assert result.max_severity == "critical"
        assert result.total_techniques_detected >= 1
        assert result.rwx_section_count == 1
        assert result.has_dynamic_resolve is True
        d = result.to_dict()
        assert "entry_point" in d

    @patch("hashguard.memory_analyzer.HAS_PEFILE", True)
    @patch("hashguard.memory_analyzer.pefile")
    def test_pe_close_called_on_error(self, mock_pefile):
        """PE.close() is called even if analysis throws."""
        pe = _make_pe(sections=[], imports=[], ep_rva=0x1000)
        # Make _get_imported_apis crash
        type(pe).DIRECTORY_ENTRY_IMPORT = PropertyMock(side_effect=RuntimeError("boom"))
        mock_pefile.PE.return_value = pe
        result = analyze_memory("crash.exe")
        pe.close.assert_called_once()
        assert "error" in result.summary.lower() or result.summary != ""

    @patch("hashguard.memory_analyzer.HAS_PEFILE", True)
    @patch("hashguard.memory_analyzer.pefile")
    def test_to_dict_serializable(self, mock_pefile):
        """Ensure to_dict() output is JSON-serializable."""
        import json

        pe = _make_pe(
            sections=[
                _make_section(".text", va=0x1000, vsize=0x2000,
                              characteristics=IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE | IMAGE_SCN_MEM_EXECUTE),
            ],
            imports=[_make_import_entry([
                "VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread",
            ])],
            ep_rva=0x1000,
        )
        mock_pefile.PE.return_value = pe
        result = analyze_memory("test.exe")
        d = result.to_dict()
        serialized = json.dumps(d)
        assert isinstance(serialized, str)
        parsed = json.loads(serialized)
        assert parsed["risk_score"] == result.risk_score

    @patch("hashguard.memory_analyzer.HAS_PEFILE", True)
    @patch("hashguard.memory_analyzer.pefile")
    def test_suspicious_apis_counted(self, mock_pefile):
        pe = _make_pe(
            sections=[_make_section()],
            imports=[_make_import_entry([
                "NtWriteVirtualMemory", "NtReadVirtualMemory",
                "NtAllocateVirtualMemory", "CreateFileA",
            ])],
            ep_rva=0x1000,
        )
        mock_pefile.PE.return_value = pe
        result = analyze_memory("sus_apis.exe")
        assert result.suspicious_api_count == 3
        assert "NtWriteVirtualMemory" in result.suspicious_apis_found


# ═══════════════════════════════════════════════════════════════════════════
# TestInjectionTechniqueDefinitions
# ═══════════════════════════════════════════════════════════════════════════

class TestInjectionTechniqueDefinitions:
    """Validate integrity of INJECTION_TECHNIQUES dictionary."""

    def test_all_have_required_keys(self):
        for name, defn in INJECTION_TECHNIQUES.items():
            assert "description" in defn, f"{name} missing description"
            assert "required_apis" in defn, f"{name} missing required_apis"
            assert "mitre" in defn, f"{name} missing mitre"
            assert "severity" in defn, f"{name} missing severity"

    def test_all_severities_valid(self):
        valid = {"low", "medium", "high", "critical"}
        for name, defn in INJECTION_TECHNIQUES.items():
            assert defn["severity"] in valid, f"{name} has invalid severity: {defn['severity']}"

    def test_all_required_apis_are_sets(self):
        for name, defn in INJECTION_TECHNIQUES.items():
            assert isinstance(defn["required_apis"], set), f"{name} required_apis should be a set"

    def test_mitre_format(self):
        for name, defn in INJECTION_TECHNIQUES.items():
            assert defn["mitre"].startswith("T"), f"{name} mitre should start with T"


# ═══════════════════════════════════════════════════════════════════════════
# TestConstants
# ═══════════════════════════════════════════════════════════════════════════

class TestConstants:
    def test_suspicious_apis_is_set(self):
        assert isinstance(SUSPICIOUS_MEMORY_APIS, set)
        assert len(SUSPICIOUS_MEMORY_APIS) > 10

    def test_dynamic_resolve_apis_is_set(self):
        assert isinstance(DYNAMIC_RESOLVE_APIS, set)
        assert "GetProcAddress" in DYNAMIC_RESOLVE_APIS
