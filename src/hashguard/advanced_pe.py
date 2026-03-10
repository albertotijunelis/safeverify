"""Advanced PE analysis for HashGuard v2.

Extends basic PE analysis with:
- TLS callback detection
- Anti-debug technique detection
- Anti-VM technique detection
- Suspicious section flag analysis
- Overlay analysis (appended data)
- Import hashing (imphash) for sample grouping
- Rich header analysis
"""

import math
import struct
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional

from hashguard.logger import get_logger

logger = get_logger(__name__)

try:
    import pefile

    HAS_PEFILE = True
except ImportError:
    HAS_PEFILE = False

try:
    import lief

    HAS_LIEF = True
except ImportError:
    HAS_LIEF = False


@dataclass
class TLSInfo:
    has_tls: bool = False
    callback_count: int = 0
    callback_addresses: List[str] = field(default_factory=list)
    warning: str = ""


@dataclass
class AntiAnalysisInfo:
    anti_debug_techniques: List[Dict[str, str]] = field(default_factory=list)
    anti_vm_techniques: List[Dict[str, str]] = field(default_factory=list)
    anti_sandbox_techniques: List[Dict[str, str]] = field(default_factory=list)
    total_detections: int = 0


@dataclass
class OverlayInfo:
    has_overlay: bool = False
    offset: int = 0
    size: int = 0
    entropy: float = 0.0
    percentage: float = 0.0  # % of file that is overlay


@dataclass
class SectionAnomaly:
    name: str
    anomaly: str
    severity: str  # low, medium, high


@dataclass
class AdvancedPEResult:
    imphash: str = ""
    tls: Optional[TLSInfo] = None
    anti_analysis: Optional[AntiAnalysisInfo] = None
    overlay: Optional[OverlayInfo] = None
    section_anomalies: List[SectionAnomaly] = field(default_factory=list)
    rich_header_hash: str = ""
    is_dotnet: bool = False
    has_debug_info: bool = False
    linker_version: str = ""

    def to_dict(self) -> dict:
        d = {"imphash": self.imphash}
        if self.tls:
            d["tls"] = {
                "has_tls": self.tls.has_tls,
                "callback_count": self.tls.callback_count,
                "callback_addresses": self.tls.callback_addresses,
                "warning": self.tls.warning,
            }
        if self.anti_analysis:
            d["anti_analysis"] = {
                "anti_debug": self.anti_analysis.anti_debug_techniques,
                "anti_vm": self.anti_analysis.anti_vm_techniques,
                "anti_sandbox": self.anti_analysis.anti_sandbox_techniques,
                "total": self.anti_analysis.total_detections,
            }
        if self.overlay:
            d["overlay"] = {
                "has_overlay": self.overlay.has_overlay,
                "offset": self.overlay.offset,
                "size": self.overlay.size,
                "entropy": self.overlay.entropy,
                "percentage": round(self.overlay.percentage, 2),
            }
        if self.section_anomalies:
            d["section_anomalies"] = [
                {"name": a.name, "anomaly": a.anomaly, "severity": a.severity}
                for a in self.section_anomalies
            ]
        d["rich_header_hash"] = self.rich_header_hash
        d["is_dotnet"] = self.is_dotnet
        d["has_debug_info"] = self.has_debug_info
        d["linker_version"] = self.linker_version
        return d


# ── Anti-debug API patterns ──────────────────────────────────────────────────

ANTI_DEBUG_APIS = {
    "IsDebuggerPresent": ("Checks PEB.BeingDebugged flag", "high"),
    "CheckRemoteDebuggerPresent": ("Checks if remote debugger attached", "high"),
    "NtQueryInformationProcess": ("Query process debug info via NT API", "high"),
    "NtSetInformationThread": ("Can hide thread from debugger (ThreadHideFromDebugger)", "high"),
    "OutputDebugStringA": ("Detect debugger via debug string side-effect", "medium"),
    "OutputDebugStringW": ("Detect debugger via debug string side-effect", "medium"),
    "QueryPerformanceCounter": ("Timing-based anti-debug", "low"),
    "GetTickCount": ("Timing-based anti-debug", "low"),
    "GetTickCount64": ("Timing-based anti-debug", "low"),
    "RtlQueryPerformanceCounter": ("Timing-based anti-debug", "low"),
    "NtQuerySystemInformation": ("System information anti-debug", "medium"),
    "CloseHandle": ("Exception-based debugger detection (invalid handle)", "low"),
    "NtClose": ("Exception-based debugger detection", "low"),
    "FindWindowA": ("Detect debugger windows by class name", "medium"),
    "FindWindowW": ("Detect debugger windows by class name", "medium"),
    "BlockInput": ("Block user input during execution", "high"),
}

ANTI_VM_STRINGS = [
    (b"VMware", "VMware detection string"),
    (b"VirtualBox", "VirtualBox detection string"),
    (b"VBOX", "VirtualBox detection string"),
    (b"QEMU", "QEMU detection string"),
    (b"Hyper-V", "Hyper-V detection string"),
    (b"Xen", "Xen detection string"),
    (b"vmtoolsd", "VMware Tools process"),
    (b"vboxservice", "VirtualBox service process"),
    (b"vmwaretray", "VMware tray process"),
    (b"VBoxTray", "VirtualBox tray process"),
    (b"SbieDll.dll", "Sandboxie DLL"),
    (b"sbiedll", "Sandboxie DLL"),
    (b"wine_get_unix_file_name", "Wine detection"),
    (b"\\REGISTRY\\MACHINE\\SYSTEM\\ControlSet001\\Services\\VBoxGuest", "VBox registry check"),
    (b"HARDWARE\\DEVICEMAP\\Scsi\\Scsi Port 0", "Hardware enumeration for VM"),
    (b"HARDWARE\\Description\\System\\SystemBiosVersion", "BIOS check for VM"),
    (b"red_pill", "Red Pill VM detection"),
    (b"CPUID", "CPUID-based VM detection"),
]

ANTI_SANDBOX_STRINGS = [
    (b"SbieDll.dll", "Sandboxie detection"),
    (b"dbghelp.dll", "Debug helper detection"),
    (b"api_log.dll", "API monitoring detection"),
    (b"dir_watch.dll", "Directory monitoring detection"),
    (b"pstorec.dll", "Protected storage detection"),
    (b"vmcheck.dll", "VM check DLL"),
    (b"wpespy.dll", "WPE Pro detection"),
    (b"\\sample", "Sample filename detection"),
    (b"\\sandbox", "Sandbox path detection"),
    (b"\\virus", "Virus path detection"),
    (b"Sleep", "Sleep-based sandbox evasion (with large values)"),
]

DEBUGGER_WINDOW_NAMES = [
    b"OllyDbg",
    b"x64dbg",
    b"x32dbg",
    b"IDA",
    b"Immunity",
    b"WinDbg",
    b"Ghidra",
    b"Process Monitor",
    b"Process Explorer",
    b"Wireshark",
    b"Fiddler",
    b"API Monitor",
]


def _entropy(data: bytes) -> float:
    if not data:
        return 0.0
    freq = [0] * 256
    for b in data:
        freq[b] += 1
    length = len(data)
    ent = 0.0
    for count in freq:
        if count:
            p = count / length
            ent -= p * math.log2(p)
    return round(ent, 4)


def analyze_advanced_pe(file_path: str) -> AdvancedPEResult:
    """Perform advanced PE analysis on a file."""
    result = AdvancedPEResult()
    path = Path(file_path)

    if not path.exists() or not HAS_PEFILE:
        return result

    try:
        pe = pefile.PE(file_path)
    except Exception as e:
        logger.debug(f"Cannot parse PE: {e}")
        return result

    try:
        # ── Imphash ──────────────────────────────────────────────────────
        result.imphash = pe.get_imphash() or ""

        # ── Linker version ───────────────────────────────────────────────
        major = pe.OPTIONAL_HEADER.MajorLinkerVersion
        minor = pe.OPTIONAL_HEADER.MinorLinkerVersion
        result.linker_version = f"{major}.{minor}"

        # ── .NET detection ───────────────────────────────────────────────
        if hasattr(pe, "DIRECTORY_ENTRY_COM_DESCRIPTOR"):
            result.is_dotnet = True
        else:
            for entry in pe.OPTIONAL_HEADER.DATA_DIRECTORY:
                if entry.name == "IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR" and entry.VirtualAddress:
                    result.is_dotnet = True
                    break

        # ── Debug info ───────────────────────────────────────────────────
        if hasattr(pe, "DIRECTORY_ENTRY_DEBUG"):
            result.has_debug_info = True

        # ── Rich header hash ─────────────────────────────────────────────
        try:
            rich = pe.parse_rich_header()
            if rich and rich.get("values"):
                import hashlib

                raw = b""
                for val in rich["values"]:
                    raw += struct.pack("<I", val)
                result.rich_header_hash = hashlib.md5(raw).hexdigest()
        except Exception:
            pass

        # ── TLS callbacks ────────────────────────────────────────────────
        result.tls = _analyze_tls(pe)

        # ── Anti-analysis techniques ─────────────────────────────────────
        result.anti_analysis = _analyze_anti_analysis(pe, path)

        # ── Overlay analysis ─────────────────────────────────────────────
        result.overlay = _analyze_overlay(pe, path)

        # ── Section anomalies ────────────────────────────────────────────
        result.section_anomalies = _analyze_sections(pe)

    except Exception as e:
        logger.debug(f"Advanced PE analysis error: {e}")
    finally:
        pe.close()

    return result


def _analyze_tls(pe) -> TLSInfo:
    """Detect TLS callbacks."""
    info = TLSInfo()
    try:
        if not hasattr(pe, "DIRECTORY_ENTRY_TLS"):
            return info

        tls = pe.DIRECTORY_ENTRY_TLS.struct
        info.has_tls = True

        callback_rva = tls.AddressOfCallBacks
        if callback_rva:
            image_base = pe.OPTIONAL_HEADER.ImageBase
            callback_offset = pe.get_offset_from_rva(callback_rva - image_base)

            ptr_size = 8 if pe.PE_TYPE == pefile.OPTIONAL_HEADER_MAGIC_PE_PLUS else 4
            fmt = "<Q" if ptr_size == 8 else "<I"

            for i in range(16):  # Max 16 callbacks
                offset = callback_offset + i * ptr_size
                if offset + ptr_size > len(pe.__data__):
                    break
                addr = struct.unpack(fmt, pe.__data__[offset : offset + ptr_size])[0]
                if addr == 0:
                    break
                info.callback_addresses.append(f"0x{addr:X}")
                info.callback_count += 1

        if info.callback_count > 0:
            info.warning = f"TLS callbacks detected ({info.callback_count}) — code executes before main entry point"

    except Exception:
        pass
    return info


def _analyze_anti_analysis(pe, path: Path) -> AntiAnalysisInfo:
    """Detect anti-debug, anti-VM, and anti-sandbox techniques."""
    info = AntiAnalysisInfo()

    # Gather all imports
    imports = set()
    try:
        pe.parse_data_directories(
            directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"]]
        )
        if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                for imp in entry.imports:
                    if imp.name:
                        imports.add(imp.name.decode("utf-8", errors="ignore"))
    except Exception:
        pass

    # Check anti-debug APIs
    for api_name, (description, severity) in ANTI_DEBUG_APIS.items():
        if api_name in imports:
            info.anti_debug_techniques.append(
                {
                    "technique": api_name,
                    "description": description,
                    "severity": severity,
                }
            )

    # Read file content for string-based detection
    try:
        content = path.read_bytes()[: 10 * 1024 * 1024]
        content_lower = content.lower()
    except OSError:
        content_lower = b""

    # Check anti-VM strings
    for pattern, description in ANTI_VM_STRINGS:
        if pattern.lower() in content_lower:
            info.anti_vm_techniques.append(
                {
                    "technique": pattern.decode("utf-8", errors="ignore"),
                    "description": description,
                }
            )

    # Check anti-sandbox strings
    for pattern, description in ANTI_SANDBOX_STRINGS:
        if pattern.lower() in content_lower:
            info.anti_sandbox_techniques.append(
                {
                    "technique": pattern.decode("utf-8", errors="ignore"),
                    "description": description,
                }
            )

    # Check for debugger window names
    for name in DEBUGGER_WINDOW_NAMES:
        if name.lower() in content_lower:
            info.anti_debug_techniques.append(
                {
                    "technique": f"FindWindow({name.decode()})",
                    "description": f"Searches for {name.decode()} window",
                    "severity": "medium",
                }
            )

    info.total_detections = (
        len(info.anti_debug_techniques)
        + len(info.anti_vm_techniques)
        + len(info.anti_sandbox_techniques)
    )
    return info


def _analyze_overlay(pe, path: Path) -> OverlayInfo:
    """Analyze data appended after the PE structure (overlay)."""
    info = OverlayInfo()
    try:
        overlay_offset = pe.get_overlay_data_start_offset()
        if overlay_offset is None:
            return info

        file_size = path.stat().st_size
        overlay_size = file_size - overlay_offset

        if overlay_size <= 0:
            return info

        info.has_overlay = True
        info.offset = overlay_offset
        info.size = overlay_size
        info.percentage = (overlay_size / file_size) * 100

        # Calculate overlay entropy
        with open(path, "rb") as f:
            f.seek(overlay_offset)
            data = f.read(min(overlay_size, 2 * 1024 * 1024))  # Max 2MB for entropy
            info.entropy = _entropy(data)

    except Exception:
        pass
    return info


def _analyze_sections(pe) -> List[SectionAnomaly]:
    """Detect suspicious section characteristics."""
    anomalies = []

    for section in pe.sections:
        name = section.Name.decode("utf-8", errors="ignore").strip("\x00")

        # Writable + Executable = suspicious
        chars = section.Characteristics
        writable = bool(chars & 0x80000000)  # IMAGE_SCN_MEM_WRITE
        executable = bool(chars & 0x20000000)  # IMAGE_SCN_MEM_EXECUTE
        readable = bool(chars & 0x40000000)  # IMAGE_SCN_MEM_READ

        if writable and executable:
            anomalies.append(
                SectionAnomaly(
                    name=name,
                    anomaly="Section is both writable and executable (W+X)",
                    severity="high",
                )
            )

        # High entropy section
        try:
            entropy = section.get_entropy()
            if entropy > 7.2:
                anomalies.append(
                    SectionAnomaly(
                        name=name,
                        anomaly=f"Very high entropy ({entropy:.2f}) — likely packed/encrypted",
                        severity="high",
                    )
                )
            elif entropy > 6.8:
                anomalies.append(
                    SectionAnomaly(
                        name=name,
                        anomaly=f"High entropy ({entropy:.2f}) — possibly packed",
                        severity="medium",
                    )
                )
        except Exception:
            pass

        # Empty section (virtual size much larger than raw size)
        if section.SizeOfRawData == 0 and section.Misc_VirtualSize > 0:
            anomalies.append(
                SectionAnomaly(
                    name=name,
                    anomaly="Section has no raw data but non-zero virtual size (runtime unpacking?)",
                    severity="medium",
                )
            )

        # Raw size much larger than virtual size
        if section.SizeOfRawData > 0 and section.Misc_VirtualSize > 0:
            ratio = section.SizeOfRawData / section.Misc_VirtualSize
            if ratio > 10:
                anomalies.append(
                    SectionAnomaly(
                        name=name,
                        anomaly=f"Raw size is {ratio:.0f}x larger than virtual size (hidden data?)",
                        severity="medium",
                    )
                )

        # Non-standard section names
        standard_names = {
            ".text",
            ".rdata",
            ".data",
            ".rsrc",
            ".reloc",
            ".pdata",
            ".idata",
            ".edata",
            ".tls",
            ".bss",
            ".CRT",
            ".debug",
        }
        if name and name not in standard_names and not name.startswith("."):
            anomalies.append(
                SectionAnomaly(
                    name=name,
                    anomaly="Non-standard section name (possible packer/protector)",
                    severity="low",
                )
            )

    return anomalies
