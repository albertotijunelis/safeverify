"""HashGuard Capability Detector — CAPA-inspired behavioral capability detection.

Detects what malware DOES, not just if it's suspicious:
- Ransomware behavior (crypto APIs, file encryption, shadow copy deletion)
- Keyloggers (key capture hooks, clipboard monitoring)
- Reverse shells (socket + cmd.exe patterns)
- Credential stealing (LSASS access, browser credential paths)
- Persistence mechanisms (registry run keys, scheduled tasks, services)
- Evasion techniques (anti-debug, anti-VM, process injection)
"""

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Set

from hashguard.logger import get_logger

logger = get_logger(__name__)

try:
    import pefile

    HAS_PEFILE = True
except ImportError:
    HAS_PEFILE = False


@dataclass
class Capability:
    name: str
    category: str
    confidence: float
    evidence: List[str] = field(default_factory=list)
    mitre_attack: str = ""
    severity: str = "medium"  # low, medium, high, critical


@dataclass
class CapabilityReport:
    capabilities: List[Capability] = field(default_factory=list)
    total_detected: int = 0
    risk_categories: Dict[str, int] = field(default_factory=dict)
    max_severity: str = "low"

    def to_dict(self) -> dict:
        return {
            "capabilities": [
                {
                    "name": c.name,
                    "category": c.category,
                    "confidence": round(c.confidence, 2),
                    "evidence": c.evidence,
                    "mitre_attack": c.mitre_attack,
                    "severity": c.severity,
                }
                for c in self.capabilities
            ],
            "total_detected": self.total_detected,
            "risk_categories": self.risk_categories,
            "max_severity": self.max_severity,
        }


# ─── Detection rule definitions ─────────────────────────────────────────────

RANSOMWARE_INDICATORS = {
    "crypto_apis": {
        "imports": [
            "CryptEncrypt",
            "CryptDecrypt",
            "CryptGenKey",
            "CryptDeriveKey",
            "CryptAcquireContext",
            "CryptImportKey",
            "CryptExportKey",
            "BCryptEncrypt",
            "BCryptDecrypt",
            "BCryptGenerateSymmetricKey",
        ],
        "strings": [
            b"AES",
            b"RSA",
            b"CryptoAPI",
            b"BCrypt",
            b"CryptGenRandom",
            b"RijndaelManaged",
        ],
        "severity": "high",
        "mitre": "T1486",
    },
    "file_encryption": {
        "imports": ["FindFirstFileW", "FindNextFileW", "MoveFileW", "MoveFileExW", "DeleteFileW"],
        "strings": [
            b".encrypted",
            b".locked",
            b".crypto",
            b".crypt",
            b".locky",
            b".cerber",
            b".zepto",
            b".zzzzz",
            b"YOUR FILES HAVE BEEN ENCRYPTED",
            b"your files are encrypted",
            b"pay bitcoin",
            b"pay ransom",
            b"decrypt your files",
            b"restore your files",
            b"personal decryption",
            b"bitcoin wallet",
        ],
        "severity": "critical",
        "mitre": "T1486",
    },
    "shadow_copy_deletion": {
        "strings": [
            b"vssadmin delete shadows",
            b"vssadmin.exe delete shadows",
            b"wmic shadowcopy delete",
            b"bcdedit /set {default} recoveryenabled no",
            b"bcdedit /set {default} bootstatuspolicy ignoreallfailures",
            b"wbadmin delete catalog",
        ],
        "severity": "critical",
        "mitre": "T1490",
    },
}

KEYLOGGER_INDICATORS = {
    "key_capture": {
        "imports": [
            "GetAsyncKeyState",
            "GetKeyState",
            "GetKeyboardState",
            "SetWindowsHookExA",
            "SetWindowsHookExW",
            "MapVirtualKeyA",
            "MapVirtualKeyW",
        ],
        "strings": [
            b"keylog",
            b"keystroke",
            b"key_log",
            b"WH_KEYBOARD",
            b"WH_KEYBOARD_LL",
        ],
        "severity": "high",
        "mitre": "T1056.001",
    },
    "clipboard_monitor": {
        "imports": ["GetClipboardData", "OpenClipboard", "SetClipboardViewer"],
        "strings": [b"clipboard", b"paste"],
        "severity": "medium",
        "mitre": "T1115",
    },
    "screen_capture": {
        "imports": ["BitBlt", "GetDesktopWindow", "CreateCompatibleBitmap", "GetDC"],
        "strings": [b"screenshot", b"screen_capture", b"PrintScreen"],
        "severity": "high",
        "mitre": "T1113",
    },
}

REVERSE_SHELL_INDICATORS = {
    "network_shell": {
        "imports": [
            "WSAStartup",
            "socket",
            "connect",
            "send",
            "recv",
            "WSASocketA",
            "WSASocketW",
            "bind",
            "listen",
            "accept",
        ],
        "strings": [
            b"cmd.exe",
            b"powershell.exe",
            b"/bin/sh",
            b"/bin/bash",
            b"CreateProcess",
            b"ShellExecute",
        ],
        "combined": [
            (b"socket", b"connect", b"cmd"),
            (b"WSAStartup", b"CreateProcess"),
        ],
        "severity": "critical",
        "mitre": "T1059",
    },
    "c2_communication": {
        "imports": ["InternetOpenA", "InternetOpenW", "HttpOpenRequestA", "HttpSendRequestA"],
        "strings": [
            b"POST /",
            b"GET /",
            b"User-Agent:",
            b"Content-Type: application",
            b"beacon",
            b"/gate.php",
            b"/panel/",
            b"/command",
        ],
        "severity": "high",
        "mitre": "T1071",
    },
}

CREDENTIAL_STEALING_INDICATORS = {
    "lsass_access": {
        "imports": ["OpenProcess", "ReadProcessMemory", "MiniDumpWriteDump"],
        "strings": [
            b"lsass.exe",
            b"lsass",
            b"sekurlsa",
            b"mimikatz",
            b"wdigest",
            b"kerberos",
            b"MiniDumpWriteDump",
        ],
        "severity": "critical",
        "mitre": "T1003.001",
    },
    "browser_credentials": {
        "strings": [
            b"Login Data",
            b"Web Data",
            b"Cookies",
            b"key3.db",
            b"key4.db",
            b"logins.json",
            b"\\Google\\Chrome\\User Data",
            b"\\Mozilla\\Firefox\\Profiles",
            b"\\Microsoft\\Edge\\User Data",
            b"\\Opera Software\\Opera Stable",
            b"\\BraveSoftware\\Brave-Browser",
            b"passwords.txt",
            b"credentials",
        ],
        "severity": "high",
        "mitre": "T1555.003",
    },
    "token_stealing": {
        "imports": ["CredEnumerateA", "CredEnumerateW", "CredReadA", "CredReadW"],
        "strings": [
            b"discord",
            b"telegram",
            b"token",
            b"leveldb",
            b"Local Storage",
            b"wallet.dat",
        ],
        "severity": "high",
        "mitre": "T1528",
    },
}

PERSISTENCE_INDICATORS = {
    "registry_run_keys": {
        "imports": [
            "RegSetValueExA",
            "RegSetValueExW",
            "RegCreateKeyExA",
            "RegCreateKeyExW",
        ],
        "strings": [
            b"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
            b"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
            b"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon",
            b"CurrentVersion\\Run",
        ],
        "severity": "high",
        "mitre": "T1547.001",
    },
    "scheduled_tasks": {
        "strings": [
            b"schtasks",
            b"/create",
            b"/sc",
            b"Schedule.Service",
            b"ITaskService",
            b"Register-ScheduledTask",
        ],
        "severity": "high",
        "mitre": "T1053.005",
    },
    "startup_folder": {
        "strings": [
            b"\\Startup\\",
            b"\\Start Menu\\Programs\\Startup",
            b"shell:startup",
            b"shell:common startup",
        ],
        "severity": "medium",
        "mitre": "T1547.001",
    },
    "service_creation": {
        "imports": ["CreateServiceA", "CreateServiceW", "OpenSCManagerA", "OpenSCManagerW"],
        "strings": [b"sc create", b"sc config", b"New-Service"],
        "severity": "high",
        "mitre": "T1543.003",
    },
    "wmi_persistence": {
        "strings": [
            b"Win32_Process",
            b"WMI",
            b"ManagementObject",
            b"__EventFilter",
            b"CommandLineEventConsumer",
        ],
        "severity": "high",
        "mitre": "T1546.003",
    },
}

EVASION_INDICATORS = {
    "anti_debug": {
        "imports": [
            "IsDebuggerPresent",
            "CheckRemoteDebuggerPresent",
            "NtQueryInformationProcess",
            "NtSetInformationThread",
            "OutputDebugStringA",
        ],
        "strings": [
            b"IsDebuggerPresent",
            b"OllyDbg",
            b"x64dbg",
            b"IDA Pro",
            b"Immunity",
            b"ProcessDebugPort",
        ],
        "severity": "medium",
        "mitre": "T1622",
    },
    "anti_vm": {
        "strings": [
            b"VMware",
            b"VirtualBox",
            b"VBOX",
            b"QEMU",
            b"Hyper-V",
            b"Xen",
            b"vmtoolsd",
            b"vboxservice",
            b"vmwaretray",
            b"SYSTEM\\CurrentControlSet\\Services\\Disk\\Enum",
            b"SOFTWARE\\VMware",
            b"SYSTEM\\ControlSet001\\Services\\VBoxGuest",
        ],
        "severity": "medium",
        "mitre": "T1497.001",
    },
    "process_injection": {
        "imports": [
            "VirtualAllocEx",
            "WriteProcessMemory",
            "CreateRemoteThread",
            "NtCreateThreadEx",
            "RtlCreateUserThread",
            "QueueUserAPC",
        ],
        "severity": "high",
        "mitre": "T1055",
    },
    "api_unhooking": {
        "imports": ["NtProtectVirtualMemory", "NtWriteVirtualMemory"],
        "strings": [b"ntdll.dll", b"unhook", b"ETW"],
        "severity": "high",
        "mitre": "T1562.001",
    },
}

INDICATOR_GROUPS = {
    "ransomware": ("Ransomware", RANSOMWARE_INDICATORS),
    "keylogger": ("Keylogger", KEYLOGGER_INDICATORS),
    "reverse_shell": ("Reverse Shell / C2", REVERSE_SHELL_INDICATORS),
    "credential_stealing": ("Credential Stealing", CREDENTIAL_STEALING_INDICATORS),
    "persistence": ("Persistence", PERSISTENCE_INDICATORS),
    "evasion": ("Evasion", EVASION_INDICATORS),
}

SEVERITY_ORDER = {"low": 0, "medium": 1, "high": 2, "critical": 3}


def _get_pe_imports(file_path: str, pe_info: Optional[dict] = None) -> Set[str]:
    """Extract import names from PE file."""
    imports: Set[str] = set()
    if pe_info and isinstance(pe_info.get("imports"), dict):
        for funcs in pe_info["imports"].values():
            if isinstance(funcs, list):
                imports.update(funcs)
    if HAS_PEFILE and not imports:
        try:
            pe = pefile.PE(file_path, fast_load=True)
            pe.parse_data_directories(
                directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"]]
            )
            if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    for imp in entry.imports:
                        if imp.name:
                            imports.add(imp.name.decode("utf-8", errors="ignore"))
            pe.close()
        except Exception:
            pass
    return imports


def detect_capabilities(
    file_path: str,
    pe_info: Optional[dict] = None,
) -> CapabilityReport:
    """Detect malware capabilities through static analysis."""
    report = CapabilityReport()
    path = Path(file_path)

    if not path.exists():
        return report

    try:
        content = path.read_bytes()[: 20 * 1024 * 1024]  # Max 20 MB
    except OSError:
        return report

    imports = _get_pe_imports(file_path, pe_info)
    content_lower = content.lower()

    for category, (display_name, indicators) in INDICATOR_GROUPS.items():
        for sub_name, rules in indicators.items():
            evidence: List[str] = []
            score = 0.0
            weights = 0.0

            # Check imports
            rule_imports = rules.get("imports", [])
            if rule_imports:
                weights += 1.0
                matched = [i for i in rule_imports if i in imports]
                if matched:
                    ratio = min(len(matched) / max(len(rule_imports) * 0.3, 1), 1.0)
                    score += ratio
                    evidence.extend(f"Import: {i}" for i in matched[:5])

            # Check strings
            rule_strings = rules.get("strings", [])
            if rule_strings:
                weights += 1.0
                matched_s = []
                for s in rule_strings:
                    if s.lower() in content_lower:
                        matched_s.append(
                            s.decode("utf-8", errors="ignore") if isinstance(s, bytes) else s
                        )
                if matched_s:
                    ratio = min(len(matched_s) / max(len(rule_strings) * 0.3, 1), 1.0)
                    score += ratio
                    evidence.extend(f"String: {s}" for s in matched_s[:5])

            # Combined patterns
            combined = rules.get("combined", [])
            if combined:
                weights += 1.0
                for pattern_set in combined:
                    if all(p.lower() in content_lower for p in pattern_set):
                        score += 1.0 / len(combined)
                        evidence.append(f"Pattern: {' + '.join(p.decode() for p in pattern_set)}")

            if weights > 0 and score > 0:
                confidence = min(score / weights, 1.0)
                if confidence >= 0.15:
                    severity = rules.get("severity", "medium")
                    mitre = rules.get("mitre", "")
                    cap = Capability(
                        name=f"{display_name}: {sub_name.replace('_', ' ').title()}",
                        category=category,
                        confidence=confidence,
                        evidence=evidence,
                        mitre_attack=mitre,
                        severity=severity,
                    )
                    report.capabilities.append(cap)
                    if SEVERITY_ORDER.get(severity, 0) > SEVERITY_ORDER.get(report.max_severity, 0):
                        report.max_severity = severity

    report.total_detected = len(report.capabilities)
    for cap in report.capabilities:
        report.risk_categories[cap.category] = report.risk_categories.get(cap.category, 0) + 1

    return report
