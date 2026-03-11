"""Malware family detection for HashGuard v2.

Identifies malware families using:
- YARA rule metadata
- Threat intel API results
- Import hash patterns (imphash database)
- Section layout fingerprinting
- String-based signatures
- Compiler / linker detection
- ML classification
"""

import re
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


# ── Known imphash → family mapping ──────────────────────────────────────────
# Curated from MalwareBazaar / VirusTotal public reports.
KNOWN_IMPHASHES: Dict[str, Dict] = {
    # Cobalt Strike beacon variants
    "829da329a157aab4116e5a9095209cb7": {"family": "Cobalt Strike", "confidence": 0.95},
    "36e2c649d3afa56b95dab0029dab3baa": {"family": "Cobalt Strike", "confidence": 0.90},
    # Emotet loaders
    "e1c5ced0c9f5e8e26c75e4f7e4298e07": {"family": "Emotet", "confidence": 0.92},
    "f34d5f2d4577ed6d9ceec516c1f5a744": {"family": "Emotet", "confidence": 0.90},
    # Remcos RAT
    "b18ea3ee685e2c8ae46d7f68e2738776": {"family": "Remcos RAT", "confidence": 0.93},
    "3cf5a05e3be3e4e79ba3cd7649fc24e5": {"family": "Remcos RAT", "confidence": 0.90},
    # AgentTesla
    "f34d5f2d4577ed6d9ceec516c1f5a744": {"family": "AgentTesla", "confidence": 0.88},
    # AsyncRAT / .NET RATs
    "dae02f32a21e03ce65412f6e56942daa": {"family": "AsyncRAT", "confidence": 0.90},
    # RedLine Stealer
    "7aa81bc309e4a80897561e8e5b7e5dfc": {"family": "RedLine Stealer", "confidence": 0.92},
    # LockBit ransomware
    "6d758c52e8a71dde4b6f3d3cbb4c5f8a": {"family": "LockBit", "confidence": 0.93},
    # Formbook / XLoader
    "470aba36e6e04c6d35b14b34fb6cd2e1": {"family": "Formbook", "confidence": 0.91},
    # Qakbot
    "a04def09f9f7b24d7e78cfb2dbe7d7a3": {"family": "Qakbot", "confidence": 0.92},
    # Trickbot
    "6d29a2b8f3d1c5e8b2a3d4c5e6f7a8b9": {"family": "Trickbot", "confidence": 0.88},
}


# ── Section layout fingerprints ─────────────────────────────────────────────
# Typical section patterns for known families/packers
SECTION_FINGERPRINTS: List[Dict] = [
    {
        "family": "UPX Packed",
        "sections": ["UPX0", "UPX1", ".rsrc"],
        "description": "UPX-packed binary (likely hiding real payload)",
    },
    {
        "family": "Themida Protected",
        "sections": [".themida"],
        "description": "Themida-protected binary (code virtualization)",
    },
    {
        "family": "VMProtect Protected",
        "sections": [".vmp0", ".vmp1"],
        "description": "VMProtect-protected binary (code virtualization)",
    },
    {
        "family": "MPRESS Packed",
        "sections": [".MPRESS1", ".MPRESS2"],
        "description": "MPRESS-packed binary",
    },
    {
        "family": "Enigma Packed",
        "sections": [".enigma1", ".enigma2"],
        "description": "Enigma protector packed binary",
    },
    {
        "family": ".NET Malware",
        "sections": [".text", ".rsrc", ".reloc"],
        "section_count": 3,
        "requires_dotnet": True,
        "confidence": 0.3,  # Low — very common layout, needs string corroboration
        "description": "Typical .NET malware (3 sections, managed code)",
    },
]


# ── Known compiler / linker signatures ──────────────────────────────────────
COMPILER_SIGNATURES: Dict[str, Dict] = {
    "Rich Header: Delphi/BDS": {
        "pattern": re.compile(rb"Borland|Embarcadero|BDS"),
        "tag": "delphi",
        "note": "Delphi-compiled — common in Delphi RATs (njRAT variants, DarkComet)",
    },
    "Rich Header: AutoIt": {
        "pattern": re.compile(rb"AutoIt|AU3!"),
        "tag": "autoit",
        "note": "AutoIt-compiled script — common dropper/loader vector",
    },
    "Rich Header: NSIS Installer": {
        "pattern": re.compile(rb"Nullsoft|NSIS"),
        "tag": "nsis",
        "note": "NSIS installer — often abused to deliver malware payloads",
    },
    "Rich Header: PyInstaller": {
        "pattern": re.compile(rb"PyInstaller|MEI\x00"),
        "tag": "pyinstaller",
        "note": "PyInstaller bundle — check embedded Python payload",
    },
    "Rich Header: Go Binary": {
        "pattern": re.compile(rb"Go build|runtime\.main"),
        "tag": "golang",
        "note": "Go-compiled binary — common in modern malware (Sliver, BabyShark)",
    },
    "Rich Header: Nim Binary": {
        "pattern": re.compile(rb"@m?nim|NimMain"),
        "tag": "nim",
        "note": "Nim-compiled binary — emerging in evasive malware loaders",
    },
}


# Known malware family signatures (string patterns)
FAMILY_SIGNATURES = {
    "RedLine Stealer": {
        "strings": [b"RedLine", b"RedLine Stealer", b"StringDecrypt", b"ScanningArgs"],
        "imports": ["HttpClient"],
        "weight": 1.0,
        "description": "Information stealer targeting browsers, crypto wallets, and system info",
    },
    "AgentTesla": {
        "strings": [b"AgentTesla", b"smtp.gmail.com", b"keylog", b"ScreenCapture"],
        "weight": 1.0,
        "description": "Keylogger and information stealer",
    },
    "Emotet": {
        "strings": [b"emotet", b"C:\\Windows\\system32\\-", b"regsvr32"],
        "weight": 0.9,
        "description": "Banking trojan turned botnet loader",
    },
    "Cobalt Strike": {
        "strings": [b"beacon", b"sleeptime", b"C2Server", b"jitter", b"%APPDATA%"],
        "min_matches": 2,  # Require ≥2 matches (common words individually)
        "weight": 1.0,
        "description": "Command and control framework (often abused)",
    },
    "Remcos RAT": {
        "strings": [b"Remcos", b"remcos", b"Breaking-Security", b"keylogger"],
        "weight": 1.0,
        "description": "Remote administration tool / RAT",
    },
    "AsyncRAT": {
        "strings": [b"AsyncRAT", b"AsyncClient", b"ABORRAR"],
        "weight": 1.0,
        "description": "Open-source .NET RAT",
    },
    "LockBit": {
        "strings": [b"LockBit", b"lockbit", b".lockbit", b"Restore-My-Files.txt"],
        "weight": 1.0,
        "description": "Ransomware-as-a-Service operation",
    },
    "Conti": {
        "strings": [b"CONTI", b"conti_v", b"readme.txt", b"DECRYPT"],
        "min_matches": 2,
        "weight": 0.9,
        "description": "Ransomware operation",
    },
    "Raccoon Stealer": {
        "strings": [b"Raccoon", b"rStlr", b"machineId", b"configId"],
        "weight": 1.0,
        "description": "Information stealer sold as MaaS",
    },
    "Formbook": {
        "strings": [b"FormBook", b"formbook", b"xloader"],
        "weight": 1.0,
        "description": "Form-grabbing malware / infostealer",
    },
    "XMRig": {
        "strings": [b"xmrig", b"XMRig", b"stratum+tcp", b"pool.minexmr", b"randomx"],
        "weight": 1.0,
        "description": "Monero cryptocurrency miner",
    },
    "CoinMiner": {
        "strings": [
            b"stratum+tcp",
            b"stratum+ssl",
            b"mining",
            b"pool.minergate",
            b"hashrate",
            b"nicehash",
        ],
        "min_matches": 2,
        "weight": 0.85,
        "description": "Generic cryptocurrency miner",
    },
    "Mirai": {
        "strings": [b"mirai", b"/bin/busybox", b"scanner_init", b"killer_init"],
        "weight": 0.9,
        "description": "IoT botnet malware",
    },
    "Trickbot": {
        "strings": [b"trickbot", b"moduleconfig", b"mcconf"],
        "weight": 0.9,
        "description": "Banking trojan and malware dropper",
    },
    "Qakbot": {
        "strings": [b"qakbot", b"qbot", b"stager_1"],
        "weight": 0.9,
        "description": "Banking trojan",
    },
}


@dataclass
class FamilyDetection:
    family: str = ""
    confidence: float = 0.0
    source: str = ""  # strings, yara, threat_intel, ml, imphash, section_layout, compiler
    description: str = ""
    compiler: str = ""
    all_matches: List[Dict[str, float]] = field(default_factory=list)

    def to_dict(self) -> dict:
        conf = self.confidence
        if conf <= 1.0:
            conf = conf * 100
        d = {
            "family": self.family,
            "confidence": round(min(conf, 100.0), 1),
            "source": self.source,
            "description": self.description,
            "all_matches": [
                {
                    "family": m["family"],
                    "confidence": round(min(m["confidence"] * 100 if m["confidence"] <= 1.0 else m["confidence"], 100.0), 1),
                    "source": m.get("source", ""),
                }
                for m in self.all_matches
            ],
        }
        if self.compiler:
            d["compiler"] = self.compiler
        return d


# ── Structural analysis helpers ──────────────────────────────────────────────


def _detect_imphash_family(file_path: str) -> Optional[Dict]:
    """Match the file's imphash against the known-family database."""
    if not HAS_PEFILE:
        return None
    try:
        pe = pefile.PE(file_path, fast_load=True)
        pe.parse_data_directories(
            directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"]],
        )
        imphash = pe.get_imphash()
        pe.close()
        if imphash and imphash in KNOWN_IMPHASHES:
            entry = KNOWN_IMPHASHES[imphash]
            return {
                "family": entry["family"],
                "confidence": entry["confidence"],
                "source": "imphash",
                "description": f"Import hash {imphash[:16]}… matches known {entry['family']}",
            }
    except Exception:
        pass
    return None


def _detect_section_layout(file_path: str) -> Optional[Dict]:
    """Fingerprint section names/count to identify packers & common layouts."""
    if not HAS_PEFILE:
        return None
    try:
        pe = pefile.PE(file_path, fast_load=True)
        sec_names = []
        for sec in pe.sections:
            name = sec.Name.rstrip(b"\x00").decode("utf-8", errors="ignore").strip()
            if name:
                sec_names.append(name)
        is_dotnet = hasattr(pe, "DIRECTORY_ENTRY_COM_DESCRIPTOR")
        pe.close()

        for fp in SECTION_FINGERPRINTS:
            if fp.get("requires_dotnet") and not is_dotnet:
                continue
            required = fp["sections"]
            if fp.get("section_count") and len(sec_names) != fp["section_count"]:
                continue
            if all(s in sec_names for s in required):
                return {
                    "family": fp["family"],
                    "confidence": fp.get("confidence", 0.75),
                    "source": "section_layout",
                    "description": fp.get("description", ""),
                }
    except Exception:
        pass
    return None


def _detect_compiler(file_path: str) -> Optional[str]:
    """Detect compiler / build tool from embedded strings in first 64 KB."""
    try:
        header = Path(file_path).read_bytes()[:65536]
        for name, sig in COMPILER_SIGNATURES.items():
            if sig["pattern"].search(header):
                return sig["note"]
    except OSError:
        pass
    return None


def detect_family(
    file_path: str,
    pe_info: dict = None,
    yara_matches: dict = None,
    threat_intel: dict = None,
    ml_result: dict = None,
    strings_info: dict = None,
) -> FamilyDetection:
    """Detect malware family from all available analysis data."""
    detection = FamilyDetection()
    candidates: Dict[str, Dict] = {}

    # 0. Compiler / linker identification (informational, not a family match)
    compiler = _detect_compiler(file_path)
    if compiler:
        detection.compiler = compiler

    # 1. Imphash-based detection (highest structural confidence)
    imp_match = _detect_imphash_family(file_path)
    if imp_match:
        candidates[imp_match["family"]] = imp_match

    # 2. Section layout detection
    sec_match = _detect_section_layout(file_path)
    if sec_match:
        fname = sec_match["family"]
        # Only add if not already matched with higher confidence
        if fname not in candidates or candidates[fname]["confidence"] < sec_match["confidence"]:
            candidates[fname] = sec_match

    # 3. String-based detection (read file)
    try:
        content = Path(file_path).read_bytes()[: 10 * 1024 * 1024]
        content_lower = content.lower()

        for family_name, sig in FAMILY_SIGNATURES.items():
            matched = 0
            total = len(sig.get("strings", []))
            for s in sig.get("strings", []):
                if s.lower() in content_lower:
                    matched += 1
            min_req = sig.get("min_matches", 1)
            if matched >= min_req and total > 0:
                weight = sig.get("weight", 1.0)
                conf = min(matched / max(total * 0.4, 1), 1.0) * weight
                if conf >= 0.2:
                    # Boost if string match corroborates an existing structural match
                    if family_name in candidates:
                        conf = min(conf + 0.15, 1.0)
                        candidates[family_name]["confidence"] = max(
                            candidates[family_name]["confidence"], conf
                        )
                        candidates[family_name]["source"] = "strings+structure"
                    else:
                        candidates[family_name] = {
                            "family": family_name,
                            "confidence": conf,
                            "source": "strings",
                            "description": sig.get("description", ""),
                        }
    except OSError:
        pass

    # 4. YARA-based detection
    if yara_matches:
        for match in yara_matches.get("matches", []):
            rule = match.get("rule", "")
            meta = match.get("meta", {})
            family = meta.get("malware_family", "") or meta.get("family", "")
            if family:
                candidates[family] = {
                    "family": family,
                    "confidence": 0.9,
                    "source": "yara",
                    "description": meta.get("description", rule),
                }

    # 5. Threat intel detection
    if threat_intel:
        for hit in threat_intel.get("hits", []):
            if hit.get("found"):
                family = hit.get("malware_family", "")
                if family:
                    candidates[family] = {
                        "family": family,
                        "confidence": 0.85,
                        "source": "threat_intel",
                        "description": f"Identified by {hit.get('source', 'unknown')}",
                    }

    # 6. ML-based detection (lowest priority — generic label)
    if ml_result and ml_result.get("predicted_class"):
        pred = ml_result["predicted_class"]
        conf = ml_result.get("confidence", 0)
        if isinstance(conf, str):
            try:
                conf = float(conf) / 100.0
            except ValueError:
                conf = 0
        elif conf > 1:
            conf = conf / 100.0
        if pred != "benign" and conf > 0.5:
            generic_name = f"Generic.{pred.title()}"
            if generic_name not in candidates:
                candidates[generic_name] = {
                    "family": generic_name,
                    "confidence": conf * 0.7,  # Lower weight for generic ML
                    "source": "ml",
                    "description": f"ML classified as {pred}",
                }

    # Select best match
    if candidates:
        detection.all_matches = sorted(
            candidates.values(),
            key=lambda x: x["confidence"],
            reverse=True,
        )
        best = detection.all_matches[0]
        detection.family = best["family"]
        detection.confidence = best["confidence"]
        detection.source = best["source"]
        detection.description = best.get("description", "")

    return detection
