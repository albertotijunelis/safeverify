"""HashGuard Script Deobfuscator — Static analysis of obfuscated scripts.

Provides pattern-based deobfuscation for common script obfuscation techniques:
- PowerShell: Base64 -EncodedCommand, char-code concatenation, string reversal,
  Invoke-Expression layers, variable substitution obfuscation
- VBScript/VBA: Chr() concatenation, StrReverse, Execute obfuscation
- JavaScript: eval/Function obfuscation, char code arrays, hex strings
- Batch: SET variable substitution, delayed expansion tricks
- HTA: script extraction from HTML Application containers

Does NOT execute any code — all analysis is regex + pattern matching.
"""

import base64
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional, Tuple

from hashguard.logger import get_logger

logger = get_logger(__name__)


@dataclass
class DeobfuscationLayer:
    """One layer of deobfuscation applied."""

    technique: str  # e.g. "base64_decode", "chr_concat"
    description: str
    original: str = ""  # Truncated original obfuscated text
    result: str = ""  # Deobfuscated result (truncated)
    confidence: str = "medium"  # low, medium, high


@dataclass
class DeobfuscationResult:
    """Complete deobfuscation analysis of a script."""

    script_type: str = "unknown"  # powershell, vbscript, javascript, batch, hta
    obfuscation_detected: bool = False
    layers: List[DeobfuscationLayer] = field(default_factory=list)
    decoded_strings: List[str] = field(default_factory=list)
    iocs_extracted: List[dict] = field(default_factory=list)  # URLs, IPs, domains
    risk_indicators: List[str] = field(default_factory=list)
    final_payload: str = ""

    def to_dict(self) -> dict:
        return {
            "script_type": self.script_type,
            "obfuscation_detected": self.obfuscation_detected,
            "layers": [
                {
                    "technique": l.technique,
                    "description": l.description,
                    "original": l.original[:200],
                    "result": l.result[:500],
                    "confidence": l.confidence,
                }
                for l in self.layers
            ],
            "decoded_strings": self.decoded_strings[:50],
            "iocs_extracted": self.iocs_extracted[:100],
            "risk_indicators": self.risk_indicators,
            "final_payload": self.final_payload[:2000],
        }


# ── Script type detection ────────────────────────────────────────────────────


def _detect_script_type(content: str, filename: str = "") -> str:
    ext = os.path.splitext(filename)[1].lower() if filename else ""
    ext_map = {
        ".ps1": "powershell",
        ".psm1": "powershell",
        ".psd1": "powershell",
        ".vbs": "vbscript",
        ".vbe": "vbscript",
        ".js": "javascript",
        ".jse": "javascript",
        ".wsf": "javascript",
        ".bat": "batch",
        ".cmd": "batch",
        ".hta": "hta",
    }
    if ext in ext_map:
        return ext_map[ext]

    content_lower = content[:2000].lower()
    if any(
        kw in content_lower
        for kw in ["invoke-expression", "iex", "new-object", "param(", "[system.", "write-host"]
    ):
        return "powershell"
    if any(kw in content_lower for kw in ["createobject", "wscript.", "dim ", "sub ", "function "]):
        return "vbscript"
    if any(kw in content_lower for kw in ["var ", "function(", "eval(", "document.", "window."]):
        return "javascript"
    if any(kw in content_lower for kw in ["@echo", "set /a", "%~", "goto ", "call :"]):
        return "batch"
    if "<hta:application" in content_lower or "< /script>" in content_lower:
        return "hta"

    return "unknown"


# ── IOC extraction (applies to all script types) ────────────────────────────

_RE_URL = re.compile(r'https?://[^\s\'"<>]{5,200}', re.IGNORECASE)
_RE_IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_RE_DOMAIN = re.compile(
    r"\b(?:[a-zA-Z0-9-]+\.)+(?:com|net|org|io|xyz|top|ru|cn|tk|pw|cc|info|biz|co|me)\b"
)
_RE_EMAIL = re.compile(r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b")
_RE_BITCOIN = re.compile(r"\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b")
_RE_FILEPATH = re.compile(r'[A-Z]:\\(?:[^\s\\:*?"<>|]+\\)*[^\s\\:*?"<>|]+', re.IGNORECASE)


def _extract_iocs(text: str) -> List[dict]:
    iocs = []
    seen = set()

    for m in _RE_URL.finditer(text):
        val = m.group()
        if val not in seen:
            seen.add(val)
            iocs.append({"type": "url", "value": val})

    for m in _RE_IPV4.finditer(text):
        val = m.group()
        parts = val.split(".")
        if all(0 <= int(p) <= 255 for p in parts) and val not in seen:
            # Skip private/localhost
            if not (
                val.startswith("127.")
                or val.startswith("0.")
                or val.startswith("10.")
                or val.startswith("192.168.")
            ):
                seen.add(val)
                iocs.append({"type": "ip", "value": val})

    for m in _RE_DOMAIN.finditer(text):
        val = m.group().lower()
        if val not in seen and not any(val.endswith(s) for s in [".example.com", ".test.com"]):
            seen.add(val)
            iocs.append({"type": "domain", "value": val})

    for m in _RE_EMAIL.finditer(text):
        val = m.group()
        if val not in seen:
            seen.add(val)
            iocs.append({"type": "email", "value": val})

    for m in _RE_BITCOIN.finditer(text):
        val = m.group()
        if val not in seen:
            seen.add(val)
            iocs.append({"type": "bitcoin", "value": val})

    return iocs


# ── Risk indicators ──────────────────────────────────────────────────────────

_RISK_PATTERNS = [
    (
        r"downloadstring|downloadfile|downloaddata|webclient|net\.webclient",
        "Downloads content from the internet",
    ),
    (r"invoke-expression|iex\s*\(|iex\s+\$", "Dynamic code execution (Invoke-Expression)"),
    (r"new-object\s+system\.net", "Creates network objects"),
    (r"start-process|invoke-item|invoke-command", "Starts external processes"),
    (r"get-credential|mimikatz|lsass", "Credential theft indicators"),
    (
        r"set-executionpolicy\s+bypass|set-executionpolicy\s+unrestricted",
        "Bypasses PowerShell execution policy",
    ),
    (r"add-type\s+-assembly|add-type\s+-typedef", "Loads .NET types dynamically"),
    (
        r"virtualalloc|virtualprotect|createthread|rtlmovememory",
        "Memory manipulation (shellcode injection)",
    ),
    (r"hidden|windowstyle\s+hidden|-w\s+hidden", "Hidden window execution"),
    (r"amsiutils|amsiscanbuffer|amsi\.dll", "AMSI bypass attempt"),
    (r"disable-.*firewall|netsh\s+.*firewall", "Firewall manipulation"),
    (r"schtasks\s*/create|register-scheduledjob", "Creates scheduled tasks"),
    (r"reg\s+add.*\\run|set-itemproperty.*\\run", "Registry persistence (Run keys)"),
    (r"frombase64string|convert.*base64|::decode", "Base64 decoding (payload staging)"),
    (r"createobject.*shell|wscript\.shell|shell\.application", "Shell object creation (VBS)"),
    (r"eval\s*\(|function\s*\(|settimeout\s*\(.*eval", "Dynamic eval execution (JS)"),
]


def _check_risk_indicators(text: str) -> List[str]:
    indicators = []
    text_lower = text.lower()
    for pattern, desc in _RISK_PATTERNS:
        if re.search(pattern, text_lower):
            indicators.append(desc)
    return indicators


# ── PowerShell deobfuscation ─────────────────────────────────────────────────


def _deobfuscate_ps_base64(content: str) -> List[DeobfuscationLayer]:
    """Decode PowerShell -EncodedCommand / -enc Base64 strings."""
    layers = []
    # Match -EncodedCommand / -enc / -e followed by base64
    pattern = re.compile(
        r"(?:-(?:encoded)?c(?:ommand)?|-enc?|-e)\s+([A-Za-z0-9+/=]{20,})",
        re.IGNORECASE,
    )
    for m in pattern.finditer(content):
        b64 = m.group(1)
        try:
            # PowerShell uses UTF-16LE for encoded commands
            decoded = base64.b64decode(b64).decode("utf-16-le", errors="replace")
            layers.append(
                DeobfuscationLayer(
                    technique="powershell_encoded_command",
                    description="Base64-encoded PowerShell command (-EncodedCommand)",
                    original=b64[:100],
                    result=decoded.strip(),
                    confidence="high",
                )
            )
        except Exception:
            pass

    # Standalone base64 strings assigned or piped
    standalone = re.compile(
        r'(?:\$\w+\s*=\s*|FromBase64String\s*\(\s*)["\']([A-Za-z0-9+/=]{40,})["\']',
        re.IGNORECASE,
    )
    for m in standalone.finditer(content):
        b64 = m.group(1)
        try:
            raw = base64.b64decode(b64)
            # Try UTF-16LE first (PowerShell default), then UTF-8
            for enc in ("utf-16-le", "utf-8", "ascii"):
                try:
                    decoded = raw.decode(enc, errors="strict")
                    if decoded.isprintable() or "\n" in decoded:
                        layers.append(
                            DeobfuscationLayer(
                                technique="base64_string",
                                description=f"Base64-encoded string ({enc})",
                                original=b64[:100],
                                result=decoded.strip(),
                                confidence="high",
                            )
                        )
                        break
                except UnicodeDecodeError:
                    continue
        except Exception:
            pass

    return layers


def _deobfuscate_ps_charcode(content: str) -> List[DeobfuscationLayer]:
    """Decode PowerShell [char]N+[char]N or [char]0xNN concatenation."""
    layers = []
    # [char]65+[char]66+... or [char]0x41+[char]0x42+...
    pattern = re.compile(
        r"(?:\[char\]\s*(?:0x[0-9a-f]+|\d+)\s*\+?\s*){3,}",
        re.IGNORECASE,
    )
    for m in pattern.finditer(content):
        expr = m.group()
        chars = re.findall(r"\[char\]\s*(0x[0-9a-f]+|\d+)", expr, re.IGNORECASE)
        try:
            decoded = "".join(
                chr(int(c, 16) if c.lower().startswith("0x") else int(c)) for c in chars
            )
            if len(decoded) >= 3:
                layers.append(
                    DeobfuscationLayer(
                        technique="char_concatenation",
                        description="PowerShell [char] code concatenation",
                        original=expr[:100],
                        result=decoded,
                        confidence="high",
                    )
                )
        except (ValueError, OverflowError):
            pass

    return layers


def _deobfuscate_ps_string_replace(content: str) -> List[DeobfuscationLayer]:
    """Detect PowerShell string replacement obfuscation."""
    layers = []
    # Pattern: 'obfuscated'.Replace('X','Y')
    pattern = re.compile(
        r"['\"]([^'\"]{10,})['\"](?:\s*-replace\s*['\"]([^'\"]+)['\"],\s*['\"]([^'\"]*)['\"])+",
        re.IGNORECASE,
    )
    for m in pattern.finditer(content):
        original = m.group(1)
        replacements = re.findall(
            r"-replace\s*['\"]([^'\"]+)['\"],\s*['\"]([^'\"]*)['\"]",
            m.group(),
            re.IGNORECASE,
        )
        result = original
        for old, new in replacements:
            result = result.replace(old, new)
        if result != original:
            layers.append(
                DeobfuscationLayer(
                    technique="string_replace",
                    description=f"PowerShell -replace obfuscation ({len(replacements)} substitution(s))",
                    original=original[:100],
                    result=result,
                    confidence="medium",
                )
            )

    return layers


def _deobfuscate_ps_reverse(content: str) -> List[DeobfuscationLayer]:
    """Detect and reverse PowerShell string reversal obfuscation."""
    layers = []
    # -join followed by array/string reversal
    pattern = re.compile(
        r"\(\s*['\"]([^'\"]{10,})['\"]\s*\[\s*-1\s*\.\.\s*-\s*\(.*?\)\s*\]\s*-join\s*['\"]['\"]",
        re.IGNORECASE,
    )
    for m in pattern.finditer(content):
        reversed_str = m.group(1)
        result = reversed_str[::-1]
        layers.append(
            DeobfuscationLayer(
                technique="string_reversal",
                description="PowerShell string reversal ([−1..-N] -join)",
                original=reversed_str[:100],
                result=result,
                confidence="medium",
            )
        )

    return layers


# ── VBScript deobfuscation ───────────────────────────────────────────────────


def _deobfuscate_vbs_chr(content: str) -> List[DeobfuscationLayer]:
    """Decode VBScript Chr() / ChrW() concatenation."""
    layers = []
    pattern = re.compile(
        r"(?:Chr[W]?\(\d+\)\s*&?\s*){3,}",
        re.IGNORECASE,
    )
    for m in pattern.finditer(content):
        expr = m.group()
        codes = re.findall(r"Chr[W]?\((\d+)\)", expr, re.IGNORECASE)
        try:
            decoded = "".join(chr(int(c)) for c in codes)
            if len(decoded) >= 3:
                layers.append(
                    DeobfuscationLayer(
                        technique="vbs_chr_concat",
                        description=f"VBScript Chr() concatenation ({len(codes)} chars)",
                        original=expr[:100],
                        result=decoded,
                        confidence="high",
                    )
                )
        except (ValueError, OverflowError):
            pass

    return layers


def _deobfuscate_vbs_strreverse(content: str) -> List[DeobfuscationLayer]:
    """Decode VBScript StrReverse()."""
    layers = []
    pattern = re.compile(r'StrReverse\s*\(\s*["\']([^"\']+)["\']\s*\)', re.IGNORECASE)
    for m in pattern.finditer(content):
        reversed_str = m.group(1)
        layers.append(
            DeobfuscationLayer(
                technique="vbs_strreverse",
                description="VBScript StrReverse()",
                original=reversed_str[:100],
                result=reversed_str[::-1],
                confidence="high",
            )
        )

    return layers


# ── JavaScript deobfuscation ─────────────────────────────────────────────────


def _deobfuscate_js_charcode(content: str) -> List[DeobfuscationLayer]:
    """Decode JavaScript String.fromCharCode() sequences."""
    layers = []
    pattern = re.compile(
        r"String\.fromCharCode\s*\(([\d,\s]+)\)",
        re.IGNORECASE,
    )
    for m in pattern.finditer(content):
        codes_str = m.group(1)
        codes = [c.strip() for c in codes_str.split(",") if c.strip().isdigit()]
        try:
            decoded = "".join(chr(int(c)) for c in codes)
            if len(decoded) >= 3:
                layers.append(
                    DeobfuscationLayer(
                        technique="js_fromcharcode",
                        description=f"JavaScript String.fromCharCode ({len(codes)} chars)",
                        original=m.group()[:100],
                        result=decoded,
                        confidence="high",
                    )
                )
        except (ValueError, OverflowError):
            pass

    return layers


def _deobfuscate_js_hex(content: str) -> List[DeobfuscationLayer]:
    """Decode JavaScript hex-escaped strings like \\x48\\x65."""
    layers = []
    pattern = re.compile(r"(?:\\x[0-9a-fA-F]{2}){4,}")
    for m in pattern.finditer(content):
        hex_str = m.group()
        hex_bytes = re.findall(r"\\x([0-9a-fA-F]{2})", hex_str)
        try:
            decoded = bytes(int(h, 16) for h in hex_bytes).decode("utf-8", errors="replace")
            if len(decoded) >= 4:
                layers.append(
                    DeobfuscationLayer(
                        technique="js_hex_string",
                        description="JavaScript hex-escaped string",
                        original=hex_str[:100],
                        result=decoded,
                        confidence="high",
                    )
                )
        except Exception:
            pass

    return layers


def _deobfuscate_js_unicode(content: str) -> List[DeobfuscationLayer]:
    """Decode JavaScript unicode-escaped strings like \\u0048."""
    layers = []
    pattern = re.compile(r"(?:\\u[0-9a-fA-F]{4}){3,}")
    for m in pattern.finditer(content):
        uni_str = m.group()
        codes = re.findall(r"\\u([0-9a-fA-F]{4})", uni_str)
        try:
            decoded = "".join(chr(int(c, 16)) for c in codes)
            if len(decoded) >= 3:
                layers.append(
                    DeobfuscationLayer(
                        technique="js_unicode_escape",
                        description="JavaScript unicode-escaped string",
                        original=uni_str[:100],
                        result=decoded,
                        confidence="high",
                    )
                )
        except (ValueError, OverflowError):
            pass

    return layers


# ── Batch file deobfuscation ─────────────────────────────────────────────────


def _deobfuscate_batch_set(content: str) -> List[DeobfuscationLayer]:
    """Resolve batch SET variable assignments and substitutions."""
    layers = []
    # Collect SET assignments: SET "var=value" or SET var=value
    var_map = {}
    for m in re.finditer(r'set\s+"?(\w+)=([^"\r\n]*)"?', content, re.IGNORECASE):
        var_map[m.group(1).lower()] = m.group(2)

    if len(var_map) < 3:
        return layers

    # Find concatenated variable usage like %a%%b%%c%
    concat_pattern = re.compile(r"(?:%(\w+)%){2,}")
    for m in concat_pattern.finditer(content):
        expr = m.group()
        var_names = re.findall(r"%(\w+)%", expr)
        resolved = ""
        for v in var_names:
            resolved += var_map.get(v.lower(), f"%{v}%")
        if resolved and resolved != expr:
            layers.append(
                DeobfuscationLayer(
                    technique="batch_variable_concat",
                    description=f"Batch SET variable concatenation ({len(var_names)} vars)",
                    original=expr[:100],
                    result=resolved,
                    confidence="medium",
                )
            )

    return layers


# ── HTA deobfuscation ────────────────────────────────────────────────────────


def _deobfuscate_hta(content: str) -> List[DeobfuscationLayer]:
    """Extract embedded scripts from HTA containers."""
    layers = []
    # Extract script blocks
    pattern = re.compile(
        r'<script[^>]*?(?:language\s*=\s*["\']?(\w+)["\']?)?[^>]*>(.*?)</script>',
        re.IGNORECASE | re.DOTALL,
    )
    for m in pattern.finditer(content):
        lang = m.group(1) or "unknown"
        script = m.group(2).strip()
        if len(script) > 10:
            layers.append(
                DeobfuscationLayer(
                    technique="hta_script_extraction",
                    description=f"Embedded {lang} script extracted from HTA",
                    original="<script>...</script>",
                    result=script[:1000],
                    confidence="high",
                )
            )

    return layers


# ── Main analysis function ───────────────────────────────────────────────────


def analyze_script(file_path: str) -> DeobfuscationResult:
    """Analyze a script file for obfuscation and extract actionable intelligence.

    Reads the file, detects its type, applies relevant deobfuscation techniques,
    extracts IOCs, and identifies risk indicators.
    """
    result = DeobfuscationResult()

    try:
        fsize = os.path.getsize(file_path)
        if fsize > 10 * 1024 * 1024:  # 10 MB guard
            logger.warning(f"Script too large for deobfuscation: {fsize} bytes")
            return result
        content = Path(file_path).read_text(encoding="utf-8", errors="replace")
    except OSError as e:
        logger.error(f"Cannot read script: {e}")
        return result

    if len(content) < 5:
        return result

    # Detect script type
    result.script_type = _detect_script_type(content, file_path)

    # Apply deobfuscation techniques based on script type
    all_layers: List[DeobfuscationLayer] = []

    if result.script_type == "powershell":
        all_layers.extend(_deobfuscate_ps_base64(content))
        all_layers.extend(_deobfuscate_ps_charcode(content))
        all_layers.extend(_deobfuscate_ps_string_replace(content))
        all_layers.extend(_deobfuscate_ps_reverse(content))

    elif result.script_type == "vbscript":
        all_layers.extend(_deobfuscate_vbs_chr(content))
        all_layers.extend(_deobfuscate_vbs_strreverse(content))

    elif result.script_type == "javascript":
        all_layers.extend(_deobfuscate_js_charcode(content))
        all_layers.extend(_deobfuscate_js_hex(content))
        all_layers.extend(_deobfuscate_js_unicode(content))

    elif result.script_type == "batch":
        all_layers.extend(_deobfuscate_batch_set(content))

    elif result.script_type == "hta":
        all_layers.extend(_deobfuscate_hta(content))
        # Also try VBS/JS deobfuscation on extracted scripts
        for layer in list(all_layers):
            if layer.result:
                all_layers.extend(_deobfuscate_vbs_chr(layer.result))
                all_layers.extend(_deobfuscate_js_charcode(layer.result))

    # Generic base64 detection (works for all types)
    generic_b64 = re.findall(r"[A-Za-z0-9+/=]{40,}", content)
    for b64 in generic_b64[:10]:
        try:
            raw = base64.b64decode(b64)
            decoded = raw.decode("utf-8", errors="strict")
            if decoded.isprintable() and len(decoded) >= 5:
                all_layers.append(
                    DeobfuscationLayer(
                        technique="generic_base64",
                        description="Standalone Base64-encoded string",
                        original=b64[:100],
                        result=decoded[:500],
                        confidence="medium",
                    )
                )
        except Exception:
            pass

    result.layers = all_layers
    result.obfuscation_detected = len(all_layers) > 0

    # Extract IOCs from original content and all decoded layers
    all_text = content
    for layer in all_layers:
        all_text += "\n" + layer.result
    result.iocs_extracted = _extract_iocs(all_text)

    # Decoded strings (unique, non-empty)
    seen_strings: set = set()
    for layer in all_layers:
        s = layer.result.strip()
        if s and s not in seen_strings and len(s) >= 5:
            seen_strings.add(s)
            result.decoded_strings.append(s)

    # Risk indicators
    result.risk_indicators = _check_risk_indicators(all_text)

    # Build final payload (the deepest decoded layer or most significant)
    if all_layers:
        longest = max(all_layers, key=lambda l: len(l.result))
        result.final_payload = longest.result

    return result
