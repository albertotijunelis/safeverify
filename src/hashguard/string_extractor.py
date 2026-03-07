"""Automated string extraction and IOC detection for HashGuard.

Extracts security-relevant strings from binary files:
- URLs, IP addresses, domain names
- PowerShell commands and suspicious paths
- Cryptocurrency wallet addresses
- Email addresses, user-agent strings
- Registry keys
"""

import re
from dataclasses import dataclass, field
from typing import Dict, List, Set

# Minimum printable ASCII run length to consider a string interesting
_MIN_LEN = 6

# --------------------------------------------------------------------------
# Regex patterns for IOC extraction
# --------------------------------------------------------------------------

_RE_URL = re.compile(rb"https?://[A-Za-z0-9._~:/?#\[\]@!$&\'()*+,;=%-]{6,256}", re.ASCII)

_RE_IP = re.compile(
    rb"\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}" rb"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b"
)

_RE_DOMAIN = re.compile(
    rb"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
    rb"(?:com|net|org|io|ru|cn|tk|xyz|top|info|biz|cc|pw|onion|su|de|uk|fr)\b",
    re.IGNORECASE,
)

_RE_EMAIL = re.compile(rb"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,7}\b")

_RE_POWERSHELL = re.compile(
    rb"(?:powershell|pwsh)[^\x00]{0,200}",
    re.IGNORECASE,
)

_RE_SUSPICIOUS_PATH = re.compile(
    rb"(?:C:\\(?:Windows\\Temp|Users\\Public|ProgramData)\\[^\x00]{3,120})",
    re.IGNORECASE,
)

# Bitcoin (legacy and bech32), Ethereum, Monero
_RE_BTC = re.compile(rb"\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b")
_RE_BTC_BECH32 = re.compile(rb"\bbc1[ac-hj-np-z02-9]{38,62}\b")
_RE_ETH = re.compile(rb"\b0x[0-9a-fA-F]{40}\b")
_RE_XMR = re.compile(rb"\b4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}\b")

_RE_USERAGENT = re.compile(
    rb"(?:Mozilla|Opera|curl|wget|python-requests)[^\x00]{5,200}",
    re.IGNORECASE,
)

_RE_REGISTRY = re.compile(
    rb"(?:HKLM|HKCU|HKCR|HKU|HKCC)\\[^\x00]{5,200}",
    re.IGNORECASE,
)

# Private / bogon IP ranges to skip (reduce noise)
_BOGON_PREFIXES = ("0.", "10.", "127.", "169.254.", "192.168.", "255.")


def _is_bogon(ip: str) -> bool:
    if any(ip.startswith(p) for p in _BOGON_PREFIXES):
        return True
    parts = ip.split(".")
    if len(parts) == 4 and parts[0] == "172":
        second = int(parts[1])
        if 16 <= second <= 31:
            return True
    return False


@dataclass
class StringExtractionResult:
    """Results of automated string extraction."""

    total_strings: int = 0
    iocs: Dict[str, list] = field(
        default_factory=lambda: {
            "urls": [],
            "ips": [],
            "domains": [],
            "emails": [],
            "powershell_commands": [],
            "suspicious_paths": [],
            "crypto_wallets": [],
            "user_agents": [],
            "registry_keys": [],
        }
    )

    def to_dict(self) -> dict:
        flat = {}
        for k, v in self.iocs.items():
            if v:
                flat[k] = v
        return {
            "total_strings": self.total_strings,
            "has_iocs": self.has_iocs,
            **flat,
        }

    @property
    def has_iocs(self) -> bool:
        return any(bool(v) for v in self.iocs.values())


def _safe_decode(data: bytes) -> str:
    """Decode bytes, replacing errors."""
    return data.decode("utf-8", errors="replace").strip("\x00\r\n ")


def _dedup_add(lst: list, item: str, limit: int = 50) -> None:
    """Append *item* to *lst* if not already present and under limit."""
    if len(lst) < limit and item not in lst:
        lst.append(item)


def extract_strings(path: str, max_bytes: int = 10 * 1024 * 1024) -> StringExtractionResult:
    """Extract IOCs and interesting strings from a file.

    Parameters
    ----------
    path : str
        File to analyse.
    max_bytes : int
        Read at most this many bytes (default 10 MB) to prevent
        excessive memory use on large files.
    """
    result = StringExtractionResult()

    try:
        with open(path, "rb") as f:
            data = f.read(max_bytes)
    except Exception:
        return result

    # Count printable ASCII runs as "strings"
    for m in re.finditer(rb"[ -~]{%d,}" % _MIN_LEN, data):
        result.total_strings += 1

    # --- URL extraction ---------------------------------------------------
    for m in _RE_URL.finditer(data):
        url = _safe_decode(m.group(0))
        _dedup_add(result.iocs["urls"], url)

    # --- IP addresses (skip bogons) ---------------------------------------
    seen_ips: Set[str] = set()
    for m in _RE_IP.finditer(data):
        ip = m.group(0).decode("ascii", errors="ignore")
        if ip not in seen_ips and not _is_bogon(ip):
            seen_ips.add(ip)
            _dedup_add(result.iocs["ips"], ip)

    # --- Domains ----------------------------------------------------------
    url_hosts = set()
    for u in result.iocs["urls"]:
        try:
            host = u.split("//", 1)[1].split("/", 1)[0].split(":")[0].lower()
            url_hosts.add(host)
        except Exception:
            pass
    for m in _RE_DOMAIN.finditer(data):
        dom = m.group(0).decode("ascii", errors="ignore").lower()
        if dom not in url_hosts:
            _dedup_add(result.iocs["domains"], dom)

    # --- Email addresses --------------------------------------------------
    for m in _RE_EMAIL.finditer(data):
        _dedup_add(result.iocs["emails"], _safe_decode(m.group(0)))

    # --- PowerShell commands ----------------------------------------------
    for m in _RE_POWERSHELL.finditer(data):
        cmd = _safe_decode(m.group(0))
        if len(cmd) > 12:
            _dedup_add(result.iocs["powershell_commands"], cmd[:200])

    # --- Suspicious Windows paths -----------------------------------------
    for m in _RE_SUSPICIOUS_PATH.finditer(data):
        _dedup_add(result.iocs["suspicious_paths"], _safe_decode(m.group(0))[:200])

    # --- Crypto wallet addresses ------------------------------------------
    for pat in (_RE_BTC, _RE_BTC_BECH32, _RE_ETH, _RE_XMR):
        for m in pat.finditer(data):
            _dedup_add(result.iocs["crypto_wallets"], m.group(0).decode("ascii", errors="ignore"))

    # --- User-Agent strings -----------------------------------------------
    for m in _RE_USERAGENT.finditer(data):
        _dedup_add(result.iocs["user_agents"], _safe_decode(m.group(0))[:200])

    # --- Registry keys ----------------------------------------------------
    for m in _RE_REGISTRY.finditer(data):
        _dedup_add(result.iocs["registry_keys"], _safe_decode(m.group(0))[:200])

    return result
