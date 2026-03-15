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

# Well-known benign IPs (DNS, NTP, CDNs) — skip as IOCs
_BENIGN_IPS = frozenset({
    "8.8.8.8", "8.8.4.4",           # Google DNS
    "1.1.1.1", "1.0.0.1",           # Cloudflare DNS
    "9.9.9.9", "149.112.112.112",   # Quad9
    "208.67.222.222", "208.67.220.220",  # OpenDNS
    "4.2.2.1", "4.2.2.2",           # Level3 DNS
})

# Well-known benign domains — skip as IOCs
_BENIGN_DOMAIN_SUFFIXES = frozenset({
    "microsoft.com", "windows.com", "windowsupdate.com", "live.com",
    "office.com", "office365.com", "outlook.com", "bing.com",
    "google.com", "googleapis.com", "gstatic.com", "youtube.com",
    "github.com", "githubusercontent.com",
    "mozilla.org", "mozilla.com", "firefox.com",
    "apple.com", "icloud.com",
    "cloudflare.com", "akamai.net", "akamaized.net",
    "amazon.com", "amazonaws.com", "aws.amazon.com",
    "digicert.com", "verisign.com", "letsencrypt.org",
    "python.org", "pypi.org", "readthedocs.io",
    "w3.org", "xml.org", "iana.org",
})

# Standard registry paths that are commonly read by legitimate software
_BENIGN_REGISTRY_PREFIXES = (
    r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths",
    r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion",
    r"HKLM\SOFTWARE\Microsoft\Cryptography",
    r"HKLM\SYSTEM\CurrentControlSet\Control\Nls",
    r"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer",
    r"HKCU\Control Panel",
)


def _is_bogon(ip: str) -> bool:
    if any(ip.startswith(p) for p in _BOGON_PREFIXES):
        return True
    parts = ip.split(".")
    if len(parts) == 4 and parts[0] == "172":
        second = int(parts[1])
        if 16 <= second <= 31:
            return True
    return False


def _is_benign_domain(domain: str) -> bool:
    """Check if a domain belongs to a well-known benign organization."""
    d = domain.lower().rstrip(".")
    return any(d == s or d.endswith("." + s) for s in _BENIGN_DOMAIN_SUFFIXES)


def _is_benign_registry(key: str) -> bool:
    """Check if a registry path is a standard benign location."""
    k = key.upper()
    return any(k.startswith(p.upper()) for p in _BENIGN_REGISTRY_PREFIXES)


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
        return {
            "total_strings": self.total_strings,
            "has_iocs": self.has_iocs,
            "iocs": {k: v for k, v in self.iocs.items() if v},
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

    # --- URL extraction (skip URLs to benign domains) ----------------------
    for m in _RE_URL.finditer(data):
        url = _safe_decode(m.group(0))
        try:
            host = url.split("//", 1)[1].split("/", 1)[0].split(":")[0].lower()
        except Exception:
            host = ""
        if not _is_benign_domain(host):
            _dedup_add(result.iocs["urls"], url)

    # --- IP addresses (skip bogons and well-known benign) -----------------
    seen_ips: Set[str] = set()
    for m in _RE_IP.finditer(data):
        ip = m.group(0).decode("ascii", errors="ignore")
        if ip not in seen_ips and not _is_bogon(ip) and ip not in _BENIGN_IPS:
            seen_ips.add(ip)
            _dedup_add(result.iocs["ips"], ip)

    # --- Domains (skip benign) --------------------------------------------
    url_hosts = set()
    for u in result.iocs["urls"]:
        try:
            host = u.split("//", 1)[1].split("/", 1)[0].split(":")[0].lower()
            url_hosts.add(host)
        except Exception:
            pass
    for m in _RE_DOMAIN.finditer(data):
        dom = m.group(0).decode("ascii", errors="ignore").lower()
        if dom not in url_hosts and not _is_benign_domain(dom):
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

    # --- Registry keys (skip standard benign paths) ------------------------
    for m in _RE_REGISTRY.finditer(data):
        key = _safe_decode(m.group(0))[:200]
        if not _is_benign_registry(key):
            _dedup_add(result.iocs["registry_keys"], key)

    return result
