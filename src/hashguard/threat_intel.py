"""Multi-source threat intelligence for HashGuard.

Queries public APIs for hash reputation:
- MalwareBazaar (abuse.ch) — requires Auth-Key
- URLhaus (abuse.ch) — requires Auth-Key
- ThreatFox (abuse.ch) — requires Auth-Key
- AlienVault OTX — free, no key required for basic lookups
- Shodan InternetDB — free, no key: open ports, CVEs, hostnames for IPs
- VirusTotal — requires API key (handled separately in scanner.py)

IP reputation:
- AbuseIPDB — free tier with API key (250 checks/day)
- AlienVault OTX — free, no key required
- Shodan InternetDB — free, no key

Result caching: TTL-based in-memory cache to avoid redundant API calls.
"""

import os
import threading
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from hashguard.logger import get_logger

logger = get_logger(__name__)


# ── TTL Cache (thread-safe) ────────────────────────────────────────────────────────
_CACHE: Dict[str, tuple] = {}  # key -> (result, timestamp)
_CACHE_TTL = 600  # 10 minutes
_CACHE_LOCK = threading.Lock()


def _cache_get(key: str):
    """Return cached value or None if expired/missing."""
    with _CACHE_LOCK:
        entry = _CACHE.get(key)
        if entry is None:
            return None
        value, ts = entry
        if time.time() - ts > _CACHE_TTL:
            del _CACHE[key]
            return None
        return value


def _cache_set(key: str, value):
    with _CACHE_LOCK:
        _CACHE[key] = (value, time.time())


def _safe_request(method: str, url: str, **kwargs):
    """Centralized request helper with timeout, error handling, and logging."""
    try:
        import requests

        kwargs.setdefault("timeout", 10)
        kwargs.setdefault("verify", True)
        resp = getattr(requests, method)(url, **kwargs)
        return resp
    except ImportError:
        logger.debug("requests library not available")
        return None
    except Exception as e:
        logger.debug(f"Request to {url} failed: {e}")
        return None


def _abuse_ch_headers() -> Dict[str, str]:
    """Return headers dict with Auth-Key if configured."""
    headers: Dict[str, str] = {}
    key = os.getenv("ABUSE_CH_API_KEY")
    if not key:
        try:
            from hashguard.config import get_default_config
            key = get_default_config().abuse_ch_api_key
        except Exception:
            pass
    if key:
        headers["Auth-Key"] = key
    return headers


@dataclass
class ThreatIntelHit:
    source: str
    found: bool = False
    malware_family: str = ""
    tags: List[str] = field(default_factory=list)
    details: Dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "source": self.source,
            "found": self.found,
            "malware_family": self.malware_family,
            "tags": self.tags,
            "details": self.details,
        }


@dataclass
class ThreatIntelResult:
    hits: List[ThreatIntelHit] = field(default_factory=list)
    total_sources: int = 0
    flagged_count: int = 0
    successful_sources: int = 0

    def to_dict(self) -> dict:
        return {
            "hits": [h.to_dict() for h in self.hits],
            "total_sources": self.total_sources,
            "flagged_count": self.flagged_count,
            "successful_sources": self.successful_sources,
        }


def query_malwarebazaar(sha256: str) -> ThreatIntelHit:
    """Query MalwareBazaar by SHA-256 hash."""
    hit = ThreatIntelHit(source="MalwareBazaar")
    cached = _cache_get(f"bazaar:{sha256}")
    if cached is not None:
        return cached
    try:
        import requests

        resp = requests.post(
            "https://mb-api.abuse.ch/api/v1/",
            data={"query": "get_info", "hash": sha256},
            headers=_abuse_ch_headers(),
            timeout=10,
            verify=True,
        )
        if resp.status_code != 200:
            return hit
        data = resp.json()
        if data.get("query_status") == "hash_not_found":
            _cache_set(f"bazaar:{sha256}", hit)
            return hit
        if data.get("query_status") == "ok" and data.get("data"):
            entry = data["data"][0]
            hit.found = True
            hit.malware_family = entry.get("signature") or ""
            hit.tags = entry.get("tags") or []
            hit.details = {
                "file_type": entry.get("file_type", ""),
                "reporter": entry.get("reporter", ""),
                "first_seen": entry.get("first_seen", ""),
                "last_seen": entry.get("last_seen", ""),
                "delivery_method": entry.get("delivery_method", ""),
            }
    except ImportError:
        logger.debug("requests not available for MalwareBazaar query")
    except Exception as e:
        logger.debug(f"MalwareBazaar query failed: {e}")
    _cache_set(f"bazaar:{sha256}", hit)
    return hit


def query_urlhaus(sha256: str) -> ThreatIntelHit:
    """Query URLhaus payload database by SHA-256."""
    hit = ThreatIntelHit(source="URLhaus")
    cached = _cache_get(f"urlhaus:{sha256}")
    if cached is not None:
        return cached
    try:
        import requests

        resp = requests.post(
            "https://urlhaus-api.abuse.ch/v1/payload/",
            data={"sha256_hash": sha256},
            headers=_abuse_ch_headers(),
            timeout=10,
            verify=True,
        )
        if resp.status_code != 200:
            return hit
        data = resp.json()
        if data.get("query_status") == "hash_not_found":
            _cache_set(f"urlhaus:{sha256}", hit)
            return hit
        if data.get("query_status") == "ok":
            hit.found = True
            hit.malware_family = data.get("signature") or ""
            hit.tags = data.get("tags") or []
            urls = data.get("urls", [])
            hit.details = {
                "file_type": data.get("file_type", ""),
                "file_size": data.get("file_size", ""),
                "url_count": len(urls),
                "first_seen": data.get("firstseen", ""),
                "last_seen": data.get("lastseen", ""),
            }
    except ImportError:
        logger.debug("requests not available for URLhaus query")
    except Exception as e:
        logger.debug(f"URLhaus query failed: {e}")
    _cache_set(f"urlhaus:{sha256}", hit)
    return hit


def query_threatfox(sha256: str) -> ThreatIntelHit:
    """Query ThreatFox IOC database (abuse.ch).

    ThreatFox tracks IOCs associated with malware families including
    C2 IPs, payload hashes, and domains.
    """
    hit = ThreatIntelHit(source="ThreatFox")
    cached = _cache_get(f"threatfox:{sha256}")
    if cached is not None:
        return cached
    try:
        resp = _safe_request(
            "post",
            "https://threatfox-api.abuse.ch/api/v1/",
            json={"query": "search_hash", "hash": sha256},
            headers=_abuse_ch_headers(),
        )
        if resp is None or resp.status_code != 200:
            return hit
        data = resp.json()
        if data.get("query_status") != "ok" or not data.get("data"):
            _cache_set(f"threatfox:{sha256}", hit)
            return hit
        entry = data["data"][0]
        hit.found = True
        hit.malware_family = entry.get("malware_printable", "")
        hit.tags = entry.get("tags") or []
        hit.details = {
            "ioc_type": entry.get("ioc_type", ""),
            "threat_type": entry.get("threat_type", ""),
            "confidence_level": entry.get("confidence_level", 0),
            "first_seen": entry.get("first_seen_utc", ""),
            "last_seen": entry.get("last_seen_utc", ""),
            "reference": entry.get("reference", ""),
            "reporter": entry.get("reporter", ""),
        }
    except Exception as e:
        logger.debug(f"ThreatFox query failed: {e}")
    _cache_set(f"threatfox:{sha256}", hit)
    return hit


def query_all(sha256: str) -> ThreatIntelResult:
    """Query all free threat intelligence sources for a SHA-256 hash.

    Queries are executed in parallel for faster results.
    """
    from concurrent.futures import ThreadPoolExecutor, as_completed

    result = ThreatIntelResult()
    sources = [query_malwarebazaar, query_urlhaus, query_alienvault_otx, query_threatfox]
    result.total_sources = len(sources)

    with ThreadPoolExecutor(max_workers=len(sources)) as pool:
        futures = {pool.submit(fn, sha256): fn for fn in sources}
        for future in as_completed(futures):
            try:
                hit = future.result()
                result.successful_sources += 1
            except Exception as exc:
                fn = futures[future]
                logger.debug(f"Threat intel query {fn.__name__} raised: {exc}")
                hit = ThreatIntelHit(source=fn.__name__)
            result.hits.append(hit)
            if hit.found:
                result.flagged_count += 1

    return result


# --------------------------------------------------------------------------
# AlienVault OTX (free, no key required for basic hash lookups)
# --------------------------------------------------------------------------


def query_alienvault_otx(sha256: str) -> ThreatIntelHit:
    """Query AlienVault OTX for file hash reputation (free, no key)."""
    hit = ThreatIntelHit(source="AlienVault OTX")
    cached = _cache_get(f"otx:{sha256}")
    if cached is not None:
        return cached
    try:
        import requests

        resp = requests.get(
            f"https://otx.alienvault.com/api/v1/indicators/file/{sha256}/general",
            headers={"Accept": "application/json"},
            timeout=10,
            verify=True,
        )
        if resp.status_code == 404:
            _cache_set(f"otx:{sha256}", hit)
            return hit
        if resp.status_code != 200:
            return hit
        data = resp.json()
        pulses = data.get("pulse_info", {}).get("count", 0)
        if pulses > 0:
            hit.found = True
            hit.malware_family = (
                data.get("pulse_info", {}).get("pulses", [{}])[0].get("name", "Threat reported")
            )
            hit.tags = data.get("pulse_info", {}).get("pulses", [{}])[0].get("tags", [])[:10]
            hit.details = {
                "pulse_count": pulses,
                "type_title": data.get("type_title", ""),
            }
    except ImportError:
        logger.debug("requests not available for OTX query")
    except Exception as e:
        logger.debug(f"AlienVault OTX query failed: {e}")
    _cache_set(f"otx:{sha256}", hit)
    return hit


# --------------------------------------------------------------------------
# AbuseIPDB (free tier, requires API key)
# --------------------------------------------------------------------------


def query_abuseipdb(ip: str, api_key: str = "") -> ThreatIntelHit:
    """Query AbuseIPDB for IP reputation (free tier, 250 checks/day)."""
    import os as _os

    hit = ThreatIntelHit(source="AbuseIPDB")
    api_key = api_key or _os.environ.get("ABUSEIPDB_API_KEY", "")
    if not api_key:
        return hit
    try:
        import requests

        resp = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            params={"ipAddress": ip, "maxAgeInDays": 90},
            headers={"Key": api_key, "Accept": "application/json"},
            timeout=10,
            verify=True,
        )
        if resp.status_code != 200:
            return hit
        data = resp.json().get("data", {})
        score = data.get("abuseConfidenceScore", 0)
        if score > 0:
            hit.found = True
            hit.malware_family = f"Abuse score {score}%"
            hit.details = {
                "isp": data.get("isp", ""),
                "country": data.get("countryCode", ""),
                "total_reports": data.get("totalReports", 0),
                "abuse_confidence": score,
            }
    except ImportError:
        pass
    except Exception as e:
        logger.debug(f"AbuseIPDB query failed: {e}")
    return hit


def query_alienvault_ip(ip: str) -> ThreatIntelHit:
    """Query AlienVault OTX for IP reputation (free, no key)."""
    hit = ThreatIntelHit(source="AlienVault OTX")
    try:
        import requests

        resp = requests.get(
            f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general",
            headers={"Accept": "application/json"},
            timeout=10,
            verify=True,
        )
        if resp.status_code != 200:
            return hit
        data = resp.json()
        pulses = data.get("pulse_info", {}).get("count", 0)
        if pulses > 0:
            hit.found = True
            hit.malware_family = f"Reported in {pulses} threat pulse(s)"
            hit.details = {
                "pulse_count": pulses,
                "country": data.get("country_name", ""),
            }
    except ImportError:
        pass
    except Exception as e:
        logger.debug(f"AlienVault OTX IP query failed: {e}")
    return hit


def query_shodan_internetdb(ip: str) -> ThreatIntelHit:
    """Query Shodan InternetDB for IP info (free, no key).

    Returns open ports, known vulnerabilities, and hostnames.
    """
    hit = ThreatIntelHit(source="Shodan InternetDB")
    cached = _cache_get(f"shodan:{ip}")
    if cached is not None:
        return cached
    try:
        resp = _safe_request("get", f"https://internetdb.shodan.io/{ip}")
        if resp is None or resp.status_code != 200:
            _cache_set(f"shodan:{ip}", hit)
            return hit
        data = resp.json()
        ports = data.get("ports", [])
        vulns = data.get("vulns", [])
        hostnames = data.get("hostnames", [])
        if ports or vulns or hostnames:
            hit.found = True
            hit.malware_family = f"{len(vulns)} CVEs, {len(ports)} open ports" if vulns else ""
            hit.tags = vulns[:10]
            hit.details = {
                "ports": ports,
                "vulns": vulns,
                "hostnames": hostnames,
                "cpes": data.get("cpes", []),
            }
    except Exception as e:
        logger.debug(f"Shodan InternetDB query failed: {e}")
    _cache_set(f"shodan:{ip}", hit)
    return hit


def query_ip_reputation(ip: str) -> ThreatIntelResult:
    """Query all IP reputation sources for a given IP address."""
    from concurrent.futures import ThreadPoolExecutor, as_completed

    result = ThreatIntelResult()
    sources = [query_alienvault_ip, query_shodan_internetdb]
    # AbuseIPDB only if key is available
    import os as _os

    if _os.environ.get("ABUSEIPDB_API_KEY"):
        sources.append(lambda i: query_abuseipdb(i))
    result.total_sources = len(sources)

    with ThreadPoolExecutor(max_workers=len(sources)) as pool:
        futures = {pool.submit(fn, ip): fn for fn in sources}
        for future in as_completed(futures):
            try:
                hit = future.result()
                result.successful_sources += 1
            except Exception:
                hit = ThreatIntelHit(source="unknown")
            result.hits.append(hit)
            if hit.found:
                result.flagged_count += 1

    return result
