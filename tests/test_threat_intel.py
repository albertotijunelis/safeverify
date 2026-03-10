"""Tests for HashGuard threat intelligence module."""

import json
from unittest.mock import MagicMock, patch

import pytest

from hashguard.threat_intel import (
    ThreatIntelHit,
    ThreatIntelResult,
    query_all,
    query_malwarebazaar,
    query_urlhaus,
    query_threatfox,
    query_alienvault_otx,
    query_abuseipdb,
    query_alienvault_ip,
    query_shodan_internetdb,
    query_ip_reputation,
    _CACHE,
    _CACHE_LOCK,
    _cache_get,
    _cache_set,
    _safe_request,
    _abuse_ch_headers,
)

FAKE_SHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"


@pytest.fixture(autouse=True)
def clear_ti_cache():
    """Clear threat intel cache before each test."""
    with _CACHE_LOCK:
        _CACHE.clear()
    yield
    with _CACHE_LOCK:
        _CACHE.clear()


class TestThreatIntelHit:
    """Tests for ThreatIntelHit dataclass."""

    def test_default(self):
        h = ThreatIntelHit(source="Test")
        assert h.source == "Test"
        assert h.found is False
        assert h.malware_family == ""
        assert h.tags == []

    def test_to_dict(self):
        h = ThreatIntelHit(
            source="MalwareBazaar",
            found=True,
            malware_family="Emotet",
            tags=["exe", "trojan"],
            details={"file_type": "exe"},
        )
        d = h.to_dict()
        assert d["source"] == "MalwareBazaar"
        assert d["found"] is True
        assert d["malware_family"] == "Emotet"
        assert "trojan" in d["tags"]


class TestThreatIntelResult:
    """Tests for ThreatIntelResult dataclass."""

    def test_default(self):
        r = ThreatIntelResult()
        assert r.hits == []
        assert r.total_sources == 0
        assert r.flagged_count == 0

    def test_to_dict(self):
        hit = ThreatIntelHit(source="Test", found=True)
        r = ThreatIntelResult(hits=[hit], total_sources=1, flagged_count=1)
        d = r.to_dict()
        assert d["total_sources"] == 1
        assert d["flagged_count"] == 1
        assert len(d["hits"]) == 1


class TestQueryMalwareBazaar:
    """Tests for MalwareBazaar query with mocked requests."""

    @patch("requests.post")
    def test_hash_not_found(self, mock_post):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"query_status": "hash_not_found"}
        mock_post.return_value = mock_resp

        hit = query_malwarebazaar(FAKE_SHA256)
        assert hit.source == "MalwareBazaar"
        assert hit.found is False

    @patch("requests.post")
    def test_hash_found(self, mock_post):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "query_status": "ok",
            "data": [
                {
                    "signature": "Emotet",
                    "tags": ["exe", "trojan"],
                    "file_type": "exe",
                    "reporter": "abuse_ch",
                    "first_seen": "2024-01-01",
                    "last_seen": "2024-06-01",
                    "delivery_method": "email",
                }
            ],
        }
        mock_post.return_value = mock_resp

        hit = query_malwarebazaar(FAKE_SHA256)
        assert hit.found is True
        assert hit.malware_family == "Emotet"
        assert "trojan" in hit.tags

    @patch("requests.post")
    def test_api_error(self, mock_post):
        mock_resp = MagicMock()
        mock_resp.status_code = 500
        mock_post.return_value = mock_resp

        hit = query_malwarebazaar(FAKE_SHA256)
        assert hit.found is False


class TestQueryURLhaus:
    """Tests for URLhaus query with mocked requests."""

    @patch("requests.post")
    def test_hash_not_found(self, mock_post):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"query_status": "hash_not_found"}
        mock_post.return_value = mock_resp

        hit = query_urlhaus(FAKE_SHA256)
        assert hit.source == "URLhaus"
        assert hit.found is False

    @patch("requests.post")
    def test_hash_found(self, mock_post):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "query_status": "ok",
            "signature": "Mirai",
            "tags": ["elf", "botnet"],
            "file_type": "elf",
            "file_size": "12345",
            "urls": [{"url": "http://example.com/payload"}],
            "firstseen": "2024-01-01",
            "lastseen": "2024-06-01",
        }
        mock_post.return_value = mock_resp

        hit = query_urlhaus(FAKE_SHA256)
        assert hit.found is True
        assert hit.malware_family == "Mirai"
        assert hit.details["url_count"] == 1


class TestQueryAll:
    """Tests for combined query function."""

    @patch("hashguard.threat_intel.query_threatfox")
    @patch("hashguard.threat_intel.query_alienvault_otx")
    @patch("hashguard.threat_intel.query_urlhaus")
    @patch("hashguard.threat_intel.query_malwarebazaar")
    def test_no_hits(self, mock_mb, mock_uh, mock_otx, mock_tf):
        mock_mb.return_value = ThreatIntelHit(source="MalwareBazaar", found=False)
        mock_uh.return_value = ThreatIntelHit(source="URLhaus", found=False)
        mock_otx.return_value = ThreatIntelHit(source="AlienVault OTX", found=False)
        mock_tf.return_value = ThreatIntelHit(source="ThreatFox", found=False)

        result = query_all(FAKE_SHA256)
        assert result.total_sources == 4
        assert result.flagged_count == 0

    @patch("hashguard.threat_intel.query_threatfox")
    @patch("hashguard.threat_intel.query_alienvault_otx")
    @patch("hashguard.threat_intel.query_urlhaus")
    @patch("hashguard.threat_intel.query_malwarebazaar")
    def test_one_hit(self, mock_mb, mock_uh, mock_otx, mock_tf):
        mock_mb.return_value = ThreatIntelHit(
            source="MalwareBazaar", found=True, malware_family="Emotet"
        )
        mock_uh.return_value = ThreatIntelHit(source="URLhaus", found=False)
        mock_otx.return_value = ThreatIntelHit(source="AlienVault OTX", found=False)
        mock_tf.return_value = ThreatIntelHit(source="ThreatFox", found=False)

        result = query_all(FAKE_SHA256)
        assert result.total_sources == 4
        assert result.flagged_count == 1

    @patch("hashguard.threat_intel.query_threatfox")
    @patch("hashguard.threat_intel.query_alienvault_otx")
    @patch("hashguard.threat_intel.query_urlhaus")
    @patch("hashguard.threat_intel.query_malwarebazaar")
    def test_both_hit(self, mock_mb, mock_uh, mock_otx, mock_tf):
        mock_mb.return_value = ThreatIntelHit(source="MalwareBazaar", found=True)
        mock_uh.return_value = ThreatIntelHit(source="URLhaus", found=True)
        mock_otx.return_value = ThreatIntelHit(source="AlienVault OTX", found=False)
        mock_tf.return_value = ThreatIntelHit(source="ThreatFox", found=False)

        result = query_all(FAKE_SHA256)
        assert result.flagged_count == 2

    @patch("hashguard.threat_intel.query_threatfox")
    @patch("hashguard.threat_intel.query_alienvault_otx")
    @patch("hashguard.threat_intel.query_urlhaus")
    @patch("hashguard.threat_intel.query_malwarebazaar")
    def test_successful_sources_tracked(self, mock_mb, mock_uh, mock_otx, mock_tf):
        mock_mb.return_value = ThreatIntelHit(source="MalwareBazaar", found=False)
        mock_uh.return_value = ThreatIntelHit(source="URLhaus", found=False)
        mock_otx.return_value = ThreatIntelHit(source="AlienVault OTX", found=False)
        mock_tf.return_value = ThreatIntelHit(source="ThreatFox", found=False)

        result = query_all(FAKE_SHA256)
        assert result.successful_sources == 4

    @patch("hashguard.threat_intel.query_threatfox")
    @patch("hashguard.threat_intel.query_alienvault_otx")
    @patch("hashguard.threat_intel.query_urlhaus")
    @patch("hashguard.threat_intel.query_malwarebazaar")
    def test_failed_source_not_counted(self, mock_mb, mock_uh, mock_otx, mock_tf):
        mock_mb.return_value = ThreatIntelHit(source="MalwareBazaar", found=False)
        mock_uh.__name__ = "query_urlhaus"
        mock_uh.side_effect = Exception("timeout")
        mock_otx.return_value = ThreatIntelHit(source="AlienVault OTX", found=False)
        mock_tf.return_value = ThreatIntelHit(source="ThreatFox", found=False)

        result = query_all(FAKE_SHA256)
        assert result.successful_sources == 3
        assert result.total_sources == 4
        assert len(result.hits) == 4


class TestQueryThreatFox:
    """Tests for ThreatFox query."""

    @patch("hashguard.threat_intel._safe_request")
    def test_not_found(self, mock_req):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"query_status": "no_result", "data": []}
        mock_req.return_value = mock_resp

        hit = query_threatfox(FAKE_SHA256)
        assert hit.source == "ThreatFox"
        assert hit.found is False

    @patch("hashguard.threat_intel._safe_request")
    def test_found(self, mock_req):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "query_status": "ok",
            "data": [
                {
                    "malware_printable": "Cobalt Strike",
                    "tags": ["c2", "beacon"],
                    "ioc_type": "payload_delivery",
                    "threat_type": "payload",
                    "confidence_level": 90,
                    "first_seen_utc": "2024-01-01",
                    "last_seen_utc": "2024-06-01",
                    "reference": "https://example.com",
                    "reporter": "researcher",
                }
            ],
        }
        mock_req.return_value = mock_resp

        hit = query_threatfox(FAKE_SHA256)
        assert hit.found is True
        assert hit.malware_family == "Cobalt Strike"
        assert hit.details["confidence_level"] == 90

    @patch("hashguard.threat_intel._safe_request")
    def test_api_returns_none(self, mock_req):
        mock_req.return_value = None
        hit = query_threatfox(FAKE_SHA256)
        assert hit.found is False


class TestQueryAlienVaultOTX:
    """Tests for AlienVault OTX hash query."""

    @patch("requests.get")
    def test_not_found_404(self, mock_get):
        mock_resp = MagicMock()
        mock_resp.status_code = 404
        mock_get.return_value = mock_resp

        hit = query_alienvault_otx(FAKE_SHA256)
        assert hit.found is False

    @patch("requests.get")
    def test_no_pulses(self, mock_get):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"pulse_info": {"count": 0, "pulses": []}}
        mock_get.return_value = mock_resp

        hit = query_alienvault_otx(FAKE_SHA256)
        assert hit.found is False

    @patch("requests.get")
    def test_has_pulses(self, mock_get):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "pulse_info": {
                "count": 3,
                "pulses": [{"name": "APT28 Campaign", "tags": ["apt", "russia"]}],
            },
            "type_title": "FileHash-SHA256",
        }
        mock_get.return_value = mock_resp

        hit = query_alienvault_otx(FAKE_SHA256)
        assert hit.found is True
        assert hit.malware_family == "APT28 Campaign"
        assert hit.details["pulse_count"] == 3


class TestQueryAbuseIPDB:
    """Tests for AbuseIPDB query."""

    def test_no_api_key(self):
        with patch.dict("os.environ", {}, clear=True):
            hit = query_abuseipdb("1.2.3.4", api_key="")
            assert hit.found is False
            assert hit.source == "AbuseIPDB"

    @patch("requests.get")
    def test_found(self, mock_get):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "data": {
                "abuseConfidenceScore": 85,
                "isp": "Evil ISP",
                "countryCode": "RU",
                "totalReports": 42,
            }
        }
        mock_get.return_value = mock_resp

        hit = query_abuseipdb("1.2.3.4", api_key="test-key")
        assert hit.found is True
        assert hit.details["abuse_confidence"] == 85

    @patch("requests.get")
    def test_clean_ip(self, mock_get):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "data": {"abuseConfidenceScore": 0, "totalReports": 0}
        }
        mock_get.return_value = mock_resp

        hit = query_abuseipdb("8.8.8.8", api_key="test-key")
        assert hit.found is False


class TestQueryAlienVaultIP:
    """Tests for AlienVault OTX IP query."""

    @patch("requests.get")
    def test_no_pulses(self, mock_get):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"pulse_info": {"count": 0}}
        mock_get.return_value = mock_resp

        hit = query_alienvault_ip("1.2.3.4")
        assert hit.found is False

    @patch("requests.get")
    def test_has_pulses(self, mock_get):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "pulse_info": {"count": 5},
            "country_name": "Russia",
        }
        mock_get.return_value = mock_resp

        hit = query_alienvault_ip("1.2.3.4")
        assert hit.found is True
        assert "5" in hit.malware_family

    @patch("requests.get")
    def test_server_error(self, mock_get):
        mock_resp = MagicMock()
        mock_resp.status_code = 500
        mock_get.return_value = mock_resp

        hit = query_alienvault_ip("1.2.3.4")
        assert hit.found is False


class TestQueryShodanInternetDB:
    """Tests for Shodan InternetDB query."""

    @patch("hashguard.threat_intel._safe_request")
    def test_not_found(self, mock_req):
        mock_resp = MagicMock()
        mock_resp.status_code = 404
        mock_req.return_value = mock_resp

        hit = query_shodan_internetdb("1.2.3.4")
        assert hit.found is False

    @patch("hashguard.threat_intel._safe_request")
    def test_found_with_vulns(self, mock_req):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "ports": [22, 80, 443],
            "vulns": ["CVE-2024-1234"],
            "hostnames": ["evil.example.com"],
            "cpes": ["cpe:/a:apache:httpd"],
        }
        mock_req.return_value = mock_resp

        hit = query_shodan_internetdb("1.2.3.4")
        assert hit.found is True
        assert "1 CVEs" in hit.malware_family
        assert hit.details["ports"] == [22, 80, 443]

    @patch("hashguard.threat_intel._safe_request")
    def test_no_data(self, mock_req):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"ports": [], "vulns": [], "hostnames": []}
        mock_req.return_value = mock_resp

        hit = query_shodan_internetdb("1.2.3.4")
        assert hit.found is False


class TestQueryIPReputation:
    """Tests for combined IP reputation query."""

    @patch("hashguard.threat_intel.query_shodan_internetdb")
    @patch("hashguard.threat_intel.query_alienvault_ip")
    def test_no_hits(self, mock_otx, mock_shodan):
        mock_otx.return_value = ThreatIntelHit(source="AlienVault OTX", found=False)
        mock_shodan.return_value = ThreatIntelHit(source="Shodan InternetDB", found=False)

        result = query_ip_reputation("8.8.8.8")
        assert result.total_sources == 2
        assert result.flagged_count == 0
        assert result.successful_sources == 2

    @patch("hashguard.threat_intel.query_shodan_internetdb")
    @patch("hashguard.threat_intel.query_alienvault_ip")
    def test_one_hit(self, mock_otx, mock_shodan):
        mock_otx.return_value = ThreatIntelHit(source="AlienVault OTX", found=True)
        mock_shodan.return_value = ThreatIntelHit(source="Shodan InternetDB", found=False)

        result = query_ip_reputation("1.2.3.4")
        assert result.flagged_count == 1


class TestCache:
    """Tests for the TTL cache."""

    def test_set_and_get(self):
        _cache_set("testkey", "testvalue")
        assert _cache_get("testkey") == "testvalue"

    def test_miss(self):
        assert _cache_get("nonexistent_key_xyz") is None

    @patch("hashguard.threat_intel.time")
    def test_expiry(self, mock_time):
        mock_time.time.return_value = 1000.0
        _cache_set("expire_test", "val")
        mock_time.time.return_value = 2000.0  # 1000s later, past 600s TTL
        assert _cache_get("expire_test") is None


class TestSafeRequest:
    """Tests for _safe_request helper."""

    @patch("requests.get")
    def test_get_success(self, mock_get):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_get.return_value = mock_resp

        resp = _safe_request("get", "https://example.com/api")
        assert resp.status_code == 200

    @patch("requests.post")
    def test_post_success(self, mock_post):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_post.return_value = mock_resp

        resp = _safe_request("post", "https://example.com/api", json={"q": "test"})
        assert resp.status_code == 200

    @patch("requests.get")
    def test_request_exception(self, mock_get):
        mock_get.side_effect = Exception("connection error")
        resp = _safe_request("get", "https://example.com/api")
        assert resp is None


class TestAbuseCHHeaders:
    """Tests for _abuse_ch_headers auth helper."""

    def test_returns_auth_key_from_env(self, monkeypatch):
        monkeypatch.setenv("ABUSE_CH_API_KEY", "env-key-test")
        headers = _abuse_ch_headers()
        assert headers["Auth-Key"] == "env-key-test"

    def test_empty_when_no_key(self, monkeypatch):
        monkeypatch.delenv("ABUSE_CH_API_KEY", raising=False)
        with patch("hashguard.config.get_default_config") as mock_cfg:
            mock_cfg.return_value.abuse_ch_api_key = None
            headers = _abuse_ch_headers()
            assert headers == {}

    def test_auth_key_from_config(self, monkeypatch):
        monkeypatch.delenv("ABUSE_CH_API_KEY", raising=False)
        with patch("hashguard.config.get_default_config") as mock_cfg:
            mock_cfg.return_value.abuse_ch_api_key = "config-key-789"
            headers = _abuse_ch_headers()
            assert headers["Auth-Key"] == "config-key-789"


class TestMalwareBazaarAuthHeader:
    """Verify that query_malwarebazaar passes Auth-Key header."""

    @patch("hashguard.threat_intel._abuse_ch_headers")
    @patch("requests.post")
    def test_sends_auth_header(self, mock_post, mock_headers):
        mock_headers.return_value = {"Auth-Key": "test-key"}
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"query_status": "hash_not_found"}
        mock_post.return_value = mock_resp
        query_malwarebazaar(FAKE_SHA256)
        call_kwargs = mock_post.call_args
        assert call_kwargs.kwargs.get("headers", {}).get("Auth-Key") == "test-key"
