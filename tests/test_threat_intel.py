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
)

FAKE_SHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"


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

    @patch("hashguard.threat_intel.query_alienvault_otx")
    @patch("hashguard.threat_intel.query_urlhaus")
    @patch("hashguard.threat_intel.query_malwarebazaar")
    def test_no_hits(self, mock_mb, mock_uh, mock_otx):
        mock_mb.return_value = ThreatIntelHit(source="MalwareBazaar", found=False)
        mock_uh.return_value = ThreatIntelHit(source="URLhaus", found=False)
        mock_otx.return_value = ThreatIntelHit(source="AlienVault OTX", found=False)

        result = query_all(FAKE_SHA256)
        assert result.total_sources == 3
        assert result.flagged_count == 0

    @patch("hashguard.threat_intel.query_alienvault_otx")
    @patch("hashguard.threat_intel.query_urlhaus")
    @patch("hashguard.threat_intel.query_malwarebazaar")
    def test_one_hit(self, mock_mb, mock_uh, mock_otx):
        mock_mb.return_value = ThreatIntelHit(
            source="MalwareBazaar", found=True, malware_family="Emotet"
        )
        mock_uh.return_value = ThreatIntelHit(source="URLhaus", found=False)
        mock_otx.return_value = ThreatIntelHit(source="AlienVault OTX", found=False)

        result = query_all(FAKE_SHA256)
        assert result.total_sources == 3
        assert result.flagged_count == 1

    @patch("hashguard.threat_intel.query_alienvault_otx")
    @patch("hashguard.threat_intel.query_urlhaus")
    @patch("hashguard.threat_intel.query_malwarebazaar")
    def test_both_hit(self, mock_mb, mock_uh, mock_otx):
        mock_mb.return_value = ThreatIntelHit(source="MalwareBazaar", found=True)
        mock_uh.return_value = ThreatIntelHit(source="URLhaus", found=True)
        mock_otx.return_value = ThreatIntelHit(source="AlienVault OTX", found=False)

        result = query_all(FAKE_SHA256)
        assert result.flagged_count == 2
