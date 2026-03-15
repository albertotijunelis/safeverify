"""Tests for the Threat Feed API router."""

import json
import os
import threading
from unittest.mock import patch

import pytest

from hashguard import database
from hashguard.web.api import HAS_FASTAPI, app

pytestmark = pytest.mark.skipif(not HAS_FASTAPI, reason="FastAPI not installed")


@pytest.fixture(autouse=True)
def _use_tmp_db(tmp_path, monkeypatch):
    monkeypatch.setattr(database, "_DB_DIR", str(tmp_path))
    monkeypatch.setattr(database, "_DB_PATH", str(tmp_path / "hashguard.db"))
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path / 'hashguard.db'}")
    from hashguard import models
    models.reset_engine()
    database._local = threading.local()
    database._DATASET_SCHEMA_APPLIED = False


@pytest.fixture
def client():
    from starlette.testclient import TestClient

    try:
        from hashguard.web.api import limiter
        if limiter:
            limiter.reset()
    except Exception:
        pass
    return TestClient(app)


_MAL_SAMPLE = {
    "path": "/tmp/evil.exe",
    "file_size": 5000,
    "hashes": {"sha256": "a" * 64, "sha1": "b" * 40, "md5": "c" * 32},
    "risk_score": {"score": 80, "verdict": "malicious"},
    "malicious": True,
    "description": "Trojan detected",
    "strings_info": {"has_iocs": True, "iocs": {"urls": ["http://evil.test/c2"], "ips": ["10.0.0.1"]}},
    "fuzzy_hashes": {"hashes": {"ssdeep": "3:xyz", "tlsh": "T1abc"}},
    "family_detection": {"family": "Emotet", "confidence": 0.95},
}

_CLEAN_SAMPLE = {
    "path": "/tmp/safe.exe",
    "file_size": 1000,
    "hashes": {"sha256": "f" * 64, "sha1": "e" * 40, "md5": "d" * 32},
    "risk_score": {"score": 5, "verdict": "clean"},
    "malicious": False,
    "description": "Clean",
    "strings_info": {},
    "fuzzy_hashes": {"hashes": {}},
}


def _seed(n_mal=1, n_clean=1):
    """Insert sample data into the DB."""
    for i in range(n_mal):
        s = dict(_MAL_SAMPLE, hashes={**_MAL_SAMPLE["hashes"], "sha256": f"{i:064x}"})
        database.store_sample(s)
    for i in range(n_clean):
        s = dict(_CLEAN_SAMPLE, hashes={**_CLEAN_SAMPLE["hashes"], "sha256": f"{0xf0 + i:064x}"})
        database.store_sample(s)


# ── /api/feeds/recent ──────────────────────────────────────────────────────


class TestFeedRecent:
    def test_empty(self, client):
        r = client.get("/api/feeds/recent")
        assert r.status_code == 200
        assert r.json()["total"] == 0

    def test_recent_returns_samples(self, client):
        _seed(2, 1)
        r = client.get("/api/feeds/recent")
        data = r.json()
        assert data["total"] == 3
        assert len(data["samples"]) == 3

    def test_filter_by_verdict(self, client):
        _seed(2, 1)
        r = client.get("/api/feeds/recent?verdict=malicious")
        data = r.json()
        assert data["total"] == 2
        for s in data["samples"]:
            assert s["verdict"] == "malicious"

    def test_pagination(self, client):
        _seed(5, 0)
        r = client.get("/api/feeds/recent?limit=2&offset=0")
        assert len(r.json()["samples"]) == 2
        r2 = client.get("/api/feeds/recent?limit=2&offset=2")
        assert len(r2.json()["samples"]) == 2


# ── /api/feeds/iocs ────────────────────────────────────────────────────────


class TestFeedIOCs:
    def test_empty(self, client):
        r = client.get("/api/feeds/iocs")
        assert r.status_code == 200
        assert r.json()["total"] == 0

    def test_returns_iocs(self, client):
        _seed(1, 0)
        r = client.get("/api/feeds/iocs")
        data = r.json()
        assert data["total"] > 0

    def test_csv_format(self, client):
        _seed(1, 0)
        r = client.get("/api/feeds/iocs?fmt=csv")
        assert r.status_code == 200
        assert "text/csv" in r.headers["content-type"]
        assert "ioc_type" in r.text

    def test_txt_format(self, client):
        _seed(1, 0)
        r = client.get("/api/feeds/iocs?fmt=txt")
        assert r.status_code == 200
        assert "text/plain" in r.headers["content-type"]

    def test_filter_by_type(self, client):
        _seed(1, 0)
        r = client.get("/api/feeds/iocs?ioc_type=url")
        for ioc in r.json()["iocs"]:
            assert ioc["ioc_type"] == "url"


# ── /api/feeds/families ────────────────────────────────────────────────────


class TestFeedFamilies:
    def test_empty(self, client):
        r = client.get("/api/feeds/families")
        assert r.status_code == 200
        assert r.json()["families"] == []

    def test_returns_families(self, client):
        _seed(2, 0)
        r = client.get("/api/feeds/families")
        fams = r.json()["families"]
        assert len(fams) >= 1
        assert fams[0]["family"] == "Emotet"


# ── /api/feeds/hashes ──────────────────────────────────────────────────────


class TestFeedHashes:
    def test_txt_default(self, client):
        _seed(3, 0)
        r = client.get("/api/feeds/hashes")
        assert r.status_code == 200
        assert "text/plain" in r.headers["content-type"]
        lines = r.text.strip().split("\n")
        assert len(lines) == 3

    def test_json_format(self, client):
        _seed(2, 0)
        r = client.get("/api/feeds/hashes?fmt=json")
        data = r.json()
        assert data["hash_type"] == "sha256"
        assert len(data["hashes"]) == 2

    def test_md5(self, client):
        _seed(1, 0)
        r = client.get("/api/feeds/hashes?hash_type=md5&fmt=json")
        data = r.json()
        assert data["hash_type"] == "md5"

    def test_no_clean_in_default(self, client):
        _seed(1, 1)
        r = client.get("/api/feeds/hashes?fmt=json")
        data = r.json()
        # Clean samples should not appear in default malicious blocklist
        assert len(data["hashes"]) == 1


# ── /api/feeds/stix ────────────────────────────────────────────────────────


class TestFeedSTIX:
    def test_empty(self, client):
        r = client.get("/api/feeds/stix")
        assert r.status_code == 200
        bundle = r.json()
        assert bundle["type"] == "bundle"

    def test_indicators(self, client):
        _seed(1, 0)
        r = client.get("/api/feeds/stix")
        bundle = r.json()
        types = [obj["type"] for obj in bundle["objects"]]
        assert "indicator" in types
        assert "malware" in types
        assert "relationship" in types

    def test_content_type(self, client):
        r = client.get("/api/feeds/stix")
        assert "stix+json" in r.headers["content-type"]


# ── /api/feeds/taxii ───────────────────────────────────────────────────────


class TestFeedTAXII:
    def test_discovery(self, client):
        r = client.get("/api/feeds/taxii")
        assert r.status_code == 200
        data = r.json()
        assert "HashGuard" in data["title"]
        assert data["default"] == "/api/feeds/stix"


# ── /api/feeds/misp ────────────────────────────────────────────────────────


class TestFeedMISP:
    def test_empty(self, client):
        r = client.get("/api/feeds/misp")
        assert r.status_code == 200
        assert r.json()["response"] == []

    def test_events(self, client):
        _seed(1, 0)
        r = client.get("/api/feeds/misp")
        events = r.json()["response"]
        assert len(events) == 1
        ev = events[0]["Event"]
        assert "HashGuard" in ev["info"]
        attrs = [a["type"] for a in ev["Attribute"]]
        assert "sha256" in attrs
