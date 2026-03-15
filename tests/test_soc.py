"""Tests for the SOC Integration router."""

import json
import os
import threading

import pytest

from hashguard import database
from hashguard.web.api import HAS_FASTAPI, app

pytestmark = pytest.mark.skipif(not HAS_FASTAPI, reason="FastAPI not installed")


@pytest.fixture(autouse=True)
def _tmp_env(tmp_path, monkeypatch):
    monkeypatch.setenv("APPDATA", str(tmp_path))
    (tmp_path / "HashGuard").mkdir(exist_ok=True)
    monkeypatch.setattr(database, "_DB_DIR", str(tmp_path / "HashGuard"))
    monkeypatch.setattr(database, "_DB_PATH", str(tmp_path / "HashGuard" / "hashguard.db"))
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{tmp_path / 'HashGuard' / 'hashguard.db'}")
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


# ── Format converters ────────────────────────────────────────────────────


class TestFormatConverters:
    def test_to_cef(self):
        from hashguard.web.routers.soc_router import to_cef
        sample = {"sha256": "a" * 64, "filename": "bad.exe", "risk_score": 90,
                  "verdict": "malicious", "family": "Emotet", "analysis_date": "2026-01-01"}
        cef = to_cef(sample)
        assert cef.startswith("CEF:0|HashGuard|")
        assert "fileHash=" + "a" * 64 in cef
        assert "fname=bad.exe" in cef
        assert "|10|" in cef  # severity 10 for malicious

    def test_to_cef_suspicious(self):
        from hashguard.web.routers.soc_router import to_cef
        cef = to_cef({"verdict": "suspicious", "sha256": "b" * 64, "risk_score": 30})
        assert "|5|" in cef

    def test_to_ecs(self):
        from hashguard.web.routers.soc_router import to_ecs
        sample = {"sha256": "a" * 64, "md5": "c" * 32, "sha1": "b" * 40,
                  "filename": "t.exe", "file_size": 1000, "risk_score": 80,
                  "verdict": "malicious", "family": "Test", "description": "Bad",
                  "analysis_date": "2026-01-01"}
        ecs = to_ecs(sample)
        assert ecs["event"]["kind"] == "alert"
        assert ecs["file"]["hash"]["sha256"] == "a" * 64
        assert ecs["threat"]["software"]["name"] == "Test"
        assert ecs["hashguard"]["risk_score"] == 80

    def test_to_sentinel(self):
        from hashguard.web.routers.soc_router import to_sentinel
        sample = {"sha256": "a" * 64, "filename": "t.exe", "risk_score": 90,
                  "verdict": "malicious", "family": "Emotet", "description": "Trojan"}
        s = to_sentinel(sample)
        assert s["severity"] == "high"
        assert s["fileHashValue"] == "a" * 64
        assert "Emotet" in s["malwareFamilyNames"]


# ── Integration CRUD ─────────────────────────────────────────────────────


class TestIntegrationCRUD:
    def test_list_empty(self, client):
        r = client.get("/api/soc/integrations")
        assert r.status_code == 200
        assert r.json()["integrations"] == []

    def test_create(self, client):
        r = client.post("/api/soc/integrations", json={
            "type": "syslog",
            "name": "My Syslog",
            "host": "10.0.0.1",
            "port": 514,
            "protocol": "udp",
        })
        assert r.status_code == 200
        data = r.json()
        assert data["ok"] is True
        assert data["integration"]["type"] == "syslog"
        assert data["integration"]["name"] == "My Syslog"

    def test_create_invalid_type(self, client):
        r = client.post("/api/soc/integrations", json={"type": "invalid"})
        assert r.status_code == 400

    def test_list_after_create(self, client):
        client.post("/api/soc/integrations", json={
            "type": "splunk_hec", "name": "Splunk",
            "url": "https://splunk:8088/services/collector",
            "token": "abc123token",
        })
        r = client.get("/api/soc/integrations")
        items = r.json()["integrations"]
        assert len(items) == 1
        # Token should be masked
        assert items[0]["token"] == "abc1***"

    def test_update(self, client):
        r1 = client.post("/api/soc/integrations", json={
            "type": "elastic", "name": "ELK",
            "url": "http://elk:9200",
        })
        iid = r1.json()["integration"]["id"]
        r2 = client.put(f"/api/soc/integrations/{iid}", json={"name": "ELK Production"})
        assert r2.json()["ok"] is True
        assert r2.json()["integration"]["name"] == "ELK Production"

    def test_update_not_found(self, client):
        r = client.put("/api/soc/integrations/nonexistent", json={"name": "X"})
        assert r.status_code == 404

    def test_delete(self, client):
        r1 = client.post("/api/soc/integrations", json={"type": "generic_http", "name": "GH", "url": "http://x"})
        iid = r1.json()["integration"]["id"]
        r2 = client.delete(f"/api/soc/integrations/{iid}")
        assert r2.json()["ok"] is True
        r3 = client.get("/api/soc/integrations")
        assert len(r3.json()["integrations"]) == 0

    def test_delete_not_found(self, client):
        r = client.delete("/api/soc/integrations/nonexistent")
        assert r.status_code == 404


# ── Format endpoints ─────────────────────────────────────────────────────


class TestFormatEndpoints:
    def test_cef_format(self, client):
        r = client.get("/api/soc/formats/cef")
        assert r.status_code == 200
        assert "CEF:0" in r.json()["example"]

    def test_ecs_format(self, client):
        r = client.get("/api/soc/formats/ecs")
        assert r.status_code == 200
        assert r.json()["example"]["event"]["kind"] == "alert"

    def test_sentinel_format(self, client):
        r = client.get("/api/soc/formats/sentinel")
        assert r.status_code == 200
        assert "Azure Sentinel" in r.json()["example"]["targetProduct"]


# ── Test endpoint ────────────────────────────────────────────────────────


class TestIntegrationTest:
    def test_test_not_found(self, client):
        r = client.post("/api/soc/integrations/nonexistent/test")
        assert r.status_code == 404

    def test_test_syslog(self, client):
        """Test syslog integration (will fail to connect but exercises the path)."""
        r1 = client.post("/api/soc/integrations", json={
            "type": "syslog", "name": "Test",
            "host": "192.0.2.1",  # TEST-NET, won't connect
            "port": 514, "protocol": "udp",
        })
        iid = r1.json()["integration"]["id"]
        r2 = client.post(f"/api/soc/integrations/{iid}/test")
        assert r2.status_code == 200
        # UDP syslog may "succeed" even without actual connectivity
        assert "result" in r2.json()


# ── forward_alert ────────────────────────────────────────────────────────


class TestForwardAlert:
    def test_forward_skips_disabled(self, client):
        from hashguard.web.routers.soc_router import _save_integrations, forward_alert
        _save_integrations([{
            "id": "soc_test",
            "type": "generic_http",
            "enabled": False,
            "url": "http://nope",
            "min_risk_score": 0,
        }])
        # Should not raise even with unreachable URL
        forward_alert({"risk_score": 90, "verdict": "malicious", "sha256": "a" * 64})

    def test_forward_skips_low_score(self, client):
        from hashguard.web.routers.soc_router import _save_integrations, forward_alert
        _save_integrations([{
            "id": "soc_test",
            "type": "generic_http",
            "enabled": True,
            "url": "http://nope",
            "min_risk_score": 50,
        }])
        # score=10 < min_risk_score=50 → skip
        forward_alert({"risk_score": 10, "verdict": "clean", "sha256": "b" * 64})
