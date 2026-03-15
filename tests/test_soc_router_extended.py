"""Tests for SOC integration router — converters, forwarders, and endpoints."""

import json
import os
import pytest
from datetime import datetime, timezone
from unittest.mock import patch, MagicMock


# ── Format Converters ───────────────────────────────────────────────────


class TestToCef:
    def test_malicious_sample(self):
        from hashguard.web.routers.soc_router import to_cef
        s = {"verdict": "malicious", "sha256": "a" * 64, "filename": "test.exe",
             "risk_score": 85, "family": "Emotet", "analysis_date": "2026-01-01"}
        cef = to_cef(s)
        assert cef.startswith("CEF:0|HashGuard")
        assert "10" in cef  # severity 10 for malicious
        assert "a" * 64 in cef

    def test_suspicious_sample(self):
        from hashguard.web.routers.soc_router import to_cef
        cef = to_cef({"verdict": "suspicious", "sha256": "x" * 64, "risk_score": 50})
        assert "|5|" in cef  # severity 5

    def test_clean_sample(self):
        from hashguard.web.routers.soc_router import to_cef
        cef = to_cef({"verdict": "clean", "sha256": "b" * 64, "risk_score": 0})
        assert "|1|" in cef  # severity 1

    def test_unknown_verdict(self):
        from hashguard.web.routers.soc_router import to_cef
        cef = to_cef({})
        assert "unknown" in cef


class TestToEcs:
    def test_full_sample(self):
        from hashguard.web.routers.soc_router import to_ecs
        s = {"sha256": "a" * 64, "md5": "b" * 32, "sha1": "c" * 40,
             "filename": "test.exe", "file_size": 1000, "risk_score": 85,
             "verdict": "malicious", "family": "Emotet", "description": "Trojan",
             "analysis_date": "2026-01-01T00:00:00Z"}
        ecs = to_ecs(s)
        assert ecs["event"]["kind"] == "alert"
        assert ecs["file"]["hash"]["sha256"] == "a" * 64
        assert ecs["threat"]["indicator"]["confidence"] == "High"
        assert ecs["hashguard"]["risk_score"] == 85

    def test_clean_sample(self):
        from hashguard.web.routers.soc_router import to_ecs
        ecs = to_ecs({"verdict": "clean"})
        assert ecs["threat"]["indicator"]["confidence"] == "Medium"

    def test_no_analysis_date_uses_now(self):
        from hashguard.web.routers.soc_router import to_ecs
        ecs = to_ecs({})
        assert "@timestamp" in ecs
        assert ecs["@timestamp"] is not None


class TestToSentinel:
    def test_malicious(self):
        from hashguard.web.routers.soc_router import to_sentinel
        s = {"sha256": "a" * 64, "filename": "mal.exe", "risk_score": 95,
             "verdict": "malicious", "family": "Ryuk", "description": "Ransom"}
        sent = to_sentinel(s)
        assert sent["severity"] == "high"
        assert "Ryuk" in sent["malwareFamilyNames"]
        assert sent["fileHashValue"] == "a" * 64

    def test_suspicious(self):
        from hashguard.web.routers.soc_router import to_sentinel
        sent = to_sentinel({"verdict": "suspicious"})
        assert sent["severity"] == "medium"

    def test_clean(self):
        from hashguard.web.routers.soc_router import to_sentinel
        sent = to_sentinel({"verdict": "clean"})
        assert sent["severity"] == "informational"

    def test_no_family(self):
        from hashguard.web.routers.soc_router import to_sentinel
        sent = to_sentinel({"sha256": "a" * 64})
        assert sent["malwareFamilyNames"] == []


# ── Forwarders ──────────────────────────────────────────────────────────


class TestForwardToSyslog:
    def test_udp(self):
        from hashguard.web.routers.soc_router import _forward_to_syslog
        integ = {"host": "127.0.0.1", "port": 9999, "protocol": "udp"}
        sample = {"sha256": "a" * 64, "verdict": "malicious"}
        with patch("socket.socket") as mock_sock:
            inst = MagicMock()
            mock_sock.return_value = inst
            result = _forward_to_syslog(integ, sample)
            assert result["ok"] is True
            assert result["format"] == "cef"

    def test_tcp(self):
        from hashguard.web.routers.soc_router import _forward_to_syslog
        integ = {"host": "127.0.0.1", "port": 9999, "protocol": "tcp"}
        sample = {"sha256": "a" * 64, "verdict": "clean"}
        with patch("socket.socket") as mock_sock:
            inst = MagicMock()
            mock_sock.return_value = inst
            result = _forward_to_syslog(integ, sample)
            assert result["ok"] is True

    def test_connection_error(self):
        from hashguard.web.routers.soc_router import _forward_to_syslog
        integ = {"host": "bad", "port": 1, "protocol": "tcp"}
        sample = {"sha256": "x"}
        with patch("socket.socket") as mock_sock:
            mock_sock.return_value.connect.side_effect = OSError("refused")
            result = _forward_to_syslog(integ, sample)
            assert result["ok"] is False


class TestForwardToSplunk:
    def test_missing_url(self):
        from hashguard.web.routers.soc_router import _forward_to_splunk
        result = _forward_to_splunk({"token": "t"}, {})
        assert result["ok"] is False

    def test_missing_token(self):
        from hashguard.web.routers.soc_router import _forward_to_splunk
        result = _forward_to_splunk({"url": "http://splunk"}, {})
        assert result["ok"] is False

    def test_success(self):
        from hashguard.web.routers.soc_router import _forward_to_splunk
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        with patch("httpx.post", return_value=mock_resp):
            result = _forward_to_splunk({"url": "http://splunk", "token": "t"}, {"sha256": "a"})
            assert result["ok"] is True

    def test_http_error(self):
        from hashguard.web.routers.soc_router import _forward_to_splunk
        mock_resp = MagicMock()
        mock_resp.status_code = 500
        with patch("httpx.post", return_value=mock_resp):
            result = _forward_to_splunk({"url": "http://splunk", "token": "t"}, {})
            assert result["ok"] is False


class TestForwardToElastic:
    def test_missing_url(self):
        from hashguard.web.routers.soc_router import _forward_to_elastic
        result = _forward_to_elastic({}, {})
        assert result["ok"] is False

    def test_success_with_api_key(self):
        from hashguard.web.routers.soc_router import _forward_to_elastic
        mock_resp = MagicMock()
        mock_resp.status_code = 201
        with patch("httpx.post", return_value=mock_resp):
            result = _forward_to_elastic(
                {"url": "http://elastic:9200", "api_key": "abc", "index": "alerts"}, {})
            assert result["ok"] is True


class TestForwardToSentinel:
    def test_missing_url(self):
        from hashguard.web.routers.soc_router import _forward_to_sentinel
        result = _forward_to_sentinel({}, {})
        assert result["ok"] is False

    def test_success(self):
        from hashguard.web.routers.soc_router import _forward_to_sentinel
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        with patch("httpx.post", return_value=mock_resp):
            result = _forward_to_sentinel(
                {"url": "http://sentinel", "shared_key": "sk"}, {"sha256": "a"})
            assert result["ok"] is True


class TestForwardToGeneric:
    def test_missing_url(self):
        from hashguard.web.routers.soc_router import _forward_to_generic
        result = _forward_to_generic({}, {})
        assert result["ok"] is False

    def test_success_with_headers(self):
        from hashguard.web.routers.soc_router import _forward_to_generic
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        with patch("httpx.post", return_value=mock_resp):
            result = _forward_to_generic(
                {"url": "http://siem", "headers": {"X-Key": "val"}}, {})
            assert result["ok"] is True


# ── forward_alert ───────────────────────────────────────────────────────


class TestForwardAlert:
    def test_no_integrations(self):
        from hashguard.web.routers.soc_router import forward_alert
        with patch("hashguard.web.routers.soc_router._load_integrations", return_value=[]):
            forward_alert({"risk_score": 100})  # Should not raise

    def test_disabled_integration_skipped(self):
        from hashguard.web.routers.soc_router import forward_alert
        items = [{"type": "generic_http", "enabled": False, "min_risk_score": 0}]
        with patch("hashguard.web.routers.soc_router._load_integrations", return_value=items):
            forward_alert({"risk_score": 100})

    def test_min_risk_filter(self):
        from hashguard.web.routers.soc_router import forward_alert
        items = [{"type": "generic_http", "enabled": True, "min_risk_score": 80}]
        with patch("hashguard.web.routers.soc_router._load_integrations", return_value=items):
            forward_alert({"risk_score": 50})  # Below threshold, should skip


# ── Config persistence ──────────────────────────────────────────────────


class TestConfigPersistence:
    def test_load_empty(self, tmp_path):
        with patch("hashguard.web.routers.soc_router._config_path", return_value=tmp_path / "soc.json"):
            from hashguard.web.routers.soc_router import _load_integrations
            assert _load_integrations() == []

    def test_save_and_load(self, tmp_path):
        path = tmp_path / "soc.json"
        with patch("hashguard.web.routers.soc_router._config_path", return_value=path):
            from hashguard.web.routers.soc_router import _save_integrations, _load_integrations
            items = [{"id": "soc_1", "type": "syslog", "enabled": True}]
            _save_integrations(items)
            loaded = _load_integrations()
            assert len(loaded) == 1
            assert loaded[0]["id"] == "soc_1"

    def test_load_corrupt_json(self, tmp_path):
        path = tmp_path / "soc.json"
        path.write_text("not json", encoding="utf-8")
        with patch("hashguard.web.routers.soc_router._config_path", return_value=path):
            from hashguard.web.routers.soc_router import _load_integrations
            assert _load_integrations() == []


# ── API Endpoints ───────────────────────────────────────────────────────


@pytest.fixture
def soc_client():
    with patch("hashguard.web.routers.soc_router._soc_dep",
               return_value=lambda: {"sub": "admin", "role": "admin"}):
        from fastapi import FastAPI
        from fastapi.testclient import TestClient
        from hashguard.web.routers.soc_router import router
        app = FastAPI()
        app.include_router(router)
        yield TestClient(app)


class TestSOCEndpoints:
    def test_list_integrations(self, soc_client):
        with patch("hashguard.web.routers.soc_router._load_integrations",
                   return_value=[{"id": "1", "type": "syslog", "token": "secret1234"}]):
            r = soc_client.get("/api/soc/integrations")
            assert r.status_code == 200
            data = r.json()
            assert data["integrations"][0]["token"].endswith("***")

    def test_create_integration_invalid_type(self, soc_client):
        r = soc_client.post("/api/soc/integrations", json={"type": "invalid"})
        assert r.status_code == 400

    def test_create_integration_success(self, soc_client):
        with patch("hashguard.web.routers.soc_router._load_integrations", return_value=[]), \
             patch("hashguard.web.routers.soc_router._save_integrations"):
            r = soc_client.post("/api/soc/integrations", json={
                "type": "syslog", "name": "test", "host": "127.0.0.1", "port": 514
            })
            assert r.status_code == 200
            assert r.json()["ok"] is True

    def test_update_integration_not_found(self, soc_client):
        with patch("hashguard.web.routers.soc_router._load_integrations", return_value=[]):
            r = soc_client.put("/api/soc/integrations/nonexist", json={"name": "x"})
            assert r.status_code == 404

    def test_update_integration_success(self, soc_client):
        items = [{"id": "soc_1", "type": "syslog", "name": "old"}]
        with patch("hashguard.web.routers.soc_router._load_integrations", return_value=items), \
             patch("hashguard.web.routers.soc_router._save_integrations"):
            r = soc_client.put("/api/soc/integrations/soc_1", json={"name": "new"})
            assert r.status_code == 200

    def test_delete_integration_not_found(self, soc_client):
        with patch("hashguard.web.routers.soc_router._load_integrations", return_value=[]):
            r = soc_client.delete("/api/soc/integrations/nonexist")
            assert r.status_code == 404

    def test_delete_integration_success(self, soc_client):
        items = [{"id": "soc_1", "type": "syslog"}]
        with patch("hashguard.web.routers.soc_router._load_integrations", return_value=items), \
             patch("hashguard.web.routers.soc_router._save_integrations"):
            r = soc_client.delete("/api/soc/integrations/soc_1")
            assert r.status_code == 200

    def test_test_integration_not_found(self, soc_client):
        with patch("hashguard.web.routers.soc_router._load_integrations", return_value=[]):
            r = soc_client.post("/api/soc/integrations/nonexist/test")
            assert r.status_code == 404

    def test_test_integration_success(self, soc_client):
        items = [{"id": "soc_1", "type": "syslog", "host": "127.0.0.1", "port": 514, "protocol": "udp"}]
        with patch("hashguard.web.routers.soc_router._load_integrations", return_value=items), \
             patch("hashguard.web.routers.soc_router._forward_to_syslog",
                   return_value={"ok": True, "format": "cef"}):
            r = soc_client.post("/api/soc/integrations/soc_1/test")
            assert r.status_code == 200

    def test_sample_cef(self, soc_client):
        r = soc_client.get("/api/soc/formats/cef")
        assert r.status_code == 200
        assert "cef" in r.json()["format"]

    def test_sample_ecs(self, soc_client):
        r = soc_client.get("/api/soc/formats/ecs")
        assert r.status_code == 200

    def test_sample_sentinel(self, soc_client):
        r = soc_client.get("/api/soc/formats/sentinel")
        assert r.status_code == 200
