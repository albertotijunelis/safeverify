"""Tests for the White-label / Branding router."""

import json
import os
import threading

import pytest

from hashguard.web.api import HAS_FASTAPI, app

pytestmark = pytest.mark.skipif(not HAS_FASTAPI, reason="FastAPI not installed")


@pytest.fixture(autouse=True)
def _tmp_branding(tmp_path, monkeypatch):
    """Redirect branding.json to a temp directory."""
    monkeypatch.setenv("APPDATA", str(tmp_path))
    (tmp_path / "HashGuard").mkdir(exist_ok=True)
    # Also redirect DB so init_db works
    from hashguard import database
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


class TestBrandingGet:
    def test_default_branding(self, client):
        r = client.get("/api/branding")
        assert r.status_code == 200
        data = r.json()
        assert data["platform_name"] == "HashGuard"
        assert data["accent_color"] == "#f97316"
        assert data["tagline"] == "Malware Research Platform"

    def test_all_default_keys_present(self, client):
        r = client.get("/api/branding")
        data = r.json()
        expected_keys = {
            "platform_name", "tagline", "logo_url", "icon_url",
            "accent_color", "accent_hover", "bg_color", "surface_color",
            "card_color", "border_color", "text_color", "muted_color",
            "danger_color", "success_color", "warn_color", "footer_text", "custom_css",
        }
        assert expected_keys.issubset(set(data.keys()))


class TestBrandingPost:
    def test_update_name(self, client):
        r = client.post("/api/branding", json={"platform_name": "AcmeThreat"})
        assert r.status_code == 200
        data = r.json()
        assert data["ok"] is True
        assert data["branding"]["platform_name"] == "AcmeThreat"

        # Verify persistence
        r2 = client.get("/api/branding")
        assert r2.json()["platform_name"] == "AcmeThreat"

    def test_update_colors(self, client):
        r = client.post("/api/branding", json={
            "accent_color": "#3b82f6",
            "bg_color": "#1a1a2e",
        })
        data = r.json()["branding"]
        assert data["accent_color"] == "#3b82f6"
        assert data["bg_color"] == "#1a1a2e"

    def test_unknown_keys_filtered(self, client):
        r = client.post("/api/branding", json={
            "platform_name": "GoodName",
            "evil_script": "<script>alert(1)</script>",
        })
        data = r.json()["branding"]
        assert data["platform_name"] == "GoodName"
        assert "evil_script" not in data

    def test_partial_update_preserves_defaults(self, client):
        client.post("/api/branding", json={"platform_name": "Custom"})
        r = client.get("/api/branding")
        data = r.json()
        assert data["platform_name"] == "Custom"
        assert data["accent_color"] == "#f97316"  # Default preserved


class TestBrandingModule:
    def test_load_save_roundtrip(self):
        from hashguard.web.routers.branding_router import load_branding, save_branding
        result = save_branding({"platform_name": "TestBrand"})
        assert result["platform_name"] == "TestBrand"
        loaded = load_branding()
        assert loaded["platform_name"] == "TestBrand"
