"""Tests for webhook API endpoints and API documentation."""

import pytest

from hashguard.web.api import HAS_FASTAPI, app

pytestmark = pytest.mark.skipif(not HAS_FASTAPI, reason="FastAPI not installed")


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


@pytest.fixture(autouse=True)
def isolate_webhooks(tmp_path, monkeypatch):
    """Use a temp directory for webhook storage."""
    monkeypatch.setattr(
        "hashguard.web.webhooks._get_webhooks_dir", lambda: tmp_path
    )


class TestWebhookEndpoints:
    def test_list_empty(self, client):
        r = client.get("/api/webhooks")
        assert r.status_code == 200
        assert r.json()["webhooks"] == []

    def test_create_webhook(self, client):
        r = client.post("/api/webhooks", data={
            "name": "test-hook",
            "url": "https://example.com/hook",
            "events": "analysis.high_risk,analysis.malicious",
            "min_risk_score": 70,
        })
        assert r.status_code == 200
        data = r.json()
        assert data["name"] == "test-hook"
        assert "hook_id" in data
        assert "secret" in data

    def test_create_invalid_event(self, client):
        r = client.post("/api/webhooks", data={
            "name": "bad",
            "url": "https://example.com",
            "events": "invalid.event",
        })
        assert r.status_code == 400

    def test_list_after_create(self, client):
        client.post("/api/webhooks", data={
            "name": "h1", "url": "https://a.com", "events": "analysis.completed",
        })
        r = client.get("/api/webhooks")
        assert len(r.json()["webhooks"]) == 1

    def test_delete_webhook(self, client):
        r = client.post("/api/webhooks", data={
            "name": "del", "url": "https://a.com", "events": "analysis.completed",
        })
        hook_id = r.json()["hook_id"]
        r2 = client.delete(f"/api/webhooks/{hook_id}")
        assert r2.status_code == 200
        assert r2.json()["deleted"] is True
        r3 = client.get("/api/webhooks")
        assert len(r3.json()["webhooks"]) == 0

    def test_delete_nonexistent(self, client):
        r = client.delete("/api/webhooks/nonexistent")
        assert r.status_code == 404

    def test_update_webhook(self, client):
        r = client.post("/api/webhooks", data={
            "name": "upd", "url": "https://a.com", "events": "analysis.completed",
        })
        hook_id = r.json()["hook_id"]
        r2 = client.put(f"/api/webhooks/{hook_id}", data={"name": "updated"})
        assert r2.status_code == 200
        hooks = client.get("/api/webhooks").json()["webhooks"]
        assert hooks[0]["name"] == "updated"

    def test_update_nonexistent(self, client):
        r = client.put("/api/webhooks/nonexistent", data={"name": "x"})
        assert r.status_code == 404

    def test_test_webhook_nonexistent(self, client):
        r = client.post("/api/webhooks/nonexistent/test")
        assert r.status_code == 404


class TestAPIDocumentation:
    def test_docs_page_accessible(self, client):
        r = client.get("/api/docs")
        assert r.status_code == 200

    def test_openapi_schema_has_tags(self, client):
        r = client.get("/openapi.json")
        assert r.status_code == 200
        schema = r.json()
        tags = [t["name"] for t in schema.get("tags", [])]
        assert "Auth" in tags
        assert "Analysis" in tags
        assert "Samples" in tags
        assert "ML" in tags
        assert "Webhooks" in tags
        assert "Settings" in tags
        assert "Ingest" in tags
        assert "Intelligence" in tags
        assert "Dataset" in tags

    def test_openapi_has_description(self, client):
        r = client.get("/openapi.json")
        schema = r.json()
        assert "HashGuard" in schema.get("info", {}).get("description", "")
        assert "Authentication" in schema.get("info", {}).get("description", "")

    def test_webhook_endpoints_tagged(self, client):
        r = client.get("/openapi.json")
        schema = r.json()
        paths = schema.get("paths", {})
        webhook_paths = [p for p in paths if "/api/webhooks" in p]
        assert len(webhook_paths) >= 3  # create, list, delete at minimum
        for wpath in webhook_paths:
            for method, details in paths[wpath].items():
                if method in ("get", "post", "delete", "put"):
                    assert "Webhooks" in details.get("tags", [])

    def test_auth_endpoints_tagged(self, client):
        r = client.get("/openapi.json")
        schema = r.json()
        paths = schema.get("paths", {})
        auth_paths = [p for p in paths if "/api/auth" in p]
        assert len(auth_paths) >= 2
        for apath in auth_paths:
            for method, details in paths[apath].items():
                if method in ("get", "post", "delete"):
                    assert "Auth" in details.get("tags", [])
