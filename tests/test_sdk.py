"""Tests for the HashGuard Python SDK."""

import json
from unittest.mock import MagicMock, patch

import pytest

# Skip entirely if httpx is not installed
httpx = pytest.importorskip("httpx")

from hashguard.sdk import HashGuardClient, HashGuardError


@pytest.fixture
def mock_client():
    """Create a client with a mocked httpx transport."""
    client = HashGuardClient.__new__(HashGuardClient)
    client.base_url = "http://test:8000"
    client._timeout = 30.0
    client._client = MagicMock(spec=httpx.Client)
    return client


def _mock_response(status=200, json_data=None, text="", headers=None):
    resp = MagicMock()
    resp.status_code = status
    resp.text = text or json.dumps(json_data or {})
    resp.json.return_value = json_data or {}
    resp.headers = headers or {"content-type": "application/json"}
    return resp


# ── Init ─────────────────────────────────────────────────────────────────


class TestInit:
    def test_api_key_header(self):
        with patch.object(httpx, "Client") as mock_cls:
            mock_cls.return_value = MagicMock()
            c = HashGuardClient("http://x", api_key="hg_test123")
            call_kwargs = mock_cls.call_args[1]
            assert call_kwargs["headers"]["X-API-Key"] == "hg_test123"
            c.close()

    def test_bearer_token(self):
        with patch.object(httpx, "Client") as mock_cls:
            mock_cls.return_value = MagicMock()
            c = HashGuardClient("http://x", token="jwt_abc")
            call_kwargs = mock_cls.call_args[1]
            assert call_kwargs["headers"]["Authorization"] == "Bearer jwt_abc"
            c.close()

    def test_context_manager(self):
        with patch.object(httpx, "Client") as mock_cls:
            mock_inst = MagicMock()
            mock_cls.return_value = mock_inst
            with HashGuardClient("http://x") as c:
                pass
            mock_inst.close.assert_called_once()


# ── Error handling ───────────────────────────────────────────────────────


class TestErrors:
    def test_http_error_raises(self, mock_client):
        mock_client._client.request.return_value = _mock_response(
            status=403, json_data={"detail": "Forbidden"}
        )
        with pytest.raises(HashGuardError) as exc:
            mock_client.get_stats()
        assert exc.value.status_code == 403
        assert "Forbidden" in str(exc.value)


# ── Stats ────────────────────────────────────────────────────────────────


class TestStats:
    def test_get_stats(self, mock_client):
        mock_client._client.request.return_value = _mock_response(
            json_data={"total_samples": 100, "malicious": 80}
        )
        stats = mock_client.get_stats()
        assert stats["total_samples"] == 100

    def test_search(self, mock_client):
        mock_client._client.request.return_value = _mock_response(
            json_data=[{"sha256": "a" * 64}]
        )
        results = mock_client.search("emotet")
        assert len(results) == 1


# ── Feeds ────────────────────────────────────────────────────────────────


class TestFeeds:
    def test_feed_recent(self, mock_client):
        mock_client._client.request.return_value = _mock_response(
            json_data={"total": 5, "samples": []}
        )
        r = mock_client.feed_recent(verdict="malicious", limit=10)
        assert r["total"] == 5

    def test_feed_hashes_txt(self, mock_client):
        mock_client._client.request.return_value = _mock_response(
            text="aaa\nbbb\nccc", headers={"content-type": "text/plain"}
        )
        r = mock_client.feed_hashes(fmt="txt")
        assert isinstance(r, str)
        assert "aaa" in r

    def test_feed_hashes_json(self, mock_client):
        mock_client._client.request.return_value = _mock_response(
            json_data={"hashes": ["aaa", "bbb"]}
        )
        r = mock_client.feed_hashes(fmt="json")
        assert isinstance(r, dict)

    def test_feed_stix(self, mock_client):
        mock_client._client.request.return_value = _mock_response(
            json_data={"type": "bundle", "objects": []}
        )
        r = mock_client.feed_stix()
        assert r["type"] == "bundle"

    def test_feed_misp(self, mock_client):
        mock_client._client.request.return_value = _mock_response(
            json_data={"response": []}
        )
        r = mock_client.feed_misp()
        assert r["response"] == []

    def test_feed_iocs_csv(self, mock_client):
        mock_client._client.request.return_value = _mock_response(
            text="ioc_type,value\nurl,http://evil.test", headers={"content-type": "text/csv"}
        )
        r = mock_client.feed_iocs(fmt="csv")
        assert isinstance(r, str)
        assert "ioc_type" in r


# ── Webhooks ─────────────────────────────────────────────────────────────


class TestWebhooks:
    def test_create_webhook(self, mock_client):
        mock_client._client.request.return_value = _mock_response(
            json_data={"id": "wh_123", "url": "http://hook.test"}
        )
        r = mock_client.create_webhook("http://hook.test", ["analysis.completed"])
        assert r["id"] == "wh_123"

    def test_list_webhooks(self, mock_client):
        mock_client._client.request.return_value = _mock_response(json_data={"webhooks": []})
        r = mock_client.list_webhooks()
        assert isinstance(r, dict)


# ── Auth ─────────────────────────────────────────────────────────────────


class TestAuth:
    def test_login_sets_bearer(self, mock_client):
        mock_client._client.request.return_value = _mock_response(
            json_data={"token": "jwt_xyz"}
        )
        mock_client._client.headers = {}
        r = mock_client.login("admin", "pass")
        assert mock_client._client.headers["Authorization"] == "Bearer jwt_xyz"

    def test_register(self, mock_client):
        mock_client._client.request.return_value = _mock_response(
            json_data={"id": 1, "username": "test"}
        )
        r = mock_client.register("test", "test@x.com", "pass")
        assert r["username"] == "test"


# ── Ingest ───────────────────────────────────────────────────────────────


class TestIngest:
    def test_start_ingest(self, mock_client):
        mock_client._client.request.return_value = _mock_response(
            json_data={"status": "running"}
        )
        r = mock_client.start_ingest(source="recent", limit=50)
        assert r["status"] == "running"

    def test_ingest_status(self, mock_client):
        mock_client._client.request.return_value = _mock_response(
            json_data={"status": "idle"}
        )
        assert mock_client.ingest_status()["status"] == "idle"


# ── Poll task ────────────────────────────────────────────────────────────


class TestPollTask:
    def test_poll_completed(self, mock_client):
        mock_client._client.request.return_value = _mock_response(
            json_data={"status": "completed", "result": {}}
        )
        r = mock_client.poll_task("task_123", poll_interval=0.01, max_wait=1.0)
        assert r["status"] == "completed"

    def test_poll_timeout(self, mock_client):
        mock_client._client.request.return_value = _mock_response(
            json_data={"status": "pending"}
        )
        with pytest.raises(TimeoutError):
            mock_client.poll_task("task_123", poll_interval=0.01, max_wait=0.05)
