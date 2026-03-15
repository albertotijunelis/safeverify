"""Tests for HashGuard SDK client."""

import io
import time
import pytest
from unittest.mock import patch, MagicMock, PropertyMock


@pytest.fixture
def mock_httpx():
    """Provide a mock httpx module and client."""
    with patch("hashguard.sdk._HAS_HTTPX", True):
        mock_client = MagicMock()
        with patch("httpx.Client", return_value=mock_client):
            from hashguard.sdk import HashGuardClient
            client = HashGuardClient("http://localhost:8000", api_key="hg_test123")
            yield client, mock_client


def _mock_response(status=200, json_data=None, text=""):
    resp = MagicMock()
    resp.status_code = status
    resp.json.return_value = json_data if json_data is not None else {}
    resp.text = text
    return resp


class TestClientInit:
    def test_no_httpx_raises(self):
        with patch("hashguard.sdk._HAS_HTTPX", False):
            from hashguard.sdk import HashGuardClient
            with pytest.raises(ImportError, match="httpx"):
                HashGuardClient()

    def test_api_key_header(self):
        with patch("hashguard.sdk._HAS_HTTPX", True), \
             patch("httpx.Client") as mock_cls:
            from hashguard.sdk import HashGuardClient
            HashGuardClient("http://localhost", api_key="hg_abc")
            call_kwargs = mock_cls.call_args[1]
            assert call_kwargs["headers"]["X-API-Key"] == "hg_abc"

    def test_token_header(self):
        with patch("hashguard.sdk._HAS_HTTPX", True), \
             patch("httpx.Client") as mock_cls:
            from hashguard.sdk import HashGuardClient
            HashGuardClient("http://localhost", token="jwt_tok")
            call_kwargs = mock_cls.call_args[1]
            assert call_kwargs["headers"]["Authorization"] == "Bearer jwt_tok"

    def test_context_manager(self):
        with patch("hashguard.sdk._HAS_HTTPX", True), \
             patch("httpx.Client") as mock_cls:
            from hashguard.sdk import HashGuardClient
            mock_client = MagicMock()
            mock_cls.return_value = mock_client
            with HashGuardClient("http://localhost") as c:
                pass
            mock_client.close.assert_called_once()


class TestRequest:
    def test_success(self, mock_httpx):
        client, mock_client = mock_httpx
        mock_client.request.return_value = _mock_response(200, {"ok": True})
        result = client._request("GET", "/test")
        assert result.json() == {"ok": True}

    def test_error_raises(self, mock_httpx):
        client, mock_client = mock_httpx
        from hashguard.sdk import HashGuardError
        mock_client.request.return_value = _mock_response(404, text="Not found")
        with pytest.raises(HashGuardError) as exc_info:
            client._request("GET", "/missing")
        assert exc_info.value.status_code == 404

    def test_error_with_json_detail(self, mock_httpx):
        client, mock_client = mock_httpx
        from hashguard.sdk import HashGuardError
        resp = _mock_response(403, text="forbidden")
        resp.json.return_value = {"detail": "Access denied"}
        mock_client.request.return_value = resp
        with pytest.raises(HashGuardError, match="Access denied"):
            client._request("GET", "/forbidden")


class TestAnalyze:
    def test_analyze_file_path(self, mock_httpx, tmp_path):
        client, mock_client = mock_httpx
        f = tmp_path / "test.exe"
        f.write_bytes(b"MZ\x00\x00")
        mock_client.request.return_value = _mock_response(200, {"risk_score": 80})
        result = client.analyze(str(f))
        assert result["risk_score"] == 80

    def test_analyze_binary_io(self, mock_httpx):
        client, mock_client = mock_httpx
        mock_client.request.return_value = _mock_response(200, {"sha256": "abc"})
        result = client.analyze(io.BytesIO(b"data"))
        assert result["sha256"] == "abc"

    def test_analyze_async_file_path(self, mock_httpx, tmp_path):
        client, mock_client = mock_httpx
        f = tmp_path / "test.bin"
        f.write_bytes(b"\x00\x01")
        mock_client.request.return_value = _mock_response(200, {"task_id": "t1"})
        result = client.analyze_async(str(f))
        assert result["task_id"] == "t1"

    def test_analyze_async_binary_io(self, mock_httpx):
        client, mock_client = mock_httpx
        mock_client.request.return_value = _mock_response(200, {"task_id": "t2"})
        result = client.analyze_async(io.BytesIO(b"data"))
        assert result["task_id"] == "t2"

    def test_analyze_url(self, mock_httpx):
        client, mock_client = mock_httpx
        mock_client.request.return_value = _mock_response(200, {"url": "http://bad.com"})
        result = client.analyze_url("http://bad.com")
        assert result["url"] == "http://bad.com"


class TestPollTask:
    def test_completed_immediately(self, mock_httpx):
        client, mock_client = mock_httpx
        mock_client.request.return_value = _mock_response(200, {"status": "completed", "result": {}})
        result = client.poll_task("t1", poll_interval=0.01, max_wait=1)
        assert result["status"] == "completed"

    def test_failed_task(self, mock_httpx):
        client, mock_client = mock_httpx
        mock_client.request.return_value = _mock_response(200, {"status": "failed", "error": "crash"})
        result = client.poll_task("t2", poll_interval=0.01, max_wait=1)
        assert result["status"] == "failed"

    def test_timeout(self, mock_httpx):
        client, mock_client = mock_httpx
        mock_client.request.return_value = _mock_response(200, {"status": "pending"})
        with pytest.raises(TimeoutError):
            client.poll_task("t3", poll_interval=0.01, max_wait=0.05)


class TestSamplesAndSearch:
    def test_get_stats(self, mock_httpx):
        client, mock_client = mock_httpx
        mock_client.request.return_value = _mock_response(200, {"total": 100})
        assert client.get_stats()["total"] == 100

    def test_get_sample(self, mock_httpx):
        client, mock_client = mock_httpx
        mock_client.request.return_value = _mock_response(200, {"id": 1})
        assert client.get_sample(1)["id"] == 1

    def test_list_samples(self, mock_httpx):
        client, mock_client = mock_httpx
        mock_client.request.return_value = _mock_response(200, {"samples": []})
        assert client.list_samples()["samples"] == []

    def test_search(self, mock_httpx):
        client, mock_client = mock_httpx
        mock_client.request.return_value = _mock_response(200, [{"sha256": "abc"}])
        results = client.search("emotet")
        assert len(results) == 1


class TestIntelligence:
    def test_get_graph(self, mock_httpx):
        client, mock_client = mock_httpx
        mock_client.request.return_value = _mock_response(200, {"nodes": []})
        assert client.get_graph(1)["nodes"] == []

    def test_get_timeline(self, mock_httpx):
        client, mock_client = mock_httpx
        mock_client.request.return_value = _mock_response(200, [])
        assert client.get_timeline(1) == []

    def test_get_clusters(self, mock_httpx):
        client, mock_client = mock_httpx
        mock_client.request.return_value = _mock_response(200, [])
        assert client.get_clusters() == []

    def test_get_enrichment(self, mock_httpx):
        client, mock_client = mock_httpx
        mock_client.request.return_value = _mock_response(200, {"iocs": []})
        assert client.get_enrichment(1)["iocs"] == []

    def test_export_stix(self, mock_httpx):
        client, mock_client = mock_httpx
        mock_client.request.return_value = _mock_response(200, {"type": "bundle"})
        assert client.export_stix(1)["type"] == "bundle"


class TestFeeds:
    def test_feed_recent(self, mock_httpx):
        client, mock_client = mock_httpx
        mock_client.request.return_value = _mock_response(200, {"samples": []})
        assert client.feed_recent(since="2024-01-01", verdict="malicious")["samples"] == []

    def test_feed_iocs_json(self, mock_httpx):
        client, mock_client = mock_httpx
        mock_client.request.return_value = _mock_response(200, {"iocs": []})
        assert client.feed_iocs(fmt="json")["iocs"] == []

    def test_feed_iocs_txt(self, mock_httpx):
        client, mock_client = mock_httpx
        resp = _mock_response(200, text="1.2.3.4\n5.6.7.8")
        mock_client.request.return_value = resp
        result = client.feed_iocs(since="2024-01-01", ioc_type="ip", fmt="txt")
        assert "1.2.3.4" in result

    def test_feed_families(self, mock_httpx):
        client, mock_client = mock_httpx
        mock_client.request.return_value = _mock_response(200, {"families": []})
        assert client.feed_families(since="2024-01-01")["families"] == []

    def test_feed_hashes_txt(self, mock_httpx):
        client, mock_client = mock_httpx
        resp = _mock_response(200, text="abc123\ndef456")
        mock_client.request.return_value = resp
        result = client.feed_hashes(fmt="txt", since="2024-01-01")
        assert "abc123" in result

    def test_feed_hashes_json(self, mock_httpx):
        client, mock_client = mock_httpx
        mock_client.request.return_value = _mock_response(200, {"hashes": []})
        assert client.feed_hashes(fmt="json")["hashes"] == []

    def test_feed_stix(self, mock_httpx):
        client, mock_client = mock_httpx
        mock_client.request.return_value = _mock_response(200, {"type": "bundle"})
        assert client.feed_stix(since="2024-01-01")["type"] == "bundle"

    def test_feed_misp(self, mock_httpx):
        client, mock_client = mock_httpx
        mock_client.request.return_value = _mock_response(200, {"events": []})
        assert client.feed_misp(since="2024-01-01")["events"] == []


class TestML:
    def test_ml_predict_path(self, mock_httpx, tmp_path):
        client, mock_client = mock_httpx
        f = tmp_path / "sample.bin"
        f.write_bytes(b"PE\x00")
        mock_client.request.return_value = _mock_response(200, {"label": "trojan"})
        assert client.ml_predict(str(f))["label"] == "trojan"

    def test_ml_predict_binary_io(self, mock_httpx):
        client, mock_client = mock_httpx
        mock_client.request.return_value = _mock_response(200, {"label": "clean"})
        assert client.ml_predict(io.BytesIO(b"data"))["label"] == "clean"

    def test_ml_models(self, mock_httpx):
        client, mock_client = mock_httpx
        mock_client.request.return_value = _mock_response(200, [])
        assert client.ml_models() == []


class TestWebhooksCRUD:
    def test_create_webhook(self, mock_httpx):
        client, mock_client = mock_httpx
        mock_client.request.return_value = _mock_response(200, {"hook_id": "h1"})
        result = client.create_webhook("http://hook.com", ["analysis.completed"], secret="sec")
        assert result["hook_id"] == "h1"

    def test_list_webhooks(self, mock_httpx):
        client, mock_client = mock_httpx
        mock_client.request.return_value = _mock_response(200, [])
        assert client.list_webhooks() == []

    def test_delete_webhook(self, mock_httpx):
        client, mock_client = mock_httpx
        mock_client.request.return_value = _mock_response(200, {"ok": True})
        assert client.delete_webhook("h1")["ok"] is True


class TestIngest:
    def test_start_ingest(self, mock_httpx):
        client, mock_client = mock_httpx
        mock_client.request.return_value = _mock_response(200, {"job_id": "j1"})
        assert client.start_ingest()["job_id"] == "j1"

    def test_ingest_status(self, mock_httpx):
        client, mock_client = mock_httpx
        mock_client.request.return_value = _mock_response(200, {"status": "running"})
        assert client.ingest_status()["status"] == "running"

    def test_stop_ingest(self, mock_httpx):
        client, mock_client = mock_httpx
        mock_client.request.return_value = _mock_response(200, {"stopped": True})
        assert client.stop_ingest()["stopped"] is True


class TestAuth:
    def test_login_sets_token(self, mock_httpx):
        client, mock_client = mock_httpx
        mock_client.request.return_value = _mock_response(200, {"token": "jwt_123"})
        result = client.login("user@test.com", "pass123")
        assert result["token"] == "jwt_123"
        assert mock_client.headers.__setitem__.called or "Authorization" in str(mock_client.headers)

    def test_login_no_token(self, mock_httpx):
        client, mock_client = mock_httpx
        mock_client.request.return_value = _mock_response(200, {"error": "bad creds"})
        result = client.login("user@test.com", "wrong")
        assert "token" not in result

    def test_register(self, mock_httpx):
        client, mock_client = mock_httpx
        mock_client.request.return_value = _mock_response(200, {"id": 1})
        assert client.register("user", "u@t.com", "pass1234")["id"] == 1

    def test_me(self, mock_httpx):
        client, mock_client = mock_httpx
        mock_client.request.return_value = _mock_response(200, {"email": "u@t.com"})
        assert client.me()["email"] == "u@t.com"


class TestHashGuardError:
    def test_error_str(self):
        from hashguard.sdk import HashGuardError
        err = HashGuardError(404, "Not found")
        assert "404" in str(err)
        assert "Not found" in str(err)
        assert err.status_code == 404
        assert err.detail == "Not found"
