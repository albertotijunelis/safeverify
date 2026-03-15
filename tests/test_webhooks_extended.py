"""Tests for webhook system — CRUD, delivery, event dispatch, notifications."""

import json
import hashlib
import hmac
import time
import pytest
from unittest.mock import patch, MagicMock, mock_open


# ── Storage helpers ─────────────────────────────────────────────────────


class TestWebhookStorage:
    def test_load_empty(self, tmp_path):
        with patch("hashguard.web.webhooks._get_webhooks_dir", return_value=tmp_path):
            from hashguard.web.webhooks import _load_webhooks
            assert _load_webhooks() == {}

    def test_save_and_load(self, tmp_path):
        with patch("hashguard.web.webhooks._get_webhooks_dir", return_value=tmp_path):
            from hashguard.web.webhooks import _save_webhooks, _load_webhooks
            hooks = {"h1": {"name": "test", "url": "http://x"}}
            _save_webhooks(hooks)
            loaded = _load_webhooks()
            assert loaded["h1"]["name"] == "test"

    def test_load_corrupt_json(self, tmp_path):
        (tmp_path / "webhooks.json").write_text("bad json", encoding="utf-8")
        with patch("hashguard.web.webhooks._get_webhooks_dir", return_value=tmp_path):
            from hashguard.web.webhooks import _load_webhooks
            assert _load_webhooks() == {}


# ── CRUD ────────────────────────────────────────────────────────────────


class TestCreateWebhook:
    def test_success(self, tmp_path):
        with patch("hashguard.web.webhooks._get_webhooks_dir", return_value=tmp_path):
            from hashguard.web.webhooks import create_webhook
            result = create_webhook(
                "Test Hook", "http://example.com/hook",
                ["analysis.completed"], min_risk_score=50, secret="mysecret")
            assert "hook_id" in result
            assert result["name"] == "Test Hook"
            assert result["secret"] == "mysecret"

    def test_auto_secret(self, tmp_path):
        with patch("hashguard.web.webhooks._get_webhooks_dir", return_value=tmp_path):
            from hashguard.web.webhooks import create_webhook
            result = create_webhook("Auto", "http://hook.com", ["analysis.malicious"])
            assert len(result["secret"]) == 32  # hex(16) = 32 chars

    def test_invalid_events(self, tmp_path):
        with patch("hashguard.web.webhooks._get_webhooks_dir", return_value=tmp_path):
            from hashguard.web.webhooks import create_webhook
            with pytest.raises(ValueError, match="Invalid events"):
                create_webhook("Bad", "http://hook.com", ["bogus.event"])

    def test_empty_url(self, tmp_path):
        with patch("hashguard.web.webhooks._get_webhooks_dir", return_value=tmp_path):
            from hashguard.web.webhooks import create_webhook
            with pytest.raises(ValueError, match="URL"):
                create_webhook("No URL", "", ["analysis.completed"])


class TestUpdateWebhook:
    def test_success(self, tmp_path):
        with patch("hashguard.web.webhooks._get_webhooks_dir", return_value=tmp_path):
            from hashguard.web.webhooks import create_webhook, update_webhook
            hook = create_webhook("Original", "http://hook.com", ["analysis.completed"])
            assert update_webhook(hook["hook_id"], name="Updated") is True

    def test_not_found(self, tmp_path):
        with patch("hashguard.web.webhooks._get_webhooks_dir", return_value=tmp_path):
            from hashguard.web.webhooks import update_webhook
            assert update_webhook("nonexistent", name="x") is False

    def test_invalid_events_on_update(self, tmp_path):
        with patch("hashguard.web.webhooks._get_webhooks_dir", return_value=tmp_path):
            from hashguard.web.webhooks import create_webhook, update_webhook
            hook = create_webhook("Test", "http://hook.com", ["analysis.completed"])
            with pytest.raises(ValueError, match="Invalid events"):
                update_webhook(hook["hook_id"], events=["bad.event"])


class TestDeleteWebhook:
    def test_success(self, tmp_path):
        with patch("hashguard.web.webhooks._get_webhooks_dir", return_value=tmp_path):
            from hashguard.web.webhooks import create_webhook, delete_webhook
            hook = create_webhook("Del", "http://hook.com", ["analysis.completed"])
            assert delete_webhook(hook["hook_id"]) is True

    def test_not_found(self, tmp_path):
        with patch("hashguard.web.webhooks._get_webhooks_dir", return_value=tmp_path):
            from hashguard.web.webhooks import delete_webhook
            assert delete_webhook("nonexistent") is False


class TestListGetWebhooks:
    def test_list_empty(self, tmp_path):
        with patch("hashguard.web.webhooks._get_webhooks_dir", return_value=tmp_path):
            from hashguard.web.webhooks import list_webhooks
            assert list_webhooks() == []

    def test_list_one(self, tmp_path):
        with patch("hashguard.web.webhooks._get_webhooks_dir", return_value=tmp_path):
            from hashguard.web.webhooks import create_webhook, list_webhooks
            create_webhook("Hook1", "http://x.com", ["analysis.completed"])
            hooks = list_webhooks()
            assert len(hooks) == 1
            assert hooks[0]["name"] == "Hook1"
            assert "secret_hash" not in hooks[0]

    def test_get_existing(self, tmp_path):
        with patch("hashguard.web.webhooks._get_webhooks_dir", return_value=tmp_path):
            from hashguard.web.webhooks import create_webhook, get_webhook
            hook = create_webhook("G", "http://x.com", ["analysis.completed"])
            got = get_webhook(hook["hook_id"])
            assert got is not None
            assert got["name"] == "G"

    def test_get_not_found(self, tmp_path):
        with patch("hashguard.web.webhooks._get_webhooks_dir", return_value=tmp_path):
            from hashguard.web.webhooks import get_webhook
            assert get_webhook("nonexistent") is None


class TestSendTest:
    def test_not_found(self, tmp_path):
        with patch("hashguard.web.webhooks._get_webhooks_dir", return_value=tmp_path):
            from hashguard.web.webhooks import send_test
            result = send_test("nonexistent")
            assert result["success"] is False

    def test_success(self, tmp_path):
        with patch("hashguard.web.webhooks._get_webhooks_dir", return_value=tmp_path):
            from hashguard.web.webhooks import create_webhook, send_test
            hook = create_webhook("T", "http://test.com", ["analysis.completed"])
            with patch("urllib.request.urlopen") as mock_urlopen:
                mock_resp = MagicMock()
                mock_resp.__enter__ = MagicMock(return_value=mock_resp)
                mock_resp.__exit__ = MagicMock(return_value=False)
                mock_resp.status = 200
                mock_resp.read.return_value = b"ok"
                mock_urlopen.return_value = mock_resp
                result = send_test(hook["hook_id"])
                assert result["success"] is True


# ── Delivery ────────────────────────────────────────────────────────────


class TestSignPayload:
    def test_deterministic(self):
        from hashguard.web.webhooks import _sign_payload
        sig1 = _sign_payload(b"hello", "secret")
        sig2 = _sign_payload(b"hello", "secret")
        assert sig1 == sig2

    def test_different_secrets(self):
        from hashguard.web.webhooks import _sign_payload
        sig1 = _sign_payload(b"data", "s1")
        sig2 = _sign_payload(b"data", "s2")
        assert sig1 != sig2


class TestDeliver:
    def test_success(self, tmp_path):
        with patch("hashguard.web.webhooks._get_webhooks_dir", return_value=tmp_path):
            from hashguard.web.webhooks import _deliver, _save_webhooks
            _save_webhooks({"h1": {"secret_hash": "abc", "trigger_count": 0}})
            with patch("urllib.request.urlopen") as mock_urlopen:
                mock_resp = MagicMock()
                mock_resp.__enter__ = MagicMock(return_value=mock_resp)
                mock_resp.__exit__ = MagicMock(return_value=False)
                mock_resp.status = 200
                mock_resp.read.return_value = b"ok"
                mock_urlopen.return_value = mock_resp
                result = _deliver("h1", {"url": "http://hook.com", "secret_hash": "abc"},
                                  {"event": "test"})
                assert result["success"] is True

    def test_http_error(self, tmp_path):
        with patch("hashguard.web.webhooks._get_webhooks_dir", return_value=tmp_path):
            from hashguard.web.webhooks import _deliver, _save_webhooks
            import urllib.error
            _save_webhooks({"h1": {"secret_hash": "abc"}})
            with patch("urllib.request.urlopen") as mock_urlopen:
                mock_urlopen.side_effect = urllib.error.HTTPError(
                    "http://hook.com", 500, "Server Error", {}, None)
                result = _deliver("h1", {"url": "http://hook.com", "secret_hash": "abc"},
                                  {"event": "test"})
                assert result["success"] is False
                assert "500" in result["error"]

    def test_url_error(self, tmp_path):
        with patch("hashguard.web.webhooks._get_webhooks_dir", return_value=tmp_path):
            from hashguard.web.webhooks import _deliver, _save_webhooks
            import urllib.error
            _save_webhooks({"h1": {"secret_hash": "abc"}})
            with patch("urllib.request.urlopen") as mock_urlopen:
                mock_urlopen.side_effect = urllib.error.URLError("Connection refused")
                result = _deliver("h1", {"url": "http://hook.com", "secret_hash": "abc"},
                                  {"event": "test"})
                assert result["success"] is False
                assert "Connection" in result["error"]

    def test_generic_exception(self, tmp_path):
        with patch("hashguard.web.webhooks._get_webhooks_dir", return_value=tmp_path):
            from hashguard.web.webhooks import _deliver, _save_webhooks
            _save_webhooks({"h1": {"secret_hash": "abc"}})
            with patch("urllib.request.urlopen") as mock_urlopen:
                mock_urlopen.side_effect = RuntimeError("timeout")
                result = _deliver("h1", {"url": "http://hook.com", "secret_hash": "abc"},
                                  {"event": "test"})
                assert result["success"] is False


# ── Event dispatch ──────────────────────────────────────────────────────


class TestFireEvent:
    def test_no_hooks(self, tmp_path):
        with patch("hashguard.web.webhooks._get_webhooks_dir", return_value=tmp_path):
            from hashguard.web.webhooks import fire_event
            assert fire_event("analysis.completed", {}) == 0

    def test_matching_hook(self, tmp_path):
        with patch("hashguard.web.webhooks._get_webhooks_dir", return_value=tmp_path):
            from hashguard.web.webhooks import create_webhook, fire_event
            create_webhook("H1", "http://hook.com", ["analysis.completed"])
            with patch("hashguard.web.webhooks._deliver"):
                count = fire_event("analysis.completed", {"risk_score": 50})
                assert count == 1

    def test_inactive_hook_skipped(self, tmp_path):
        with patch("hashguard.web.webhooks._get_webhooks_dir", return_value=tmp_path):
            from hashguard.web.webhooks import create_webhook, update_webhook, fire_event
            hook = create_webhook("H", "http://hook.com", ["analysis.completed"])
            update_webhook(hook["hook_id"], active=False)
            with patch("hashguard.web.webhooks._deliver"):
                assert fire_event("analysis.completed", {}) == 0

    def test_event_mismatch_skipped(self, tmp_path):
        with patch("hashguard.web.webhooks._get_webhooks_dir", return_value=tmp_path):
            from hashguard.web.webhooks import create_webhook, fire_event
            create_webhook("H", "http://hook.com", ["analysis.malicious"])
            with patch("hashguard.web.webhooks._deliver"):
                assert fire_event("analysis.completed", {}) == 0

    def test_risk_score_filter(self, tmp_path):
        with patch("hashguard.web.webhooks._get_webhooks_dir", return_value=tmp_path):
            from hashguard.web.webhooks import create_webhook, fire_event
            create_webhook("H", "http://hook.com", ["analysis.high_risk"], min_risk_score=80)
            with patch("hashguard.web.webhooks._deliver"):
                # Below threshold
                assert fire_event("analysis.high_risk", {"risk_score": 50}) == 0
                # Above threshold
                assert fire_event("analysis.high_risk", {"risk_score": 90}) == 1


# ── Notify analysis complete ────────────────────────────────────────────


class TestNotifyAnalysisComplete:
    def test_clean_sample(self):
        from hashguard.web.webhooks import notify_analysis_complete
        with patch("hashguard.web.webhooks.fire_event", return_value=0) as mock_fire:
            result = {"risk_score": {"score": 10, "verdict": "clean"},
                      "hashes": {"sha256": "abc"}, "path": "/tmp/test.exe"}
            notify_analysis_complete(result)
            # Should fire analysis.completed only (not malicious/high_risk)
            events = [c[0][0] for c in mock_fire.call_args_list]
            assert "analysis.completed" in events
            assert "analysis.malicious" not in events
            assert "analysis.high_risk" not in events

    def test_malicious_sample(self):
        from hashguard.web.webhooks import notify_analysis_complete
        with patch("hashguard.web.webhooks.fire_event", return_value=1) as mock_fire:
            result = {"risk_score": {"score": 95, "verdict": "malicious"},
                      "hashes": {"sha256": "abc"}, "path": "/tmp/bad.exe",
                      "malicious": True, "family_detection": {"family": "Emotet"}}
            notify_analysis_complete(result)
            events = [c[0][0] for c in mock_fire.call_args_list]
            assert "analysis.completed" in events
            assert "analysis.malicious" in events
            assert "analysis.high_risk" in events

    def test_high_risk_not_malicious(self):
        from hashguard.web.webhooks import notify_analysis_complete
        with patch("hashguard.web.webhooks.fire_event", return_value=0) as mock_fire:
            result = {"risk_score": 75, "hashes": {"sha256": "x"}, "path": "f.exe"}
            notify_analysis_complete(result)
            events = [c[0][0] for c in mock_fire.call_args_list]
            assert "analysis.completed" in events
            assert "analysis.high_risk" in events

    def test_numeric_risk_score(self):
        from hashguard.web.webhooks import notify_analysis_complete
        with patch("hashguard.web.webhooks.fire_event", return_value=0) as mock_fire:
            result = {"risk_score": 30}
            notify_analysis_complete(result)
            events = [c[0][0] for c in mock_fire.call_args_list]
            assert "analysis.completed" in events
