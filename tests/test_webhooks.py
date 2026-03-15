"""Tests for HashGuard webhook notification system."""

import json
import os
import time
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest

from hashguard.web.webhooks import (
    VALID_EVENTS,
    _get_webhooks_dir,
    _load_webhooks,
    _save_webhooks,
    _sign_payload,
    create_webhook,
    delete_webhook,
    fire_event,
    get_webhook,
    list_webhooks,
    notify_analysis_complete,
    send_test,
    update_webhook,
)


@pytest.fixture(autouse=True)
def isolate_webhooks(tmp_path, monkeypatch):
    """Use a temp directory for webhook storage in every test."""
    monkeypatch.setattr(
        "hashguard.web.webhooks._get_webhooks_dir", lambda: tmp_path
    )
    yield tmp_path


# ── CRUD tests ───────────────────────────────────────────────────────────────


class TestCreateWebhook:
    def test_create_basic(self):
        result = create_webhook(
            name="test-hook",
            url="https://example.com/hook",
            events=["analysis.high_risk"],
        )
        assert "hook_id" in result
        assert result["name"] == "test-hook"
        assert result["url"] == "https://example.com/hook"
        assert result["events"] == ["analysis.high_risk"]
        assert "secret" in result
        assert len(result["secret"]) == 32  # hex 16 bytes

    def test_create_with_custom_secret(self):
        result = create_webhook(
            name="custom",
            url="https://example.com/hook",
            events=["analysis.completed"],
            secret="my-custom-secret",
        )
        assert result["secret"] == "my-custom-secret"

    def test_create_with_min_risk_score(self):
        create_webhook(
            name="high-risk",
            url="https://example.com",
            events=["analysis.high_risk"],
            min_risk_score=75,
        )
        hooks = list_webhooks()
        assert hooks[0]["min_risk_score"] == 75

    def test_create_invalid_event(self):
        with pytest.raises(ValueError, match="Invalid events"):
            create_webhook(
                name="bad",
                url="https://example.com",
                events=["invalid.event"],
            )

    def test_create_empty_url_raises(self):
        with pytest.raises(ValueError, match="URL is required"):
            create_webhook(name="no-url", url="", events=["analysis.completed"])

    def test_create_persists_to_file(self, isolate_webhooks):
        create_webhook(
            name="persist",
            url="https://example.com",
            events=["analysis.completed"],
        )
        data = json.loads((isolate_webhooks / "webhooks.json").read_text())
        assert len(data) == 1

    def test_create_multiple(self):
        create_webhook(name="h1", url="https://a.com", events=["analysis.completed"])
        create_webhook(name="h2", url="https://b.com", events=["analysis.malicious"])
        assert len(list_webhooks()) == 2


class TestDeleteWebhook:
    def test_delete_existing(self):
        result = create_webhook(name="del", url="https://a.com", events=["analysis.completed"])
        assert delete_webhook(result["hook_id"]) is True
        assert len(list_webhooks()) == 0

    def test_delete_nonexistent(self):
        assert delete_webhook("nonexistent") is False


class TestUpdateWebhook:
    def test_update_name(self):
        result = create_webhook(name="old", url="https://a.com", events=["analysis.completed"])
        assert update_webhook(result["hook_id"], name="new") is True
        hook = get_webhook(result["hook_id"])
        assert hook["name"] == "new"

    def test_update_active(self):
        result = create_webhook(name="act", url="https://a.com", events=["analysis.completed"])
        update_webhook(result["hook_id"], active=False)
        hook = get_webhook(result["hook_id"])
        assert hook["active"] is False

    def test_update_events(self):
        result = create_webhook(name="ev", url="https://a.com", events=["analysis.completed"])
        update_webhook(result["hook_id"], events=["analysis.high_risk", "analysis.malicious"])
        hook = get_webhook(result["hook_id"])
        assert set(hook["events"]) == {"analysis.high_risk", "analysis.malicious"}

    def test_update_invalid_events(self):
        result = create_webhook(name="ev", url="https://a.com", events=["analysis.completed"])
        with pytest.raises(ValueError, match="Invalid events"):
            update_webhook(result["hook_id"], events=["bad.event"])

    def test_update_nonexistent(self):
        assert update_webhook("nonexistent", name="x") is False


class TestListWebhooks:
    def test_list_empty(self):
        assert list_webhooks() == []

    def test_list_returns_all_fields(self):
        create_webhook(name="full", url="https://a.com", events=["analysis.completed"], min_risk_score=50)
        hooks = list_webhooks()
        assert len(hooks) == 1
        h = hooks[0]
        assert "hook_id" in h
        assert h["name"] == "full"
        assert h["url"] == "https://a.com"
        assert h["min_risk_score"] == 50
        assert h["active"] is True
        assert h["trigger_count"] == 0
        # Secret should NOT be in list response
        assert "secret" not in h
        assert "secret_hash" not in h

    def test_list_multiple(self):
        for i in range(5):
            create_webhook(name=f"h{i}", url=f"https://{i}.com", events=["analysis.completed"])
        assert len(list_webhooks()) == 5


class TestGetWebhook:
    def test_get_existing(self):
        result = create_webhook(name="get", url="https://a.com", events=["analysis.completed"])
        hook = get_webhook(result["hook_id"])
        assert hook is not None
        assert hook["name"] == "get"

    def test_get_nonexistent(self):
        assert get_webhook("nonexistent") is None


# ── Signing tests ────────────────────────────────────────────────────────────


class TestSignature:
    def test_sign_payload_deterministic(self):
        payload = b'{"event": "test"}'
        sig1 = _sign_payload(payload, "secret_hash")
        sig2 = _sign_payload(payload, "secret_hash")
        assert sig1 == sig2

    def test_sign_payload_different_keys(self):
        payload = b'{"event": "test"}'
        sig1 = _sign_payload(payload, "key1")
        sig2 = _sign_payload(payload, "key2")
        assert sig1 != sig2


# ── Event dispatch tests ────────────────────────────────────────────────────


class TestFireEvent:
    def test_fire_returns_match_count(self):
        create_webhook(name="h1", url="https://a.com", events=["analysis.high_risk"])
        create_webhook(name="h2", url="https://b.com", events=["analysis.malicious"])
        # Only h1 should match
        with patch("hashguard.web.webhooks._deliver"):
            count = fire_event("analysis.high_risk", {"risk_score": 80})
        assert count == 1

    def test_fire_no_match(self):
        create_webhook(name="h1", url="https://a.com", events=["analysis.malicious"])
        with patch("hashguard.web.webhooks._deliver"):
            count = fire_event("analysis.completed", {})
        assert count == 0

    def test_fire_skips_inactive(self):
        result = create_webhook(name="h1", url="https://a.com", events=["analysis.high_risk"])
        update_webhook(result["hook_id"], active=False)
        with patch("hashguard.web.webhooks._deliver"):
            count = fire_event("analysis.high_risk", {"risk_score": 90})
        assert count == 0

    def test_fire_respects_min_risk_score(self):
        create_webhook(
            name="h1", url="https://a.com", events=["analysis.high_risk"], min_risk_score=80
        )
        with patch("hashguard.web.webhooks._deliver"):
            count = fire_event("analysis.high_risk", {"risk_score": 50})
        assert count == 0

    def test_fire_passes_min_risk_score(self):
        create_webhook(
            name="h1", url="https://a.com", events=["analysis.high_risk"], min_risk_score=80
        )
        with patch("hashguard.web.webhooks._deliver"):
            count = fire_event("analysis.high_risk", {"risk_score": 90})
        assert count == 1

    def test_fire_multiple_hooks(self):
        create_webhook(name="h1", url="https://a.com", events=["analysis.completed"])
        create_webhook(name="h2", url="https://b.com", events=["analysis.completed"])
        create_webhook(name="h3", url="https://c.com", events=["analysis.malicious"])
        with patch("hashguard.web.webhooks._deliver"):
            count = fire_event("analysis.completed", {})
        assert count == 2


# ── Notify analysis complete ─────────────────────────────────────────────────


class TestNotifyAnalysisComplete:
    def test_notify_high_risk(self):
        create_webhook(name="h1", url="https://a.com", events=["analysis.high_risk", "analysis.completed"])
        with patch("hashguard.web.webhooks._deliver"):
            total = notify_analysis_complete({
                "hashes": {"sha256": "abc123"},
                "risk_score": {"score": 85, "verdict": "malicious"},
                "malicious": True,
                "path": "/tmp/test.exe",
            })
        # analysis.completed + analysis.malicious + analysis.high_risk
        assert total >= 2

    def test_notify_clean(self):
        create_webhook(name="h1", url="https://a.com", events=["analysis.completed"])
        with patch("hashguard.web.webhooks._deliver"):
            total = notify_analysis_complete({
                "hashes": {"sha256": "abc123"},
                "risk_score": {"score": 0, "verdict": "clean"},
                "malicious": False,
                "path": "/tmp/clean.exe",
            })
        assert total == 1  # only analysis.completed

    def test_notify_no_webhooks(self):
        total = notify_analysis_complete({
            "hashes": {"sha256": "abc123"},
            "risk_score": {"score": 90, "verdict": "malicious"},
            "malicious": True,
        })
        assert total == 0


# ── Test webhook endpoint ────────────────────────────────────────────────────


class TestSendTest:
    def test_test_nonexistent(self):
        result = send_test("nonexistent")
        assert result["success"] is False
        assert "not found" in result["error"].lower()


# ── Valid events ─────────────────────────────────────────────────────────────


class TestValidEvents:
    def test_all_valid_events_exist(self):
        expected = {
            "analysis.completed",
            "analysis.high_risk",
            "analysis.malicious",
            "family.new",
            "anomaly.detected",
            "ingest.completed",
        }
        assert VALID_EVENTS == expected
