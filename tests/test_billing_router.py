"""Tests for HashGuard billing API router.

Uses mocking for DB and business-layer functions to isolate router logic.
"""

import os
import pytest
from unittest.mock import patch, MagicMock

from hashguard.web.billing import PLANS


@pytest.fixture(autouse=True)
def _disable_auth():
    """Disable auth for all router tests."""
    old = os.environ.get("HASHGUARD_AUTH")
    os.environ["HASHGUARD_AUTH"] = "0"
    yield
    if old is None:
        os.environ.pop("HASHGUARD_AUTH", None)
    else:
        os.environ["HASHGUARD_AUTH"] = old


_FREE_PLAN_INFO = {
    "plan_id": "free", "status": "active",
    "stripe_customer_id": "", "stripe_subscription_id": "",
    "current_period_end": None,
}

_FREE_USAGE = {
    "analyses_today": 0, "daily_limit": 10,
    "daily_remaining": 10, "total_samples": 0, "plan_id": "free",
}


def _mock_db():
    """Return a context-manager-like mock for Depends(get_db)."""
    return iter([MagicMock()])


@pytest.fixture
def client():
    """Create a TestClient with get_db mocked out."""
    with patch("hashguard.web.routers.billing_router.get_db", side_effect=_mock_db):
        from fastapi import FastAPI
        from fastapi.testclient import TestClient
        from hashguard.web.routers.billing_router import router

        app = FastAPI()
        app.include_router(router)

        with TestClient(app) as tc:
            yield tc


class TestListPlans:
    """GET /api/billing/plans — public endpoint."""

    def test_returns_four_plans(self, client):
        resp = client.get("/api/billing/plans")
        assert resp.status_code == 200
        assert len(resp.json()["plans"]) == 4

    def test_plans_include_ids(self, client):
        ids = [p["id"] for p in client.get("/api/billing/plans").json()["plans"]]
        assert set(ids) == {"free", "pro", "team", "enterprise"}


class TestCurrentPlan:
    """GET /api/billing/current — requires auth."""

    @patch("hashguard.web.routers.billing_router.get_usage", return_value=_FREE_USAGE)
    @patch("hashguard.web.routers.billing_router.get_tenant_plan", return_value=_FREE_PLAN_INFO)
    def test_default_free_plan(self, _plan, _usage, client):
        resp = client.get("/api/billing/current")
        assert resp.status_code == 200
        data = resp.json()
        assert data["plan"]["id"] == "free"
        assert data["subscription"]["plan_id"] == "free"
        assert data["usage"]["analyses_today"] == 0

    @patch("hashguard.web.routers.billing_router.get_usage")
    @patch("hashguard.web.routers.billing_router.get_tenant_plan")
    def test_pro_plan(self, mock_plan, mock_usage, client):
        mock_plan.return_value = {
            "plan_id": "pro", "status": "active",
            "stripe_customer_id": "cus_123", "stripe_subscription_id": "sub_456",
            "current_period_end": None,
        }
        mock_usage.return_value = {
            "analyses_today": 42, "daily_limit": 500,
            "daily_remaining": 458, "total_samples": 100, "plan_id": "pro",
        }
        resp = client.get("/api/billing/current")
        assert resp.status_code == 200
        assert resp.json()["plan"]["id"] == "pro"
        assert resp.json()["usage"]["analyses_today"] == 42


class TestCheckout:
    """POST /api/billing/checkout."""

    def test_stripe_not_configured(self, client):
        resp = client.post("/api/billing/checkout", json={"plan_id": "pro"})
        assert resp.status_code == 503

    def test_invalid_plan_id_rejected(self, client):
        resp = client.post("/api/billing/checkout", json={"plan_id": "invalid"})
        assert resp.status_code == 422

    @patch("hashguard.web.routers.billing_router.create_checkout_session")
    def test_successful_checkout(self, mock_cs, client):
        mock_cs.return_value = {"url": "https://checkout.stripe.com/xxx"}
        resp = client.post("/api/billing/checkout", json={"plan_id": "pro"})
        assert resp.status_code == 200
        assert resp.json()["url"] == "https://checkout.stripe.com/xxx"


class TestPortal:
    """POST /api/billing/portal."""

    @patch("hashguard.web.routers.billing_router.get_tenant_plan", return_value=_FREE_PLAN_INFO)
    def test_no_customer_id_returns_400(self, _plan, client):
        resp = client.post("/api/billing/portal", json={})
        assert resp.status_code == 400

    @patch("hashguard.web.routers.billing_router.create_customer_portal_session")
    @patch("hashguard.web.routers.billing_router.get_tenant_plan")
    def test_with_customer_id(self, mock_plan, mock_portal, client):
        mock_plan.return_value = {
            "plan_id": "pro", "status": "active",
            "stripe_customer_id": "cus_123", "stripe_subscription_id": "",
            "current_period_end": None,
        }
        mock_portal.return_value = {"url": "https://billing.stripe.com/xxx"}
        resp = client.post("/api/billing/portal", json={})
        assert resp.status_code == 200
        assert resp.json()["url"] == "https://billing.stripe.com/xxx"


class TestWebhook:
    """POST /api/billing/webhook — no auth, verified by Stripe signature."""

    def test_missing_signature(self, client):
        resp = client.post("/api/billing/webhook", content=b"{}")
        assert resp.status_code == 400

    def test_invalid_webhook(self, client):
        resp = client.post(
            "/api/billing/webhook",
            content=b"{}",
            headers={"stripe-signature": "invalid"},
        )
        assert resp.status_code == 400

    @patch("hashguard.web.routers.billing_router.handle_webhook_event")
    def test_valid_webhook(self, mock_wh, client):
        mock_wh.return_value = {"event": "test", "action": "ok"}
        resp = client.post(
            "/api/billing/webhook",
            content=b"{}",
            headers={"stripe-signature": "t=123,v1=abc"},
        )
        assert resp.status_code == 200
        assert resp.json()["action"] == "ok"


class TestUsageStats:
    """GET /api/billing/usage."""

    @patch("hashguard.web.routers.billing_router.get_usage", return_value=_FREE_USAGE)
    @patch("hashguard.web.routers.billing_router.get_tenant_plan", return_value=_FREE_PLAN_INFO)
    def test_empty_usage(self, _plan, _usage, client):
        resp = client.get("/api/billing/usage")
        assert resp.status_code == 200
        data = resp.json()
        assert data["plan_id"] == "free"
        assert data["usage"]["analyses_today"] == 0
        assert "limits" in data

    @patch("hashguard.web.routers.billing_router.get_usage")
    @patch("hashguard.web.routers.billing_router.get_tenant_plan", return_value=_FREE_PLAN_INFO)
    def test_usage_with_records(self, _plan, mock_usage, client):
        mock_usage.return_value = {
            "analyses_today": 5, "daily_limit": 10,
            "daily_remaining": 5, "total_samples": 3, "plan_id": "free",
        }
        resp = client.get("/api/billing/usage")
        assert resp.json()["usage"]["analyses_today"] == 5
