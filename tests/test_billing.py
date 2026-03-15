"""Tests for HashGuard SaaS billing module."""

import pytest
from unittest.mock import patch, MagicMock

from hashguard.web.billing import (
    PLANS,
    get_plans,
    get_plan,
    create_checkout_session,
    create_customer_portal_session,
    handle_webhook_event,
    _handle_checkout_completed,
    _handle_subscription_updated,
    _handle_subscription_deleted,
    _handle_payment_failed,
)


class TestPlans:
    """Tests for plan definitions and retrieval."""

    def test_plans_has_four_tiers(self):
        assert len(PLANS) == 4
        assert set(PLANS.keys()) == {"free", "pro", "team", "enterprise"}

    def test_free_plan_limits(self):
        free = PLANS["free"]
        assert free["price_monthly"] == 0
        assert free["analyses_per_day"] == 10
        assert free["api_access"] is False
        assert free["stix_export"] is False
        assert free["max_users"] == 1

    def test_pro_plan_limits(self):
        pro = PLANS["pro"]
        assert pro["price_monthly"] == 29
        assert pro["analyses_per_day"] == 500
        assert pro["api_access"] is True
        assert pro["stix_export"] is True

    def test_team_plan_limits(self):
        team = PLANS["team"]
        assert team["price_monthly"] == 99
        assert team["analyses_per_day"] == 5000
        assert team["webhooks"] is True
        assert team["max_users"] == 10

    def test_enterprise_unlimited(self):
        ent = PLANS["enterprise"]
        assert ent["price_monthly"] == -1
        assert ent["analyses_per_day"] == -1
        assert ent["max_users"] == -1

    def test_get_plans_returns_all(self):
        plans = get_plans()
        assert len(plans) == 4
        for p in plans:
            assert "id" in p
            assert "name" in p
            assert "features" in p

    def test_get_plan_existing(self):
        plan = get_plan("pro")
        assert plan is not None
        assert plan["id"] == "pro"
        assert plan["name"] == "Pro"

    def test_get_plan_nonexistent(self):
        assert get_plan("nonexistent") is None

    def test_each_plan_has_features_list(self):
        for plan_id, plan in PLANS.items():
            assert isinstance(plan["features"], list)
            assert len(plan["features"]) >= 3


class TestCheckout:
    """Tests for Stripe checkout session creation."""

    def test_no_stripe_returns_none(self):
        """Without Stripe configured, returns None."""
        result = create_checkout_session(
            plan_id="pro",
            user_email="test@example.com",
            tenant_id="t1",
            success_url="http://localhost/success",
            cancel_url="http://localhost/cancel",
        )
        assert result is None

    def test_free_plan_not_checkable(self):
        """Free plan cannot create checkout."""
        result = create_checkout_session(
            plan_id="free",
            user_email="test@example.com",
            tenant_id="t1",
            success_url="http://localhost/success",
            cancel_url="http://localhost/cancel",
        )
        assert result is None

    def test_enterprise_not_checkable(self):
        """Enterprise plan (custom pricing) cannot create checkout."""
        result = create_checkout_session(
            plan_id="enterprise",
            user_email="test@example.com",
            tenant_id="t1",
            success_url="http://localhost/success",
            cancel_url="http://localhost/cancel",
        )
        assert result is None

    def test_portal_no_stripe_returns_none(self):
        result = create_customer_portal_session("cus_123", "http://localhost")
        assert result is None


class TestWebhookHandlers:
    """Tests for Stripe webhook event handlers."""

    def test_checkout_completed(self):
        session = {
            "metadata": {"tenant_id": "t1", "plan_id": "pro"},
            "customer": "cus_123",
            "subscription": "sub_456",
        }
        with patch("hashguard.web.billing._update_tenant_plan"):
            result = _handle_checkout_completed(session)
        assert result["event"] == "checkout.session.completed"
        assert result["action"] == "subscription_activated"
        assert result["tenant_id"] == "t1"
        assert result["plan_id"] == "pro"

    def test_subscription_updated(self):
        sub = {
            "id": "sub_456",
            "metadata": {"tenant_id": "t1", "plan_id": "team"},
            "status": "active",
            "customer": "cus_123",
        }
        with patch("hashguard.web.billing._update_tenant_plan"):
            result = _handle_subscription_updated(sub)
        assert result["action"] == "plan_updated"
        assert result["plan_id"] == "team"
        assert result["status"] == "active"

    def test_subscription_deleted(self):
        sub = {"metadata": {"tenant_id": "t1"}}
        with patch("hashguard.web.billing._update_tenant_plan"):
            result = _handle_subscription_deleted(sub)
        assert result["action"] == "downgraded_to_free"
        assert result["tenant_id"] == "t1"

    def test_payment_failed(self):
        invoice = {"customer": "cus_789"}
        result = _handle_payment_failed(invoice)
        assert result["action"] == "payment_failed"
        assert result["customer_id"] == "cus_789"

    def test_webhook_no_stripe_returns_none(self):
        result = handle_webhook_event(b"payload", "sig")
        assert result is None

    def test_checkout_no_metadata(self):
        """Checkout with missing metadata doesn't crash."""
        session = {"metadata": {}, "customer": "", "subscription": ""}
        with patch("hashguard.web.billing._update_tenant_plan"):
            result = _handle_checkout_completed(session)
        assert result["action"] == "subscription_activated"
        assert result["tenant_id"] == ""
