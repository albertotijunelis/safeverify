"""Tests for billing module — plans, feature gating, Stripe integration."""

import os
import pytest
from unittest.mock import patch, MagicMock


# ── Plan definitions ────────────────────────────────────────────────────


class TestPlanDefinitions:
    def test_plans_exist(self):
        from hashguard.web.billing import PLANS
        assert "free" in PLANS
        assert "pro" in PLANS
        assert "team" in PLANS
        assert "enterprise" in PLANS

    def test_free_plan_no_api(self):
        from hashguard.web.billing import PLANS
        assert PLANS["free"]["api_access"] is False
        assert PLANS["free"]["stix_export"] is False

    def test_pro_plan_has_api(self):
        from hashguard.web.billing import PLANS
        assert PLANS["pro"]["api_access"] is True
        assert PLANS["pro"]["stix_export"] is True

    def test_team_plan_has_webhooks(self):
        from hashguard.web.billing import PLANS
        assert PLANS["team"]["webhooks"] is True
        assert PLANS["team"]["max_users"] == 10

    def test_get_plans(self):
        from hashguard.web.billing import get_plans
        plans = get_plans()
        assert len(plans) == 4
        assert all("id" in p for p in plans)

    def test_get_plan_existing(self):
        from hashguard.web.billing import get_plan
        p = get_plan("pro")
        assert p is not None
        assert p["id"] == "pro"

    def test_get_plan_nonexistent(self):
        from hashguard.web.billing import get_plan
        assert get_plan("nonexistent") is None


# ── Feature gating ──────────────────────────────────────────────────────


class TestCheckFeatureAllowed:
    def test_free_no_api(self):
        from hashguard.web.billing import check_feature_allowed
        assert check_feature_allowed({"plan": "free"}, "api_access") is False

    def test_pro_has_api(self):
        from hashguard.web.billing import check_feature_allowed
        assert check_feature_allowed({"plan": "pro"}, "api_access") is True

    def test_free_no_webhooks(self):
        from hashguard.web.billing import check_feature_allowed
        assert check_feature_allowed({"plan": "free"}, "webhooks") is False

    def test_team_has_webhooks(self):
        from hashguard.web.billing import check_feature_allowed
        assert check_feature_allowed({"plan": "team"}, "webhooks") is True

    def test_unknown_feature_allowed(self):
        from hashguard.web.billing import check_feature_allowed
        assert check_feature_allowed({"plan": "free"}, "unknown_feature") is True

    def test_soc_requires_team(self):
        from hashguard.web.billing import check_feature_allowed
        assert check_feature_allowed({"plan": "free"}, "soc") is False
        assert check_feature_allowed({"plan": "team"}, "soc") is True


class TestGetUserPlanId:
    def test_direct_plan_field(self):
        from hashguard.web.billing import get_user_plan_id
        assert get_user_plan_id({"plan": "pro"}) == "pro"

    def test_no_plan_fallback_free(self):
        from hashguard.web.billing import get_user_plan_id
        with patch("hashguard.web.billing.get_user_plan_id") as mock_fn:
            # When DB lookup fails, should return "free"
            pass
        # Direct test: no plan field, DB import fails
        user = {"tenant_id": "t1"}
        with patch.dict("sys.modules", {"hashguard.models": None}):
            result = get_user_plan_id(user)
            assert result == "free"

    def test_db_lookup_success(self):
        from hashguard.web.billing import get_user_plan_id
        mock_db = MagicMock()
        mock_session = MagicMock()
        with patch("hashguard.web.billing.get_user_plan_id", wraps=get_user_plan_id):
            with patch("hashguard.models.get_orm_session", return_value=mock_db):
                with patch("hashguard.web.usage_metering.get_tenant_plan",
                           return_value={"plan_id": "team"}):
                    result = get_user_plan_id({"tenant_id": "t1"})
                    assert result == "team"


class TestRequireFeature:
    def test_returns_callable(self):
        from hashguard.web.billing import require_feature
        dep = require_feature("api_access")
        assert callable(dep)


# ── Stripe functions ────────────────────────────────────────────────────


class TestGetStripe:
    def test_no_stripe_module(self):
        from hashguard.web.billing import _get_stripe
        with patch("hashguard.web.billing.HAS_STRIPE", False):
            assert _get_stripe() is None

    def test_no_env_key(self):
        from hashguard.web.billing import _get_stripe
        with patch("hashguard.web.billing.HAS_STRIPE", True), \
             patch.dict(os.environ, {"STRIPE_SECRET_KEY": ""}, clear=False):
            assert _get_stripe() is None


class TestCreateCheckoutSession:
    def test_no_stripe(self):
        from hashguard.web.billing import create_checkout_session
        with patch("hashguard.web.billing._get_stripe", return_value=None):
            result = create_checkout_session("pro", "a@b.c", "t1", "http://ok", "http://cancel")
            assert result is None

    def test_invalid_plan(self):
        from hashguard.web.billing import create_checkout_session
        with patch("hashguard.web.billing._get_stripe", return_value=MagicMock()):
            result = create_checkout_session("nonexistent", "a@b.c", "t1", "http://ok", "http://cancel")
            assert result is None

    def test_free_plan_no_checkout(self):
        from hashguard.web.billing import create_checkout_session
        with patch("hashguard.web.billing._get_stripe", return_value=MagicMock()):
            result = create_checkout_session("free", "a@b.c", "t1", "http://ok", "http://cancel")
            assert result is None

    def test_missing_price_env(self):
        from hashguard.web.billing import create_checkout_session
        mock_s = MagicMock()
        with patch("hashguard.web.billing._get_stripe", return_value=mock_s), \
             patch.dict(os.environ, {}, clear=False):
            # Remove any STRIPE_PRICE_* vars
            for key in list(os.environ):
                if key.startswith("STRIPE_PRICE_"):
                    os.environ.pop(key, None)
            result = create_checkout_session("pro", "a@b.c", "t1", "http://ok", "http://cancel")
            assert result is None

    def test_success_monthly(self):
        from hashguard.web.billing import create_checkout_session
        mock_s = MagicMock()
        mock_session = MagicMock()
        mock_session.id = "sess_123"
        mock_session.url = "https://checkout.stripe.com/sess_123"
        mock_s.checkout.Session.create.return_value = mock_session
        with patch("hashguard.web.billing._get_stripe", return_value=mock_s), \
             patch.dict(os.environ, {"STRIPE_PRICE_PRO": "price_pro_123"}, clear=False):
            result = create_checkout_session("pro", "a@b.c", "t1", "http://ok", "http://cancel")
            assert result is not None
            assert result["session_id"] == "sess_123"

    def test_success_annual(self):
        from hashguard.web.billing import create_checkout_session
        mock_s = MagicMock()
        mock_session = MagicMock()
        mock_session.id = "sess_456"
        mock_session.url = "https://checkout.stripe.com/sess_456"
        mock_s.checkout.Session.create.return_value = mock_session
        with patch("hashguard.web.billing._get_stripe", return_value=mock_s), \
             patch.dict(os.environ, {"STRIPE_PRICE_PRO_ANNUAL": "price_pro_ann"}, clear=False):
            result = create_checkout_session(
                "pro", "a@b.c", "t1", "http://ok", "http://cancel", billing_period="annual")
            assert result is not None

    def test_stripe_exception(self):
        from hashguard.web.billing import create_checkout_session
        mock_s = MagicMock()
        mock_s.checkout.Session.create.side_effect = Exception("Stripe error")
        with patch("hashguard.web.billing._get_stripe", return_value=mock_s), \
             patch.dict(os.environ, {"STRIPE_PRICE_PRO": "price_pro_123"}, clear=False):
            result = create_checkout_session("pro", "a@b.c", "t1", "http://ok", "http://cancel")
            assert result is None

    def test_promo_code(self):
        from hashguard.web.billing import create_checkout_session
        mock_s = MagicMock()
        mock_session = MagicMock()
        mock_session.id = "sess_promo"
        mock_session.url = "https://checkout.stripe.com/sess_promo"
        mock_s.checkout.Session.create.return_value = mock_session
        with patch("hashguard.web.billing._get_stripe", return_value=mock_s), \
             patch.dict(os.environ, {"STRIPE_PRICE_PRO": "price_pro_123"}, clear=False):
            result = create_checkout_session(
                "pro", "a@b.c", "t1", "http://ok", "http://cancel", promo_code="SAVE10")
            assert result is not None
            # Verify allow_promotion_codes was set
            call_kwargs = mock_s.checkout.Session.create.call_args[1]
            assert call_kwargs.get("allow_promotion_codes") is True


class TestCreateCustomerPortalSession:
    def test_no_stripe(self):
        from hashguard.web.billing import create_customer_portal_session
        with patch("hashguard.web.billing._get_stripe", return_value=None):
            assert create_customer_portal_session("cus_123", "http://return") is None

    def test_success(self):
        from hashguard.web.billing import create_customer_portal_session
        mock_s = MagicMock()
        mock_session = MagicMock()
        mock_session.url = "https://portal.stripe.com"
        mock_s.billing_portal.Session.create.return_value = mock_session
        with patch("hashguard.web.billing._get_stripe", return_value=mock_s):
            result = create_customer_portal_session("cus_123", "http://return")
            assert result == {"portal_url": "https://portal.stripe.com"}

    def test_exception(self):
        from hashguard.web.billing import create_customer_portal_session
        mock_s = MagicMock()
        mock_s.billing_portal.Session.create.side_effect = Exception("fail")
        with patch("hashguard.web.billing._get_stripe", return_value=mock_s):
            assert create_customer_portal_session("cus_123", "http://return") is None


# ── Webhook event handling ──────────────────────────────────────────────


class TestHandleWebhookEvent:
    def test_no_stripe(self):
        from hashguard.web.billing import handle_webhook_event
        with patch("hashguard.web.billing._get_stripe", return_value=None):
            assert handle_webhook_event(b"", "") is None

    def test_no_webhook_secret(self):
        from hashguard.web.billing import handle_webhook_event
        mock_s = MagicMock()
        with patch("hashguard.web.billing._get_stripe", return_value=mock_s), \
             patch.dict(os.environ, {"STRIPE_WEBHOOK_SECRET": ""}, clear=False):
            assert handle_webhook_event(b"", "") is None

    def test_signature_failure(self):
        from hashguard.web.billing import handle_webhook_event
        mock_s = MagicMock()
        mock_s.Webhook.construct_event.side_effect = ValueError("bad sig")
        mock_s.error.SignatureVerificationError = Exception
        with patch("hashguard.web.billing._get_stripe", return_value=mock_s), \
             patch.dict(os.environ, {"STRIPE_WEBHOOK_SECRET": "whsec_123"}, clear=False):
            assert handle_webhook_event(b"payload", "sig") is None

    def test_checkout_completed(self):
        from hashguard.web.billing import handle_webhook_event
        mock_s = MagicMock()
        mock_s.error.SignatureVerificationError = Exception
        event = {
            "type": "checkout.session.completed",
            "data": {"object": {"metadata": {"tenant_id": "t1", "plan_id": "pro"},
                                "customer": "cus_1", "subscription": "sub_1"}},
        }
        mock_s.Webhook.construct_event.return_value = event
        with patch("hashguard.web.billing._get_stripe", return_value=mock_s), \
             patch.dict(os.environ, {"STRIPE_WEBHOOK_SECRET": "whsec_123"}, clear=False), \
             patch("hashguard.web.billing._update_tenant_plan"):
            result = handle_webhook_event(b"p", "sig")
            assert result["action"] == "subscription_activated"

    def test_subscription_updated(self):
        from hashguard.web.billing import handle_webhook_event
        mock_s = MagicMock()
        mock_s.error.SignatureVerificationError = Exception
        event = {
            "type": "customer.subscription.updated",
            "data": {"object": {"id": "sub_1", "metadata": {"tenant_id": "t1", "plan_id": "team"},
                                "status": "active", "customer": "cus_1"}},
        }
        mock_s.Webhook.construct_event.return_value = event
        with patch("hashguard.web.billing._get_stripe", return_value=mock_s), \
             patch.dict(os.environ, {"STRIPE_WEBHOOK_SECRET": "whsec_123"}, clear=False), \
             patch("hashguard.web.billing._update_tenant_plan"):
            result = handle_webhook_event(b"p", "sig")
            assert result["action"] == "plan_updated"

    def test_subscription_deleted(self):
        from hashguard.web.billing import handle_webhook_event
        mock_s = MagicMock()
        mock_s.error.SignatureVerificationError = Exception
        event = {
            "type": "customer.subscription.deleted",
            "data": {"object": {"metadata": {"tenant_id": "t1"}}},
        }
        mock_s.Webhook.construct_event.return_value = event
        with patch("hashguard.web.billing._get_stripe", return_value=mock_s), \
             patch.dict(os.environ, {"STRIPE_WEBHOOK_SECRET": "whsec_123"}, clear=False), \
             patch("hashguard.web.billing._update_tenant_plan"):
            result = handle_webhook_event(b"p", "sig")
            assert result["action"] == "downgraded_to_free"

    def test_payment_failed(self):
        from hashguard.web.billing import handle_webhook_event
        mock_s = MagicMock()
        mock_s.error.SignatureVerificationError = Exception
        event = {
            "type": "invoice.payment_failed",
            "data": {"object": {"customer": "cus_fail"}},
        }
        mock_s.Webhook.construct_event.return_value = event
        with patch("hashguard.web.billing._get_stripe", return_value=mock_s), \
             patch.dict(os.environ, {"STRIPE_WEBHOOK_SECRET": "whsec_123"}, clear=False):
            result = handle_webhook_event(b"p", "sig")
            assert result["action"] == "payment_failed"

    def test_unknown_event_ignored(self):
        from hashguard.web.billing import handle_webhook_event
        mock_s = MagicMock()
        mock_s.error.SignatureVerificationError = Exception
        event = {
            "type": "some.other.event",
            "data": {"object": {}},
        }
        mock_s.Webhook.construct_event.return_value = event
        with patch("hashguard.web.billing._get_stripe", return_value=mock_s), \
             patch.dict(os.environ, {"STRIPE_WEBHOOK_SECRET": "whsec_123"}, clear=False):
            result = handle_webhook_event(b"p", "sig")
            assert result["action"] == "ignored"


# ── Internal handlers ───────────────────────────────────────────────────


class TestWebhookHandlers:
    def test_handle_checkout_completed(self):
        from hashguard.web.billing import _handle_checkout_completed
        with patch("hashguard.web.billing._update_tenant_plan") as mock_update:
            result = _handle_checkout_completed({
                "metadata": {"tenant_id": "t1", "plan_id": "pro"},
                "customer": "cus_1", "subscription": "sub_1",
            })
            assert result["event"] == "checkout.session.completed"
            mock_update.assert_called_once_with("t1", "pro", "cus_1", "sub_1")

    def test_handle_checkout_no_metadata(self):
        from hashguard.web.billing import _handle_checkout_completed
        with patch("hashguard.web.billing._update_tenant_plan") as mock_update:
            result = _handle_checkout_completed({})
            mock_update.assert_not_called()

    def test_handle_subscription_updated_active(self):
        from hashguard.web.billing import _handle_subscription_updated
        with patch("hashguard.web.billing._update_tenant_plan") as mock_update:
            result = _handle_subscription_updated({
                "id": "sub_1", "metadata": {"tenant_id": "t1", "plan_id": "team"},
                "status": "active", "customer": "cus_1",
            })
            assert result["action"] == "plan_updated"
            mock_update.assert_called_once()

    def test_handle_subscription_updated_inactive(self):
        from hashguard.web.billing import _handle_subscription_updated
        with patch("hashguard.web.billing._update_tenant_plan") as mock_update:
            result = _handle_subscription_updated({
                "id": "sub_1", "metadata": {"tenant_id": "t1", "plan_id": "team"},
                "status": "past_due", "customer": "cus_1",
            })
            mock_update.assert_not_called()

    def test_handle_subscription_deleted(self):
        from hashguard.web.billing import _handle_subscription_deleted
        with patch("hashguard.web.billing._update_tenant_plan") as mock_update:
            result = _handle_subscription_deleted({"metadata": {"tenant_id": "t1"}})
            mock_update.assert_called_once_with("t1", "free", "", "")

    def test_handle_payment_failed(self):
        from hashguard.web.billing import _handle_payment_failed
        result = _handle_payment_failed({"customer": "cus_fail"})
        assert result["customer_id"] == "cus_fail"


class TestUpdateTenantPlan:
    def test_db_error_handled(self):
        from hashguard.web.billing import _update_tenant_plan
        with patch("hashguard.models.get_session_factory", side_effect=Exception("no db")):
            # Should not raise
            _update_tenant_plan("t1", "pro", "cus_1", "sub_1")

    def test_success(self):
        from hashguard.web.billing import _update_tenant_plan
        mock_session_cls = MagicMock()
        mock_db = MagicMock()
        mock_session_cls.return_value = mock_db
        with patch("hashguard.models.get_session_factory", return_value=mock_session_cls), \
             patch("hashguard.web.usage_metering.set_tenant_plan") as mock_set:
            _update_tenant_plan("t1", "pro", "cus_1", "sub_1")
            mock_set.assert_called_once_with(mock_db, "t1", "pro", "cus_1", "sub_1")
            mock_db.close.assert_called_once()
