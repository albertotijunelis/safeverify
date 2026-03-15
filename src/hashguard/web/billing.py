"""Stripe billing integration for HashGuard SaaS.

Manages subscription plans, checkout sessions, customer portal,
and webhook events from Stripe.

Plans:
- free:       10 analyses/day, no API, no STIX
- pro:        500 analyses/day, API, STIX, 5 feeds  ($29/mo)
- team:       5000 analyses/day, multi-user, webhooks ($99/mo)
- enterprise: unlimited, self-hosted, SLA (custom)
"""

import os
from typing import Optional

from hashguard.logger import get_logger

logger = get_logger(__name__)

try:
    import stripe

    HAS_STRIPE = True
except ImportError:
    HAS_STRIPE = False


# ── Plan definitions ────────────────────────────────────────────────────────

PLANS = {
    "free": {
        "name": "Free",
        "price_monthly": 0,
        "price_annual": 0,
        "analyses_per_day": 10,
        "api_access": False,
        "stix_export": False,
        "max_users": 1,
        "webhooks": False,
        "features": ["10 analyses/day", "Dashboard access", "Basic reports"],
    },
    "pro": {
        "name": "Pro",
        "price_monthly": 29,
        "price_annual": 290,
        "analyses_per_day": 500,
        "api_access": True,
        "stix_export": True,
        "max_users": 1,
        "webhooks": False,
        "features": [
            "500 analyses/day",
            "REST API access",
            "STIX 2.1 export",
            "5 threat intel feeds",
            "ML classification",
            "Priority support",
        ],
    },
    "team": {
        "name": "Team",
        "price_monthly": 99,
        "price_annual": 990,
        "analyses_per_day": 5000,
        "api_access": True,
        "stix_export": True,
        "max_users": 10,
        "webhooks": True,
        "features": [
            "5,000 analyses/day",
            "Everything in Pro",
            "Up to 10 users",
            "Webhook notifications",
            "Malware clustering",
            "Batch ingestion",
        ],
    },
    "enterprise": {
        "name": "Enterprise",
        "price_monthly": -1,  # Custom pricing
        "price_annual": -1,
        "analyses_per_day": -1,  # Unlimited
        "api_access": True,
        "stix_export": True,
        "max_users": -1,  # Unlimited
        "webhooks": True,
        "features": [
            "Unlimited analyses",
            "Everything in Team",
            "Unlimited users",
            "Self-hosted option",
            "SLA guarantee",
            "Dedicated support",
        ],
    },
}

# Feature-to-plan map: which plan flag must be True for a feature.
# Used by require_feature() to gate endpoint access.
FEATURE_PLAN_FLAGS = {
    "api_access": "api_access",
    "stix_export": "stix_export",
    "webhooks": "webhooks",
    "soc": "webhooks",       # SOC integrations require Team+ (same gate as webhooks)
    "feeds_premium": "stix_export",  # STIX/MISP feeds require Pro+ (same gate as stix_export)
    "teams": "webhooks",     # Team management requires Team+
    "batch_ingest": "webhooks",  # Batch ingest requires Team+
}


def get_user_plan_id(user: dict) -> str:
    """Resolve the plan ID for a user dict (from auth dependency).

    Checks user['plan'] (set for local/no-auth mode), then looks up
    the tenant's active subscription in the DB.
    """
    # Direct plan field (set by auth when HASHGUARD_AUTH=0)
    if user.get("plan"):
        return user["plan"]

    tenant_id = user.get("tenant_id", "default")
    try:
        from hashguard.models import get_orm_session
        from hashguard.web.usage_metering import get_tenant_plan
        db = get_orm_session()
        try:
            info = get_tenant_plan(db, tenant_id)
            return info.get("plan_id", "free")
        finally:
            db.close()
    except Exception:
        return "free"


def check_feature_allowed(user: dict, feature: str) -> bool:
    """Return True if the user's plan allows *feature*."""
    plan_id = get_user_plan_id(user)
    plan = PLANS.get(plan_id, PLANS["free"])
    flag = FEATURE_PLAN_FLAGS.get(feature)
    if flag is None:
        return True  # Unknown feature = not gated
    return bool(plan.get(flag, False))


def require_feature(feature: str):
    """FastAPI dependency that gates an endpoint by plan feature.

    Usage:
        @router.get("/stix")
        async def stix_feed(user=Depends(require_feature("stix_export"))):
            ...

    Raises 403 if the user's plan does not include the feature.
    """
    try:
        from fastapi import Depends, HTTPException
        from hashguard.web.auth import get_current_user
    except ImportError:
        return None

    auth_dep = get_current_user()

    async def _check_feature(user: dict = Depends(auth_dep)) -> dict:
        if not check_feature_allowed(user, feature):
            plan_id = get_user_plan_id(user)
            raise HTTPException(
                status_code=403,
                detail=f"Your plan ({plan_id}) does not include this feature. Please upgrade.",
            )
        return user

    return _check_feature


def _get_stripe():
    """Initialize and return stripe module, or None."""
    if not HAS_STRIPE:
        return None
    key = os.environ.get("STRIPE_SECRET_KEY", "")
    if not key:
        return None
    stripe.api_key = key
    return stripe


def get_plans() -> list:
    """Return list of available plans with details."""
    return [{"id": k, **v} for k, v in PLANS.items()]


def get_plan(plan_id: str) -> Optional[dict]:
    """Get a single plan by ID."""
    plan = PLANS.get(plan_id)
    if plan:
        return {"id": plan_id, **plan}
    return None


def create_checkout_session(
    plan_id: str,
    user_email: str,
    tenant_id: str,
    success_url: str,
    cancel_url: str,
    billing_period: str = "monthly",
    promo_code: Optional[str] = None,
) -> Optional[dict]:
    """Create a Stripe Checkout Session for a subscription.

    Args:
        billing_period: "monthly" or "annual"
        promo_code: optional Stripe promotion code

    Returns dict with session_id and checkout_url, or None if Stripe unavailable.
    """
    s = _get_stripe()
    if not s:
        logger.warning("Stripe not configured — cannot create checkout session")
        return None

    plan = PLANS.get(plan_id)
    if not plan or plan["price_monthly"] <= 0:
        return None

    # Annual uses a separate Stripe price ID: STRIPE_PRICE_PRO_ANNUAL, etc.
    if billing_period == "annual":
        price_id = os.environ.get(f"STRIPE_PRICE_{plan_id.upper()}_ANNUAL")
    else:
        price_id = os.environ.get(f"STRIPE_PRICE_{plan_id.upper()}")

    if not price_id:
        logger.error("Missing STRIPE_PRICE_%s%s env var", plan_id.upper(),
                      "_ANNUAL" if billing_period == "annual" else "")
        return None

    session_kwargs = {
        "mode": "subscription",
        "customer_email": user_email,
        "line_items": [{"price": price_id, "quantity": 1}],
        "success_url": success_url,
        "cancel_url": cancel_url,
        "metadata": {
            "tenant_id": tenant_id,
            "plan_id": plan_id,
            "billing_period": billing_period,
        },
        "subscription_data": {
            "metadata": {
                "tenant_id": tenant_id,
                "plan_id": plan_id,
                "billing_period": billing_period,
            }
        },
    }

    if promo_code:
        session_kwargs["allow_promotion_codes"] = True

    try:
        session = s.checkout.Session.create(**session_kwargs)
        logger.info("Checkout session created")
        return {
            "session_id": session.id,
            "checkout_url": session.url,
        }
    except Exception as e:
        logger.error("Stripe checkout error: %s", e)
        return None


def create_customer_portal_session(
    customer_id: str,
    return_url: str,
) -> Optional[dict]:
    """Create a Stripe Customer Portal session for managing subscriptions."""
    s = _get_stripe()
    if not s:
        return None

    try:
        session = s.billing_portal.Session.create(
            customer=customer_id,
            return_url=return_url,
        )
        return {"portal_url": session.url}
    except Exception as e:
        logger.error("Stripe portal error: %s", e)
        return None


def handle_webhook_event(payload: bytes, sig_header: str) -> Optional[dict]:
    """Process a Stripe webhook event.

    Verifies signature and handles subscription lifecycle events.
    Returns dict with action taken, or None on verification failure.
    """
    s = _get_stripe()
    if not s:
        return None

    webhook_secret = os.environ.get("STRIPE_WEBHOOK_SECRET", "")
    if not webhook_secret:
        logger.error("STRIPE_WEBHOOK_SECRET not set")
        return None

    try:
        event = s.Webhook.construct_event(payload, sig_header, webhook_secret)
    except (ValueError, s.error.SignatureVerificationError) as e:
        logger.warning("Stripe webhook signature verification failed: %s", e)
        return None

    event_type = event["type"]
    data = event["data"]["object"]

    if event_type == "checkout.session.completed":
        return _handle_checkout_completed(data)
    elif event_type == "customer.subscription.updated":
        return _handle_subscription_updated(data)
    elif event_type == "customer.subscription.deleted":
        return _handle_subscription_deleted(data)
    elif event_type == "invoice.payment_failed":
        return _handle_payment_failed(data)

    return {"event": event_type, "action": "ignored"}


def _handle_checkout_completed(session: dict) -> dict:
    """Handle successful checkout — activate subscription."""
    tenant_id = session.get("metadata", {}).get("tenant_id", "")
    plan_id = session.get("metadata", {}).get("plan_id", "")
    customer_id = session.get("customer", "")
    subscription_id = session.get("subscription", "")

    if tenant_id and plan_id:
        _update_tenant_plan(tenant_id, plan_id, customer_id, subscription_id)
        logger.info("Subscription activated: tenant=%s plan=%s", tenant_id, plan_id)

    return {
        "event": "checkout.session.completed",
        "action": "subscription_activated",
        "tenant_id": tenant_id,
        "plan_id": plan_id,
    }


def _handle_subscription_updated(subscription: dict) -> dict:
    """Handle plan changes (upgrade/downgrade)."""
    tenant_id = subscription.get("metadata", {}).get("tenant_id", "")
    plan_id = subscription.get("metadata", {}).get("plan_id", "")
    status = subscription.get("status", "")

    if tenant_id and status == "active":
        _update_tenant_plan(tenant_id, plan_id, subscription.get("customer", ""), subscription["id"])
        logger.info("Subscription updated: tenant=%s plan=%s", tenant_id, plan_id)

    return {
        "event": "customer.subscription.updated",
        "action": "plan_updated",
        "tenant_id": tenant_id,
        "plan_id": plan_id,
        "status": status,
    }


def _handle_subscription_deleted(subscription: dict) -> dict:
    """Handle subscription cancellation — downgrade to free."""
    tenant_id = subscription.get("metadata", {}).get("tenant_id", "")

    if tenant_id:
        _update_tenant_plan(tenant_id, "free", "", "")
        logger.info("Subscription cancelled: tenant=%s -> free", tenant_id)

    return {
        "event": "customer.subscription.deleted",
        "action": "downgraded_to_free",
        "tenant_id": tenant_id,
    }


def _handle_payment_failed(invoice: dict) -> dict:
    """Handle failed payment — log warning."""
    customer = invoice.get("customer", "")
    logger.warning("Payment failed for customer %s", customer)
    return {
        "event": "invoice.payment_failed",
        "action": "payment_failed",
        "customer_id": customer,
    }


def _update_tenant_plan(
    tenant_id: str, plan_id: str, customer_id: str, subscription_id: str
) -> None:
    """Update tenant's subscription info in the database."""
    try:
        from hashguard.models import get_session_factory
        from hashguard.web.usage_metering import set_tenant_plan

        Session = get_session_factory()
        db = Session()
        try:
            set_tenant_plan(db, tenant_id, plan_id, customer_id, subscription_id)
        finally:
            db.close()
    except Exception as e:
        logger.error("Failed to update tenant plan: %s", e)
