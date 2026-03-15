"""Billing API router for HashGuard SaaS.

Endpoints:
- GET  /api/billing/plans          List available plans
- GET  /api/billing/current        Current plan & usage for authenticated user
- POST /api/billing/checkout       Create Stripe checkout session
- POST /api/billing/portal         Create Stripe customer portal session
- POST /api/billing/webhook        Stripe webhook handler
- GET  /api/billing/usage          Usage statistics for current tenant
"""

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from hashguard.models import get_db
from hashguard.web.auth import get_current_user
from hashguard.web.billing import (
    PLANS,
    create_checkout_session,
    create_customer_portal_session,
    get_plan,
    get_plans,
    handle_webhook_event,
)
from hashguard.web.usage_metering import get_usage, get_tenant_plan

router = APIRouter(prefix="/api/billing", tags=["Billing"])


# ── Request models ──────────────────────────────────────────────────────────


class CheckoutRequest(BaseModel):
    plan_id: str = Field(..., pattern="^(pro|team)$")
    billing_period: str = Field(default="monthly", pattern="^(monthly|annual)$")
    promo_code: Optional[str] = None
    success_url: str = Field(default="")
    cancel_url: str = Field(default="")


class PortalRequest(BaseModel):
    return_url: str = Field(default="")


# ── Endpoints ───────────────────────────────────────────────────────────────


@router.get("/plans")
async def list_plans():
    """List all available subscription plans."""
    return {"plans": get_plans()}


@router.get("/current")
async def current_plan(
    user=Depends(get_current_user()),
    db: Session = Depends(get_db),
):
    """Get current plan and usage for the authenticated user."""
    tenant_id = user.get("tenant_id", "default")
    plan_info = get_tenant_plan(db, tenant_id)
    usage = get_usage(db, tenant_id)
    plan_details = get_plan(plan_info["plan_id"]) or get_plan("free")

    return {
        "plan": plan_details,
        "subscription": plan_info,
        "usage": usage,
    }


@router.post("/checkout")
async def create_checkout(
    req: CheckoutRequest,
    request: Request,
    user=Depends(get_current_user()),
):
    """Create a Stripe Checkout Session for upgrading."""
    tenant_id = user.get("tenant_id", "default")
    email = user.get("sub", "")

    base = str(request.base_url).rstrip("/")
    success = req.success_url or f"{base}/?billing=success"
    cancel = req.cancel_url or f"{base}/?billing=cancel"

    result = create_checkout_session(
        plan_id=req.plan_id,
        user_email=email,
        tenant_id=tenant_id,
        success_url=success,
        cancel_url=cancel,
        billing_period=req.billing_period,
        promo_code=req.promo_code,
    )
    if not result:
        raise HTTPException(
            status_code=503,
            detail="Stripe not configured or plan unavailable. Set STRIPE_SECRET_KEY and STRIPE_PRICE_* env vars.",
        )
    return result


@router.post("/portal")
async def customer_portal(
    req: PortalRequest,
    request: Request,
    user=Depends(get_current_user()),
    db: Session = Depends(get_db),
):
    """Create a Stripe Customer Portal session for managing subscription."""
    tenant_id = user.get("tenant_id", "default")
    plan_info = get_tenant_plan(db, tenant_id)
    customer_id = plan_info.get("stripe_customer_id", "")

    if not customer_id:
        raise HTTPException(status_code=400, detail="No active Stripe subscription found")

    base = str(request.base_url).rstrip("/")
    return_url = req.return_url or f"{base}/?page=billing"

    result = create_customer_portal_session(customer_id, return_url)
    if not result:
        raise HTTPException(status_code=503, detail="Stripe not configured")
    return result


@router.post("/webhook")
async def stripe_webhook(request: Request):
    """Handle Stripe webhook events (no auth — verified by signature)."""
    payload = await request.body()
    sig = request.headers.get("stripe-signature", "")

    if not sig:
        raise HTTPException(status_code=400, detail="Missing stripe-signature header")

    result = handle_webhook_event(payload, sig)
    if result is None:
        raise HTTPException(status_code=400, detail="Webhook verification failed")
    return result


@router.get("/usage")
async def usage_stats(
    user=Depends(get_current_user()),
    db: Session = Depends(get_db),
):
    """Get detailed usage statistics for the current tenant."""
    tenant_id = user.get("tenant_id", "default")
    usage = get_usage(db, tenant_id)
    plan_info = get_tenant_plan(db, tenant_id)
    plan = get_plan(plan_info["plan_id"]) or get_plan("free")

    limits = PLANS.get(plan_info["plan_id"], PLANS["free"])

    return {
        "usage": usage,
        "limits": {
            "analyses_per_day": limits["analyses_per_day"],
            "api_access": limits["api_access"],
            "stix_export": limits["stix_export"],
            "max_users": limits["max_users"],
            "webhooks": limits["webhooks"],
        },
        "plan_id": plan_info["plan_id"],
        "plan_name": plan["name"] if plan else "Free",
    }
