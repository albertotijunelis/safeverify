"""Usage metering for HashGuard SaaS.

Tracks analysis usage per tenant per day and enforces plan limits.
Provides functions to:
- Record an analysis event
- Check if tenant has remaining quota
- Get usage statistics
- Get/set tenant plan information
"""

from datetime import date, datetime, timezone
from typing import Optional

from sqlalchemy.orm import Session

from hashguard.logger import get_logger
from hashguard.web.billing import PLANS

logger = get_logger(__name__)


def _today() -> str:
    return date.today().isoformat()


def get_tenant_plan(db: Session, tenant_id: str) -> dict:
    """Get the current plan info for a tenant from the Subscription table."""
    try:
        from hashguard.models import Subscription

        sub = (
            db.query(Subscription)
            .filter(
                Subscription.tenant_id == tenant_id,
                Subscription.status == "active",
            )
            .first()
        )
        if sub:
            return {
                "plan_id": sub.plan_id,
                "status": sub.status,
                "stripe_customer_id": sub.stripe_customer_id or "",
                "stripe_subscription_id": sub.stripe_subscription_id or "",
                "current_period_end": sub.current_period_end.isoformat() if sub.current_period_end else None,
            }
    except Exception as e:
        logger.debug("Subscription lookup: %s", e)

    return {
        "plan_id": "free",
        "status": "active",
        "stripe_customer_id": "",
        "stripe_subscription_id": "",
        "current_period_end": None,
    }


def set_tenant_plan(
    db: Session,
    tenant_id: str,
    plan_id: str,
    stripe_customer_id: str = "",
    stripe_subscription_id: str = "",
) -> None:
    """Create or update a tenant's subscription."""
    from hashguard.models import Subscription

    sub = (
        db.query(Subscription)
        .filter(Subscription.tenant_id == tenant_id)
        .first()
    )
    if sub:
        sub.plan_id = plan_id
        sub.status = "active"
        sub.stripe_customer_id = stripe_customer_id or sub.stripe_customer_id
        sub.stripe_subscription_id = stripe_subscription_id or sub.stripe_subscription_id
        sub.updated_at = datetime.now(timezone.utc)
    else:
        sub = Subscription(
            tenant_id=tenant_id,
            plan_id=plan_id,
            status="active",
            stripe_customer_id=stripe_customer_id,
            stripe_subscription_id=stripe_subscription_id,
        )
        db.add(sub)

    db.commit()
    logger.info("Tenant %s plan set to %s", tenant_id, plan_id)


def record_analysis(db: Session, tenant_id: str) -> None:
    """Record one analysis event for the tenant today."""
    from hashguard.models import UsageRecord

    today = _today()
    record = (
        db.query(UsageRecord)
        .filter(
            UsageRecord.tenant_id == tenant_id,
            UsageRecord.date == today,
        )
        .first()
    )
    if record:
        record.analyses_count += 1
    else:
        record = UsageRecord(
            tenant_id=tenant_id,
            date=today,
            analyses_count=1,
        )
        db.add(record)
    db.commit()


def check_quota(db: Session, tenant_id: str) -> dict:
    """Check if the tenant has remaining analyses today.

    Returns dict with:
      - allowed: bool
      - used: int
      - limit: int  (-1 = unlimited)
      - remaining: int (-1 = unlimited)
    """
    plan_info = get_tenant_plan(db, tenant_id)
    plan_id = plan_info["plan_id"]
    plan = PLANS.get(plan_id, PLANS["free"])
    limit = plan["analyses_per_day"]

    # Unlimited
    if limit == -1:
        return {"allowed": True, "used": 0, "limit": -1, "remaining": -1}

    from hashguard.models import UsageRecord

    today = _today()
    record = (
        db.query(UsageRecord)
        .filter(
            UsageRecord.tenant_id == tenant_id,
            UsageRecord.date == today,
        )
        .first()
    )
    used = record.analyses_count if record else 0
    remaining = max(0, limit - used)

    return {
        "allowed": used < limit,
        "used": used,
        "limit": limit,
        "remaining": remaining,
    }


def get_usage(db: Session, tenant_id: str) -> dict:
    """Get usage statistics for a tenant."""
    from hashguard.models import UsageRecord, Sample

    today = _today()

    # Today's usage
    today_record = (
        db.query(UsageRecord)
        .filter(
            UsageRecord.tenant_id == tenant_id,
            UsageRecord.date == today,
        )
        .first()
    )
    today_count = today_record.analyses_count if today_record else 0

    # Total samples for tenant
    total_samples = (
        db.query(Sample)
        .filter(Sample.tenant_id == tenant_id)
        .count()
    )

    # Plan limits
    plan_info = get_tenant_plan(db, tenant_id)
    plan = PLANS.get(plan_info["plan_id"], PLANS["free"])
    daily_limit = plan["analyses_per_day"]

    return {
        "analyses_today": today_count,
        "daily_limit": daily_limit,
        "daily_remaining": max(0, daily_limit - today_count) if daily_limit > 0 else -1,
        "total_samples": total_samples,
        "plan_id": plan_info["plan_id"],
    }
