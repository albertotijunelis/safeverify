"""Comprehensive tests for HashGuard SaaS usage metering module."""

import pytest
from unittest.mock import patch, MagicMock
from datetime import datetime, timezone

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from hashguard.models import Base, Subscription, UsageRecord, Sample
from hashguard.web.usage_metering import (
    get_tenant_plan,
    set_tenant_plan,
    record_analysis,
    check_quota,
    get_usage,
    _today,
)


@pytest.fixture
def db():
    """Create an in-memory SQLite database for testing."""
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine)
    session = Session()
    yield session
    session.close()


class TestTodayHelper:
    """Tests for _today() helper."""

    def test_returns_iso_format(self):
        result = _today()
        assert len(result) == 10  # YYYY-MM-DD
        parts = result.split("-")
        assert len(parts) == 3
        assert len(parts[0]) == 4

    def test_returns_string(self):
        assert isinstance(_today(), str)


class TestGetTenantPlan:
    """Tests for get_tenant_plan."""

    def test_default_free_plan(self, db):
        result = get_tenant_plan(db, "t_new")
        assert result["plan_id"] == "free"
        assert result["status"] == "active"
        assert result["stripe_customer_id"] == ""

    def test_active_subscription(self, db):
        sub = Subscription(
            tenant_id="t1",
            plan_id="pro",
            status="active",
            stripe_customer_id="cus_123",
            stripe_subscription_id="sub_456",
        )
        db.add(sub)
        db.commit()

        result = get_tenant_plan(db, "t1")
        assert result["plan_id"] == "pro"
        assert result["status"] == "active"
        assert result["stripe_customer_id"] == "cus_123"
        assert result["stripe_subscription_id"] == "sub_456"

    def test_canceled_subscription_fallback(self, db):
        sub = Subscription(
            tenant_id="t2",
            plan_id="team",
            status="canceled",
        )
        db.add(sub)
        db.commit()

        # canceled status shouldn't match active filter
        result = get_tenant_plan(db, "t2")
        assert result["plan_id"] == "free"

    def test_nonexistent_tenant(self, db):
        result = get_tenant_plan(db, "nonexistent")
        assert result["plan_id"] == "free"

    def test_multiple_tenants_isolation(self, db):
        db.add(Subscription(tenant_id="t1", plan_id="pro", status="active"))
        db.add(Subscription(tenant_id="t2", plan_id="team", status="active"))
        db.commit()

        assert get_tenant_plan(db, "t1")["plan_id"] == "pro"
        assert get_tenant_plan(db, "t2")["plan_id"] == "team"


class TestSetTenantPlan:
    """Tests for set_tenant_plan."""

    def test_create_new_subscription(self, db):
        set_tenant_plan(db, "t1", "pro", "cus_1", "sub_1")

        sub = db.query(Subscription).filter_by(tenant_id="t1").first()
        assert sub is not None
        assert sub.plan_id == "pro"
        assert sub.status == "active"
        assert sub.stripe_customer_id == "cus_1"

    def test_update_existing_subscription(self, db):
        set_tenant_plan(db, "t1", "pro", "cus_1", "sub_1")
        set_tenant_plan(db, "t1", "team", "cus_1", "sub_2")

        subs = db.query(Subscription).filter_by(tenant_id="t1").all()
        assert len(subs) == 1
        assert subs[0].plan_id == "team"
        assert subs[0].stripe_subscription_id == "sub_2"

    def test_update_preserves_customer_id(self, db):
        set_tenant_plan(db, "t1", "pro", "cus_1", "sub_1")
        set_tenant_plan(db, "t1", "team")  # no customer id

        sub = db.query(Subscription).filter_by(tenant_id="t1").first()
        assert sub.stripe_customer_id == "cus_1"

    def test_downgrade_to_free(self, db):
        set_tenant_plan(db, "t1", "pro", "cus_1")
        set_tenant_plan(db, "t1", "free")

        sub = db.query(Subscription).filter_by(tenant_id="t1").first()
        assert sub.plan_id == "free"
        assert sub.status == "active"


class TestRecordAnalysis:
    """Tests for record_analysis."""

    def test_first_analysis_creates_record(self, db):
        record_analysis(db, "t1")

        records = db.query(UsageRecord).filter_by(tenant_id="t1").all()
        assert len(records) == 1
        assert records[0].analyses_count == 1
        assert records[0].date == _today()

    def test_increments_existing_record(self, db):
        record_analysis(db, "t1")
        record_analysis(db, "t1")
        record_analysis(db, "t1")

        record = db.query(UsageRecord).filter_by(tenant_id="t1").first()
        assert record.analyses_count == 3

    def test_separate_tenants(self, db):
        record_analysis(db, "t1")
        record_analysis(db, "t1")
        record_analysis(db, "t2")

        r1 = db.query(UsageRecord).filter_by(tenant_id="t1").first()
        r2 = db.query(UsageRecord).filter_by(tenant_id="t2").first()
        assert r1.analyses_count == 2
        assert r2.analyses_count == 1

    def test_different_dates(self, db):
        """Records for different dates should be separate."""
        record_analysis(db, "t1")

        # Manually insert a record for yesterday
        db.add(UsageRecord(tenant_id="t1", date="2024-01-01", analyses_count=5))
        db.commit()

        records = db.query(UsageRecord).filter_by(tenant_id="t1").all()
        assert len(records) == 2


class TestCheckQuota:
    """Tests for check_quota."""

    def test_free_plan_default_allows(self, db):
        """New tenant on free plan should have quota."""
        result = check_quota(db, "t_new")
        assert result["allowed"] is True
        assert result["limit"] == 10
        assert result["used"] == 0
        assert result["remaining"] == 10

    def test_free_plan_limit_reached(self, db):
        """Free plan at 10 analyses should be denied."""
        db.add(UsageRecord(tenant_id="t1", date=_today(), analyses_count=10))
        db.commit()

        result = check_quota(db, "t1")
        assert result["allowed"] is False
        assert result["used"] == 10
        assert result["remaining"] == 0

    def test_free_plan_under_limit(self, db):
        db.add(UsageRecord(tenant_id="t1", date=_today(), analyses_count=5))
        db.commit()

        result = check_quota(db, "t1")
        assert result["allowed"] is True
        assert result["used"] == 5
        assert result["remaining"] == 5

    def test_pro_plan_higher_limit(self, db):
        set_tenant_plan(db, "t1", "pro")
        db.add(UsageRecord(tenant_id="t1", date=_today(), analyses_count=100))
        db.commit()

        result = check_quota(db, "t1")
        assert result["allowed"] is True
        assert result["limit"] == 500
        assert result["remaining"] == 400

    def test_enterprise_unlimited(self, db):
        set_tenant_plan(db, "t1", "enterprise")

        result = check_quota(db, "t1")
        assert result["allowed"] is True
        assert result["limit"] == -1
        assert result["remaining"] == -1

    def test_no_usage_record(self, db):
        """Tenant with no usage records should have full quota."""
        result = check_quota(db, "t1")
        assert result["used"] == 0
        assert result["allowed"] is True


class TestGetUsage:
    """Tests for get_usage."""

    def test_new_tenant_empty_usage(self, db):
        result = get_usage(db, "t_new")
        assert result["analyses_today"] == 0
        assert result["total_samples"] == 0
        assert result["plan_id"] == "free"
        assert result["daily_limit"] == 10

    def test_usage_with_analyses(self, db):
        db.add(UsageRecord(tenant_id="t1", date=_today(), analyses_count=7))
        db.commit()

        result = get_usage(db, "t1")
        assert result["analyses_today"] == 7
        assert result["daily_remaining"] == 3  # 10 - 7

    def test_usage_with_pro_plan(self, db):
        set_tenant_plan(db, "t1", "pro")

        result = get_usage(db, "t1")
        assert result["plan_id"] == "pro"
        assert result["daily_limit"] == 500

    def test_enterprise_unlimited_remaining(self, db):
        set_tenant_plan(db, "t1", "enterprise")

        result = get_usage(db, "t1")
        assert result["daily_remaining"] == -1

    def test_total_samples_count(self, db):
        # Add some sample records
        db.add(Sample(
            sha256="a" * 64, tenant_id="t1", filename="test1.exe",
            file_size=100,
        ))
        db.add(Sample(
            sha256="b" * 64, tenant_id="t1", filename="test2.exe",
            file_size=200,
        ))
        db.commit()

        result = get_usage(db, "t1")
        assert result["total_samples"] == 2
