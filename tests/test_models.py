"""Tests for SQLAlchemy ORM models and database engine."""

import os
import pytest
from unittest.mock import patch

from hashguard.models import (
    Base,
    User,
    APIKey,
    Sample,
    IOC,
    Behavior,
    Family,
    Cluster,
    ClusterMember,
    TimelineEvent,
    Webhook,
    get_engine,
    get_session_factory,
    init_orm_db,
    reset_engine,
)


@pytest.fixture(autouse=True)
def _clean_engine():
    """Reset engine before/after each test."""
    reset_engine()
    yield
    reset_engine()


@pytest.fixture
def db_session(tmp_path):
    """Create an in-memory SQLite session for testing."""
    db_url = f"sqlite:///{tmp_path / 'test.db'}"
    with patch.dict(os.environ, {"DATABASE_URL": db_url}):
        init_orm_db()
        SessionLocal = get_session_factory()
        session = SessionLocal()
        yield session
        session.close()


class TestModels:
    """Test ORM model definitions."""

    def test_user_model(self, db_session):
        user = User(
            email="test@example.com",
            password_hash="$2b$12$fake",
            display_name="Test User",
            role="analyst",
            tenant_id="default",
        )
        db_session.add(user)
        db_session.commit()

        fetched = db_session.query(User).filter_by(email="test@example.com").first()
        assert fetched is not None
        assert fetched.email == "test@example.com"
        assert fetched.role == "analyst"
        assert fetched.is_active is True
        assert fetched.email_verified is False

    def test_user_unique_email(self, db_session):
        user1 = User(email="dup@test.com", password_hash="hash1")
        db_session.add(user1)
        db_session.commit()

        user2 = User(email="dup@test.com", password_hash="hash2")
        db_session.add(user2)
        with pytest.raises(Exception):
            db_session.commit()

    def test_api_key_model(self, db_session):
        user = User(email="key@test.com", password_hash="hash")
        db_session.add(user)
        db_session.commit()

        key = APIKey(
            key_id="test123",
            key_hash="sha256hash",
            name="Test Key",
            role="analyst",
            user_id=user.id,
        )
        db_session.add(key)
        db_session.commit()

        fetched = db_session.query(APIKey).filter_by(key_id="test123").first()
        assert fetched is not None
        assert fetched.name == "Test Key"
        assert fetched.user_id == user.id

    def test_api_key_cascade_delete(self, db_session):
        user = User(email="cascade@test.com", password_hash="hash")
        db_session.add(user)
        db_session.commit()

        key = APIKey(key_id="del123", key_hash="h", name="Del", user_id=user.id)
        db_session.add(key)
        db_session.commit()

        db_session.delete(user)
        db_session.commit()

        assert db_session.query(APIKey).filter_by(key_id="del123").first() is None

    def test_sample_model(self, db_session):
        sample = Sample(
            filename="malware.exe",
            sha256="a" * 64,
            risk_score=85,
            verdict="malicious",
            is_malicious=1,
        )
        db_session.add(sample)
        db_session.commit()

        fetched = db_session.query(Sample).filter_by(sha256="a" * 64).first()
        assert fetched is not None
        assert fetched.filename == "malware.exe"
        assert fetched.risk_score == 85

    def test_ioc_relationship(self, db_session):
        sample = Sample(filename="test.exe", sha256="b" * 64)
        db_session.add(sample)
        db_session.commit()

        ioc = IOC(sample_id=sample.id, ioc_type="url", value="http://evil.com")
        db_session.add(ioc)
        db_session.commit()

        fetched = db_session.query(Sample).filter_by(id=sample.id).first()
        assert len(fetched.iocs) == 1
        assert fetched.iocs[0].value == "http://evil.com"

    def test_behavior_relationship(self, db_session):
        sample = Sample(filename="test2.exe", sha256="c" * 64)
        db_session.add(sample)
        db_session.commit()

        beh = Behavior(sample_id=sample.id, category="persistence", description="Registry key")
        db_session.add(beh)
        db_session.commit()

        assert len(sample.behaviors) == 1

    def test_webhook_model(self, db_session):
        wh = Webhook(
            webhook_id="wh_test",
            url="https://example.com/webhook",
            events='["analysis.complete"]',
            tenant_id="default",
        )
        db_session.add(wh)
        db_session.commit()

        fetched = db_session.query(Webhook).filter_by(webhook_id="wh_test").first()
        assert fetched.url == "https://example.com/webhook"

    def test_cluster_members(self, db_session):
        sample = Sample(filename="clustered.exe", sha256="d" * 64)
        db_session.add(sample)
        db_session.commit()

        cluster = Cluster(name="Test Cluster", algorithm="fuzzy", sample_count=1)
        db_session.add(cluster)
        db_session.commit()

        member = ClusterMember(cluster_id=cluster.id, sample_id=sample.id, similarity=0.95)
        db_session.add(member)
        db_session.commit()

        assert len(cluster.members) == 1
        assert cluster.members[0].similarity == 0.95

    def test_timeline_events(self, db_session):
        sample = Sample(filename="timeline.exe", sha256="e" * 64)
        db_session.add(sample)
        db_session.commit()

        event = TimelineEvent(sample_id=sample.id, event_type="first_seen", description="Initial detection")
        db_session.add(event)
        db_session.commit()

        assert len(sample.timeline_events) == 1

    def test_family_model(self, db_session):
        fam = Family(name="Emotet", description="Banking trojan", sample_count=100)
        db_session.add(fam)
        db_session.commit()

        fetched = db_session.query(Family).filter_by(name="Emotet").first()
        assert fetched.sample_count == 100


class TestEngineFactory:
    """Test engine creation and configuration."""

    def test_sqlite_engine(self, tmp_path):
        db_url = f"sqlite:///{tmp_path / 'eng_test.db'}"
        with patch.dict(os.environ, {"DATABASE_URL": db_url}):
            engine = get_engine()
            assert "sqlite" in str(engine.url)

    def test_default_url(self):
        # Without DATABASE_URL, should use default APPDATA path
        with patch.dict(os.environ, {}, clear=False):
            if "DATABASE_URL" in os.environ:
                del os.environ["DATABASE_URL"]
            engine = get_engine()
            assert "sqlite" in str(engine.url)

    def test_reset_engine(self, tmp_path):
        db_url = f"sqlite:///{tmp_path / 'reset_test.db'}"
        with patch.dict(os.environ, {"DATABASE_URL": db_url}):
            e1 = get_engine()
            reset_engine()
            e2 = get_engine()
            assert e1 is not e2

    def test_init_creates_tables(self, tmp_path):
        db_url = f"sqlite:///{tmp_path / 'init_test.db'}"
        with patch.dict(os.environ, {"DATABASE_URL": db_url}):
            init_orm_db()
            engine = get_engine()
            from sqlalchemy import inspect
            inspector = inspect(engine)
            tables = inspector.get_table_names()
            assert "users" in tables
            assert "samples" in tables
            assert "api_keys" in tables
            assert "webhooks" in tables
