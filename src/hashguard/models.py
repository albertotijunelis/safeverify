"""SQLAlchemy ORM models for HashGuard.

Provides a dual-database backend:
- SQLite for local/desktop usage (default)
- PostgreSQL for SaaS/production deployment

Set DATABASE_URL env var to switch:
- sqlite:///path/to/hashguard.db  (default)
- postgresql://user:pass@host/hashguard
"""

import os
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    create_engine,
    event,
)
from sqlalchemy.orm import (
    DeclarativeBase,
    Mapped,
    Session,
    mapped_column,
    relationship,
    sessionmaker,
)

from hashguard.logger import get_logger

logger = get_logger(__name__)


# ── Base ────────────────────────────────────────────────────────────────────


class Base(DeclarativeBase):
    pass


# ── User model (new for SaaS) ──────────────────────────────────────────────


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    email: Mapped[str] = mapped_column(String(255), unique=True, nullable=False, index=True)
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    display_name: Mapped[Optional[str]] = mapped_column(String(255))
    role: Mapped[str] = mapped_column(String(50), default="analyst", server_default="analyst")
    tenant_id: Mapped[str] = mapped_column(String(100), default="default", server_default="default", index=True)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, server_default="1")
    email_verified: Mapped[bool] = mapped_column(Boolean, default=False, server_default="0")
    auth_provider: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)  # "google", "github", or None for email/password
    auth_provider_id: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)  # Provider's user ID
    avatar_url: Mapped[Optional[str]] = mapped_column(String(512), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))
    last_login: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)

    api_keys: Mapped[list["APIKey"]] = relationship(back_populates="user", cascade="all, delete-orphan")


# ── API Key model ──────────────────────────────────────────────────────────


class APIKey(Base):
    __tablename__ = "api_keys"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    key_id: Mapped[str] = mapped_column(String(64), unique=True, nullable=False, index=True)
    key_hash: Mapped[str] = mapped_column(String(128), nullable=False)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    role: Mapped[str] = mapped_column(String(50), default="analyst", server_default="analyst")
    user_id: Mapped[Optional[int]] = mapped_column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=True)
    tenant_id: Mapped[str] = mapped_column(String(100), default="default", server_default="default", index=True)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, server_default="1")
    created_at: Mapped[float] = mapped_column(Float, default=0.0)
    last_used: Mapped[float] = mapped_column(Float, default=0.0)

    user: Mapped[Optional["User"]] = relationship(back_populates="api_keys")


# ── Sample model ───────────────────────────────────────────────────────────


class Sample(Base):
    __tablename__ = "samples"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    filename: Mapped[str] = mapped_column(String(512), nullable=False)
    file_path: Mapped[Optional[str]] = mapped_column(String(1024))
    sha256: Mapped[Optional[str]] = mapped_column(String(64), unique=True)
    sha1: Mapped[Optional[str]] = mapped_column(String(40))
    md5: Mapped[Optional[str]] = mapped_column(String(32))
    ssdeep: Mapped[Optional[str]] = mapped_column(String(255))
    tlsh: Mapped[Optional[str]] = mapped_column(String(255))
    imphash: Mapped[Optional[str]] = mapped_column(String(64))
    file_size: Mapped[int] = mapped_column(Integer, default=0, server_default="0")
    analysis_date: Mapped[Optional[str]] = mapped_column(String(50))
    risk_score: Mapped[int] = mapped_column(Integer, default=0, server_default="0")
    verdict: Mapped[str] = mapped_column(String(50), default="unknown", server_default="unknown")
    is_malicious: Mapped[int] = mapped_column(Integer, default=0, server_default="0")
    description: Mapped[Optional[str]] = mapped_column(Text)
    full_result: Mapped[Optional[str]] = mapped_column(Text)
    capabilities: Mapped[Optional[str]] = mapped_column(Text)
    advanced_pe: Mapped[Optional[str]] = mapped_column(Text)
    ml_classification: Mapped[Optional[str]] = mapped_column(Text)
    family: Mapped[Optional[str]] = mapped_column(String(255))
    family_confidence: Mapped[float] = mapped_column(Float, default=0.0, server_default="0.0")
    tenant_id: Mapped[str] = mapped_column(String(100), default="default", server_default="default")

    iocs: Mapped[list["IOC"]] = relationship(back_populates="sample", cascade="all, delete-orphan")
    behaviors: Mapped[list["Behavior"]] = relationship(back_populates="sample", cascade="all, delete-orphan")
    timeline_events: Mapped[list["TimelineEvent"]] = relationship(back_populates="sample", cascade="all, delete-orphan")

    __table_args__ = (
        Index("idx_samples_sha256", "sha256"),
        Index("idx_samples_md5", "md5"),
        Index("idx_samples_family", "family"),
        Index("idx_samples_tenant", "tenant_id"),
    )


# ── IOC model ──────────────────────────────────────────────────────────────


class IOC(Base):
    __tablename__ = "iocs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    sample_id: Mapped[int] = mapped_column(Integer, ForeignKey("samples.id", ondelete="CASCADE"))
    ioc_type: Mapped[str] = mapped_column(String(100), nullable=False)
    value: Mapped[str] = mapped_column(String(1024), nullable=False)
    context: Mapped[Optional[str]] = mapped_column(Text)

    sample: Mapped["Sample"] = relationship(back_populates="iocs")

    __table_args__ = (
        Index("idx_iocs_type", "ioc_type"),
        Index("idx_iocs_value", "value"),
    )


# ── Behavior model ─────────────────────────────────────────────────────────


class Behavior(Base):
    __tablename__ = "behaviors"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    sample_id: Mapped[int] = mapped_column(Integer, ForeignKey("samples.id", ondelete="CASCADE"))
    category: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text)
    severity: Mapped[str] = mapped_column(String(50), default="medium")
    mitre_attack: Mapped[Optional[str]] = mapped_column(String(50))

    sample: Mapped["Sample"] = relationship(back_populates="behaviors")

    __table_args__ = (
        Index("idx_behaviors_category", "category"),
    )


# ── Family model ──────────────────────────────────────────────────────────


class Family(Base):
    __tablename__ = "families"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    name: Mapped[str] = mapped_column(String(255), unique=True, nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text)
    first_seen: Mapped[Optional[str]] = mapped_column(String(50))
    sample_count: Mapped[int] = mapped_column(Integer, default=0)


# ── Cluster models ─────────────────────────────────────────────────────────


class Cluster(Base):
    __tablename__ = "clusters"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    name: Mapped[Optional[str]] = mapped_column(String(255))
    centroid_sha256: Mapped[Optional[str]] = mapped_column(String(64))
    algorithm: Mapped[Optional[str]] = mapped_column(String(50))
    created_date: Mapped[Optional[str]] = mapped_column(String(50))
    sample_count: Mapped[int] = mapped_column(Integer, default=0)
    shared_iocs: Mapped[Optional[str]] = mapped_column(Text)

    members: Mapped[list["ClusterMember"]] = relationship(back_populates="cluster", cascade="all, delete-orphan")


class ClusterMember(Base):
    __tablename__ = "cluster_members"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    cluster_id: Mapped[int] = mapped_column(Integer, ForeignKey("clusters.id", ondelete="CASCADE"))
    sample_id: Mapped[int] = mapped_column(Integer, ForeignKey("samples.id", ondelete="CASCADE"))
    similarity: Mapped[float] = mapped_column(Float, default=0.0)

    cluster: Mapped["Cluster"] = relationship(back_populates="members")


# ── Timeline model ─────────────────────────────────────────────────────────


class TimelineEvent(Base):
    __tablename__ = "timeline_events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    sample_id: Mapped[int] = mapped_column(Integer, ForeignKey("samples.id", ondelete="CASCADE"))
    timestamp: Mapped[Optional[str]] = mapped_column(String(50))
    event_type: Mapped[Optional[str]] = mapped_column(String(100))
    description: Mapped[Optional[str]] = mapped_column(Text)
    details: Mapped[Optional[str]] = mapped_column(Text)

    sample: Mapped["Sample"] = relationship(back_populates="timeline_events")


# ── Webhook model (move from JSON file storage) ───────────────────────────


class Webhook(Base):
    __tablename__ = "webhooks"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    webhook_id: Mapped[str] = mapped_column(String(64), unique=True, nullable=False, index=True)
    url: Mapped[str] = mapped_column(String(2048), nullable=False)
    events: Mapped[str] = mapped_column(Text, default="[]", server_default="[]")  # JSON array
    secret: Mapped[Optional[str]] = mapped_column(String(128))
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, server_default="1")
    tenant_id: Mapped[str] = mapped_column(String(100), default="default", server_default="default", index=True)
    created_at: Mapped[Optional[str]] = mapped_column(String(50))
    last_triggered: Mapped[Optional[str]] = mapped_column(String(50))
    failure_count: Mapped[int] = mapped_column(Integer, default=0)


# ── Subscription model (SaaS billing) ─────────────────────────────────


class Subscription(Base):
    __tablename__ = "subscriptions"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    tenant_id: Mapped[str] = mapped_column(String(100), unique=True, nullable=False, index=True)
    plan_id: Mapped[str] = mapped_column(String(50), default="free", server_default="free")
    status: Mapped[str] = mapped_column(String(50), default="active", server_default="active")  # active, canceled, past_due
    stripe_customer_id: Mapped[Optional[str]] = mapped_column(String(255))
    stripe_subscription_id: Mapped[Optional[str]] = mapped_column(String(255))
    current_period_end: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))


# ── Usage tracking model ──────────────────────────────────────────────


class UsageRecord(Base):
    __tablename__ = "usage_records"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    tenant_id: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    date: Mapped[str] = mapped_column(String(10), nullable=False)  # YYYY-MM-DD
    analyses_count: Mapped[int] = mapped_column(Integer, default=0, server_default="0")

    __table_args__ = (
        Index("idx_usage_tenant_date", "tenant_id", "date", unique=True),
    )


# ── Team / Organization model ─────────────────────────────────────────


class Team(Base):
    """Organization/team that owns a tenant and its members."""
    __tablename__ = "teams"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    tenant_id: Mapped[str] = mapped_column(String(100), unique=True, nullable=False, index=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    owner_id: Mapped[int] = mapped_column(Integer, ForeignKey("users.id", ondelete="CASCADE"))
    max_members: Mapped[int] = mapped_column(Integer, default=1)  # derived from plan
    created_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))

    members: Mapped[list["TeamMember"]] = relationship(back_populates="team", cascade="all, delete-orphan")
    invites: Mapped[list["TeamInvite"]] = relationship(back_populates="team", cascade="all, delete-orphan")


class TeamMember(Base):
    """A user who belongs to a team."""
    __tablename__ = "team_members"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    team_id: Mapped[int] = mapped_column(Integer, ForeignKey("teams.id", ondelete="CASCADE"))
    user_id: Mapped[int] = mapped_column(Integer, ForeignKey("users.id", ondelete="CASCADE"))
    role: Mapped[str] = mapped_column(String(50), default="analyst")  # admin, analyst, viewer
    joined_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))

    team: Mapped["Team"] = relationship(back_populates="members")

    __table_args__ = (
        Index("idx_tm_team_user", "team_id", "user_id", unique=True),
    )


class TeamInvite(Base):
    """Pending invitation to join a team."""
    __tablename__ = "team_invites"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    team_id: Mapped[int] = mapped_column(Integer, ForeignKey("teams.id", ondelete="CASCADE"))
    email: Mapped[str] = mapped_column(String(255), nullable=False)
    role: Mapped[str] = mapped_column(String(50), default="analyst")
    token: Mapped[str] = mapped_column(String(128), unique=True, nullable=False, index=True)
    invited_by: Mapped[int] = mapped_column(Integer, ForeignKey("users.id", ondelete="CASCADE"))
    status: Mapped[str] = mapped_column(String(20), default="pending")  # pending, accepted, expired
    expires_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))

    team: Mapped["Team"] = relationship(back_populates="invites")

    __table_args__ = (
        Index("idx_invite_email", "email"),
    )


# ── Password Reset ────────────────────────────────────────────────────


class PasswordReset(Base):
    """Token for password reset flow."""
    __tablename__ = "password_resets"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    user_id: Mapped[int] = mapped_column(Integer, ForeignKey("users.id", ondelete="CASCADE"))
    token: Mapped[str] = mapped_column(String(128), unique=True, nullable=False, index=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    used: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))


# ── Audit Log ─────────────────────────────────────────────────────────


class AuditLog(Base):
    """Immutable audit trail for admin/compliance."""
    __tablename__ = "audit_logs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    tenant_id: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    user_id: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    action: Mapped[str] = mapped_column(String(100), nullable=False)  # e.g. "sample.analyze", "team.invite"
    resource_type: Mapped[Optional[str]] = mapped_column(String(50))  # e.g. "sample", "user", "team"
    resource_id: Mapped[Optional[str]] = mapped_column(String(255))
    details: Mapped[Optional[str]] = mapped_column(Text)  # JSON
    ip_address: Mapped[Optional[str]] = mapped_column(String(45))
    created_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))

    __table_args__ = (
        Index("idx_audit_tenant_date", "tenant_id", "created_at"),
        Index("idx_audit_action", "action"),
    )


class DatasetVersion(Base):
    """Tracks versioned snapshots of the ML dataset."""
    __tablename__ = "dataset_versions"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    version: Mapped[str] = mapped_column(String(20), nullable=False, unique=True)  # semver: "1.0.0"
    sample_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    malicious_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    benign_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    feature_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    file_size_bytes: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    sha256_checksum: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    format: Mapped[str] = mapped_column(String(20), nullable=False, default="parquet")  # parquet, csv, jsonl
    notes: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    created_by: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))


# ── Engine factory ─────────────────────────────────────────────────────────

_engine = None
_SessionLocal = None


def _default_database_url() -> str:
    """Build default SQLite URL from APPDATA."""
    app_data = os.environ.get("APPDATA") or os.path.expanduser("~")
    db_dir = os.path.join(app_data, "HashGuard")
    os.makedirs(db_dir, exist_ok=True)
    db_path = os.path.join(db_dir, "hashguard.db")
    return f"sqlite:///{db_path}"


def get_engine():
    """Get or create the SQLAlchemy engine (singleton)."""
    global _engine
    if _engine is not None:
        return _engine

    url = os.environ.get("DATABASE_URL", _default_database_url())

    # Normalize postgres:// to postgresql:// (Heroku compatibility)
    if url.startswith("postgres://"):
        url = url.replace("postgres://", "postgresql://", 1)

    is_sqlite = url.startswith("sqlite")

    connect_args = {}
    if is_sqlite:
        connect_args["check_same_thread"] = False

    _engine = create_engine(
        url,
        connect_args=connect_args,
        pool_pre_ping=True,
        echo=False,
    )

    # SQLite pragmas
    if is_sqlite:
        @event.listens_for(_engine, "connect")
        def _set_sqlite_pragma(dbapi_conn, connection_record):
            cursor = dbapi_conn.cursor()
            cursor.execute("PRAGMA journal_mode=WAL")
            cursor.execute("PRAGMA foreign_keys=ON")
            cursor.close()

    logger.info("Database engine created: %s", "SQLite" if is_sqlite else "PostgreSQL")
    return _engine


def get_session_factory():
    """Get or create the session factory."""
    global _SessionLocal
    if _SessionLocal is None:
        _SessionLocal = sessionmaker(bind=get_engine(), expire_on_commit=False)
    return _SessionLocal


def get_db() -> Session:
    """FastAPI dependency — yields a database session.

    Usage:
        @app.get("/api/endpoint")
        async def endpoint(db: Session = Depends(get_db)):
            ...
    """
    SessionLocal = get_session_factory()
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def get_orm_session() -> Session:
    """Get a standalone ORM session (not a FastAPI dependency).

    Caller is responsible for closing the session.
    """
    SessionLocal = get_session_factory()
    return SessionLocal()


def init_orm_db() -> None:
    """Create all tables from ORM models.

    Safe to call multiple times (CREATE TABLE IF NOT EXISTS).
    """
    engine = get_engine()
    Base.metadata.create_all(bind=engine)

    # Migrate: add OAuth columns to users table if missing
    from sqlalchemy import inspect as sa_inspect, text
    insp = sa_inspect(engine)
    if "users" in insp.get_table_names():
        existing = {c["name"] for c in insp.get_columns("users")}
        migrations = [
            ("auth_provider", "VARCHAR(50)"),
            ("auth_provider_id", "VARCHAR(255)"),
            ("avatar_url", "VARCHAR(512)"),
        ]
        with engine.begin() as conn:
            for col, dtype in migrations:
                if col not in existing:
                    conn.execute(text(f"ALTER TABLE users ADD COLUMN {col} {dtype}"))
                    logger.info("Added column users.%s", col)

    logger.info("ORM database tables initialized")


def reset_engine() -> None:
    """Reset the engine singleton (for testing)."""
    global _engine, _SessionLocal
    if _engine:
        _engine.dispose()
    _engine = None
    _SessionLocal = None
