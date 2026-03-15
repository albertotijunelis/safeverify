"""User account management for HashGuard SaaS.

Provides registration, login, password hashing (bcrypt), and user CRUD
backed by SQLAlchemy ORM.
"""

import secrets
import time
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy.orm import Session

from hashguard.logger import get_logger
from hashguard.models import User, APIKey

logger = get_logger(__name__)

try:
    import bcrypt
    HAS_BCRYPT = True
except ImportError:
    HAS_BCRYPT = False


def _hash_password(password: str) -> str:
    """Hash a password with bcrypt."""
    if not HAS_BCRYPT:
        raise RuntimeError("bcrypt not installed. Run: pip install bcrypt")
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


def _verify_password(password: str, hashed: str) -> bool:
    """Verify a password against a bcrypt hash."""
    if not HAS_BCRYPT:
        raise RuntimeError("bcrypt not installed")
    return bcrypt.checkpw(password.encode("utf-8"), hashed.encode("utf-8"))


def register_user(
    db: Session,
    email: str,
    password: str,
    display_name: Optional[str] = None,
    role: str = "analyst",
    tenant_id: str = "default",
) -> dict:
    """Register a new user account.

    Returns dict with user info (no password hash).
    Raises ValueError if email already exists or role is invalid.
    """
    from hashguard.web.auth import ROLES

    email = email.strip().lower()
    if not email or "@" not in email:
        raise ValueError("Invalid email address")

    if role not in ROLES:
        raise ValueError(f"Invalid role: {role}. Must be one of {ROLES}")

    if len(password) < 8:
        raise ValueError("Password must be at least 8 characters")

    existing = db.query(User).filter(User.email == email).first()
    if existing:
        raise ValueError("Email already registered")

    user = User(
        email=email,
        password_hash=_hash_password(password),
        display_name=display_name or email.split("@")[0],
        role=role,
        tenant_id=tenant_id,
        is_active=True,
        email_verified=False,
        created_at=datetime.now(timezone.utc),
    )
    db.add(user)
    db.commit()
    db.refresh(user)

    logger.info("Registered user %s (role=%s, tenant=%s)", email, role, tenant_id)
    return _user_to_dict(user)


def authenticate_user(db: Session, email: str, password: str) -> Optional[dict]:
    """Authenticate a user by email and password.

    Returns user dict on success, None on failure.
    Updates last_login timestamp.
    """
    email = email.strip().lower()
    user = db.query(User).filter(User.email == email, User.is_active == True).first()
    if not user:
        return None

    if not _verify_password(password, user.password_hash):
        return None

    user.last_login = datetime.now(timezone.utc)
    db.commit()

    logger.info("User %s authenticated", email)
    return _user_to_dict(user)


def get_user_by_email(db: Session, email: str) -> Optional[dict]:
    """Look up a user by email."""
    user = db.query(User).filter(User.email == email.strip().lower()).first()
    return _user_to_dict(user) if user else None


def get_user_by_id(db: Session, user_id: int) -> Optional[dict]:
    """Look up a user by ID."""
    user = db.query(User).filter(User.id == user_id).first()
    return _user_to_dict(user) if user else None


def list_users(db: Session, tenant_id: Optional[str] = None) -> list:
    """List all users, optionally filtered by tenant."""
    query = db.query(User)
    if tenant_id:
        query = query.filter(User.tenant_id == tenant_id)
    return [_user_to_dict(u) for u in query.order_by(User.created_at.desc()).all()]


def update_user(db: Session, user_id: int, **updates) -> Optional[dict]:
    """Update user fields. Allowed: display_name, role, is_active, email_verified."""
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        return None

    allowed = {"display_name", "role", "is_active", "email_verified"}
    for key, value in updates.items():
        if key in allowed:
            setattr(user, key, value)

    db.commit()
    db.refresh(user)
    return _user_to_dict(user)


def change_password(db: Session, user_id: int, old_password: str, new_password: str) -> bool:
    """Change a user's password. Returns True on success."""
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        return False

    if not _verify_password(old_password, user.password_hash):
        return False

    if len(new_password) < 8:
        return False

    user.password_hash = _hash_password(new_password)
    db.commit()
    return True


def delete_user(db: Session, user_id: int) -> bool:
    """Delete a user and their API keys."""
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        return False

    db.delete(user)
    db.commit()
    logger.info("Deleted user %s", user.email)
    return True


def _user_to_dict(user: User) -> dict:
    """Convert User ORM object to dict (no password hash)."""
    return {
        "id": user.id,
        "email": user.email,
        "display_name": user.display_name,
        "role": user.role,
        "tenant_id": user.tenant_id,
        "is_active": user.is_active,
        "email_verified": user.email_verified,
        "created_at": user.created_at.isoformat() if user.created_at else None,
        "last_login": user.last_login.isoformat() if user.last_login else None,
    }
