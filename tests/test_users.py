"""Tests for user account management."""

import os
import pytest
from unittest.mock import patch

from hashguard.models import init_orm_db, get_session_factory, reset_engine


@pytest.fixture(autouse=True)
def _clean_engine():
    reset_engine()
    yield
    reset_engine()


@pytest.fixture
def db_session(tmp_path):
    db_url = f"sqlite:///{tmp_path / 'users_test.db'}"
    with patch.dict(os.environ, {"DATABASE_URL": db_url}):
        init_orm_db()
        SessionLocal = get_session_factory()
        session = SessionLocal()
        yield session
        session.close()


class TestUserRegistration:
    def test_register_user(self, db_session):
        from hashguard.web.users import register_user
        user = register_user(db_session, "test@example.com", "password123")
        assert user["email"] == "test@example.com"
        assert user["role"] == "analyst"
        assert user["is_active"] is True
        assert "password_hash" not in user

    def test_register_duplicate_email(self, db_session):
        from hashguard.web.users import register_user
        register_user(db_session, "dup@example.com", "password123")
        with pytest.raises(ValueError, match="already registered"):
            register_user(db_session, "dup@example.com", "password456")

    def test_register_invalid_email(self, db_session):
        from hashguard.web.users import register_user
        with pytest.raises(ValueError, match="Invalid email"):
            register_user(db_session, "notanemail", "password123")

    def test_register_short_password(self, db_session):
        from hashguard.web.users import register_user
        with pytest.raises(ValueError, match="at least 8"):
            register_user(db_session, "short@example.com", "1234567")

    def test_register_invalid_role(self, db_session):
        from hashguard.web.users import register_user
        with pytest.raises(ValueError, match="Invalid role"):
            register_user(db_session, "role@example.com", "password123", role="superadmin")

    def test_register_normalizes_email(self, db_session):
        from hashguard.web.users import register_user
        user = register_user(db_session, "  TEST@Example.COM  ", "password123")
        assert user["email"] == "test@example.com"


class TestUserAuthentication:
    def test_authenticate_success(self, db_session):
        from hashguard.web.users import register_user, authenticate_user
        register_user(db_session, "auth@example.com", "mypassword")
        user = authenticate_user(db_session, "auth@example.com", "mypassword")
        assert user is not None
        assert user["email"] == "auth@example.com"
        assert user["last_login"] is not None

    def test_authenticate_wrong_password(self, db_session):
        from hashguard.web.users import register_user, authenticate_user
        register_user(db_session, "wrong@example.com", "correctpassword")
        user = authenticate_user(db_session, "wrong@example.com", "wrongpassword")
        assert user is None

    def test_authenticate_nonexistent(self, db_session):
        from hashguard.web.users import authenticate_user
        user = authenticate_user(db_session, "ghost@example.com", "password")
        assert user is None

    def test_authenticate_inactive_user(self, db_session):
        from hashguard.web.users import register_user, authenticate_user, update_user
        user = register_user(db_session, "inactive@example.com", "password123")
        update_user(db_session, user["id"], is_active=False)
        result = authenticate_user(db_session, "inactive@example.com", "password123")
        assert result is None


class TestUserManagement:
    def test_list_users(self, db_session):
        from hashguard.web.users import register_user, list_users
        register_user(db_session, "u1@test.com", "password1234")
        register_user(db_session, "u2@test.com", "password1234")
        users = list_users(db_session)
        assert len(users) == 2

    def test_list_users_by_tenant(self, db_session):
        from hashguard.web.users import register_user, list_users
        register_user(db_session, "t1@test.com", "password1234", tenant_id="tenant1")
        register_user(db_session, "t2@test.com", "password1234", tenant_id="tenant2")
        users = list_users(db_session, tenant_id="tenant1")
        assert len(users) == 1
        assert users[0]["tenant_id"] == "tenant1"

    def test_update_user(self, db_session):
        from hashguard.web.users import register_user, update_user
        user = register_user(db_session, "upd@test.com", "password1234")
        updated = update_user(db_session, user["id"], display_name="New Name", role="admin")
        assert updated["display_name"] == "New Name"
        assert updated["role"] == "admin"

    def test_change_password(self, db_session):
        from hashguard.web.users import register_user, authenticate_user, change_password
        user = register_user(db_session, "chg@test.com", "oldpassword1")
        assert change_password(db_session, user["id"], "oldpassword1", "newpassword1") is True
        # Old password should fail
        assert authenticate_user(db_session, "chg@test.com", "oldpassword1") is None
        # New password should work
        assert authenticate_user(db_session, "chg@test.com", "newpassword1") is not None

    def test_delete_user(self, db_session):
        from hashguard.web.users import register_user, delete_user, get_user_by_id
        user = register_user(db_session, "del@test.com", "password1234")
        assert delete_user(db_session, user["id"]) is True
        assert get_user_by_id(db_session, user["id"]) is None

    def test_get_user_by_email(self, db_session):
        from hashguard.web.users import register_user, get_user_by_email
        register_user(db_session, "find@test.com", "password1234")
        user = get_user_by_email(db_session, "find@test.com")
        assert user is not None
        assert user["email"] == "find@test.com"
