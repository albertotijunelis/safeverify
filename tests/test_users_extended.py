"""Tests for users module — registration, authentication, CRUD."""

import pytest
from unittest.mock import patch, MagicMock, PropertyMock
from datetime import datetime, timezone


# ── Password hashing ───────────────────────────────────────────────────


class TestPasswordHashing:
    def test_hash_and_verify(self):
        from hashguard.web.users import _hash_password, _verify_password, HAS_BCRYPT
        if not HAS_BCRYPT:
            pytest.skip("bcrypt not installed")
        hashed = _hash_password("testpass123")
        assert hashed != "testpass123"
        assert _verify_password("testpass123", hashed) is True
        assert _verify_password("wrongpass", hashed) is False

    def test_no_bcrypt_raises(self):
        with patch("hashguard.web.users.HAS_BCRYPT", False):
            from hashguard.web.users import _hash_password
            with pytest.raises(RuntimeError, match="bcrypt"):
                _hash_password("test")


# ── Register user ──────────────────────────────────────────────────────


class TestRegisterUser:
    def _mock_db(self, existing_user=None):
        db = MagicMock()
        db.query.return_value.filter.return_value.first.return_value = existing_user
        return db

    def test_success(self):
        from hashguard.web.users import register_user, HAS_BCRYPT
        if not HAS_BCRYPT:
            pytest.skip("bcrypt not installed")
        db = self._mock_db(existing_user=None)
        mock_user = MagicMock()
        mock_user.id = 1
        mock_user.email = "new@test.com"
        mock_user.display_name = "new"
        mock_user.role = "analyst"
        mock_user.tenant_id = "default"
        mock_user.is_active = True
        mock_user.email_verified = False
        mock_user.created_at = datetime.now(timezone.utc)
        mock_user.last_login = None
        # After db.refresh, the user object should be returned
        with patch("hashguard.web.users.User") as MockUser:
            MockUser.return_value = mock_user
            result = register_user(db, "new@test.com", "password123")
            assert result["email"] == "new@test.com"
            db.add.assert_called_once()
            db.commit.assert_called_once()

    def test_duplicate_email(self):
        from hashguard.web.users import register_user, HAS_BCRYPT
        if not HAS_BCRYPT:
            pytest.skip("bcrypt not installed")
        existing = MagicMock()
        db = self._mock_db(existing_user=existing)
        with pytest.raises(ValueError, match="already registered"):
            register_user(db, "existing@test.com", "password123")

    def test_invalid_email(self):
        from hashguard.web.users import register_user, HAS_BCRYPT
        if not HAS_BCRYPT:
            pytest.skip("bcrypt not installed")
        db = self._mock_db()
        with pytest.raises(ValueError, match="Invalid email"):
            register_user(db, "bademail", "password123")

    def test_invalid_role(self):
        from hashguard.web.users import register_user, HAS_BCRYPT
        if not HAS_BCRYPT:
            pytest.skip("bcrypt not installed")
        db = self._mock_db()
        with pytest.raises(ValueError, match="Invalid role"):
            register_user(db, "user@test.com", "password123", role="superadmin")

    def test_short_password(self):
        from hashguard.web.users import register_user, HAS_BCRYPT
        if not HAS_BCRYPT:
            pytest.skip("bcrypt not installed")
        db = self._mock_db()
        with pytest.raises(ValueError, match="8 characters"):
            register_user(db, "user@test.com", "short")


# ── Authenticate user ─────────────────────────────────────────────────


class TestAuthenticateUser:
    def test_success(self):
        from hashguard.web.users import authenticate_user, _hash_password, HAS_BCRYPT
        if not HAS_BCRYPT:
            pytest.skip("bcrypt not installed")
        hashed = _hash_password("correct_pass")
        mock_user = MagicMock()
        mock_user.password_hash = hashed
        mock_user.id = 1
        mock_user.email = "user@test.com"
        mock_user.display_name = "user"
        mock_user.role = "analyst"
        mock_user.tenant_id = "default"
        mock_user.is_active = True
        mock_user.email_verified = True
        mock_user.created_at = datetime.now(timezone.utc)
        mock_user.last_login = None

        db = MagicMock()
        db.query.return_value.filter.return_value.first.return_value = mock_user
        result = authenticate_user(db, "user@test.com", "correct_pass")
        assert result is not None
        assert result["email"] == "user@test.com"
        db.commit.assert_called_once()

    def test_wrong_password(self):
        from hashguard.web.users import authenticate_user, _hash_password, HAS_BCRYPT
        if not HAS_BCRYPT:
            pytest.skip("bcrypt not installed")
        hashed = _hash_password("correct_pass")
        mock_user = MagicMock()
        mock_user.password_hash = hashed
        db = MagicMock()
        db.query.return_value.filter.return_value.first.return_value = mock_user
        assert authenticate_user(db, "user@test.com", "wrong_pass") is None

    def test_user_not_found(self):
        from hashguard.web.users import authenticate_user
        db = MagicMock()
        db.query.return_value.filter.return_value.first.return_value = None
        assert authenticate_user(db, "ghost@test.com", "pass") is None


# ── Lookup helpers ─────────────────────────────────────────────────────


class TestLookups:
    def _make_user(self, **kwargs):
        user = MagicMock()
        defaults = {
            "id": 1, "email": "u@t.com", "display_name": "u",
            "role": "analyst", "tenant_id": "default",
            "is_active": True, "email_verified": True,
            "created_at": datetime.now(timezone.utc), "last_login": None,
        }
        defaults.update(kwargs)
        for k, v in defaults.items():
            setattr(user, k, v)
        return user

    def test_get_user_by_email_found(self):
        from hashguard.web.users import get_user_by_email
        db = MagicMock()
        db.query.return_value.filter.return_value.first.return_value = self._make_user()
        result = get_user_by_email(db, "u@t.com")
        assert result is not None

    def test_get_user_by_email_not_found(self):
        from hashguard.web.users import get_user_by_email
        db = MagicMock()
        db.query.return_value.filter.return_value.first.return_value = None
        assert get_user_by_email(db, "ghost@t.com") is None

    def test_get_user_by_id_found(self):
        from hashguard.web.users import get_user_by_id
        db = MagicMock()
        db.query.return_value.filter.return_value.first.return_value = self._make_user(id=42)
        result = get_user_by_id(db, 42)
        assert result is not None
        assert result["id"] == 42

    def test_get_user_by_id_not_found(self):
        from hashguard.web.users import get_user_by_id
        db = MagicMock()
        db.query.return_value.filter.return_value.first.return_value = None
        assert get_user_by_id(db, 999) is None


# ── List users ─────────────────────────────────────────────────────────


class TestListUsers:
    def test_list_all(self):
        from hashguard.web.users import list_users
        db = MagicMock()
        u = MagicMock()
        u.id, u.email, u.display_name, u.role = 1, "a@b.com", "a", "admin"
        u.tenant_id, u.is_active, u.email_verified = "default", True, True
        u.created_at, u.last_login = datetime.now(timezone.utc), None
        db.query.return_value.order_by.return_value.all.return_value = [u]
        result = list_users(db)
        assert len(result) == 1

    def test_list_by_tenant(self):
        from hashguard.web.users import list_users
        db = MagicMock()
        db.query.return_value.filter.return_value.order_by.return_value.all.return_value = []
        result = list_users(db, tenant_id="t1")
        assert result == []


# ── Update user ────────────────────────────────────────────────────────


class TestUpdateUser:
    def test_success(self):
        from hashguard.web.users import update_user
        mock_user = MagicMock()
        mock_user.id, mock_user.email = 1, "u@t.com"
        mock_user.display_name, mock_user.role = "old", "viewer"
        mock_user.tenant_id, mock_user.is_active = "default", True
        mock_user.email_verified = True
        mock_user.created_at = datetime.now(timezone.utc)
        mock_user.last_login = None
        db = MagicMock()
        db.query.return_value.filter.return_value.first.return_value = mock_user
        result = update_user(db, 1, display_name="new_name")
        assert result is not None
        db.commit.assert_called_once()

    def test_not_found(self):
        from hashguard.web.users import update_user
        db = MagicMock()
        db.query.return_value.filter.return_value.first.return_value = None
        assert update_user(db, 999, display_name="x") is None

    def test_ignores_disallowed_fields(self):
        from hashguard.web.users import update_user
        mock_user = MagicMock()
        mock_user.id, mock_user.email = 1, "u@t.com"
        mock_user.display_name = "orig"
        mock_user.role, mock_user.tenant_id = "analyst", "default"
        mock_user.is_active, mock_user.email_verified = True, True
        mock_user.created_at = datetime.now(timezone.utc)
        mock_user.last_login = None
        db = MagicMock()
        db.query.return_value.filter.return_value.first.return_value = mock_user
        update_user(db, 1, password_hash="hacked")
        # password_hash should NOT be set
        assert not any(call[0][0] == "password_hash" for call in mock_user.setattr.call_args_list
                       if hasattr(mock_user, 'setattr'))


# ── Change password ────────────────────────────────────────────────────


class TestChangePassword:
    def test_success(self):
        from hashguard.web.users import change_password, _hash_password, HAS_BCRYPT
        if not HAS_BCRYPT:
            pytest.skip("bcrypt not installed")
        old_hash = _hash_password("oldpass123")
        mock_user = MagicMock()
        mock_user.password_hash = old_hash
        db = MagicMock()
        db.query.return_value.filter.return_value.first.return_value = mock_user
        assert change_password(db, 1, "oldpass123", "newpass12345") is True
        db.commit.assert_called_once()

    def test_wrong_old_password(self):
        from hashguard.web.users import change_password, _hash_password, HAS_BCRYPT
        if not HAS_BCRYPT:
            pytest.skip("bcrypt not installed")
        old_hash = _hash_password("oldpass123")
        mock_user = MagicMock()
        mock_user.password_hash = old_hash
        db = MagicMock()
        db.query.return_value.filter.return_value.first.return_value = mock_user
        assert change_password(db, 1, "wrongpass", "newpass12345") is False

    def test_short_new_password(self):
        from hashguard.web.users import change_password, _hash_password, HAS_BCRYPT
        if not HAS_BCRYPT:
            pytest.skip("bcrypt not installed")
        old_hash = _hash_password("oldpass123")
        mock_user = MagicMock()
        mock_user.password_hash = old_hash
        db = MagicMock()
        db.query.return_value.filter.return_value.first.return_value = mock_user
        assert change_password(db, 1, "oldpass123", "short") is False

    def test_user_not_found(self):
        from hashguard.web.users import change_password
        db = MagicMock()
        db.query.return_value.filter.return_value.first.return_value = None
        assert change_password(db, 999, "old", "newpass12345") is False


# ── Delete user ────────────────────────────────────────────────────────


class TestDeleteUser:
    def test_success(self):
        from hashguard.web.users import delete_user
        mock_user = MagicMock()
        mock_user.email = "del@test.com"
        db = MagicMock()
        db.query.return_value.filter.return_value.first.return_value = mock_user
        assert delete_user(db, 1) is True
        db.delete.assert_called_once_with(mock_user)
        db.commit.assert_called_once()

    def test_not_found(self):
        from hashguard.web.users import delete_user
        db = MagicMock()
        db.query.return_value.filter.return_value.first.return_value = None
        assert delete_user(db, 999) is False


# ── User to dict ──────────────────────────────────────────────────────


class TestUserToDict:
    def test_converts_user(self):
        from hashguard.web.users import _user_to_dict
        mock_user = MagicMock()
        mock_user.id = 1
        mock_user.email = "u@t.com"
        mock_user.display_name = "User"
        mock_user.role = "admin"
        mock_user.tenant_id = "t1"
        mock_user.is_active = True
        mock_user.email_verified = True
        mock_user.created_at = datetime(2024, 1, 1, tzinfo=timezone.utc)
        mock_user.last_login = None
        d = _user_to_dict(mock_user)
        assert d["id"] == 1
        assert d["email"] == "u@t.com"
        assert d["last_login"] is None
        assert "password_hash" not in d
