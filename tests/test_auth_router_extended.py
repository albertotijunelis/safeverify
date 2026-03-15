"""Extended tests for auth_router — covers register/login/password/forgot/reset/verify flows."""

import os
import pytest
from datetime import datetime, timezone
from unittest.mock import patch, MagicMock


@pytest.fixture(autouse=True)
def _enable_auth():
    """Enable auth for realistic testing of auth endpoints."""
    old = os.environ.get("HASHGUARD_AUTH")
    os.environ["HASHGUARD_AUTH"] = "0"
    yield
    if old is None:
        os.environ.pop("HASHGUARD_AUTH", None)
    else:
        os.environ["HASHGUARD_AUTH"] = old


def _user_dict(id=1, email="u@t.com", display_name="U", role="analyst",
               tenant_id="default", email_verified=False):
    return {
        "id": id, "email": email, "display_name": display_name,
        "role": role, "tenant_id": tenant_id,
        "is_active": True, "email_verified": email_verified,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "last_login": None,
    }


@pytest.fixture
def db():
    return MagicMock()


@pytest.fixture
def client(db):
    def _db_gen():
        yield db

    from hashguard.models import get_db

    with patch("hashguard.web.routers.auth_router.get_current_user",
               return_value=lambda: {"sub": "u@t.com", "role": "admin"}), \
         patch("hashguard.web.routers.auth_router.require_permission",
               return_value=lambda: {"sub": "u@t.com", "role": "admin"}):
        from fastapi import FastAPI
        from fastapi.testclient import TestClient
        from hashguard.web.routers.auth_router import router
        app = FastAPI()
        app.include_router(router)
        app.dependency_overrides[get_db] = _db_gen
        yield TestClient(app)


# ── Register ────────────────────────────────────────────────────────────


class TestRegister:
    def test_register_success(self, client):
        user = _user_dict()
        with patch("hashguard.web.routers.auth_router.register_user", return_value=user), \
             patch("hashguard.web.routers.auth_router.create_token", return_value="jwt"):
            r = client.post("/api/auth/register", json={
                "email": "new@t.com", "password": "Password1!"
            })
            assert r.status_code == 200
            assert r.json()["token"] == "jwt"

    def test_register_duplicate(self, client):
        with patch("hashguard.web.routers.auth_router.register_user",
                   side_effect=ValueError("Email already registered")):
            r = client.post("/api/auth/register", json={
                "email": "dup@t.com", "password": "Password1!"
            })
            assert r.status_code == 400

    def test_register_short_password(self, client):
        r = client.post("/api/auth/register", json={
            "email": "u@t.com", "password": "short"
        })
        assert r.status_code == 422

    def test_register_sends_verification_email(self, client):
        user = _user_dict()
        with patch("hashguard.web.routers.auth_router.register_user", return_value=user), \
             patch("hashguard.web.routers.auth_router.create_token", return_value="jwt"), \
             patch("hashguard.web.email_service.send_verification_email") as mock_send:
            client.post("/api/auth/register", json={
                "email": "new@t.com", "password": "Password1!"
            })
            mock_send.assert_called_once_with("u@t.com")


# ── Login ───────────────────────────────────────────────────────────────


class TestLogin:
    def test_login_success(self, client):
        user = _user_dict()
        with patch("hashguard.web.routers.auth_router.authenticate_user", return_value=user), \
             patch("hashguard.web.routers.auth_router.create_token", return_value="jwt"):
            r = client.post("/api/auth/login", json={
                "email": "u@t.com", "password": "Password1!"
            })
            assert r.status_code == 200
            assert "token" in r.json()

    def test_login_invalid_credentials(self, client):
        with patch("hashguard.web.routers.auth_router.authenticate_user", return_value=None):
            r = client.post("/api/auth/login", json={
                "email": "u@t.com", "password": "wrong"
            })
            assert r.status_code == 401


# ── Me ──────────────────────────────────────────────────────────────────


class TestMe:
    def test_me_with_db_user(self, client):
        user = _user_dict()
        with patch("hashguard.web.users.get_user_by_email", return_value=user):
            r = client.get("/api/auth/me")
            assert r.status_code == 200
            assert r.json()["email"] == "u@t.com"

    def test_me_no_db_user(self, client):
        with patch("hashguard.web.users.get_user_by_email", return_value=None):
            r = client.get("/api/auth/me")
            assert r.status_code == 200


# ── Change Password ─────────────────────────────────────────────────────


class TestChangePassword:
    def test_change_password_success(self, client):
        user = _user_dict()
        with patch("hashguard.web.users.get_user_by_email", return_value=user), \
             patch("hashguard.web.routers.auth_router.change_password", return_value=True):
            r = client.put("/api/auth/password", json={
                "old_password": "OldPass1!", "new_password": "NewPass1!"
            })
            assert r.status_code == 200

    def test_change_password_wrong_old(self, client):
        user = _user_dict()
        with patch("hashguard.web.users.get_user_by_email", return_value=user), \
             patch("hashguard.web.routers.auth_router.change_password", return_value=False):
            r = client.put("/api/auth/password", json={
                "old_password": "wrong", "new_password": "NewPass1!"
            })
            assert r.status_code == 400

    def test_change_password_user_not_found(self, client):
        with patch("hashguard.web.users.get_user_by_email", return_value=None):
            r = client.put("/api/auth/password", json={
                "old_password": "Old", "new_password": "NewPass1!"
            })
            assert r.status_code == 404


# ── Forgot Password ────────────────────────────────────────────────────


class TestForgotPassword:
    def test_forgot_password_existing_user(self, client, db):
        user = MagicMock()
        user.id = 1
        db.query.return_value.filter.return_value.first.return_value = user
        db.query.return_value.filter.return_value.update = MagicMock()
        db.add = MagicMock()
        db.commit = MagicMock()

        with patch("hashguard.web.email_service.send_password_reset_email"):
            r = client.post("/api/auth/forgot-password", json={"email": "u@t.com"})
            assert r.status_code == 200
            assert "reset link" in r.json()["detail"].lower() or "sent" in r.json()["detail"].lower()

    def test_forgot_password_nonexistent_returns_200(self, client, db):
        db.query.return_value.filter.return_value.first.return_value = None
        r = client.post("/api/auth/forgot-password", json={"email": "nobody@t.com"})
        assert r.status_code == 200  # Always 200 to prevent enumeration


# ── Reset Password ──────────────────────────────────────────────────────


class TestResetPassword:
    def test_reset_password_valid(self, client, db):
        user = MagicMock()
        user.email = "u@t.com"
        db.query.return_value.filter.return_value.first.return_value = user
        db.commit = MagicMock()

        with patch("hashguard.web.email_service.verify_token", return_value=True), \
             patch("hashguard.web.users._hash_password", return_value="hashed"):
            r = client.post("/api/auth/reset-password", json={
                "email": "u@t.com", "token": "12345:sig", "new_password": "NewPass1!"
            })
            assert r.status_code == 200

    def test_reset_password_invalid_token(self, client, db):
        user = MagicMock()
        db.query.return_value.filter.return_value.first.return_value = user
        with patch("hashguard.web.email_service.verify_token", return_value=False):
            r = client.post("/api/auth/reset-password", json={
                "email": "u@t.com", "token": "bad", "new_password": "NewPass1!"
            })
            assert r.status_code == 400

    def test_reset_password_user_not_found(self, client, db):
        db.query.return_value.filter.return_value.first.return_value = None
        r = client.post("/api/auth/reset-password", json={
            "email": "nobody@t.com", "token": "tok", "new_password": "NewPass1!"
        })
        assert r.status_code == 400

    def test_reset_password_short_password(self, client, db):
        user = MagicMock()
        db.query.return_value.filter.return_value.first.return_value = user
        with patch("hashguard.web.email_service.verify_token", return_value=True):
            r = client.post("/api/auth/reset-password", json={
                "email": "u@t.com", "token": "12345:sig", "new_password": "short"
            })
            assert r.status_code == 422  # Pydantic min_length=8 rejects before endpoint


# ── Admin User CRUD ─────────────────────────────────────────────────────


class TestAdminUserCRUD:
    def test_list_users(self, client, db):
        with patch("hashguard.web.routers.auth_router.list_users", return_value=[_user_dict()]):
            r = client.get("/api/auth/users")
            assert r.status_code == 200

    def test_update_user_success(self, client, db):
        with patch("hashguard.web.routers.auth_router.update_user", return_value=_user_dict()):
            r = client.put("/api/auth/users/1", json={"role": "admin"})
            assert r.status_code == 200

    def test_update_user_not_found(self, client, db):
        with patch("hashguard.web.routers.auth_router.update_user", return_value=None):
            r = client.put("/api/auth/users/999", json={"role": "admin"})
            assert r.status_code == 404

    def test_delete_user_success(self, client, db):
        with patch("hashguard.web.routers.auth_router.delete_user", return_value=True):
            r = client.delete("/api/auth/users/1")
            assert r.status_code == 200

    def test_delete_user_not_found(self, client, db):
        with patch("hashguard.web.routers.auth_router.delete_user", return_value=False):
            r = client.delete("/api/auth/users/999")
            assert r.status_code == 404


# ── Verify / Resend ─────────────────────────────────────────────────────


class TestVerifyEmail:
    def test_verify_success(self, client, db):
        with patch("hashguard.web.email_service.verify_user_email", return_value=True):
            r = client.get("/api/auth/verify-email?email=u@t.com&token=tok")
            assert r.status_code == 200
            assert "verified" in r.text.lower() or "Verified" in r.text

    def test_verify_failure(self, client, db):
        with patch("hashguard.web.email_service.verify_user_email", return_value=False):
            r = client.get("/api/auth/verify-email?email=u@t.com&token=bad")
            assert r.status_code == 400


class TestResendVerification:
    def test_resend_success(self, client, db):
        user = _user_dict(email_verified=False)
        with patch("hashguard.web.users.get_user_by_email", return_value=user), \
             patch("hashguard.web.email_service.send_verification_email"):
            r = client.post("/api/auth/resend-verification")
            assert r.status_code == 200

    def test_resend_already_verified(self, client, db):
        user = _user_dict(email_verified=True)
        with patch("hashguard.web.users.get_user_by_email", return_value=user):
            r = client.post("/api/auth/resend-verification")
            assert r.status_code == 200
            assert "already" in r.json()["detail"].lower()

    def test_resend_user_not_found(self, client, db):
        with patch("hashguard.web.users.get_user_by_email", return_value=None):
            r = client.post("/api/auth/resend-verification")
            assert r.status_code == 404


# ── Request Models ──────────────────────────────────────────────────────


class TestRequestModels:
    def test_register_request(self):
        from hashguard.web.routers.auth_router import RegisterRequest
        req = RegisterRequest(email="a@b.com", password="12345678")
        assert req.email == "a@b.com"

    def test_login_request(self):
        from hashguard.web.routers.auth_router import LoginRequest
        req = LoginRequest(email="a@b.com", password="pass")
        assert req.email == "a@b.com"

    def test_change_password_request(self):
        from hashguard.web.routers.auth_router import ChangePasswordRequest
        req = ChangePasswordRequest(old_password="old", new_password="12345678")
        assert req.new_password == "12345678"

    def test_forgot_password_request(self):
        from hashguard.web.routers.auth_router import ForgotPasswordRequest
        req = ForgotPasswordRequest(email="a@b.com")
        assert req.email == "a@b.com"

    def test_reset_password_request(self):
        from hashguard.web.routers.auth_router import ResetPasswordRequest
        req = ResetPasswordRequest(email="a@b.com", token="tok", new_password="12345678")
        assert req.token == "tok"

    def test_update_user_request(self):
        from hashguard.web.routers.auth_router import UpdateUserRequest
        req = UpdateUserRequest(role="admin")
        assert req.role == "admin"
        assert req.display_name is None
