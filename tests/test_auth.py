"""Tests for HashGuard authentication & authorization module."""

import asyncio
import json
import os
import tempfile
import time
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest

from hashguard.web.auth import (
    _hash_api_key,
    create_api_key,
    revoke_api_key,
    list_api_keys,
    validate_api_key,
    create_token,
    verify_token,
    _is_auth_enabled,
    ROLES,
    ROLE_PERMISSIONS,
    _get_auth_dir,
    _get_secret_key,
    get_current_user,
    require_permission,
)


@pytest.fixture(autouse=True)
def _isolated_auth_dir(tmp_path, monkeypatch):
    """Redirect auth storage to a temp directory for every test."""
    monkeypatch.setattr(
        "hashguard.web.auth._get_auth_dir", lambda: tmp_path
    )
    # Also clear any cached secret
    monkeypatch.delenv("HASHGUARD_AUTH", raising=False)
    yield tmp_path


# ── API Key hashing ────────────────────────────────────────────────────────

class TestHashApiKey:
    def test_deterministic(self):
        h1 = _hash_api_key("hg_abc123")
        h2 = _hash_api_key("hg_abc123")
        assert h1 == h2

    def test_different_keys_differ(self):
        h1 = _hash_api_key("hg_abc123")
        h2 = _hash_api_key("hg_xyz789")
        assert h1 != h2

    def test_returns_hex_string(self):
        h = _hash_api_key("test")
        assert len(h) == 64  # SHA-256 hex digest
        assert all(c in "0123456789abcdef" for c in h)


# ── API Key CRUD ────────────────────────────────────────────────────────────

class TestCreateApiKey:
    def test_creates_key_with_prefix(self):
        result = create_api_key("test-key")
        assert result["api_key"].startswith("hg_")
        assert result["name"] == "test-key"
        assert result["role"] == "analyst"
        assert "key_id" in result

    def test_creates_key_with_custom_role(self):
        result = create_api_key("admin-key", role="admin")
        assert result["role"] == "admin"

    def test_rejects_invalid_role(self):
        with pytest.raises(ValueError, match="Invalid role"):
            create_api_key("bad-key", role="superuser")

    def test_key_stored_on_disk(self, _isolated_auth_dir):
        create_api_key("disk-key")
        keys_file = _isolated_auth_dir / "api_keys.json"
        assert keys_file.exists()
        data = json.loads(keys_file.read_text())
        assert len(data) == 1

    def test_multiple_keys(self):
        create_api_key("key1")
        create_api_key("key2")
        result = list_api_keys()
        assert len(result) == 2


class TestRevokeApiKey:
    def test_revoke_existing_key(self):
        result = create_api_key("to-revoke")
        key_id = result["key_id"]
        assert revoke_api_key(key_id) is True

    def test_revoke_nonexistent_key(self):
        assert revoke_api_key("nonexistent") is False

    def test_revoked_key_inactive(self):
        result = create_api_key("to-revoke")
        revoke_api_key(result["key_id"])
        keys = list_api_keys()
        revoked = [k for k in keys if k["key_id"] == result["key_id"]]
        assert revoked[0]["active"] is False


class TestListApiKeys:
    def test_empty(self):
        assert list_api_keys() == []

    def test_no_hashes_exposed(self):
        create_api_key("secret-key")
        keys = list_api_keys()
        for k in keys:
            assert "key_hash" not in k
            assert "api_key" not in k

    def test_fields_present(self):
        create_api_key("field-test", role="viewer")
        keys = list_api_keys()
        k = keys[0]
        assert k["name"] == "field-test"
        assert k["role"] == "viewer"
        assert k["active"] is True
        assert "created_at" in k
        assert "key_id" in k


class TestValidateApiKey:
    def test_valid_key(self):
        result = create_api_key("valid-key")
        raw_key = result["api_key"]
        info = validate_api_key(raw_key)
        assert info is not None
        assert info["name"] == "valid-key"
        assert info["role"] == "analyst"

    def test_invalid_key(self):
        assert validate_api_key("hg_bogus") is None

    def test_revoked_key_returns_none(self):
        result = create_api_key("revoked")
        revoke_api_key(result["key_id"])
        assert validate_api_key(result["api_key"]) is None

    def test_updates_last_used(self):
        result = create_api_key("used-key")
        before = time.time()
        validate_api_key(result["api_key"])
        keys = list_api_keys()
        k = [x for x in keys if x["key_id"] == result["key_id"]][0]
        assert k["last_used"] >= before


# ── JWT Tokens ──────────────────────────────────────────────────────────────

class TestJWT:
    def test_create_and_verify(self):
        token = create_token("testuser", role="analyst")
        payload = verify_token(token)
        assert payload["sub"] == "testuser"
        assert payload["role"] == "analyst"

    def test_admin_token(self):
        token = create_token("admin", role="admin")
        payload = verify_token(token)
        assert payload["role"] == "admin"

    def test_expired_token(self):
        import jwt as pyjwt

        token = create_token("expired", expiry_seconds=-1)
        with pytest.raises(pyjwt.ExpiredSignatureError):
            verify_token(token)

    def test_tampered_token_rejected(self):
        import jwt as pyjwt

        token = create_token("user")
        # Tamper with the token
        parts = token.split(".")
        parts[1] = parts[1][::-1]  # reverse payload
        tampered = ".".join(parts)
        with pytest.raises(Exception):
            verify_token(tampered)

    def test_token_has_iat_and_exp(self):
        token = create_token("user", expiry_seconds=3600)
        payload = verify_token(token)
        assert "iat" in payload
        assert "exp" in payload
        assert payload["exp"] - payload["iat"] == 3600


# ── Secret Key ──────────────────────────────────────────────────────────────

class TestSecretKey:
    def test_generates_key_file(self, _isolated_auth_dir):
        key = _get_secret_key()
        key_file = _isolated_auth_dir / ".jwt_secret"
        assert key_file.exists()
        assert len(key) == 64  # 32 bytes = 64 hex chars

    def test_persistent_across_calls(self):
        key1 = _get_secret_key()
        key2 = _get_secret_key()
        assert key1 == key2


# ── Auth enabled flag ──────────────────────────────────────────────────────

class TestAuthEnabled:
    def test_disabled_by_default(self, monkeypatch):
        monkeypatch.delenv("HASHGUARD_AUTH", raising=False)
        assert _is_auth_enabled() is False

    def test_enabled_via_env(self, monkeypatch):
        monkeypatch.setenv("HASHGUARD_AUTH", "1")
        assert _is_auth_enabled() is True

    def test_enabled_via_true(self, monkeypatch):
        monkeypatch.setenv("HASHGUARD_AUTH", "true")
        assert _is_auth_enabled() is True

    def test_disabled_via_zero(self, monkeypatch):
        monkeypatch.setenv("HASHGUARD_AUTH", "0")
        assert _is_auth_enabled() is False


# ── Roles & Permissions ────────────────────────────────────────────────────

class TestRolesAndPermissions:
    def test_all_roles_defined(self):
        assert ROLES == {"admin", "analyst", "viewer"}

    def test_admin_has_all_permissions(self):
        admin_perms = ROLE_PERMISSIONS["admin"]
        for role, perms in ROLE_PERMISSIONS.items():
            assert perms.issubset(admin_perms), f"{role} has perms not in admin"

    def test_viewer_cannot_analyze(self):
        viewer_perms = ROLE_PERMISSIONS["viewer"]
        assert "analyze" not in viewer_perms
        assert "ingest" not in viewer_perms
        assert "train" not in viewer_perms
        assert "settings" not in viewer_perms

    def test_analyst_can_analyze(self):
        perms = ROLE_PERMISSIONS["analyst"]
        assert "analyze" in perms
        assert "read" in perms
        assert "ingest" in perms

    def test_analyst_cannot_manage_keys(self):
        perms = ROLE_PERMISSIONS["analyst"]
        assert "manage_keys" not in perms


# ── FastAPI dependency (unit-level) ─────────────────────────────────────────

class TestGetCurrentUser:
    def test_returns_callable(self):
        dep = get_current_user()
        assert callable(dep)

    def test_auth_disabled_returns_local_admin(self, monkeypatch):
        monkeypatch.delenv("HASHGUARD_AUTH", raising=False)
        dep = get_current_user()
        mock_request = MagicMock()
        result = asyncio.run(dep(request=mock_request, credentials=None))
        assert result["sub"] == "local"
        assert result["role"] == "admin"

    def test_auth_enabled_no_creds_raises(self, monkeypatch):
        monkeypatch.setenv("HASHGUARD_AUTH", "1")
        from fastapi import HTTPException

        dep = get_current_user()
        mock_request = MagicMock()
        with pytest.raises(HTTPException) as exc_info:
            asyncio.run(dep(request=mock_request, credentials=None))
        assert exc_info.value.status_code == 401

    def test_auth_enabled_valid_api_key(self, monkeypatch):
        monkeypatch.setenv("HASHGUARD_AUTH", "1")
        result = create_api_key("test", role="analyst")
        raw_key = result["api_key"]

        dep = get_current_user()
        mock_request = MagicMock()
        mock_creds = MagicMock()
        mock_creds.credentials = raw_key
        user = asyncio.run(dep(request=mock_request, credentials=mock_creds))
        assert user["sub"] == "test"
        assert user["role"] == "analyst"

    def test_auth_enabled_valid_jwt(self, monkeypatch):
        monkeypatch.setenv("HASHGUARD_AUTH", "1")
        token = create_token("jwtuser", role="admin")

        dep = get_current_user()
        mock_request = MagicMock()
        mock_creds = MagicMock()
        mock_creds.credentials = token
        user = asyncio.run(dep(request=mock_request, credentials=mock_creds))
        assert user["sub"] == "jwtuser"
        assert user["role"] == "admin"

    def test_auth_enabled_invalid_token_raises(self, monkeypatch):
        monkeypatch.setenv("HASHGUARD_AUTH", "1")
        from fastapi import HTTPException

        dep = get_current_user()
        mock_request = MagicMock()
        mock_creds = MagicMock()
        mock_creds.credentials = "invalid.jwt.token"
        with pytest.raises(HTTPException) as exc_info:
            asyncio.run(dep(request=mock_request, credentials=mock_creds))
        assert exc_info.value.status_code == 401


class TestRequirePermission:
    def test_returns_callable(self):
        dep = require_permission("analyze")
        assert callable(dep)

    def test_admin_has_all_permissions(self):
        dep = require_permission("manage_keys")
        user = asyncio.run(dep(user={"sub": "admin", "role": "admin"}))
        assert user["role"] == "admin"

    def test_viewer_denied_analyze(self):
        from fastapi import HTTPException

        dep = require_permission("analyze")
        with pytest.raises(HTTPException) as exc_info:
            asyncio.run(dep(user={"sub": "viewer", "role": "viewer"}))
        assert exc_info.value.status_code == 403

    def test_analyst_allowed_analyze(self):
        dep = require_permission("analyze")
        user = asyncio.run(dep(user={"sub": "analyst", "role": "analyst"}))
        assert user["role"] == "analyst"

    def test_analyst_denied_manage_keys(self):
        from fastapi import HTTPException

        dep = require_permission("manage_keys")
        with pytest.raises(HTTPException) as exc_info:
            asyncio.run(dep(user={"sub": "analyst", "role": "analyst"}))
        assert exc_info.value.status_code == 403
