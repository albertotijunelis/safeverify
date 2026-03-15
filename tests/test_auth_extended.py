"""Tests for auth module — JWT, API keys, dependencies."""

import os
import time
import pytest
from unittest.mock import patch, MagicMock


# ── JWT tokens ──────────────────────────────────────────────────────────


class TestCreateToken:
    def test_creates_valid_token(self, tmp_path):
        key_file = tmp_path / ".jwt_secret"
        key_file.write_text("testsecret123456", encoding="utf-8")
        with patch("hashguard.web.auth._get_auth_dir", return_value=tmp_path):
            from hashguard.web.auth import create_token, verify_token, HAS_JWT
            if not HAS_JWT:
                pytest.skip("PyJWT not installed")
            token = create_token("admin@test.com", role="admin")
            payload = verify_token(token)
            assert payload["sub"] == "admin@test.com"
            assert payload["role"] == "admin"

    def test_expiry(self, tmp_path):
        key_file = tmp_path / ".jwt_secret"
        key_file.write_text("testsecret123456", encoding="utf-8")
        with patch("hashguard.web.auth._get_auth_dir", return_value=tmp_path):
            from hashguard.web.auth import create_token, verify_token, HAS_JWT
            if not HAS_JWT:
                pytest.skip("PyJWT not installed")
            # Create token with 0s expiry
            token = create_token("user@test.com", expiry_seconds=0)
            time.sleep(0.1)
            import jwt as pyjwt
            with pytest.raises(pyjwt.ExpiredSignatureError):
                verify_token(token)


class TestVerifyToken:
    def test_invalid_token(self, tmp_path):
        key_file = tmp_path / ".jwt_secret"
        key_file.write_text("testsecret123456", encoding="utf-8")
        with patch("hashguard.web.auth._get_auth_dir", return_value=tmp_path):
            from hashguard.web.auth import verify_token, HAS_JWT
            if not HAS_JWT:
                pytest.skip("PyJWT not installed")
            with pytest.raises(Exception):
                verify_token("invalid.jwt.token")


# ── Secret key ──────────────────────────────────────────────────────────


class TestGetSecretKey:
    def test_creates_key_file(self, tmp_path):
        with patch("hashguard.web.auth._get_auth_dir", return_value=tmp_path):
            from hashguard.web.auth import _get_secret_key
            key = _get_secret_key()
            assert len(key) == 64  # hex(32) = 64 chars
            # Should persist
            key2 = _get_secret_key()
            assert key == key2

    def test_reads_existing_key(self, tmp_path):
        key_file = tmp_path / ".jwt_secret"
        key_file.write_text("myexistingkey", encoding="utf-8")
        with patch("hashguard.web.auth._get_auth_dir", return_value=tmp_path):
            from hashguard.web.auth import _get_secret_key
            assert _get_secret_key() == "myexistingkey"


# ── API Keys ────────────────────────────────────────────────────────────


class TestCreateApiKey:
    def test_success(self, tmp_path):
        with patch("hashguard.web.auth._get_auth_dir", return_value=tmp_path):
            from hashguard.web.auth import create_api_key
            result = create_api_key("test-key", role="analyst")
            assert result["api_key"].startswith("hg_")
            assert result["role"] == "analyst"
            assert "key_id" in result

    def test_invalid_role(self, tmp_path):
        with patch("hashguard.web.auth._get_auth_dir", return_value=tmp_path):
            from hashguard.web.auth import create_api_key
            with pytest.raises(ValueError, match="Invalid role"):
                create_api_key("bad", role="superuser")


class TestValidateApiKey:
    def test_valid_key(self, tmp_path):
        with patch("hashguard.web.auth._get_auth_dir", return_value=tmp_path):
            from hashguard.web.auth import create_api_key, validate_api_key
            result = create_api_key("my-key")
            raw_key = result["api_key"]
            info = validate_api_key(raw_key)
            assert info is not None
            assert info["name"] == "my-key"

    def test_invalid_key(self, tmp_path):
        with patch("hashguard.web.auth._get_auth_dir", return_value=tmp_path):
            from hashguard.web.auth import validate_api_key
            assert validate_api_key("hg_nonexistent") is None

    def test_revoked_key(self, tmp_path):
        with patch("hashguard.web.auth._get_auth_dir", return_value=tmp_path):
            from hashguard.web.auth import create_api_key, revoke_api_key, validate_api_key
            result = create_api_key("revokable")
            raw_key = result["api_key"]
            revoke_api_key(result["key_id"])
            assert validate_api_key(raw_key) is None


class TestRevokeApiKey:
    def test_success(self, tmp_path):
        with patch("hashguard.web.auth._get_auth_dir", return_value=tmp_path):
            from hashguard.web.auth import create_api_key, revoke_api_key
            result = create_api_key("rev")
            assert revoke_api_key(result["key_id"]) is True

    def test_not_found(self, tmp_path):
        with patch("hashguard.web.auth._get_auth_dir", return_value=tmp_path):
            from hashguard.web.auth import revoke_api_key
            assert revoke_api_key("nonexistent") is False


class TestListApiKeys:
    def test_empty(self, tmp_path):
        with patch("hashguard.web.auth._get_auth_dir", return_value=tmp_path):
            from hashguard.web.auth import list_api_keys
            assert list_api_keys() == []

    def test_with_keys(self, tmp_path):
        with patch("hashguard.web.auth._get_auth_dir", return_value=tmp_path):
            from hashguard.web.auth import create_api_key, list_api_keys
            create_api_key("k1")
            create_api_key("k2")
            keys = list_api_keys()
            assert len(keys) == 2
            # Should not contain key_hash
            assert all("key_hash" not in k for k in keys)


# ── Auth enabled check ──────────────────────────────────────────────────


class TestIsAuthEnabled:
    def test_enabled_via_env(self):
        from hashguard.web.auth import _is_auth_enabled
        with patch.dict(os.environ, {"HASHGUARD_AUTH": "1"}, clear=False):
            assert _is_auth_enabled() is True

    def test_disabled_via_env(self):
        from hashguard.web.auth import _is_auth_enabled
        with patch.dict(os.environ, {"HASHGUARD_AUTH": "0"}, clear=False):
            assert _is_auth_enabled() is False

    def test_default_disabled(self):
        from hashguard.web.auth import _is_auth_enabled
        with patch.dict(os.environ, {"HASHGUARD_AUTH": ""}, clear=False):
            assert _is_auth_enabled() is False

    def test_true_string(self):
        from hashguard.web.auth import _is_auth_enabled
        with patch.dict(os.environ, {"HASHGUARD_AUTH": "true"}, clear=False):
            assert _is_auth_enabled() is True

    def test_false_string(self):
        from hashguard.web.auth import _is_auth_enabled
        with patch.dict(os.environ, {"HASHGUARD_AUTH": "false"}, clear=False):
            assert _is_auth_enabled() is False


# ── Role permissions ────────────────────────────────────────────────────


class TestRolePermissions:
    def test_admin_has_all(self):
        from hashguard.web.auth import ROLE_PERMISSIONS
        perms = ROLE_PERMISSIONS["admin"]
        assert "analyze" in perms
        assert "settings" in perms
        assert "manage_keys" in perms

    def test_analyst_no_settings(self):
        from hashguard.web.auth import ROLE_PERMISSIONS
        perms = ROLE_PERMISSIONS["analyst"]
        assert "analyze" in perms
        assert "settings" not in perms

    def test_viewer_read_only(self):
        from hashguard.web.auth import ROLE_PERMISSIONS
        perms = ROLE_PERMISSIONS["viewer"]
        assert "read" in perms
        assert "search" in perms
        assert "analyze" not in perms


# ── Get current user dependency ─────────────────────────────────────────


class TestGetCurrentUser:
    def test_returns_callable(self):
        from hashguard.web.auth import get_current_user
        dep = get_current_user()
        assert callable(dep)

    def test_require_permission_returns_callable(self):
        from hashguard.web.auth import require_permission
        dep = require_permission("analyze")
        assert callable(dep)


# ── Key store persistence ──────────────────────────────────────────────


class TestKeyStorePersistence:
    def test_load_empty(self, tmp_path):
        with patch("hashguard.web.auth._get_auth_dir", return_value=tmp_path):
            from hashguard.web.auth import _load_keys
            assert _load_keys() == {}

    def test_load_corrupt(self, tmp_path):
        (tmp_path / "api_keys.json").write_text("broken", encoding="utf-8")
        with patch("hashguard.web.auth._get_auth_dir", return_value=tmp_path):
            from hashguard.web.auth import _load_keys
            assert _load_keys() == {}

    def test_save_and_load(self, tmp_path):
        with patch("hashguard.web.auth._get_auth_dir", return_value=tmp_path):
            from hashguard.web.auth import _save_keys, _load_keys
            keys = {"k1": {"key_hash": "h", "name": "test", "role": "admin",
                          "created_at": time.time(), "active": True}}
            _save_keys(keys)
            loaded = _load_keys()
            assert "k1" in loaded


# ── Hash API key ────────────────────────────────────────────────────────


class TestHashApiKey:
    def test_deterministic(self):
        from hashguard.web.auth import _hash_api_key
        h1 = _hash_api_key("hg_test123")
        h2 = _hash_api_key("hg_test123")
        assert h1 == h2

    def test_different_keys(self):
        from hashguard.web.auth import _hash_api_key
        h1 = _hash_api_key("hg_key1")
        h2 = _hash_api_key("hg_key2")
        assert h1 != h2
