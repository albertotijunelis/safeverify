"""Tests for HashGuard OAuth2/SSO router.

Tests Google and GitHub OAuth2 login flows, user creation,
and provider discovery endpoint.
"""

import os
import pytest
from datetime import datetime, timezone
from unittest.mock import patch, MagicMock, AsyncMock


@pytest.fixture(autouse=True)
def _disable_auth():
    old = os.environ.get("HASHGUARD_AUTH")
    os.environ["HASHGUARD_AUTH"] = "0"
    yield
    if old is None:
        os.environ.pop("HASHGUARD_AUTH", None)
    else:
        os.environ["HASHGUARD_AUTH"] = old


@pytest.fixture(autouse=True)
def _clear_oauth_env():
    keys = ["GOOGLE_CLIENT_ID", "GOOGLE_CLIENT_SECRET", "GITHUB_CLIENT_ID", "GITHUB_CLIENT_SECRET"]
    old = {k: os.environ.get(k) for k in keys}
    for k in keys:
        os.environ.pop(k, None)
    yield
    for k, v in old.items():
        if v is not None:
            os.environ[k] = v
        else:
            os.environ.pop(k, None)


@pytest.fixture
def client():
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    from hashguard.web.routers.oauth_router import router

    app = FastAPI()
    app.include_router(router)
    with TestClient(app, follow_redirects=False) as tc:
        yield tc


# ── Provider Discovery ──────────────────────────────────────────────────────


class TestProviders:
    def test_no_providers_configured(self, client):
        r = client.get("/api/auth/oauth/providers")
        assert r.status_code == 200
        data = r.json()
        assert data["google"] is False
        assert data["github"] is False

    def test_google_configured(self, client):
        os.environ["GOOGLE_CLIENT_ID"] = "test-google-id"
        r = client.get("/api/auth/oauth/providers")
        assert r.json()["google"] is True
        assert r.json()["github"] is False

    def test_github_configured(self, client):
        os.environ["GITHUB_CLIENT_ID"] = "test-github-id"
        r = client.get("/api/auth/oauth/providers")
        assert r.json()["google"] is False
        assert r.json()["github"] is True

    def test_both_configured(self, client):
        os.environ["GOOGLE_CLIENT_ID"] = "test-google-id"
        os.environ["GITHUB_CLIENT_ID"] = "test-github-id"
        r = client.get("/api/auth/oauth/providers")
        assert r.json()["google"] is True
        assert r.json()["github"] is True


# ── Google Login ────────────────────────────────────────────────────────────


class TestGoogleLogin:
    def test_not_configured_returns_501(self, client):
        r = client.get("/api/auth/oauth/google/login")
        assert r.status_code == 501

    def test_configured_redirects(self, client):
        os.environ["GOOGLE_CLIENT_ID"] = "test-google-id"
        r = client.get("/api/auth/oauth/google/login")
        assert r.status_code == 307
        location = r.headers["location"]
        assert location.startswith("https://accounts.google.com/")
        assert "test-google-id" in location
        assert "openid" in location


# ── Google Callback ─────────────────────────────────────────────────────────


class TestGoogleCallback:
    def test_error_param_redirects(self, client):
        r = client.get("/api/auth/oauth/google/callback?error=access_denied")
        assert r.status_code == 307
        assert "oauth_error=auth_failed" in r.headers["location"]

    def test_invalid_state_redirects(self, client):
        r = client.get("/api/auth/oauth/google/callback?code=abc&state=invalid")
        assert r.status_code == 307
        assert "invalid_state" in r.headers["location"]

    def test_no_state_redirects(self, client):
        r = client.get("/api/auth/oauth/google/callback?code=abc")
        assert r.status_code == 307
        assert "invalid_state" in r.headers["location"]

    def test_missing_config_redirects(self, client):
        from hashguard.web.routers.oauth_router import _oauth_states
        _oauth_states["test_state"] = {"provider": "google"}
        r = client.get("/api/auth/oauth/google/callback?code=abc&state=test_state")
        assert r.status_code == 307
        assert "config_error" in r.headers["location"]


# ── GitHub Login ────────────────────────────────────────────────────────────


class TestGithubLogin:
    def test_not_configured_returns_501(self, client):
        r = client.get("/api/auth/oauth/github/login")
        assert r.status_code == 501

    def test_configured_redirects(self, client):
        os.environ["GITHUB_CLIENT_ID"] = "test-github-id"
        r = client.get("/api/auth/oauth/github/login")
        assert r.status_code == 307
        location = r.headers["location"]
        assert location.startswith("https://github.com/login/oauth")
        assert "test-github-id" in location


# ── GitHub Callback ─────────────────────────────────────────────────────────


class TestGithubCallback:
    def test_error_param_redirects(self, client):
        r = client.get("/api/auth/oauth/github/callback?error=access_denied")
        assert r.status_code == 307
        assert "oauth_error=auth_failed" in r.headers["location"]

    def test_invalid_state_redirects(self, client):
        r = client.get("/api/auth/oauth/github/callback?code=abc&state=invalid")
        assert r.status_code == 307
        assert "invalid_state" in r.headers["location"]

    def test_missing_config_redirects(self, client):
        from hashguard.web.routers.oauth_router import _oauth_states
        _oauth_states["gh_state"] = {"provider": "github"}
        r = client.get("/api/auth/oauth/github/callback?code=abc&state=gh_state")
        assert r.status_code == 307
        assert "config_error" in r.headers["location"]


# ── _get_or_create_oauth_user ───────────────────────────────────────────────


class TestGetOrCreateOauthUser:
    def test_create_new_user(self):
        from hashguard.web.routers.oauth_router import _get_or_create_oauth_user
        db = MagicMock()
        db.query.return_value.filter.return_value.first.return_value = None

        new_user = MagicMock()
        new_user.id = 1
        new_user.email = "new@test.com"
        new_user.display_name = "New User"
        new_user.role = "analyst"
        new_user.avatar_url = "https://avatar.url/pic.jpg"

        def refresh_side(u):
            u.id = 1
            u.email = "new@test.com"
            u.display_name = "New User"
            u.role = "analyst"
            u.avatar_url = "https://avatar.url/pic.jpg"

        db.refresh = refresh_side
        db.add = MagicMock()
        db.commit = MagicMock()

        result = _get_or_create_oauth_user(
            db, email="new@test.com", display_name="New User",
            avatar_url="https://avatar.url/pic.jpg", provider="google",
            provider_id="12345"
        )
        assert db.add.called
        assert db.commit.called

    def test_update_existing_user(self):
        from hashguard.web.routers.oauth_router import _get_or_create_oauth_user
        db = MagicMock()
        existing = MagicMock()
        existing.id = 1
        existing.email = "existing@test.com"
        existing.display_name = "Existing"
        existing.role = "analyst"
        existing.avatar_url = None
        existing.auth_provider = None

        db.query.return_value.filter.return_value.first.return_value = existing

        result = _get_or_create_oauth_user(
            db, email="existing@test.com", display_name="Updated Name",
            avatar_url="https://avatar.url/pic.jpg", provider="github",
            provider_id="67890"
        )
        db.commit.assert_called()
        assert existing.auth_provider == "github"

    def test_existing_user_preserves_display_name(self):
        from hashguard.web.routers.oauth_router import _get_or_create_oauth_user
        db = MagicMock()
        existing = MagicMock()
        existing.id = 1
        existing.email = "user@test.com"
        existing.display_name = "Already Set"
        existing.role = "admin"
        existing.avatar_url = "existing.jpg"
        existing.auth_provider = "google"

        db.query.return_value.filter.return_value.first.return_value = existing

        result = _get_or_create_oauth_user(
            db, email="user@test.com", display_name="New Name",
            avatar_url="new.jpg", provider="google", provider_id="111"
        )
        # display_name should not change since it's already set
        assert existing.display_name == "Already Set"

    def test_user_without_email_uses_prefix(self):
        from hashguard.web.routers.oauth_router import _get_or_create_oauth_user
        db = MagicMock()
        db.query.return_value.filter.return_value.first.return_value = None

        new_user = MagicMock()
        new_user.id = 1
        new_user.email = "test@example.com"
        new_user.display_name = "test"
        new_user.role = "analyst"
        new_user.avatar_url = None

        db.refresh = lambda u: setattr(u, 'id', 1)

        result = _get_or_create_oauth_user(
            db, email="test@example.com", display_name=None,
            avatar_url=None, provider="google", provider_id="123"
        )
        db.add.assert_called_once()


# ── Helper Functions ────────────────────────────────────────────────────────


class TestHelpers:
    def test_redirect_uri_google(self):
        from hashguard.web.routers.oauth_router import _redirect_uri
        uri = _redirect_uri("google")
        assert "google/callback" in uri
        assert uri.startswith("http")

    def test_redirect_uri_github(self):
        from hashguard.web.routers.oauth_router import _redirect_uri
        uri = _redirect_uri("github")
        assert "github/callback" in uri

    def test_oauth_states_dict(self):
        from hashguard.web.routers.oauth_router import _oauth_states
        assert isinstance(_oauth_states, dict)
