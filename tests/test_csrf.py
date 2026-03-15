"""Tests for CSRF middleware."""

import pytest
from unittest.mock import patch

from starlette.testclient import TestClient
from fastapi import FastAPI
from hashguard.web.csrf import CSRFMiddleware, CSRF_COOKIE_NAME, CSRF_HEADER_NAME


@pytest.fixture
def csrf_app():
    app = FastAPI()
    app.add_middleware(CSRFMiddleware)

    @app.get("/api/data")
    async def get_data():
        return {"data": "ok"}

    @app.post("/api/data")
    async def post_data():
        return {"created": True}

    @app.post("/api/auth/login")
    async def login():
        return {"token": "jwt"}

    @app.post("/api/auth/register")
    async def register():
        return {"user": "new"}

    return app


@pytest.fixture
def client(csrf_app):
    return TestClient(csrf_app)


class TestCSRFMiddleware:
    def test_get_requests_exempt(self, client):
        resp = client.get("/api/data")
        assert resp.status_code == 200

    def test_get_sets_csrf_cookie(self, client):
        resp = client.get("/api/data")
        assert CSRF_COOKIE_NAME in resp.cookies

    def test_post_without_csrf_fails(self, client):
        resp = client.post("/api/data")
        assert resp.status_code == 403
        assert "CSRF" in resp.json()["detail"]

    def test_post_with_valid_csrf(self, client):
        # First get to receive CSRF cookie
        get_resp = client.get("/api/data")
        token = get_resp.cookies[CSRF_COOKIE_NAME]

        resp = client.post(
            "/api/data",
            headers={CSRF_HEADER_NAME: token},
            cookies={CSRF_COOKIE_NAME: token},
        )
        assert resp.status_code == 200

    def test_post_with_mismatched_csrf(self, client):
        resp = client.post(
            "/api/data",
            headers={CSRF_HEADER_NAME: "wrong_token"},
            cookies={CSRF_COOKIE_NAME: "correct_token"},
        )
        assert resp.status_code == 403

    def test_login_exempt_from_csrf(self, client):
        resp = client.post("/api/auth/login")
        assert resp.status_code == 200

    def test_register_exempt_from_csrf(self, client):
        resp = client.post("/api/auth/register")
        assert resp.status_code == 200

    def test_bearer_token_exempt(self, client):
        resp = client.post(
            "/api/data",
            headers={"Authorization": "Bearer sometoken"},
        )
        assert resp.status_code == 200

    def test_api_key_exempt(self, client):
        resp = client.post(
            "/api/data",
            headers={"X-API-Key": "hg_somekey"},
        )
        assert resp.status_code == 200
