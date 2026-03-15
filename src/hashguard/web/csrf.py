"""CSRF protection middleware for HashGuard.

Uses the double-submit cookie pattern:
1. Server sets a CSRF token cookie on every response
2. Client sends the token back via X-CSRF-Token header on state-changing requests
3. Middleware validates cookie value matches header value

API key and JWT Bearer token requests are exempt (machine-to-machine).
GET/HEAD/OPTIONS requests are exempt (safe methods).
"""

import secrets
from typing import Set

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response, JSONResponse

from hashguard.logger import get_logger

logger = get_logger(__name__)

SAFE_METHODS: Set[str] = {"GET", "HEAD", "OPTIONS"}
CSRF_COOKIE_NAME = "hashguard_csrf"
CSRF_HEADER_NAME = "x-csrf-token"
TOKEN_LENGTH = 32


class CSRFMiddleware(BaseHTTPMiddleware):
    """Double-submit cookie CSRF protection."""

    async def dispatch(self, request: Request, call_next) -> Response:
        # Skip CSRF for safe methods
        if request.method in SAFE_METHODS:
            response = await call_next(request)
            _ensure_csrf_cookie(request, response)
            return response

        # Skip CSRF for API key / Bearer token auth (machine-to-machine)
        auth_header = request.headers.get("authorization", "")
        if auth_header.startswith(("Bearer ", "bearer ")):
            return await call_next(request)

        api_key = request.headers.get("x-api-key", "")
        if api_key:
            return await call_next(request)

        # Skip CSRF for /api/auth/login and /api/auth/register (no cookie yet)
        path = request.url.path.rstrip("/")
        if path in ("/api/auth/login", "/api/auth/register"):
            response = await call_next(request)
            _ensure_csrf_cookie(request, response)
            return response

        # Validate CSRF token
        cookie_token = request.cookies.get(CSRF_COOKIE_NAME, "")
        header_token = request.headers.get(CSRF_HEADER_NAME, "")

        if not cookie_token or not header_token or not secrets.compare_digest(cookie_token, header_token):
            return JSONResponse(
                status_code=403,
                content={"detail": "CSRF validation failed"},
            )

        response = await call_next(request)
        _ensure_csrf_cookie(request, response)
        return response


def _ensure_csrf_cookie(request: Request, response: Response) -> None:
    """Set CSRF cookie if not already present."""
    if CSRF_COOKIE_NAME not in request.cookies:
        token = secrets.token_hex(TOKEN_LENGTH)
        response.set_cookie(
            key=CSRF_COOKIE_NAME,
            value=token,
            httponly=False,  # JS needs to read this
            samesite="lax",
            secure=request.url.scheme == "https",
            path="/",
        )
