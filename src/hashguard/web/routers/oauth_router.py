"""OAuth2 / SSO router for HashGuard SaaS.

Supports Google and GitHub OAuth2 login.  Users are auto-created on first
login with ``email_verified=True`` and ``auth_provider`` set.

Env vars required:
  GOOGLE_CLIENT_ID / GOOGLE_CLIENT_SECRET
  GITHUB_CLIENT_ID / GITHUB_CLIENT_SECRET
"""

import os
import secrets
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import RedirectResponse
from sqlalchemy.orm import Session

from hashguard.logger import get_logger
from hashguard.models import User, get_db
from hashguard.web.auth import create_token

logger = get_logger(__name__)

router = APIRouter(prefix="/api/auth/oauth", tags=["Auth"])

# ── helpers ────────────────────────────────────────────────────────────────

_BASE_URL = os.environ.get("HASHGUARD_URL", "http://localhost:8000").rstrip("/")


def _redirect_uri(provider: str) -> str:
    return f"{_BASE_URL}/api/auth/oauth/{provider}/callback"


def _get_or_create_oauth_user(
    db: Session,
    *,
    email: str,
    display_name: Optional[str],
    avatar_url: Optional[str],
    provider: str,
    provider_id: str,
) -> dict:
    """Find existing user by email or create a new one for OAuth login."""
    user = db.query(User).filter(User.email == email).first()

    if user:
        # Update provider info if not set (user registered via email first)
        if not user.auth_provider:
            user.auth_provider = provider
            user.auth_provider_id = provider_id
        if avatar_url and not user.avatar_url:
            user.avatar_url = avatar_url
        if display_name and not user.display_name:
            user.display_name = display_name
        user.email_verified = True
        user.last_login = datetime.now(timezone.utc)
        db.commit()
    else:
        user = User(
            email=email,
            password_hash="",  # OAuth users have no password
            display_name=display_name or email.split("@")[0],
            role="analyst",
            is_active=True,
            email_verified=True,
            auth_provider=provider,
            auth_provider_id=provider_id,
            avatar_url=avatar_url,
            last_login=datetime.now(timezone.utc),
        )
        db.add(user)
        db.commit()
        db.refresh(user)
        logger.info(f"Created OAuth user: {email} via {provider}")

    return {
        "id": user.id,
        "email": user.email,
        "display_name": user.display_name,
        "role": user.role,
        "avatar_url": user.avatar_url,
    }


# In-memory state store (short-lived, CSRF protection)
_oauth_states: dict[str, dict] = {}

# ── Google OAuth2 ──────────────────────────────────────────────────────────

_GOOGLE_AUTH_URL = "https://accounts.google.com/o/oauth2/v2/auth"
_GOOGLE_TOKEN_URL = "https://oauth2.googleapis.com/token"
_GOOGLE_USERINFO_URL = "https://www.googleapis.com/oauth2/v2/userinfo"


@router.get("/google/login")
async def google_login():
    """Redirect user to Google OAuth2 consent screen."""
    client_id = os.environ.get("GOOGLE_CLIENT_ID")
    if not client_id:
        raise HTTPException(status_code=501, detail="Google OAuth not configured")

    state = secrets.token_urlsafe(32)
    _oauth_states[state] = {"provider": "google"}

    params = {
        "client_id": client_id,
        "redirect_uri": _redirect_uri("google"),
        "response_type": "code",
        "scope": "openid email profile",
        "state": state,
        "access_type": "offline",
        "prompt": "select_account",
    }
    url = _GOOGLE_AUTH_URL + "?" + "&".join(f"{k}={v}" for k, v in params.items())
    return RedirectResponse(url)


@router.get("/google/callback")
async def google_callback(code: Optional[str] = None, state: Optional[str] = None, error: Optional[str] = None):
    """Handle Google OAuth2 callback."""
    if error:
        return RedirectResponse("/?oauth_error=auth_failed")

    if not state or state not in _oauth_states:
        return RedirectResponse("/?oauth_error=invalid_state")

    del _oauth_states[state]

    client_id = os.environ.get("GOOGLE_CLIENT_ID", "")
    client_secret = os.environ.get("GOOGLE_CLIENT_SECRET", "")

    if not client_id or not client_secret or not code:
        return RedirectResponse("/?oauth_error=config_error")

    import httpx

    # Exchange code for token
    async with httpx.AsyncClient() as client:
        token_resp = await client.post(
            _GOOGLE_TOKEN_URL,
            data={
                "code": code,
                "client_id": client_id,
                "client_secret": client_secret,
                "redirect_uri": _redirect_uri("google"),
                "grant_type": "authorization_code",
            },
        )
        if token_resp.status_code != 200:
            logger.error(f"Google token exchange failed: {token_resp.text}")
            return RedirectResponse("/?oauth_error=token_error")

        tokens = token_resp.json()
        access_token = tokens.get("access_token")

        # Fetch user info
        info_resp = await client.get(
            _GOOGLE_USERINFO_URL,
            headers={"Authorization": f"Bearer {access_token}"},
        )
        if info_resp.status_code != 200:
            return RedirectResponse("/?oauth_error=userinfo_error")

        info = info_resp.json()

    email = info.get("email")
    if not email:
        return RedirectResponse("/?oauth_error=no_email")

    db = next(get_db())
    try:
        user = _get_or_create_oauth_user(
            db,
            email=email,
            display_name=info.get("name"),
            avatar_url=info.get("picture"),
            provider="google",
            provider_id=str(info.get("id", "")),
        )
    finally:
        db.close()

    jwt = create_token(subject=user["email"], role=user["role"])
    return RedirectResponse(f"/?token={jwt}")


# ── GitHub OAuth2 ──────────────────────────────────────────────────────────

_GITHUB_AUTH_URL = "https://github.com/login/oauth/authorize"
_GITHUB_TOKEN_URL = "https://github.com/login/oauth/access_token"
_GITHUB_USER_URL = "https://api.github.com/user"
_GITHUB_EMAILS_URL = "https://api.github.com/user/emails"


@router.get("/github/login")
async def github_login():
    """Redirect user to GitHub OAuth2 consent screen."""
    client_id = os.environ.get("GITHUB_CLIENT_ID")
    if not client_id:
        raise HTTPException(status_code=501, detail="GitHub OAuth not configured")

    state = secrets.token_urlsafe(32)
    _oauth_states[state] = {"provider": "github"}

    params = {
        "client_id": client_id,
        "redirect_uri": _redirect_uri("github"),
        "scope": "user:email",
        "state": state,
    }
    url = _GITHUB_AUTH_URL + "?" + "&".join(f"{k}={v}" for k, v in params.items())
    return RedirectResponse(url)


@router.get("/github/callback")
async def github_callback(code: Optional[str] = None, state: Optional[str] = None, error: Optional[str] = None):
    """Handle GitHub OAuth2 callback."""
    if error:
        return RedirectResponse("/?oauth_error=auth_failed")

    if not state or state not in _oauth_states:
        return RedirectResponse("/?oauth_error=invalid_state")

    del _oauth_states[state]

    client_id = os.environ.get("GITHUB_CLIENT_ID", "")
    client_secret = os.environ.get("GITHUB_CLIENT_SECRET", "")

    if not client_id or not client_secret or not code:
        return RedirectResponse("/?oauth_error=config_error")

    import httpx

    async with httpx.AsyncClient() as client:
        # Exchange code for token
        token_resp = await client.post(
            _GITHUB_TOKEN_URL,
            data={
                "code": code,
                "client_id": client_id,
                "client_secret": client_secret,
                "redirect_uri": _redirect_uri("github"),
            },
            headers={"Accept": "application/json"},
        )
        if token_resp.status_code != 200:
            logger.error(f"GitHub token exchange failed: {token_resp.text}")
            return RedirectResponse("/?oauth_error=token_error")

        tokens = token_resp.json()
        access_token = tokens.get("access_token")
        if not access_token:
            return RedirectResponse("/?oauth_error=token_error")

        headers = {
            "Authorization": f"Bearer {access_token}",
            "Accept": "application/json",
        }

        # Fetch user profile
        user_resp = await client.get(_GITHUB_USER_URL, headers=headers)
        if user_resp.status_code != 200:
            return RedirectResponse("/?oauth_error=userinfo_error")
        gh_user = user_resp.json()

        # Fetch email (may be private)
        email = gh_user.get("email")
        if not email:
            emails_resp = await client.get(_GITHUB_EMAILS_URL, headers=headers)
            if emails_resp.status_code == 200:
                for em in emails_resp.json():
                    if em.get("primary") and em.get("verified"):
                        email = em["email"]
                        break

    if not email:
        return RedirectResponse("/?oauth_error=no_email")

    db = next(get_db())
    try:
        user = _get_or_create_oauth_user(
            db,
            email=email,
            display_name=gh_user.get("name") or gh_user.get("login"),
            avatar_url=gh_user.get("avatar_url"),
            provider="github",
            provider_id=str(gh_user.get("id", "")),
        )
    finally:
        db.close()

    jwt = create_token(subject=user["email"], role=user["role"])
    return RedirectResponse(f"/?token={jwt}")


# ── Discovery endpoint ────────────────────────────────────────────────────

@router.get("/providers")
async def oauth_providers():
    """Return which OAuth providers are configured."""
    return {
        "google": bool(os.environ.get("GOOGLE_CLIENT_ID")),
        "github": bool(os.environ.get("GITHUB_CLIENT_ID")),
    }
