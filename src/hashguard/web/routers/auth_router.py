"""User authentication API router for HashGuard SaaS.

Endpoints:
- POST /api/auth/register          Register a new user
- POST /api/auth/login             Login and get JWT token
- GET  /api/auth/me                Get current user info
- PUT  /api/auth/password          Change password
- POST /api/auth/forgot-password   Request password reset email
- POST /api/auth/reset-password    Reset password with token
- GET  /api/auth/users             List users (admin only)
"""

import secrets
from datetime import datetime, timezone, timedelta

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, EmailStr, Field
from sqlalchemy.orm import Session

from hashguard.models import get_db, PasswordReset, User
from hashguard.web.auth import (
    create_token,
    get_current_user,
    require_permission,
)
from hashguard.web.users import (
    authenticate_user,
    change_password,
    delete_user,
    get_user_by_id,
    list_users,
    register_user,
    update_user,
)

router = APIRouter(prefix="/api/auth", tags=["Auth"])


# ── Request/Response models ─────────────────────────────────────────────────


class RegisterRequest(BaseModel):
    email: str = Field(..., min_length=5, max_length=255)
    password: str = Field(..., min_length=8, max_length=128)
    display_name: Optional[str] = None


class LoginRequest(BaseModel):
    email: str
    password: str


class ChangePasswordRequest(BaseModel):
    old_password: str
    new_password: str = Field(..., min_length=8, max_length=128)


class UpdateUserRequest(BaseModel):
    display_name: Optional[str] = None
    role: Optional[str] = None
    is_active: Optional[bool] = None


class ForgotPasswordRequest(BaseModel):
    email: str = Field(..., min_length=5, max_length=255)


class ResetPasswordRequest(BaseModel):
    email: str = Field(..., min_length=5, max_length=255)
    token: str
    new_password: str = Field(..., min_length=8, max_length=128)


# ── Endpoints ───────────────────────────────────────────────────────────────


@router.post("/register")
async def api_register(req: RegisterRequest, db: Session = Depends(get_db)):
    """Register a new user account."""
    try:
        user = register_user(
            db,
            email=req.email,
            password=req.password,
            display_name=req.display_name,
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    # Send verification email (non-blocking — doesn't fail registration)
    try:
        from hashguard.web.email_service import send_verification_email
        send_verification_email(user["email"])
    except Exception:
        pass

    token = create_token(subject=user["email"], role=user["role"])
    return {"user": user, "token": token}


@router.post("/login")
async def api_login(req: LoginRequest, db: Session = Depends(get_db)):
    """Login with email and password, returns JWT token."""
    user = authenticate_user(db, email=req.email, password=req.password)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid email or password")

    token = create_token(subject=user["email"], role=user["role"])
    return {"user": user, "token": token}


@router.get("/me")
async def api_me(
    user=Depends(get_current_user()),
    db: Session = Depends(get_db),
):
    """Get current authenticated user info."""
    from hashguard.web.users import get_user_by_email

    db_user = get_user_by_email(db, user.get("sub", ""))
    if db_user:
        return db_user
    return user


@router.put("/password")
async def api_change_password(
    req: ChangePasswordRequest,
    user=Depends(get_current_user()),
    db: Session = Depends(get_db),
):
    """Change the current user's password."""
    from hashguard.web.users import get_user_by_email

    db_user = get_user_by_email(db, user.get("sub", ""))
    if not db_user:
        raise HTTPException(status_code=404, detail="User not found")

    ok = change_password(db, db_user["id"], req.old_password, req.new_password)
    if not ok:
        raise HTTPException(status_code=400, detail="Invalid old password or new password too short")
    return {"detail": "Password changed"}


@router.post("/forgot-password")
async def api_forgot_password(req: ForgotPasswordRequest, db: Session = Depends(get_db)):
    """Request a password reset email. Always returns 200 to prevent enumeration."""
    email = req.email.strip().lower()
    user = db.query(User).filter(User.email == email).first()

    if user:
        # Invalidate existing reset tokens
        db.query(PasswordReset).filter(
            PasswordReset.user_id == user.id, PasswordReset.used == False
        ).update({"used": True})

        token = secrets.token_urlsafe(48)
        reset = PasswordReset(
            user_id=user.id,
            token=token,
            expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
            used=False,
            created_at=datetime.now(timezone.utc),
        )
        db.add(reset)
        db.commit()

        try:
            from hashguard.web.email_service import send_password_reset_email

            send_password_reset_email(email)
        except Exception:
            pass

    return {"detail": "If the email exists, a reset link has been sent"}


@router.post("/reset-password")
async def api_reset_password(req: ResetPasswordRequest, db: Session = Depends(get_db)):
    """Reset password using a token from the reset email."""
    from hashguard.web.email_service import verify_token as verify_email_token
    from hashguard.web.users import _hash_password

    email = req.email.strip().lower()
    user = db.query(User).filter(User.email == email).first()
    if not user:
        raise HTTPException(status_code=400, detail="Invalid reset request")

    # Verify the HMAC-based token from email_service
    if not verify_email_token(email, req.token, max_age=3600):
        raise HTTPException(status_code=400, detail="Invalid or expired reset token")

    if len(req.new_password) < 8:
        raise HTTPException(status_code=400, detail="Password must be at least 8 characters")

    user.password_hash = _hash_password(req.new_password)
    db.commit()
    return {"detail": "Password has been reset successfully"}


@router.get("/users")
async def api_list_users(
    user=Depends(require_permission("manage_keys")),
    db: Session = Depends(get_db),
):
    """List all users (admin only)."""
    return list_users(db)


@router.put("/users/{user_id}")
async def api_update_user(
    user_id: int,
    req: UpdateUserRequest,
    user=Depends(require_permission("manage_keys")),
    db: Session = Depends(get_db),
):
    """Update a user (admin only)."""
    updates = {k: v for k, v in req.model_dump().items() if v is not None}
    result = update_user(db, user_id, **updates)
    if not result:
        raise HTTPException(status_code=404, detail="User not found")
    return result


@router.delete("/users/{user_id}")
async def api_delete_user(
    user_id: int,
    user=Depends(require_permission("manage_keys")),
    db: Session = Depends(get_db),
):
    """Delete a user (admin only)."""
    ok = delete_user(db, user_id)
    if not ok:
        raise HTTPException(status_code=404, detail="User not found")
    return {"detail": "User deleted"}


@router.get("/verify-email")
async def api_verify_email(
    email: str,
    token: str,
    db: Session = Depends(get_db),
):
    """Verify a user's email address via token link."""
    from hashguard.web.email_service import verify_user_email
    from fastapi.responses import HTMLResponse

    if verify_user_email(db, email, token):
        return HTMLResponse(
            content="""<html><body style="background:#0f172a;color:#e2e8f0;font-family:sans-serif;display:flex;justify-content:center;align-items:center;height:100vh">
            <div style="text-align:center"><h1 style="color:#22d3ee">✅ Email Verified!</h1>
            <p>Your email has been verified. You can close this page and return to HashGuard.</p>
            <a href="/" style="color:#22d3ee">Go to Dashboard</a></div></body></html>""",
            status_code=200,
        )
    raise HTTPException(status_code=400, detail="Invalid or expired verification link")


@router.post("/resend-verification")
async def api_resend_verification(
    user=Depends(get_current_user()),
    db: Session = Depends(get_db),
):
    """Resend the verification email for the current user."""
    from hashguard.web.email_service import send_verification_email
    from hashguard.web.users import get_user_by_email

    db_user = get_user_by_email(db, user.get("sub", ""))
    if not db_user:
        raise HTTPException(status_code=404, detail="User not found")
    if db_user.get("email_verified"):
        return {"detail": "Email already verified"}

    send_verification_email(db_user["email"])
    return {"detail": "Verification email sent"}
