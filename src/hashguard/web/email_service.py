"""Email verification service for HashGuard SaaS.

Sends verification emails on registration and handles token verification.
Supports SMTP (Resend, custom), or console fallback for dev.

Configuration via environment variables:
  SMTP_HOST      - SMTP server (default: smtp.resend.com)
  SMTP_PORT      - SMTP port (default: 465)
  SMTP_USER      - SMTP username (default: resend for Resend)
  SMTP_PASS      - SMTP password / API key
  SMTP_FROM      - From address (defaults to noreply@hashguard.org)
  HASHGUARD_URL  - Base URL for verification links (default: http://localhost:8000)
"""

import hashlib
import hmac
import os
import smtplib
import time
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import Optional

from sqlalchemy.orm import Session

from hashguard.logger import get_logger

logger = get_logger(__name__)


# ── Configuration ───────────────────────────────────────────────────────────


def _smtp_config() -> dict:
    return {
        "host": os.environ.get("SMTP_HOST", "smtp.resend.com"),
        "port": int(os.environ.get("SMTP_PORT", "465")),
        "user": os.environ.get("SMTP_USER", "resend"),
        "password": os.environ.get("SMTP_PASS", ""),
        "from_addr": os.environ.get("SMTP_FROM", "noreply@hashguard.org"),
    }


def _base_url() -> str:
    return os.environ.get("HASHGUARD_URL", "http://localhost:8000").rstrip("/")


def _get_secret() -> str:
    """Get the signing secret for verification tokens (reuses JWT secret)."""
    from hashguard.web.auth import _get_secret_key

    return _get_secret_key()


# ── Token generation ────────────────────────────────────────────────────────


def generate_verification_token(email: str) -> str:
    """Generate a time-limited verification token for an email."""
    secret = _get_secret()
    ts = str(int(time.time()))
    payload = f"{email}:{ts}"
    sig = hmac.new(secret.encode(), payload.encode(), hashlib.sha256).hexdigest()[:32]
    return f"{ts}:{sig}"


def verify_token(email: str, token: str, max_age: int = 86400) -> bool:
    """Verify a token is valid and not expired (default 24h)."""
    try:
        ts_str, sig = token.split(":", 1)
        ts = int(ts_str)
    except (ValueError, AttributeError):
        return False

    # Check expiry
    if time.time() - ts > max_age:
        return False

    # Verify signature
    secret = _get_secret()
    payload = f"{email}:{ts_str}"
    expected = hmac.new(secret.encode(), payload.encode(), hashlib.sha256).hexdigest()[:32]
    return hmac.compare_digest(sig, expected)


# ── Email sending ───────────────────────────────────────────────────────────


def _send_smtp(to: str, subject: str, html_body: str) -> bool:
    """Send an email via SMTP."""
    cfg = _smtp_config()
    if not cfg["user"] or not cfg["password"]:
        logger.warning("SMTP not configured — logging email to console")
        logger.info("Email to=%s subject=%s", to, subject)
        logger.debug("Body: %s", html_body[:500])
        return True  # Don't block registration in dev

    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"] = cfg["from_addr"]
    msg["To"] = to
    msg.attach(MIMEText(html_body, "html", "utf-8"))

    try:
        port = cfg["port"]
        if port == 465:
            with smtplib.SMTP_SSL(cfg["host"], port, timeout=10) as server:
                server.login(cfg["user"], cfg["password"])
                server.sendmail(cfg["from_addr"], [to], msg.as_string())
        else:
            with smtplib.SMTP(cfg["host"], port, timeout=10) as server:
                server.starttls()
                server.login(cfg["user"], cfg["password"])
                server.sendmail(cfg["from_addr"], [to], msg.as_string())
        logger.info("Verification email sent to %s", to)
        return True
    except Exception as e:
        logger.error("Failed to send email to %s: %s", to, e)
        return False


def send_verification_email(email: str) -> bool:
    """Send a verification email with a unique token link."""
    token = generate_verification_token(email)
    base = _base_url()
    verify_url = f"{base}/api/auth/verify-email?email={email}&token={token}"

    html = f"""
    <div style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; max-width: 600px; margin: 0 auto; background: #0f172a; color: #e2e8f0; padding: 40px; border-radius: 12px;">
      <div style="text-align: center; margin-bottom: 30px;">
        <h1 style="color: #22d3ee; margin: 0; font-size: 28px;">🛡️ HashGuard</h1>
        <p style="color: #64748b; margin-top: 8px;">Malware Research Platform</p>
      </div>
      <h2 style="color: #f1f5f9; font-size: 20px;">Verify your email</h2>
      <p style="color: #94a3b8; line-height: 1.6;">
        Click the button below to verify your email address and activate your account.
        This link expires in 24 hours.
      </p>
      <div style="text-align: center; margin: 30px 0;">
        <a href="{verify_url}" style="background: #22d3ee; color: #0f172a; padding: 12px 32px; border-radius: 8px; text-decoration: none; font-weight: 600; font-size: 16px;">
          Verify Email
        </a>
      </div>
      <p style="color: #64748b; font-size: 13px;">
        If the button doesn't work, copy and paste this URL:<br>
        <a href="{verify_url}" style="color: #22d3ee; word-break: break-all;">{verify_url}</a>
      </p>
      <hr style="border: none; border-top: 1px solid #1e293b; margin: 30px 0;">
      <p style="color: #475569; font-size: 12px; text-align: center;">
        HashGuard — hashguard.org
      </p>
    </div>
    """
    return _send_smtp(email, "Verify your HashGuard account", html)


def send_password_reset_email(email: str) -> bool:
    """Send a password reset email."""
    token = generate_verification_token(email)
    base = _base_url()
    reset_url = f"{base}/?reset_token={token}&email={email}"

    html = f"""
    <div style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; max-width: 600px; margin: 0 auto; background: #0f172a; color: #e2e8f0; padding: 40px; border-radius: 12px;">
      <div style="text-align: center; margin-bottom: 30px;">
        <h1 style="color: #22d3ee; margin: 0; font-size: 28px;">🛡️ HashGuard</h1>
      </div>
      <h2 style="color: #f1f5f9; font-size: 20px;">Reset your password</h2>
      <p style="color: #94a3b8; line-height: 1.6;">
        Someone requested a password reset for your account. Click below to set a new password.
        This link expires in 1 hour.
      </p>
      <div style="text-align: center; margin: 30px 0;">
        <a href="{reset_url}" style="background: #f97316; color: #0f172a; padding: 12px 32px; border-radius: 8px; text-decoration: none; font-weight: 600; font-size: 16px;">
          Reset Password
        </a>
      </div>
      <p style="color: #64748b; font-size: 13px;">If you didn't request this, ignore this email.</p>
    </div>
    """
    return _send_smtp(email, "Reset your HashGuard password", html)


# ── Verification endpoint helper ────────────────────────────────────────────


def verify_user_email(db: Session, email: str, token: str) -> bool:
    """Verify a user's email and update the database."""
    if not verify_token(email, token):
        return False

    from hashguard.models import User

    user = db.query(User).filter(User.email == email.strip().lower()).first()
    if not user:
        return False

    user.email_verified = True
    db.commit()
    logger.info("Email verified for %s", email)
    return True


def send_team_invite_email(email: str, team_name: str, invited_by: str, token: str) -> bool:
    """Send a team invitation email with a join link."""
    base = _base_url()
    invite_url = f"{base}/?invite_token={token}"

    html = f"""
    <div style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; max-width: 600px; margin: 0 auto; background: #0f172a; color: #e2e8f0; padding: 40px; border-radius: 12px;">
      <div style="text-align: center; margin-bottom: 30px;">
        <h1 style="color: #22d3ee; margin: 0; font-size: 28px;">&#128737; HashGuard</h1>
        <p style="color: #64748b; margin-top: 8px;">Malware Research Platform</p>
      </div>
      <h2 style="color: #f1f5f9; font-size: 20px;">You've been invited to a team</h2>
      <p style="color: #94a3b8; line-height: 1.6;">
        <strong style="color: #e2e8f0;">{invited_by}</strong> has invited you to join
        <strong style="color: #22d3ee;">{team_name}</strong> on HashGuard.
        This invitation expires in 7 days.
      </p>
      <div style="text-align: center; margin: 30px 0;">
        <a href="{invite_url}" style="background: #22d3ee; color: #0f172a; padding: 12px 32px; border-radius: 8px; text-decoration: none; font-weight: 600; font-size: 16px;">
          Join Team
        </a>
      </div>
      <p style="color: #64748b; font-size: 13px;">
        If you don't have an account yet, create one first at
        <a href="{base}" style="color: #22d3ee;">hashguard.org</a>, then use the link above.
      </p>
      <hr style="border: none; border-top: 1px solid #1e293b; margin: 30px 0;">
      <p style="color: #475569; font-size: 12px; text-align: center;">
        HashGuard &mdash; hashguard.org
      </p>
    </div>
    """
    return _send_smtp(email, f"Join {team_name} on HashGuard", html)
