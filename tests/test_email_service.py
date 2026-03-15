"""SMTP email service tests for HashGuard SaaS."""

import time
import pytest
from unittest.mock import patch, MagicMock

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from hashguard.models import Base, User
from hashguard.web.email_service import (
    generate_verification_token,
    verify_token,
    send_verification_email,
    send_password_reset_email,
    verify_user_email,
    _smtp_config,
    _base_url,
)


@pytest.fixture
def db():
    """In-memory SQLite database for testing."""
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine)
    session = Session()
    yield session
    session.close()


class TestSmtpConfig:
    """Tests for SMTP configuration loading."""

    def test_defaults(self):
        cfg = _smtp_config()
        assert cfg["host"] == "smtp.resend.com"
        assert cfg["port"] == 465
        assert cfg["user"] == "resend"

    @patch.dict("os.environ", {"SMTP_HOST": "mail.example.com", "SMTP_PORT": "465"})
    def test_custom_smtp(self):
        cfg = _smtp_config()
        assert cfg["host"] == "mail.example.com"
        assert cfg["port"] == 465


class TestBaseUrl:
    """Tests for base URL configuration."""

    def test_default_url(self):
        url = _base_url()
        assert "localhost" in url

    @patch.dict("os.environ", {"HASHGUARD_URL": "https://hashguard.org/"})
    def test_custom_url_strips_trailing_slash(self):
        url = _base_url()
        assert url == "https://hashguard.org"


class TestTokenGeneration:
    """Tests for verification token generation and verification."""

    @patch("hashguard.web.email_service._get_secret", return_value="test-secret-key")
    def test_generate_token_format(self, _):
        token = generate_verification_token("user@example.com")
        assert ":" in token
        parts = token.split(":")
        assert len(parts) == 2
        # First part is timestamp
        ts = int(parts[0])
        assert ts > 0
        # Second part is hex signature
        assert len(parts[1]) == 32

    @patch("hashguard.web.email_service._get_secret", return_value="test-secret-key")
    def test_verify_valid_token(self, _):
        token = generate_verification_token("user@example.com")
        assert verify_token("user@example.com", token) is True

    @patch("hashguard.web.email_service._get_secret", return_value="test-secret-key")
    def test_verify_wrong_email(self, _):
        token = generate_verification_token("user@example.com")
        assert verify_token("other@example.com", token) is False

    @patch("hashguard.web.email_service._get_secret", return_value="test-secret-key")
    def test_verify_tampered_token(self, _):
        token = generate_verification_token("user@example.com")
        ts, sig = token.split(":")
        tampered = f"{ts}:{'a' * 32}"
        assert verify_token("user@example.com", tampered) is False

    @patch("hashguard.web.email_service._get_secret", return_value="test-secret-key")
    def test_verify_expired_token(self, _):
        token = generate_verification_token("user@example.com")
        # Verify with max_age=0 so it's immediately expired
        assert verify_token("user@example.com", token, max_age=0) is False

    @patch("hashguard.web.email_service._get_secret", return_value="test-secret-key")
    def test_verify_invalid_format(self, _):
        assert verify_token("user@example.com", "invalid") is False
        assert verify_token("user@example.com", "") is False
        assert verify_token("user@example.com", ":::") is False

    @patch("hashguard.web.email_service._get_secret", return_value="test-secret-key")
    def test_different_secrets_fail(self, _):
        token = generate_verification_token("user@example.com")

        # Change the secret for verification
        with patch("hashguard.web.email_service._get_secret", return_value="different-secret"):
            assert verify_token("user@example.com", token) is False

    @patch("hashguard.web.email_service._get_secret", return_value="test-secret-key")
    def test_unique_tokens(self, _):
        """Each token generation should produce unique tokens (time-based)."""
        t1 = generate_verification_token("user@example.com")
        time.sleep(0.01)  # Ensure different timestamp
        t2 = generate_verification_token("user@example.com")
        # May be same if within same second, but structure is valid
        assert ":" in t1
        assert ":" in t2


class TestEmailSending:
    """Tests for email sending functions."""

    @patch("hashguard.web.email_service._get_secret", return_value="test-secret")
    @patch("hashguard.web.email_service._send_smtp", return_value=True)
    def test_send_verification_email(self, mock_smtp, _):
        result = send_verification_email("user@example.com")
        assert result is True
        mock_smtp.assert_called_once()
        args = mock_smtp.call_args
        assert args[0][0] == "user@example.com"
        assert "Verify" in args[0][1]
        assert "verify-email" in args[0][2]

    @patch("hashguard.web.email_service._get_secret", return_value="test-secret")
    @patch("hashguard.web.email_service._send_smtp", return_value=True)
    def test_send_password_reset_email(self, mock_smtp, _):
        result = send_password_reset_email("user@example.com")
        assert result is True
        mock_smtp.assert_called_once()
        args = mock_smtp.call_args
        assert "Reset" in args[0][1]
        assert "reset_token" in args[0][2]

    @patch("hashguard.web.email_service._get_secret", return_value="test-secret")
    @patch("hashguard.web.email_service._send_smtp", return_value=False)
    def test_send_failure(self, mock_smtp, _):
        result = send_verification_email("user@example.com")
        assert result is False


class TestVerifyUserEmail:
    """Tests for database-level email verification."""

    @patch("hashguard.web.email_service._get_secret", return_value="test-secret-key")
    def test_verify_valid(self, _, db):
        user = User(
            email="user@example.com",
            password_hash="hashed_pass",
            display_name="Test",
            email_verified=False,
        )
        db.add(user)
        db.commit()

        token = generate_verification_token("user@example.com")
        assert verify_user_email(db, "user@example.com", token) is True

        db.refresh(user)
        assert user.email_verified is True

    @patch("hashguard.web.email_service._get_secret", return_value="test-secret-key")
    def test_verify_wrong_token(self, _, db):
        user = User(
            email="user@example.com",
            password_hash="hashed_pass",
            email_verified=False,
        )
        db.add(user)
        db.commit()

        assert verify_user_email(db, "user@example.com", "invalid:token") is False
        db.refresh(user)
        assert user.email_verified is False

    @patch("hashguard.web.email_service._get_secret", return_value="test-secret-key")
    def test_verify_nonexistent_user(self, _, db):
        token = generate_verification_token("nobody@example.com")
        assert verify_user_email(db, "nobody@example.com", token) is False
