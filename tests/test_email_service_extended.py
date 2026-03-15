"""Tests for email service — token generation, SMTP sending, verification."""

import time
import pytest
from unittest.mock import patch, MagicMock


# ── Token generation ────────────────────────────────────────────────────


class TestGenerateVerificationToken:
    def test_format(self):
        with patch("hashguard.web.email_service._get_secret", return_value="testsecret"):
            from hashguard.web.email_service import generate_verification_token
            token = generate_verification_token("user@test.com")
            parts = token.split(":")
            assert len(parts) == 2
            assert parts[0].isdigit()
            assert len(parts[1]) == 32

    def test_different_emails_different_tokens(self):
        with patch("hashguard.web.email_service._get_secret", return_value="testsecret"):
            from hashguard.web.email_service import generate_verification_token
            t1 = generate_verification_token("a@b.com")
            t2 = generate_verification_token("c@d.com")
            assert t1.split(":")[1] != t2.split(":")[1]


class TestVerifyToken:
    def test_valid_token(self):
        with patch("hashguard.web.email_service._get_secret", return_value="testsecret"):
            from hashguard.web.email_service import generate_verification_token, verify_token
            token = generate_verification_token("user@test.com")
            assert verify_token("user@test.com", token) is True

    def test_expired_token(self):
        with patch("hashguard.web.email_service._get_secret", return_value="testsecret"):
            from hashguard.web.email_service import verify_token
            old_ts = str(int(time.time()) - 90000)  # > 24h ago
            import hmac, hashlib
            payload = f"user@test.com:{old_ts}"
            sig = hmac.new("testsecret".encode(), payload.encode(), hashlib.sha256).hexdigest()[:32]
            token = f"{old_ts}:{sig}"
            assert verify_token("user@test.com", token) is False

    def test_wrong_email(self):
        with patch("hashguard.web.email_service._get_secret", return_value="testsecret"):
            from hashguard.web.email_service import generate_verification_token, verify_token
            token = generate_verification_token("a@b.com")
            assert verify_token("wrong@b.com", token) is False

    def test_invalid_format(self):
        with patch("hashguard.web.email_service._get_secret", return_value="testsecret"):
            from hashguard.web.email_service import verify_token
            assert verify_token("a@b.com", "notavalidtoken") is False

    def test_none_token(self):
        with patch("hashguard.web.email_service._get_secret", return_value="testsecret"):
            from hashguard.web.email_service import verify_token
            assert verify_token("a@b.com", None) is False

    def test_custom_max_age(self):
        with patch("hashguard.web.email_service._get_secret", return_value="testsecret"):
            from hashguard.web.email_service import generate_verification_token, verify_token
            token = generate_verification_token("user@test.com")
            # With very short max_age, it's still valid right away
            assert verify_token("user@test.com", token, max_age=10) is True


# ── SMTP sending ────────────────────────────────────────────────────────


class TestSendSmtp:
    def test_no_config_logs_to_console(self):
        with patch("hashguard.web.email_service._smtp_config",
                   return_value={"host": "", "port": 465, "user": "", "password": "",
                                "from_addr": "noreply@test.com"}):
            from hashguard.web.email_service import _send_smtp
            result = _send_smtp("to@test.com", "Subject", "<p>Body</p>")
            assert result is True  # Dev mode: don't block

    def test_ssl_port_465(self):
        cfg = {"host": "smtp.test.com", "port": 465, "user": "user",
               "password": "pass", "from_addr": "from@test.com"}
        with patch("hashguard.web.email_service._smtp_config", return_value=cfg):
            from hashguard.web.email_service import _send_smtp
            with patch("smtplib.SMTP_SSL") as mock_ssl:
                mock_server = MagicMock()
                mock_ssl.return_value.__enter__ = MagicMock(return_value=mock_server)
                mock_ssl.return_value.__exit__ = MagicMock(return_value=False)
                result = _send_smtp("to@test.com", "Test", "<p>Hi</p>")
                assert result is True

    def test_starttls_port_587(self):
        cfg = {"host": "smtp.test.com", "port": 587, "user": "user",
               "password": "pass", "from_addr": "from@test.com"}
        with patch("hashguard.web.email_service._smtp_config", return_value=cfg):
            from hashguard.web.email_service import _send_smtp
            with patch("smtplib.SMTP") as mock_smtp:
                mock_server = MagicMock()
                mock_smtp.return_value.__enter__ = MagicMock(return_value=mock_server)
                mock_smtp.return_value.__exit__ = MagicMock(return_value=False)
                result = _send_smtp("to@test.com", "Test", "<p>Hi</p>")
                assert result is True

    def test_smtp_exception(self):
        cfg = {"host": "smtp.test.com", "port": 465, "user": "user",
               "password": "pass", "from_addr": "from@test.com"}
        with patch("hashguard.web.email_service._smtp_config", return_value=cfg):
            from hashguard.web.email_service import _send_smtp
            with patch("smtplib.SMTP_SSL") as mock_ssl:
                mock_ssl.side_effect = Exception("SMTP error")
                result = _send_smtp("to@test.com", "Test", "<p>Hi</p>")
                assert result is False


# ── Email templates ─────────────────────────────────────────────────────


class TestSendVerificationEmail:
    def test_calls_smtp(self):
        with patch("hashguard.web.email_service._get_secret", return_value="secret"), \
             patch("hashguard.web.email_service._send_smtp", return_value=True) as mock_send:
            from hashguard.web.email_service import send_verification_email
            result = send_verification_email("user@test.com")
            assert result is True
            mock_send.assert_called_once()
            args = mock_send.call_args
            assert "Verify" in args[0][1]  # subject
            assert "user@test.com" in args[0][2]  # body contains email


class TestSendPasswordResetEmail:
    def test_calls_smtp(self):
        with patch("hashguard.web.email_service._get_secret", return_value="secret"), \
             patch("hashguard.web.email_service._send_smtp", return_value=True) as mock_send:
            from hashguard.web.email_service import send_password_reset_email
            result = send_password_reset_email("user@test.com")
            assert result is True
            args = mock_send.call_args
            assert "Reset" in args[0][1]


class TestSendTeamInviteEmail:
    def test_calls_smtp(self):
        with patch("hashguard.web.email_service._get_secret", return_value="secret"), \
             patch("hashguard.web.email_service._send_smtp", return_value=True) as mock_send:
            from hashguard.web.email_service import send_team_invite_email
            result = send_team_invite_email("new@test.com", "Team Alpha", "admin@test.com", "tok123")
            assert result is True
            args = mock_send.call_args
            assert "Team Alpha" in args[0][1]  # subject
            assert "admin@test.com" in args[0][2]  # body contains inviter


# ── Verify user email ──────────────────────────────────────────────────


class TestVerifyUserEmail:
    def test_invalid_token(self):
        with patch("hashguard.web.email_service._get_secret", return_value="secret"):
            from hashguard.web.email_service import verify_user_email
            mock_db = MagicMock()
            result = verify_user_email(mock_db, "user@test.com", "bad:token")
            assert result is False

    def test_user_not_found(self):
        with patch("hashguard.web.email_service._get_secret", return_value="secret"):
            from hashguard.web.email_service import generate_verification_token, verify_user_email
            token = generate_verification_token("user@test.com")
            mock_db = MagicMock()
            mock_db.query.return_value.filter.return_value.first.return_value = None
            result = verify_user_email(mock_db, "user@test.com", token)
            assert result is False

    def test_success(self):
        with patch("hashguard.web.email_service._get_secret", return_value="secret"):
            from hashguard.web.email_service import generate_verification_token, verify_user_email
            token = generate_verification_token("user@test.com")
            mock_db = MagicMock()
            mock_user = MagicMock()
            mock_user.email_verified = False
            mock_db.query.return_value.filter.return_value.first.return_value = mock_user
            result = verify_user_email(mock_db, "user@test.com", token)
            assert result is True
            assert mock_user.email_verified is True
            mock_db.commit.assert_called_once()
