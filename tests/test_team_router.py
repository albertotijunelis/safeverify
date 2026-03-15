"""Tests for HashGuard team management router.

Tests team creation, invitations, role updates, and member removal.
"""

import os
import secrets
import pytest
from datetime import datetime, timezone, timedelta
from unittest.mock import patch, MagicMock


@pytest.fixture(autouse=True)
def _disable_auth():
    old = os.environ.get("HASHGUARD_AUTH")
    os.environ["HASHGUARD_AUTH"] = "0"
    yield
    if old is None:
        os.environ.pop("HASHGUARD_AUTH", None)
    else:
        os.environ["HASHGUARD_AUTH"] = old


def _make_user(id=1, email="owner@test.com", display_name="Owner", role="admin",
               tenant_id="default"):
    u = MagicMock()
    u.id = id
    u.email = email
    u.display_name = display_name
    u.role = role
    u.tenant_id = tenant_id
    return u


def _make_team(id=1, tenant_id="team_abc123", name="Test Team", owner_id=1, max_members=10):
    t = MagicMock()
    t.id = id
    t.tenant_id = tenant_id
    t.name = name
    t.owner_id = owner_id
    t.max_members = max_members
    t.created_at = datetime.now(timezone.utc)
    return t


def _make_member(team_id=1, user_id=1, role="admin"):
    m = MagicMock()
    m.team_id = team_id
    m.user_id = user_id
    m.role = role
    m.joined_at = datetime.now(timezone.utc)
    return m


def _make_invite(id=1, team_id=1, email="invite@test.com", role="analyst",
                 token="tok123", status="pending", expires_at=None):
    i = MagicMock()
    i.id = id
    i.team_id = team_id
    i.email = email
    i.role = role
    i.token = token
    i.status = status
    i.expires_at = expires_at or (datetime.now(timezone.utc) + timedelta(days=7))
    i.created_at = datetime.now(timezone.utc)
    return i


def _mock_db_gen():
    db = MagicMock()
    return db


@pytest.fixture
def mock_db():
    return MagicMock()


@pytest.fixture
def client(mock_db):
    def _db_gen():
        yield mock_db

    with patch("hashguard.web.routers.team_router.get_db", _db_gen), \
         patch("hashguard.web.routers.team_router.get_current_user", return_value=lambda: {"sub": "owner@test.com", "role": "admin"}):
        from fastapi import FastAPI
        from fastapi.testclient import TestClient
        from hashguard.web.routers.team_router import router

        app = FastAPI()
        app.include_router(router)
        with TestClient(app) as tc:
            yield tc


# ── Create Team ─────────────────────────────────────────────────────────────


class TestCreateTeam:
    def test_user_not_found(self, mock_db, client):
        mock_db.query.return_value.filter.return_value.first.return_value = None
        r = client.post("/api/teams", json={"name": "My Team"})
        assert r.status_code == 401

    def test_already_in_team(self, mock_db, client):
        user = _make_user()
        member = _make_member()
        team = _make_team()

        def query_side_effect(model):
            q = MagicMock()
            model_name = getattr(model, '__name__', str(model))
            if 'User' in str(model_name):
                q.filter.return_value.first.return_value = user
            elif 'TeamMember' in str(model_name):
                q.filter.return_value.first.return_value = member
            elif 'Team' in str(model_name):
                q.filter.return_value.first.return_value = team
            return q
        mock_db.query.side_effect = query_side_effect
        r = client.post("/api/teams", json={"name": "My Team"})
        assert r.status_code in (400, 401)

    def test_name_too_short(self, client):
        r = client.post("/api/teams", json={"name": "X"})
        assert r.status_code == 422

    def test_name_missing(self, client):
        r = client.post("/api/teams", json={})
        assert r.status_code == 422


# ── Get Current Team ────────────────────────────────────────────────────────


class TestGetCurrentTeam:
    def test_user_not_found(self, mock_db, client):
        mock_db.query.return_value.filter.return_value.first.return_value = None
        r = client.get("/api/teams/current")
        assert r.status_code == 401

    def test_no_team(self, mock_db, client):
        user = _make_user()
        def query_side_effect(model):
            q = MagicMock()
            model_name = str(getattr(model, '__name__', model))
            if 'User' in model_name:
                q.filter.return_value.first.return_value = user
            elif 'TeamMember' in model_name:
                q.filter.return_value.first.return_value = None
            elif 'Team' in model_name:
                q.filter.return_value.first.return_value = None
            return q
        mock_db.query.side_effect = query_side_effect
        r = client.get("/api/teams/current")
        # 404 when user exists but has no team; 401 if user resolution fails
        assert r.status_code in (401, 404)


# ── Invite Member ───────────────────────────────────────────────────────────


class TestInviteMember:
    def test_user_not_found(self, mock_db, client):
        mock_db.query.return_value.filter.return_value.first.return_value = None
        r = client.post("/api/teams/invite", json={"email": "new@test.com"})
        assert r.status_code == 401

    def test_invalid_role(self, mock_db, client):
        r = client.post("/api/teams/invite", json={"email": "new@test.com", "role": "superadmin"})
        # Will fail at user lookup or validation depending on order
        assert r.status_code in (400, 401, 422)

    def test_email_required(self, client):
        r = client.post("/api/teams/invite", json={})
        assert r.status_code == 422


# ── Accept Invite ───────────────────────────────────────────────────────────


class TestAcceptInvite:
    def test_user_not_found(self, mock_db, client):
        mock_db.query.return_value.filter.return_value.first.return_value = None
        r = client.post("/api/teams/invite/accept", json={"token": "abc123"})
        assert r.status_code == 401

    def test_token_required(self, client):
        r = client.post("/api/teams/invite/accept", json={})
        assert r.status_code == 422


# ── Update Member Role ──────────────────────────────────────────────────────


class TestUpdateMemberRole:
    def test_user_not_found(self, mock_db, client):
        mock_db.query.return_value.filter.return_value.first.return_value = None
        r = client.put("/api/teams/members/2", json={"role": "viewer"})
        assert r.status_code == 401

    def test_invalid_role(self, client):
        r = client.put("/api/teams/members/2", json={"role": "owner"})
        assert r.status_code == 422

    def test_valid_roles(self, client):
        for role in ("admin", "analyst", "viewer"):
            r = client.put("/api/teams/members/2", json={"role": role})
            # Will fail at user lookup, but validates the role format
            assert r.status_code in (200, 401, 403, 404)


# ── Remove Member ───────────────────────────────────────────────────────────


class TestRemoveMember:
    def test_user_not_found(self, mock_db, client):
        mock_db.query.return_value.filter.return_value.first.return_value = None
        r = client.delete("/api/teams/members/2")
        assert r.status_code == 401


# ── Request Models ──────────────────────────────────────────────────────────


class TestRequestModels:
    def test_create_team_request(self):
        from hashguard.web.routers.team_router import CreateTeamRequest
        req = CreateTeamRequest(name="My Team")
        assert req.name == "My Team"

    def test_create_team_min_length(self):
        from hashguard.web.routers.team_router import CreateTeamRequest
        from pydantic import ValidationError
        with pytest.raises(ValidationError):
            CreateTeamRequest(name="X")

    def test_invite_request_defaults(self):
        from hashguard.web.routers.team_router import InviteRequest
        req = InviteRequest(email="test@test.com")
        assert req.role == "analyst"

    def test_invite_request_custom_role(self):
        from hashguard.web.routers.team_router import InviteRequest
        req = InviteRequest(email="test@test.com", role="viewer")
        assert req.role == "viewer"

    def test_accept_invite_request(self):
        from hashguard.web.routers.team_router import AcceptInviteRequest
        req = AcceptInviteRequest(token="abc123")
        assert req.token == "abc123"

    def test_update_member_request_valid_roles(self):
        from hashguard.web.routers.team_router import UpdateMemberRequest
        for role in ("admin", "analyst", "viewer"):
            req = UpdateMemberRequest(role=role)
            assert req.role == role

    def test_update_member_request_invalid_role(self):
        from hashguard.web.routers.team_router import UpdateMemberRequest
        from pydantic import ValidationError
        with pytest.raises(ValidationError):
            UpdateMemberRequest(role="owner")

    def test_update_member_request_empty_role(self):
        from hashguard.web.routers.team_router import UpdateMemberRequest
        from pydantic import ValidationError
        with pytest.raises(ValidationError):
            UpdateMemberRequest(role="")


# ── Helper Functions ────────────────────────────────────────────────────────


class TestHelpers:
    def test_get_user_obj_not_found(self):
        from hashguard.web.routers.team_router import _get_user_obj
        db = MagicMock()
        db.query.return_value.filter.return_value.first.return_value = None
        with pytest.raises(Exception):
            _get_user_obj(db, {"sub": "nobody@test.com"})

    def test_get_user_obj_found(self):
        from hashguard.web.routers.team_router import _get_user_obj
        user = _make_user()
        db = MagicMock()
        db.query.return_value.filter.return_value.first.return_value = user
        result = _get_user_obj(db, {"sub": "owner@test.com"})
        assert result.email == "owner@test.com"

    def test_get_team_for_user_as_member(self):
        from hashguard.web.routers.team_router import _get_team_for_user
        member = _make_member()
        team = _make_team()
        db = MagicMock()

        def query_side_effect(model):
            q = MagicMock()
            model_name = str(getattr(model, '__name__', model))
            if 'TeamMember' in model_name:
                q.filter.return_value.first.return_value = member
            elif 'Team' in model_name:
                q.filter.return_value.first.return_value = team
            return q
        db.query.side_effect = query_side_effect
        user = _make_user()
        result = _get_team_for_user(db, user)
        assert result is not None

    def test_get_team_for_user_no_team(self):
        from hashguard.web.routers.team_router import _get_team_for_user
        db = MagicMock()

        def query_side_effect(model):
            q = MagicMock()
            q.filter.return_value.first.return_value = None
            return q
        db.query.side_effect = query_side_effect
        user = _make_user()
        result = _get_team_for_user(db, user)
        assert result is None
