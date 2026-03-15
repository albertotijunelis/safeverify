"""Team / Organization management router for HashGuard SaaS.

Endpoints:
- POST   /api/teams              Create a new team
- GET    /api/teams/current      Get current user's team info + members
- POST   /api/teams/invite       Invite a member by email
- POST   /api/teams/invite/accept  Accept an invite (token in body)
- PUT    /api/teams/members/{id}  Update a member's role
- DELETE /api/teams/members/{id}  Remove a member from the team
"""

import secrets
from datetime import datetime, timezone, timedelta

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from hashguard.logger import get_logger
from hashguard.models import Team, TeamMember, TeamInvite, User, get_db
from hashguard.web.auth import get_current_user, ROLES
from hashguard.web.billing import PLANS

logger = get_logger(__name__)

router = APIRouter(prefix="/api/teams", tags=["Teams"])


# ── Request / Response models ───────────────────────────────────────────────


class CreateTeamRequest(BaseModel):
    name: str = Field(..., min_length=2, max_length=255)


class InviteRequest(BaseModel):
    email: str = Field(..., min_length=5, max_length=255)
    role: str = Field(default="analyst")


class AcceptInviteRequest(BaseModel):
    token: str


class UpdateMemberRequest(BaseModel):
    role: str = Field(..., pattern="^(admin|analyst|viewer)$")


# ── Helpers ─────────────────────────────────────────────────────────────────


def _get_user_obj(db: Session, user_info: dict) -> User:
    """Resolve the current JWT/API-key user to a User ORM object."""
    sub = user_info.get("sub", "")
    u = db.query(User).filter(User.email == sub).first()
    if not u:
        raise HTTPException(status_code=401, detail="User not found in database")
    return u


def _get_team_for_user(db: Session, user: User) -> Optional["Team"]:
    """Return the team a user belongs to (via TeamMember or as owner)."""
    membership = (
        db.query(TeamMember)
        .filter(TeamMember.user_id == user.id)
        .first()
    )
    if membership:
        return db.query(Team).filter(Team.id == membership.team_id).first()

    # Also check if user is owner but not yet a member row (shouldn't happen, but safety)
    return db.query(Team).filter(Team.owner_id == user.id).first()


def _max_users_for_user(db: Session, user: User) -> int:
    """Get the max_users limit from the user's subscription plan."""
    from hashguard.models import Subscription

    sub = (
        db.query(Subscription)
        .filter(Subscription.user_id == user.id, Subscription.status == "active")
        .first()
    )
    plan_key = sub.plan if sub else "free"
    plan = PLANS.get(plan_key, PLANS["free"])
    return plan["max_users"]


def _team_to_dict(team: Team, db: Session) -> dict:
    """Serialize a Team with its members list."""
    members = (
        db.query(TeamMember, User)
        .join(User, TeamMember.user_id == User.id)
        .filter(TeamMember.team_id == team.id)
        .all()
    )
    pending = (
        db.query(TeamInvite)
        .filter(TeamInvite.team_id == team.id, TeamInvite.status == "pending")
        .all()
    )
    return {
        "id": team.id,
        "tenant_id": team.tenant_id,
        "name": team.name,
        "owner_id": team.owner_id,
        "max_members": team.max_members,
        "created_at": team.created_at.isoformat() if team.created_at else None,
        "members": [
            {
                "user_id": u.id,
                "email": u.email,
                "display_name": u.display_name,
                "role": tm.role,
                "joined_at": tm.joined_at.isoformat() if tm.joined_at else None,
            }
            for tm, u in members
        ],
        "pending_invites": [
            {
                "id": inv.id,
                "email": inv.email,
                "role": inv.role,
                "status": inv.status,
                "expires_at": inv.expires_at.isoformat() if inv.expires_at else None,
            }
            for inv in pending
        ],
    }


# ── Endpoints ───────────────────────────────────────────────────────────────


@router.post("")
async def create_team(
    req: CreateTeamRequest,
    user=Depends(get_current_user()),
    db: Session = Depends(get_db),
):
    """Create a new team. The requesting user becomes the owner."""
    u = _get_user_obj(db, user)

    # Check user doesn't already belong to a team
    existing = _get_team_for_user(db, u)
    if existing:
        raise HTTPException(status_code=400, detail="You already belong to a team")

    max_users = _max_users_for_user(db, u)
    if max_users == 1:
        raise HTTPException(
            status_code=403,
            detail="Your plan does not support teams. Upgrade to Team or Enterprise.",
        )

    tenant_id = f"team_{secrets.token_hex(8)}"
    team = Team(
        tenant_id=tenant_id,
        name=req.name,
        owner_id=u.id,
        max_members=max_users,
        created_at=datetime.now(timezone.utc),
        updated_at=datetime.now(timezone.utc),
    )
    db.add(team)
    db.flush()

    # Add owner as admin member
    member = TeamMember(
        team_id=team.id,
        user_id=u.id,
        role="admin",
        joined_at=datetime.now(timezone.utc),
    )
    db.add(member)

    # Update user's tenant_id
    u.tenant_id = tenant_id
    db.commit()
    db.refresh(team)

    logger.info("Team '%s' created by %s (tenant=%s)", req.name, u.email, tenant_id)
    return _team_to_dict(team, db)


@router.get("/current")
async def get_current_team(
    user=Depends(get_current_user()),
    db: Session = Depends(get_db),
):
    """Get the current user's team information and members."""
    u = _get_user_obj(db, user)
    team = _get_team_for_user(db, u)
    if not team:
        raise HTTPException(status_code=404, detail="You don't belong to any team")
    return _team_to_dict(team, db)


@router.post("/invite")
async def invite_member(
    req: InviteRequest,
    user=Depends(get_current_user()),
    db: Session = Depends(get_db),
):
    """Invite a user to join the team. Requires team admin role."""
    u = _get_user_obj(db, user)
    team = _get_team_for_user(db, u)
    if not team:
        raise HTTPException(status_code=404, detail="You don't belong to any team")

    # Only team admins (or team owner) can invite
    membership = (
        db.query(TeamMember)
        .filter(TeamMember.team_id == team.id, TeamMember.user_id == u.id)
        .first()
    )
    if not membership or membership.role != "admin":
        raise HTTPException(status_code=403, detail="Only team admins can invite members")

    if req.role not in ROLES:
        raise HTTPException(status_code=400, detail=f"Invalid role: {req.role}")

    # Check max_members limit
    current_count = (
        db.query(TeamMember).filter(TeamMember.team_id == team.id).count()
    )
    pending_count = (
        db.query(TeamInvite)
        .filter(TeamInvite.team_id == team.id, TeamInvite.status == "pending")
        .count()
    )
    if team.max_members > 0 and (current_count + pending_count) >= team.max_members:
        raise HTTPException(
            status_code=403,
            detail=f"Team member limit reached ({team.max_members}). Upgrade your plan.",
        )

    # Check if already a member
    email = req.email.strip().lower()
    existing_user = db.query(User).filter(User.email == email).first()
    if existing_user:
        already = (
            db.query(TeamMember)
            .filter(TeamMember.team_id == team.id, TeamMember.user_id == existing_user.id)
            .first()
        )
        if already:
            raise HTTPException(status_code=400, detail="User is already a team member")

    # Check for existing pending invite
    existing_invite = (
        db.query(TeamInvite)
        .filter(
            TeamInvite.team_id == team.id,
            TeamInvite.email == email,
            TeamInvite.status == "pending",
        )
        .first()
    )
    if existing_invite:
        raise HTTPException(status_code=400, detail="Invite already sent to this email")

    token = secrets.token_urlsafe(48)
    invite = TeamInvite(
        team_id=team.id,
        email=email,
        role=req.role,
        token=token,
        invited_by=u.id,
        status="pending",
        expires_at=datetime.now(timezone.utc) + timedelta(days=7),
        created_at=datetime.now(timezone.utc),
    )
    db.add(invite)
    db.commit()

    # Send invite email (non-blocking)
    try:
        from hashguard.web.email_service import send_team_invite_email

        send_team_invite_email(email, team.name, u.display_name or u.email, token)
    except Exception as e:
        logger.warning("Failed to send invite email to %s: %s", email, e)

    logger.info("Invite sent to %s for team '%s' by %s", email, team.name, u.email)
    return {
        "detail": f"Invitation sent to {email}",
        "invite_id": invite.id,
        "expires_at": invite.expires_at.isoformat(),
    }


@router.post("/invite/accept")
async def accept_invite(
    req: AcceptInviteRequest,
    user=Depends(get_current_user()),
    db: Session = Depends(get_db),
):
    """Accept a team invite using the token."""
    u = _get_user_obj(db, user)

    # Check user doesn't already belong to a team
    existing = _get_team_for_user(db, u)
    if existing:
        raise HTTPException(status_code=400, detail="You already belong to a team")

    invite = (
        db.query(TeamInvite)
        .filter(TeamInvite.token == req.token, TeamInvite.status == "pending")
        .first()
    )
    if not invite:
        raise HTTPException(status_code=404, detail="Invalid or expired invite token")

    if invite.expires_at < datetime.now(timezone.utc):
        invite.status = "expired"
        db.commit()
        raise HTTPException(status_code=400, detail="Invite has expired")

    # Verify email matches
    if invite.email != u.email:
        raise HTTPException(status_code=403, detail="This invite was sent to a different email")

    team = db.query(Team).filter(Team.id == invite.team_id).first()
    if not team:
        raise HTTPException(status_code=404, detail="Team no longer exists")

    # Add as member
    member = TeamMember(
        team_id=team.id,
        user_id=u.id,
        role=invite.role,
        joined_at=datetime.now(timezone.utc),
    )
    db.add(member)

    # Update user's tenant_id
    u.tenant_id = team.tenant_id

    # Mark invite as accepted
    invite.status = "accepted"
    db.commit()

    logger.info("User %s accepted invite to team '%s'", u.email, team.name)
    return {"detail": f"You have joined team '{team.name}'", "team": _team_to_dict(team, db)}


@router.put("/members/{member_user_id}")
async def update_member_role(
    member_user_id: int,
    req: UpdateMemberRequest,
    user=Depends(get_current_user()),
    db: Session = Depends(get_db),
):
    """Update a team member's role. Only team admin/owner can do this."""
    u = _get_user_obj(db, user)
    team = _get_team_for_user(db, u)
    if not team:
        raise HTTPException(status_code=404, detail="You don't belong to any team")

    # Must be admin
    my_membership = (
        db.query(TeamMember)
        .filter(TeamMember.team_id == team.id, TeamMember.user_id == u.id)
        .first()
    )
    if not my_membership or my_membership.role != "admin":
        raise HTTPException(status_code=403, detail="Only team admins can update roles")

    # Can't change own role if you're the owner
    if member_user_id == team.owner_id and u.id == team.owner_id:
        raise HTTPException(status_code=400, detail="Cannot change the owner's role")

    target = (
        db.query(TeamMember)
        .filter(TeamMember.team_id == team.id, TeamMember.user_id == member_user_id)
        .first()
    )
    if not target:
        raise HTTPException(status_code=404, detail="Member not found in this team")

    target.role = req.role
    db.commit()

    logger.info("Updated role for user %d to %s in team %s", member_user_id, req.role, team.name)
    return {"detail": f"Role updated to {req.role}"}


@router.delete("/members/{member_user_id}")
async def remove_member(
    member_user_id: int,
    user=Depends(get_current_user()),
    db: Session = Depends(get_db),
):
    """Remove a member from the team. Owner cannot be removed."""
    u = _get_user_obj(db, user)
    team = _get_team_for_user(db, u)
    if not team:
        raise HTTPException(status_code=404, detail="You don't belong to any team")

    # Must be admin or removing yourself
    my_membership = (
        db.query(TeamMember)
        .filter(TeamMember.team_id == team.id, TeamMember.user_id == u.id)
        .first()
    )
    is_self = member_user_id == u.id
    if not is_self and (not my_membership or my_membership.role != "admin"):
        raise HTTPException(status_code=403, detail="Only team admins can remove members")

    if member_user_id == team.owner_id:
        raise HTTPException(status_code=400, detail="Cannot remove the team owner")

    target = (
        db.query(TeamMember)
        .filter(TeamMember.team_id == team.id, TeamMember.user_id == member_user_id)
        .first()
    )
    if not target:
        raise HTTPException(status_code=404, detail="Member not found in this team")

    # Reset their tenant_id
    target_user = db.query(User).filter(User.id == member_user_id).first()
    if target_user:
        target_user.tenant_id = "default"

    db.delete(target)
    db.commit()

    verb = "left" if is_self else "removed from"
    logger.info("User %d %s team '%s'", member_user_id, verb, team.name)
    return {"detail": f"Member {verb} team"}
