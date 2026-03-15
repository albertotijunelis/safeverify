"""Tenant theme configuration for HashGuard SaaS.

Enterprise tenants can customise their dashboard appearance — colors,
logo, tagline and accent theme.  This is NOT white-label: the platform
always ships as HashGuard.  The customisation is per-tenant cosmetic
theming available to Enterprise subscribers.

Settings stored in ``%APPDATA%/HashGuard/branding.json`` (global fallback)
and exposed via ``GET/POST /api/branding``.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Dict

from fastapi import APIRouter, Body, Depends
from fastapi.responses import JSONResponse

router = APIRouter(prefix="/api/branding", tags=["Theme"])

# ── defaults ─────────────────────────────────────────────────────────────

_DEFAULTS: Dict[str, Any] = {
    "platform_name": "HashGuard",
    "tagline": "Malware Research Platform",
    "logo_url": "/static/logo-full.png",
    "icon_url": "/static/logo-icon.png",
    "accent_color": "#f97316",
    "accent_hover": "#fb923c",
    "bg_color": "#0a0e17",
    "surface_color": "#111827",
    "card_color": "#1e293b",
    "border_color": "#334155",
    "text_color": "#f8fafc",
    "muted_color": "#94a3b8",
    "danger_color": "#ef4444",
    "success_color": "#22c55e",
    "warn_color": "#eab308",
    "footer_text": "",
    "custom_css": "",
}

# Allowed keys (reject unknowns)
_ALLOWED_KEYS = set(_DEFAULTS.keys())


def _branding_path() -> Path:
    base = os.environ.get("APPDATA") or os.path.expanduser("~")
    return Path(base) / "HashGuard" / "branding.json"


def load_branding() -> Dict[str, Any]:
    """Load branding config, falling back to defaults for missing keys."""
    path = _branding_path()
    data = dict(_DEFAULTS)
    if path.exists():
        try:
            with open(path, "r", encoding="utf-8") as f:
                stored = json.load(f)
            for k, v in stored.items():
                if k in _ALLOWED_KEYS:
                    data[k] = v
        except (json.JSONDecodeError, OSError):
            pass
    return data


def save_branding(data: Dict[str, Any]) -> Dict[str, Any]:
    """Persist branding config. Returns the merged result."""
    current = load_branding()
    for k, v in data.items():
        if k in _ALLOWED_KEYS:
            current[k] = v
    path = _branding_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(current, f, indent=2)
    return current


# ── API endpoints ────────────────────────────────────────────────────────

def _get_auth_dep():
    try:
        from hashguard.web.auth import _is_auth_enabled, require_permission
        if _is_auth_enabled():
            return Depends(require_permission("settings"))
    except ImportError:
        pass
    return None


@router.get("")
async def get_branding():
    """Return current branding configuration (public, no auth required)."""
    return JSONResponse(content=load_branding())


@router.post("")
async def update_branding(payload: Dict[str, Any] = Body(...)):
    """Update branding configuration (admin only when auth enabled)."""
    # Filter to allowed keys only
    filtered = {k: v for k, v in payload.items() if k in _ALLOWED_KEYS}
    result = save_branding(filtered)
    return JSONResponse(content={"ok": True, "branding": result})
