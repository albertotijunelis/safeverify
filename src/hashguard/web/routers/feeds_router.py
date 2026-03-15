"""Threat Feed API — Expose HashGuard intelligence as consumable feeds.

Endpoints
---------
GET  /api/feeds/recent          Recent malicious/suspicious samples (paginated)
GET  /api/feeds/iocs            Aggregated IOC feed (IPs, domains, URLs, hashes)
GET  /api/feeds/families        Malware family summary feed
GET  /api/feeds/hashes          Hash blocklist (SHA256 / MD5 / SHA1)
GET  /api/feeds/stix            STIX 2.1 bundle feed
GET  /api/feeds/taxii           TAXII 2.1 discovery stub
GET  /api/feeds/misp            MISP-format event feed

All feeds support ``since`` (ISO-8601 timestamp) for incremental pulls
and ``format`` (json / csv / txt) where applicable.
"""

from __future__ import annotations

import csv
import io
import json
from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import APIRouter, Depends, Query, Response

router = APIRouter(prefix="/api/feeds", tags=["feeds"])

# ---------------------------------------------------------------------------
# Auth & plan dependencies
# ---------------------------------------------------------------------------

def _auth_dep():
    """Auth dependency — validates user identity."""
    from hashguard.web.auth import get_current_user
    return get_current_user()


def _premium_feed_dep():
    """Plan dependency — STIX/MISP feeds require Pro+ plan."""
    from hashguard.web.billing import require_feature
    return require_feature("feeds_premium")


def _since_clause(since: Optional[str], params: list) -> str:
    """Build an ``AND analysis_date >= ?`` clause if *since* is given."""
    if not since:
        return ""
    params.append(since)
    return " AND analysis_date >= ?"


def _db():
    from hashguard.database import get_connection, init_db
    init_db()
    return get_connection()


# ---------------------------------------------------------------------------
# GET /api/feeds/recent
# ---------------------------------------------------------------------------

@router.get("/recent")
async def feed_recent(
    since: Optional[str] = Query(None, description="ISO-8601 timestamp for incremental pull"),
    verdict: Optional[str] = Query(None, description="Filter by verdict (malicious, suspicious, clean)"),
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    user: dict = Depends(_auth_dep()),
):
    """Recent samples — lightweight threat intel feed."""
    conn = _db()
    params: list = []
    clauses = "WHERE 1=1"
    if verdict:
        clauses += " AND verdict = ?"
        params.append(verdict)
    clauses += _since_clause(since, params)

    total = conn.execute(f"SELECT COUNT(*) FROM samples {clauses}", params).fetchone()[0]
    params.extend([limit, offset])
    rows = conn.execute(
        f"SELECT id, filename, sha256, sha1, md5, file_size, risk_score, verdict, "
        f"family, analysis_date, description FROM samples {clauses} "
        f"ORDER BY analysis_date DESC LIMIT ? OFFSET ?",
        params,
    ).fetchall()

    return {
        "total": total,
        "limit": limit,
        "offset": offset,
        "samples": [dict(r) for r in rows],
    }


# ---------------------------------------------------------------------------
# GET /api/feeds/iocs
# ---------------------------------------------------------------------------

@router.get("/iocs")
async def feed_iocs(
    since: Optional[str] = Query(None),
    ioc_type: Optional[str] = Query(None, description="Filter: url, ip, domain, email, hash, registry, crypto_wallet"),
    limit: int = Query(500, ge=1, le=5000),
    fmt: str = Query("json", description="Output format: json, csv, txt"),
    user: dict = Depends(_auth_dep()),
):
    """Aggregated IOC feed across all analysed samples."""
    conn = _db()
    params: list = []
    clauses = "WHERE 1=1"
    if ioc_type:
        clauses += " AND i.ioc_type = ?"
        params.append(ioc_type)
    if since:
        clauses += " AND s.analysis_date >= ?"
        params.append(since)
    params.append(limit)

    rows = conn.execute(
        f"SELECT i.ioc_type, i.value, i.context, s.sha256, s.verdict, s.analysis_date "
        f"FROM iocs i JOIN samples s ON i.sample_id = s.id {clauses} "
        f"ORDER BY s.analysis_date DESC LIMIT ?",
        params,
    ).fetchall()

    items = [dict(r) for r in rows]

    if fmt == "csv":
        buf = io.StringIO()
        writer = csv.DictWriter(buf, fieldnames=["ioc_type", "value", "context", "sha256", "verdict", "analysis_date"])
        writer.writeheader()
        writer.writerows(items)
        return Response(content=buf.getvalue(), media_type="text/csv",
                        headers={"Content-Disposition": "attachment; filename=iocs.csv"})
    if fmt == "txt":
        lines = [row["value"] for row in items]
        return Response(content="\n".join(lines), media_type="text/plain")

    return {"total": len(items), "iocs": items}


# ---------------------------------------------------------------------------
# GET /api/feeds/families
# ---------------------------------------------------------------------------

@router.get("/families")
async def feed_families(
    since: Optional[str] = Query(None),
    limit: int = Query(50, ge=1, le=500),
    user: dict = Depends(_auth_dep()),
):
    """Malware family summary: count, first/last seen, avg risk score."""
    conn = _db()
    params: list = []
    clauses = "WHERE family != '' AND family IS NOT NULL"
    clauses += _since_clause(since, params)
    params.append(limit)

    rows = conn.execute(
        f"SELECT family, COUNT(*) as sample_count, "
        f"MIN(analysis_date) as first_seen, MAX(analysis_date) as last_seen, "
        f"ROUND(AVG(risk_score), 1) as avg_risk "
        f"FROM samples {clauses} GROUP BY family ORDER BY sample_count DESC LIMIT ?",
        params,
    ).fetchall()

    return {"families": [dict(r) for r in rows]}


# ---------------------------------------------------------------------------
# GET /api/feeds/hashes
# ---------------------------------------------------------------------------

@router.get("/hashes")
async def feed_hashes(
    since: Optional[str] = Query(None),
    hash_type: str = Query("sha256", description="sha256, md5, or sha1"),
    verdict: str = Query("malicious", description="malicious or suspicious"),
    fmt: str = Query("txt", description="txt, json, csv"),
    limit: int = Query(10000, ge=1, le=100000),
    user: dict = Depends(_auth_dep()),
):
    """Hash blocklist — plaintext list ideal for SIEM/firewall import."""
    if hash_type not in ("sha256", "md5", "sha1"):
        hash_type = "sha256"

    conn = _db()
    params: list = [verdict]
    clauses = "WHERE verdict = ?"
    clauses += _since_clause(since, params)
    params.append(limit)

    rows = conn.execute(
        f"SELECT {hash_type} FROM samples {clauses} AND {hash_type} != '' "
        f"ORDER BY analysis_date DESC LIMIT ?",
        params,
    ).fetchall()

    hashes = [r[0] for r in rows]

    if fmt == "json":
        return {"hash_type": hash_type, "verdict": verdict, "total": len(hashes), "hashes": hashes}
    if fmt == "csv":
        return Response(content=f"{hash_type}\n" + "\n".join(hashes),
                        media_type="text/csv",
                        headers={"Content-Disposition": f"attachment; filename={hash_type}_blocklist.csv"})
    # txt
    return Response(content="\n".join(hashes), media_type="text/plain")


# ---------------------------------------------------------------------------
# GET /api/feeds/stix
# ---------------------------------------------------------------------------

@router.get("/stix")
async def feed_stix(
    since: Optional[str] = Query(None),
    limit: int = Query(100, ge=1, le=1000),
    user: dict = Depends(_premium_feed_dep()),
):
    """STIX 2.1 bundle — malware indicators for threat sharing."""
    conn = _db()
    params: list = []
    clauses = "WHERE verdict IN ('malicious', 'suspicious')"
    clauses += _since_clause(since, params)
    params.append(limit)

    rows = conn.execute(
        f"SELECT id, sha256, md5, sha1, filename, verdict, risk_score, family, analysis_date, description "
        f"FROM samples {clauses} ORDER BY analysis_date DESC LIMIT ?",
        params,
    ).fetchall()

    objects = [
        {
            "type": "identity",
            "spec_version": "2.1",
            "id": "identity--hashguard-platform",
            "name": "HashGuard",
            "identity_class": "system",
        }
    ]

    for r in rows:
        sample = dict(r)
        sha256 = sample["sha256"]
        ts = sample.get("analysis_date") or datetime.now(timezone.utc).isoformat()

        # Indicator (hash pattern)
        indicator_id = f"indicator--sha256-{sha256[:12]}"
        pattern = f"[file:hashes.'SHA-256' = '{sha256}']"
        objects.append({
            "type": "indicator",
            "spec_version": "2.1",
            "id": indicator_id,
            "created": ts,
            "modified": ts,
            "name": sample.get("filename", sha256[:16]),
            "description": sample.get("description", ""),
            "pattern": pattern,
            "pattern_type": "stix",
            "valid_from": ts,
            "indicator_types": ["malicious-activity"] if sample["verdict"] == "malicious" else ["anomalous-activity"],
            "labels": [sample["verdict"]],
        })

        # Malware SDO if family known
        if sample.get("family"):
            malware_id = f"malware--{sample['family'].lower()[:20]}-{sha256[:8]}"
            objects.append({
                "type": "malware",
                "spec_version": "2.1",
                "id": malware_id,
                "created": ts,
                "modified": ts,
                "name": sample["family"],
                "is_family": False,
                "malware_types": ["trojan"],
            })
            objects.append({
                "type": "relationship",
                "spec_version": "2.1",
                "id": f"relationship--{sha256[:16]}",
                "created": ts,
                "modified": ts,
                "relationship_type": "indicates",
                "source_ref": indicator_id,
                "target_ref": malware_id,
            })

        # IOCs for this sample
        iocs = conn.execute(
            "SELECT ioc_type, value FROM iocs WHERE sample_id = ?", (sample["id"],)
        ).fetchall()
        for ioc in iocs:
            ioc_dict = dict(ioc)
            obs = _ioc_to_stix_observable(ioc_dict, sha256, ts)
            if obs:
                objects.append(obs)

    bundle = {
        "type": "bundle",
        "id": f"bundle--hashguard-feed-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}",
        "objects": objects,
    }
    return Response(
        content=json.dumps(bundle, default=str),
        media_type="application/stix+json;version=2.1",
    )


def _ioc_to_stix_observable(ioc: dict, sha256: str, ts: str) -> Optional[dict]:
    """Convert a HashGuard IOC row into a STIX 2.1 observed-data entry."""
    ioc_type = ioc["ioc_type"]
    value = ioc["value"]
    obs_id = f"observed-data--{sha256[:8]}-{hash(value) % 100000}"

    if ioc_type == "ip":
        return {
            "type": "observed-data",
            "spec_version": "2.1",
            "id": obs_id,
            "created": ts,
            "modified": ts,
            "first_observed": ts,
            "last_observed": ts,
            "number_observed": 1,
            "object_refs": [],
            "x_hashguard_ioc_type": "ipv4-addr",
            "x_hashguard_value": value,
        }
    if ioc_type in ("url", "domain"):
        return {
            "type": "observed-data",
            "spec_version": "2.1",
            "id": obs_id,
            "created": ts,
            "modified": ts,
            "first_observed": ts,
            "last_observed": ts,
            "number_observed": 1,
            "object_refs": [],
            "x_hashguard_ioc_type": ioc_type,
            "x_hashguard_value": value,
        }
    return None


# ---------------------------------------------------------------------------
# GET /api/feeds/taxii  (TAXII 2.1 discovery stub)
# ---------------------------------------------------------------------------

@router.get("/taxii")
async def feed_taxii_discovery(user: dict = Depends(_auth_dep())):
    """TAXII 2.1 discovery document — points clients to the STIX feed."""
    return {
        "title": "HashGuard TAXII Server",
        "description": "Threat intelligence feed from HashGuard malware research platform",
        "default": "/api/feeds/stix",
        "api_roots": ["/api/feeds/"],
    }


# ---------------------------------------------------------------------------
# GET /api/feeds/misp
# ---------------------------------------------------------------------------

@router.get("/misp")
async def feed_misp(
    since: Optional[str] = Query(None),
    limit: int = Query(100, ge=1, le=1000),
    user: dict = Depends(_premium_feed_dep()),
):
    """MISP-format event feed — compatible with MISP feed import."""
    conn = _db()
    params: list = []
    clauses = "WHERE verdict IN ('malicious', 'suspicious')"
    clauses += _since_clause(since, params)
    params.append(limit)

    rows = conn.execute(
        f"SELECT id, sha256, md5, sha1, filename, verdict, risk_score, family, analysis_date, description "
        f"FROM samples {clauses} ORDER BY analysis_date DESC LIMIT ?",
        params,
    ).fetchall()

    events = []
    for r in rows:
        sample = dict(r)
        ts = sample.get("analysis_date") or datetime.now(timezone.utc).isoformat()
        attributes = [
            {"type": "sha256", "category": "Payload delivery", "value": sample["sha256"]},
        ]
        if sample.get("md5"):
            attributes.append({"type": "md5", "category": "Payload delivery", "value": sample["md5"]})
        if sample.get("sha1"):
            attributes.append({"type": "sha1", "category": "Payload delivery", "value": sample["sha1"]})
        if sample.get("family"):
            attributes.append({"type": "text", "category": "Attribution", "value": sample["family"]})

        # Attach IOCs
        iocs = conn.execute(
            "SELECT ioc_type, value FROM iocs WHERE sample_id = ?", (sample["id"],)
        ).fetchall()
        for ioc in iocs:
            ioc_d = dict(ioc)
            misp_type = {"ip": "ip-dst", "url": "url", "domain": "domain", "email": "email-src"}.get(ioc_d["ioc_type"])
            if misp_type:
                attributes.append({"type": misp_type, "category": "Network activity", "value": ioc_d["value"]})

        events.append({
            "Event": {
                "info": f"HashGuard: {sample.get('filename', sample['sha256'][:16])}",
                "date": ts[:10] if len(ts) >= 10 else ts,
                "threat_level_id": "1" if sample["verdict"] == "malicious" else "2",
                "analysis": "2",
                "distribution": "0",
                "Attribute": attributes,
                "Tag": [
                    {"name": f"hashguard:verdict={sample['verdict']}"},
                    {"name": f"hashguard:risk_score={sample['risk_score']}"},
                ],
            }
        })

    return {"response": events}
