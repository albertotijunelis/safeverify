"""HashGuard STIX 2.1 Exporter.

Converts analysis results into a STIX 2.1 Bundle suitable for import
into MISP, OpenCTI, TheHive, Splunk SOAR, or any STIX-compatible platform.

Mapping:
    File hashes           → File (SCO)
    Extracted URLs        → URL (SCO) + Relationship
    Extracted IPs         → IPv4-Address (SCO) + Relationship
    Extracted domains     → Domain-Name (SCO) + Relationship
    Extracted emails      → Email-Address (SCO) + Relationship
    YARA matches          → Indicator (SDO) + Relationship
    Family detection      → Malware (SDO) + Relationship
    Capabilities / ATT&CK → Attack-Pattern (SDO) + Relationship
    Risk score / ML       → Note (SDO)
    Threat intel hits     → External references on Malware SDO
"""

import re
from datetime import datetime, timezone
from typing import Any

from hashguard.logger import get_logger

logger = get_logger(__name__)

try:
    import stix2

    HAS_STIX2 = True
except ImportError:
    HAS_STIX2 = False

# Deterministic namespace for HashGuard-generated UUIDv5 identifiers.
_HASHGUARD_NAMESPACE = "hashguard-malware-research-platform"

# STIX malware_types mapping from HashGuard family/classification labels.
_MALWARE_TYPE_MAP = {
    "trojan": "trojan",
    "ransomware": "ransomware",
    "miner": "resource-exploitation",
    "stealer": "spyware",
    "benign": "benign",
    "rat": "remote-access-trojan",
    "worm": "worm",
    "backdoor": "backdoor",
    "downloader": "downloader",
    "dropper": "dropper",
    "keylogger": "keylogger",
    "rootkit": "rootkit",
    "adware": "adware",
    "botnet": "bot",
}


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")


def _safe_str(val: Any) -> str:
    if val is None:
        return ""
    return str(val).strip()


def _classify_malware_type(label: str) -> list[str]:
    """Map a HashGuard label to STIX malware_types vocabulary."""
    lower = label.lower()
    for key, stix_type in _MALWARE_TYPE_MAP.items():
        if key in lower:
            return [stix_type]
    return ["unknown"]


def _is_valid_ipv4(s: str) -> bool:
    parts = s.split(".")
    if len(parts) != 4:
        return False
    for p in parts:
        try:
            n = int(p)
            if n < 0 or n > 255:
                return False
        except ValueError:
            return False
    return True


def _sanitize_domain(d: str) -> str:
    """Strip protocol prefixes and paths from domain strings."""
    d = re.sub(r"^https?://", "", d)
    d = d.split("/")[0].split(":")[0]
    return d.lower().strip()


def export_stix_bundle(result: dict) -> dict:
    """Convert a HashGuard analysis result dict to a STIX 2.1 Bundle.

    Parameters
    ----------
    result : dict
        A full analysis result as returned by ``_run_full_analysis()`` or
        stored in ``samples.full_result``.

    Returns
    -------
    dict
        The STIX 2.1 Bundle serialized to a plain dict.

    Raises
    ------
    RuntimeError
        If the ``stix2`` library is not installed.
    """
    if not HAS_STIX2:
        raise RuntimeError(
            "stix2 library is required for STIX export. "
            "Install it with: pip install stix2"
        )

    objects: list = []
    now = _now_iso()

    # ── Identity: HashGuard as the analysis tool ─────────────────────────
    identity = stix2.Identity(
        name="HashGuard",
        identity_class="system",
        description="HashGuard Malware Research Platform — automated analysis",
        created=now,
        modified=now,
    )
    objects.append(identity)

    # ── File Observable (SCO) ────────────────────────────────────────────
    hashes_dict = result.get("hashes", {})
    file_hashes = {}
    if hashes_dict.get("sha256"):
        file_hashes["SHA-256"] = hashes_dict["sha256"]
    if hashes_dict.get("sha1"):
        file_hashes["SHA-1"] = hashes_dict["sha1"]
    if hashes_dict.get("md5"):
        file_hashes["MD5"] = hashes_dict["md5"]

    fuzzy = result.get("fuzzy_hashes", {})
    if isinstance(fuzzy, dict):
        fh = fuzzy.get("hashes", {})
        if fh.get("ssdeep"):
            file_hashes["SSDEEP"] = fh["ssdeep"]
        if fh.get("tlsh"):
            tlsh_val = fh["tlsh"]
            # stix2 expects 70 lowercase hex chars, no "T1" prefix
            if tlsh_val.upper().startswith("T1"):
                tlsh_val = tlsh_val[2:]
            file_hashes["TLSH"] = tlsh_val.lower()

    file_kwargs: dict[str, Any] = {}
    if file_hashes:
        file_kwargs["hashes"] = file_hashes
    if result.get("file_size"):
        file_kwargs["size"] = int(result["file_size"])

    fname = _safe_str(result.get("filename") or result.get("path", ""))
    if fname:
        file_kwargs["name"] = fname.split("\\")[-1].split("/")[-1]

    file_obj = stix2.File(**file_kwargs) if file_kwargs else None
    if file_obj:
        objects.append(file_obj)

    # ── Malware SDO (from family detection or classification) ────────────
    malware_obj = None

    family_info = result.get("family_detection", {})
    family_name = ""
    if isinstance(family_info, dict):
        family_name = _safe_str(family_info.get("family", ""))

    ml_info = result.get("ml_classification", {})
    ml_label = ""
    if isinstance(ml_info, dict):
        ml_label = _safe_str(ml_info.get("predicted_class", ""))

    is_malicious = result.get("malicious", False)

    if family_name:
        malware_types = _classify_malware_type(family_name)
        malware_obj = stix2.Malware(
            name=family_name,
            is_family=True,
            malware_types=malware_types,
            description=f"Detected by HashGuard with "
            f"{family_info.get('confidence', 0):.0f}% confidence "
            f"(source: {family_info.get('source', 'unknown')})",
            created_by_ref=identity.id,
            created=now,
            modified=now,
        )
        objects.append(malware_obj)
    elif is_malicious:
        label = ml_label or "unknown"
        malware_types = _classify_malware_type(label)
        malware_obj = stix2.Malware(
            name=label,
            is_family=False,
            malware_types=malware_types,
            description=f"Classified as malicious by HashGuard "
            f"(ML: {ml_label or 'N/A'})",
            created_by_ref=identity.id,
            created=now,
            modified=now,
        )
        objects.append(malware_obj)

    # File → Malware relationship
    if file_obj and malware_obj:
        objects.append(
            stix2.Relationship(
                source_ref=malware_obj.id,
                relationship_type="derived-from",
                target_ref=file_obj.id,
                created_by_ref=identity.id,
                created=now,
                modified=now,
            )
        )

    # ── Threat Intel → external references on Malware ────────────────────
    ti = result.get("threat_intel", {})
    if isinstance(ti, dict):
        hits = ti.get("hits", [])
        for hit in hits:
            if not isinstance(hit, dict) or not hit.get("found"):
                continue
            source = hit.get("source", "unknown")
            ti_family = _safe_str(hit.get("malware_family", ""))
            if ti_family and not malware_obj:
                malware_obj = stix2.Malware(
                    name=ti_family,
                    is_family=True,
                    malware_types=_classify_malware_type(ti_family),
                    description=f"Identified by {source}",
                    created_by_ref=identity.id,
                    created=now,
                    modified=now,
                )
                objects.append(malware_obj)
                if file_obj:
                    objects.append(
                        stix2.Relationship(
                            source_ref=malware_obj.id,
                            relationship_type="derived-from",
                            target_ref=file_obj.id,
                            created_by_ref=identity.id,
                            created=now,
                            modified=now,
                        )
                    )

    # ── IOC Observables ──────────────────────────────────────────────────
    strings_info = result.get("strings", {}) or result.get("strings_info", {})
    if isinstance(strings_info, dict):
        _add_ioc_observables(
            objects, strings_info, file_obj, malware_obj, identity, now
        )

    # ── YARA Indicators ──────────────────────────────────────────────────
    yara_info = result.get("yara_matches", {})
    if isinstance(yara_info, dict):
        matches = yara_info.get("matches", [])
        for m in matches:
            if not isinstance(m, dict):
                continue
            rule_name = m.get("rule", "unknown")
            meta = m.get("meta", {})
            description = meta.get("description", f"YARA rule: {rule_name}")
            indicator = stix2.Indicator(
                name=f"YARA: {rule_name}",
                pattern=f"[file:name = '{rule_name}']",
                pattern_type="stix",
                description=description,
                valid_from=now,
                created_by_ref=identity.id,
                created=now,
                modified=now,
            )
            objects.append(indicator)

            target = malware_obj or file_obj
            if target:
                objects.append(
                    stix2.Relationship(
                        source_ref=indicator.id,
                        relationship_type="indicates",
                        target_ref=target.id,
                        created_by_ref=identity.id,
                        created=now,
                        modified=now,
                    )
                )

    # ── Capabilities → ATT&CK Patterns ──────────────────────────────────
    caps = result.get("capabilities", {})
    if isinstance(caps, dict):
        cap_list = caps.get("capabilities", [])
        seen_attacks = set()
        for cap in cap_list:
            if not isinstance(cap, dict):
                continue
            attack_id = _safe_str(cap.get("mitre_attack", ""))
            if not attack_id or attack_id in seen_attacks:
                continue
            seen_attacks.add(attack_id)

            attack_pattern = stix2.AttackPattern(
                name=cap.get("name", attack_id),
                description=f"Category: {cap.get('category', 'unknown')} | "
                f"Severity: {cap.get('severity', 'unknown')}",
                external_references=[
                    stix2.ExternalReference(
                        source_name="mitre-attack",
                        external_id=attack_id,
                        url=f"https://attack.mitre.org/techniques/{attack_id.replace('.', '/')}/",
                    )
                ],
                created_by_ref=identity.id,
                created=now,
                modified=now,
            )
            objects.append(attack_pattern)

            if malware_obj:
                objects.append(
                    stix2.Relationship(
                        source_ref=malware_obj.id,
                        relationship_type="uses",
                        target_ref=attack_pattern.id,
                        created_by_ref=identity.id,
                        created=now,
                        modified=now,
                    )
                )

    # ── Analysis Note (risk score + ML) ──────────────────────────────────
    risk = result.get("risk_score", {})
    note_lines = []
    if isinstance(risk, dict) and risk.get("score") is not None:
        note_lines.append(
            f"Risk Score: {risk.get('score', 'N/A')}/100 "
            f"({risk.get('verdict', 'unknown')})"
        )
        for f in risk.get("factors", []):
            if isinstance(f, dict):
                note_lines.append(
                    f"  +{f.get('points', 0)} — {f.get('name', '')} "
                    f"({f.get('detail', '')})"
                )

    if isinstance(ml_info, dict) and ml_info.get("predicted_class"):
        note_lines.append(
            f"\nML Classification: {ml_info['predicted_class']} "
            f"(confidence: {ml_info.get('confidence', 0):.1f}%)"
        )

    trained = result.get("trained_model_prediction", {})
    if isinstance(trained, dict) and trained.get("predicted_class"):
        note_lines.append(
            f"Trained Model: {trained['predicted_class']} "
            f"(confidence: {trained.get('confidence', 0):.1f}%, "
            f"model: {trained.get('model_id', 'N/A')})"
        )

    if note_lines:
        note_refs = []
        if malware_obj:
            note_refs.append(malware_obj.id)
        elif file_obj:
            note_refs.append(file_obj.id)

        if note_refs:
            note = stix2.Note(
                content="\n".join(note_lines),
                object_refs=note_refs,
                created_by_ref=identity.id,
                created=now,
                modified=now,
            )
            objects.append(note)

    # ── Build Bundle ─────────────────────────────────────────────────────
    bundle = stix2.Bundle(objects=objects)
    return _bundle_to_dict(bundle)


def _add_ioc_observables(
    objects: list,
    strings_info: dict,
    file_obj,
    malware_obj,
    identity,
    now: str,
) -> None:
    """Extract IOC observables from strings_info and add to objects list."""
    target = malware_obj or file_obj

    # URLs
    for url in strings_info.get("urls", []):
        url_str = _safe_str(url)
        if not url_str:
            continue
        url_obj = stix2.URL(value=url_str)
        objects.append(url_obj)
        if target:
            objects.append(
                stix2.Relationship(
                    source_ref=target.id,
                    relationship_type="communicates-with",
                    target_ref=url_obj.id,
                    created_by_ref=identity.id,
                    created=now,
                    modified=now,
                )
            )

    # IPs
    for ip in strings_info.get("ips", []):
        ip_str = _safe_str(ip)
        if not ip_str or not _is_valid_ipv4(ip_str):
            continue
        ip_obj = stix2.IPv4Address(value=ip_str)
        objects.append(ip_obj)
        if target:
            objects.append(
                stix2.Relationship(
                    source_ref=target.id,
                    relationship_type="communicates-with",
                    target_ref=ip_obj.id,
                    created_by_ref=identity.id,
                    created=now,
                    modified=now,
                )
            )

    # Domains
    for domain in strings_info.get("domains", []):
        d = _sanitize_domain(_safe_str(domain))
        if not d or "." not in d:
            continue
        domain_obj = stix2.DomainName(value=d)
        objects.append(domain_obj)
        if target:
            objects.append(
                stix2.Relationship(
                    source_ref=target.id,
                    relationship_type="communicates-with",
                    target_ref=domain_obj.id,
                    created_by_ref=identity.id,
                    created=now,
                    modified=now,
                )
            )

    # Emails
    for email in strings_info.get("emails", []):
        email_str = _safe_str(email)
        if not email_str or "@" not in email_str:
            continue
        email_obj = stix2.EmailAddress(value=email_str)
        objects.append(email_obj)
        if target:
            objects.append(
                stix2.Relationship(
                    source_ref=target.id,
                    relationship_type="related-to",
                    target_ref=email_obj.id,
                    created_by_ref=identity.id,
                    created=now,
                    modified=now,
                )
            )


def _bundle_to_dict(bundle) -> dict:
    """Serialize a stix2 Bundle to a plain dict."""
    import json

    return json.loads(bundle.serialize())
