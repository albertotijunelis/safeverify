"""Risk scoring engine for HashGuard.

Computes a composite 0-100 risk score from multiple analysis signals.

Score ranges:
    0-15   CLEAN
    16-35  SUSPICIOUS
    36-100 MALICIOUS
"""

from dataclasses import dataclass, field
from typing import List, Optional


@dataclass
class RiskFactor:
    """A single risk signal contributing to the overall score."""

    name: str
    points: int
    detail: str = ""


@dataclass
class RiskScore:
    """Composite risk assessment."""

    score: int = 0
    verdict: str = "clean"
    factors: List[RiskFactor] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "score": self.score,
            "verdict": self.verdict,
            "factors": [
                {"name": f.name, "points": f.points, "detail": f.detail} for f in self.factors
            ],
        }


def _clamp(val: int, lo: int = 0, hi: int = 100) -> int:
    return max(lo, min(hi, val))


def compute_risk(
    *,
    signature_match: bool = False,
    signature_name: str = "",
    pe_info: Optional[dict] = None,
    yara_matches: Optional[dict] = None,
    threat_intel: Optional[dict] = None,
    vt_result: Optional[dict] = None,
    strings_info: Optional[dict] = None,
    capabilities: Optional[dict] = None,
    ml_result: Optional[dict] = None,
) -> RiskScore:
    """Compute a risk score from all available analysis data.

    Each signal adds points; the final score is clamped to 0-100.
    """
    factors: List[RiskFactor] = []

    # --- Known hash match -------------------------------------------------
    if signature_match:
        factors.append(
            RiskFactor(
                "Known malware hash",
                100,
                signature_name or "Matched signature database",
            )
        )

    # --- PE analysis signals ----------------------------------------------
    if pe_info and pe_info.get("is_pe"):
        entropy = pe_info.get("overall_entropy", 0)
        if entropy > 7.2:
            factors.append(RiskFactor("Very high entropy", 15, f"Entropy {entropy:.2f} / 8.0"))
        elif entropy > 6.8:
            factors.append(RiskFactor("High entropy", 8, f"Entropy {entropy:.2f} / 8.0"))

        if pe_info.get("packed"):
            factors.append(RiskFactor("Packed executable", 20, pe_info.get("packer_hint", "")))

        suspicious = pe_info.get("suspicious_imports", [])
        if len(suspicious) >= 8:
            factors.append(
                RiskFactor("Many suspicious imports", 20, f"{len(suspicious)} suspicious API calls")
            )
        elif len(suspicious) >= 5:
            factors.append(
                RiskFactor("Suspicious imports", 12, f"{len(suspicious)} suspicious API calls")
            )
        elif suspicious:
            factors.append(
                RiskFactor("Suspicious imports", 5, f"{len(suspicious)} suspicious API calls")
            )

        warnings = pe_info.get("warnings", [])
        for w in warnings:
            if "writable and executable" in w.lower():
                factors.append(RiskFactor("W+X section", 10, w))
                break

    # --- YARA rule matches ------------------------------------------------
    if yara_matches:
        matches = yara_matches.get("matches", [])
        for m in matches:
            meta = m.get("meta", {})
            sev = meta.get("severity", "medium")
            pts = {"critical": 40, "high": 30, "medium": 20, "low": 10}.get(sev, 20)
            factors.append(
                RiskFactor(
                    f"YARA: {m['rule']}",
                    pts,
                    meta.get("description", ""),
                )
            )

    # --- Threat intelligence hits -----------------------------------------
    if threat_intel:
        # Weight by source quality: curated feeds score higher than
        # community-driven ones (e.g., OTX community pulses).
        _ti_weights = {
            "MalwareBazaar": 40,
            "URLhaus": 40,
            "ThreatFox": 35,
            "AbuseIPDB": 30,
        }
        for hit in threat_intel.get("hits", []):
            if hit.get("found"):
                source = hit.get("source", "")
                pts = _ti_weights.get(source, 15)
                factors.append(
                    RiskFactor(
                        f"Threat intel: {source}",
                        pts,
                        hit.get("malware_family", "Flagged"),
                    )
                )

    # --- VirusTotal -------------------------------------------------------
    if vt_result:
        data = vt_result.get("data", {})
        attrs = data.get("attributes", {}) if data else {}
        stats = attrs.get("last_analysis_stats", {})
        positives = stats.get("malicious", 0)
        if positives >= 10:
            factors.append(RiskFactor("VirusTotal detections", 50, f"{positives} engines"))
        elif positives >= 3:
            factors.append(RiskFactor("VirusTotal detections", 30, f"{positives} engines"))
        elif positives >= 1:
            factors.append(RiskFactor("VirusTotal detections", 15, f"{positives} engine(s)"))

    # --- String extraction signals ----------------------------------------
    if strings_info:
        urls = strings_info.get("urls", [])
        ips = strings_info.get("ips", [])
        crypto_wallets = strings_info.get("crypto_wallets", [])
        powershell = strings_info.get("powershell_commands", [])

        if powershell:
            factors.append(
                RiskFactor("PowerShell commands", 15, f"{len(powershell)} command(s) found")
            )
        if crypto_wallets:
            factors.append(
                RiskFactor("Crypto wallet addresses", 10, f"{len(crypto_wallets)} address(es)")
            )
        if len(urls) > 5:
            factors.append(RiskFactor("Many embedded URLs", 8, f"{len(urls)} URLs extracted"))
        if ips:
            factors.append(RiskFactor("Embedded IP addresses", 5, f"{len(ips)} IP(s) found"))

    # --- Capability detection signals -------------------------------------
    _severity_pts = {"critical": 30, "high": 20, "medium": 10, "low": 5}
    if capabilities:
        caps_list = capabilities.get("capabilities", [])
        for cap in caps_list:
            sev = cap.get("severity", "medium")
            pts = _severity_pts.get(sev, 10)
            factors.append(
                RiskFactor(
                    f"Capability: {cap.get('name', 'unknown')}",
                    pts,
                    f"Confidence {cap.get('confidence', 0):.0%}",
                )
            )

    # --- ML classification signals ----------------------------------------
    if ml_result:
        predicted = ml_result.get("predicted_class", "unknown")
        confidence = ml_result.get("confidence", 0)
        if predicted not in ("benign", "unknown") and confidence >= 0.6:
            pts = 35 if confidence >= 0.85 else 25 if confidence >= 0.75 else 15
            factors.append(
                RiskFactor(
                    f"ML: {predicted}",
                    pts,
                    f"Confidence {confidence:.0%}",
                )
            )
        if ml_result.get("is_anomaly"):
            factors.append(RiskFactor("ML anomaly detected", 10, "Statistical outlier"))

    # --- Compute total ----------------------------------------------------
    raw = sum(f.points for f in factors)
    score = _clamp(raw)

    if score <= 15:
        verdict = "clean"
    elif score <= 35:
        verdict = "suspicious"
    else:
        verdict = "malicious"

    return RiskScore(score=score, verdict=verdict, factors=factors)
