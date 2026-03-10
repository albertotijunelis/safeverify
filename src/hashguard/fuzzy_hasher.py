"""Fuzzy hashing and malware similarity detection for HashGuard v2.

Implements:
- ssdeep (context-triggered piecewise hashing) via ppdeep
- TLSH (Trend Micro Locality Sensitive Hash)
- Similarity comparison and clustering support
"""

import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from hashguard.logger import get_logger

logger = get_logger(__name__)

try:
    import ppdeep

    HAS_SSDEEP = True
except ImportError:
    HAS_SSDEEP = False

try:
    import tlsh

    HAS_TLSH = True
except ImportError:
    HAS_TLSH = False


@dataclass
class FuzzyHash:
    ssdeep: str = ""
    tlsh: str = ""


@dataclass
class SimilarityMatch:
    filename: str
    sha256: str
    ssdeep_score: int = 0  # 0-100, higher = more similar
    tlsh_distance: int = 999  # 0-999, lower = more similar
    combined_score: float = 0.0  # 0-100 normalized


@dataclass
class FuzzyHashResult:
    hashes: FuzzyHash = field(default_factory=FuzzyHash)
    similar_samples: List[SimilarityMatch] = field(default_factory=list)
    best_match: Optional[SimilarityMatch] = None
    available_algorithms: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        d = {
            "hashes": {"ssdeep": self.hashes.ssdeep, "tlsh": self.hashes.tlsh},
            "available_algorithms": self.available_algorithms,
            "similar_samples": [
                {
                    "filename": m.filename,
                    "sha256": m.sha256,
                    "ssdeep_score": m.ssdeep_score,
                    "tlsh_distance": m.tlsh_distance,
                    "combined_score": round(m.combined_score, 1),
                }
                for m in self.similar_samples
            ],
        }
        if self.best_match:
            d["best_match"] = {
                "filename": self.best_match.filename,
                "sha256": self.best_match.sha256,
                "combined_score": round(self.best_match.combined_score, 1),
            }
        return d


# ── Local hash database for similarity lookups ───────────────────────────────

_DB_FILE = os.path.join(
    os.environ.get("APPDATA", os.path.expanduser("~")),
    "HashGuard",
    "fuzzy_db.json",
)


def _load_db() -> Dict[str, dict]:
    """Load the local fuzzy hash database."""
    try:
        if os.path.isfile(_DB_FILE):
            with open(_DB_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
    except Exception:
        pass
    return {}


def _save_db(db: Dict[str, dict]) -> None:
    """Save the local fuzzy hash database."""
    try:
        os.makedirs(os.path.dirname(_DB_FILE), exist_ok=True)
        with open(_DB_FILE, "w", encoding="utf-8") as f:
            json.dump(db, f, indent=2)
    except Exception as e:
        logger.debug(f"Could not save fuzzy DB: {e}")


def compute_fuzzy_hashes(file_path: str) -> FuzzyHash:
    """Compute ssdeep and TLSH hashes for a file."""
    fh = FuzzyHash()

    try:
        data = Path(file_path).read_bytes()
    except OSError:
        return fh

    if HAS_SSDEEP:
        try:
            fh.ssdeep = ppdeep.hash(data)
        except Exception as e:
            logger.debug(f"ssdeep hash failed: {e}")

    if HAS_TLSH:
        try:
            h = tlsh.hash(data)
            if h and h != "TNULL":
                fh.tlsh = h
        except Exception as e:
            logger.debug(f"TLSH hash failed: {e}")

    return fh


def compare_ssdeep(hash1: str, hash2: str) -> int:
    """Compare two ssdeep hashes. Returns 0-100 (higher = more similar)."""
    if not HAS_SSDEEP or not hash1 or not hash2:
        return 0
    try:
        return ppdeep.compare(hash1, hash2)
    except Exception:
        return 0


def compare_tlsh(hash1: str, hash2: str) -> int:
    """Compare two TLSH hashes. Returns distance 0-999 (lower = more similar)."""
    if not HAS_TLSH or not hash1 or not hash2:
        return 999
    try:
        return tlsh.diff(hash1, hash2)
    except Exception:
        return 999


def find_similar(
    file_path: str,
    sha256: str = "",
    top_n: int = 10,
    min_ssdeep: int = 20,
    max_tlsh: int = 200,
) -> FuzzyHashResult:
    """Compute fuzzy hashes and find similar samples in local database."""
    result = FuzzyHashResult()

    if HAS_SSDEEP:
        result.available_algorithms.append("ssdeep")
    if HAS_TLSH:
        result.available_algorithms.append("tlsh")

    # Compute hashes for target
    result.hashes = compute_fuzzy_hashes(file_path)

    # Store in database
    filename = os.path.basename(file_path)
    db = _load_db()
    if sha256:
        db[sha256] = {
            "filename": filename,
            "ssdeep": result.hashes.ssdeep,
            "tlsh": result.hashes.tlsh,
        }
        _save_db(db)

    # Find similar samples
    matches = []
    for db_sha256, entry in db.items():
        if db_sha256 == sha256:
            continue

        ssdeep_score = 0
        tlsh_distance = 999

        if result.hashes.ssdeep and entry.get("ssdeep"):
            ssdeep_score = compare_ssdeep(result.hashes.ssdeep, entry["ssdeep"])

        if result.hashes.tlsh and entry.get("tlsh"):
            tlsh_distance = compare_tlsh(result.hashes.tlsh, entry["tlsh"])

        # Calculate combined score
        combined = 0.0
        factors = 0
        if ssdeep_score > 0:
            combined += ssdeep_score
            factors += 1
        if tlsh_distance < 999:
            tlsh_normalized = max(0, 100 - (tlsh_distance / 3))
            combined += tlsh_normalized
            factors += 1

        if factors > 0:
            combined /= factors

        if ssdeep_score >= min_ssdeep or tlsh_distance <= max_tlsh:
            matches.append(
                SimilarityMatch(
                    filename=entry.get("filename", "unknown"),
                    sha256=db_sha256,
                    ssdeep_score=ssdeep_score,
                    tlsh_distance=tlsh_distance,
                    combined_score=combined,
                )
            )

    # Sort by combined score descending
    matches.sort(key=lambda m: m.combined_score, reverse=True)
    result.similar_samples = matches[:top_n]

    if result.similar_samples:
        result.best_match = result.similar_samples[0]

    return result
