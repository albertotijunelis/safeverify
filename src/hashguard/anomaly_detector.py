"""Anomaly detection for HashGuard — statistical and ML-based.

Detects files that deviate significantly from known-good and known-bad
distributions, catching zero-day malware and novel variants that
supervised classifiers miss.

Approaches
----------
1. **Isolation Forest** on the full ~61 feature set (trained from DB).
2. **Mahalanobis distance** per-class: how far is a sample from each
   known class centroid in feature space.
3. **Feature-level z-score** flags: highlights *which* individual
   features are abnormal, providing explainability.

The module is designed to complement ``ml_classifier`` and
``ml_trainer`` — it reuses the same ``NUMERIC_FEATURES`` feature list
and ``StandardScaler`` conventions.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from hashguard.logger import get_logger

logger = get_logger(__name__)

try:
    import numpy as np
    from sklearn.ensemble import IsolationForest
    from sklearn.covariance import EllipticEnvelope
    from sklearn.preprocessing import StandardScaler

    HAS_ML = True
except ImportError:
    HAS_ML = False

MODEL_DIR = os.path.join(
    os.environ.get("APPDATA", os.path.expanduser("~")), "HashGuard", "models"
)
_ANOMALY_MODEL_NAME = "anomaly_detector.joblib"
_HMAC_KEY = b"HashGuard-AnomalyDetector-v1"


# ── Result dataclass ───────────────────────────────────────────────────────


@dataclass
class AnomalyResult:
    """Output of the anomaly detector."""

    is_anomaly: bool = False
    anomaly_score: float = 0.0          # raw IF score (negative = more anomalous)
    anomaly_percentile: float = 0.0     # 0-100, higher = more anomalous
    mahalanobis_nearest_class: str = "" # closest known class
    mahalanobis_distance: float = 0.0   # distance to nearest centroid
    abnormal_features: List[Dict[str, Any]] = field(default_factory=list)
    model_sample_count: int = 0         # how many training samples were used
    explanation: str = ""

    def to_dict(self) -> dict:
        return {
            "is_anomaly": self.is_anomaly,
            "anomaly_score": round(self.anomaly_score, 4),
            "anomaly_percentile": round(self.anomaly_percentile, 1),
            "mahalanobis_nearest_class": self.mahalanobis_nearest_class,
            "mahalanobis_distance": round(self.mahalanobis_distance, 2),
            "abnormal_features": self.abnormal_features[:10],
            "model_sample_count": self.model_sample_count,
            "explanation": self.explanation,
        }


# ── Training ───────────────────────────────────────────────────────────────


def train_anomaly_model(
    contamination: float = 0.05,
    min_samples: int = 200,
) -> Dict[str, Any]:
    """Train an anomaly detection model from the dataset_features table.

    Parameters
    ----------
    contamination : float
        Expected proportion of outliers (default 5%).
    min_samples : int
        Minimum dataset rows required to train.

    Returns
    -------
    Dict with training metadata (sample_count, feature_count, etc.)
    or ``{"error": "..."}`` on failure.
    """
    if not HAS_ML:
        return {"error": "scikit-learn not installed"}

    from hashguard.ml_trainer import NUMERIC_FEATURES

    X, verdicts, families = _load_features(NUMERIC_FEATURES)
    if X is None or len(X) < min_samples:
        return {
            "error": f"Not enough data ({0 if X is None else len(X)} rows, need {min_samples})"
        }

    # Fit scaler
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    # ── Isolation Forest ─────────────────────────────────────────────────
    iso = IsolationForest(
        n_estimators=200,
        contamination=contamination,
        max_features=0.8,
        random_state=42,
        n_jobs=-1,
    )
    iso.fit(X_scaled)

    # Compute score distribution for percentile mapping
    scores = iso.score_samples(X_scaled)
    score_min = float(np.min(scores))
    score_max = float(np.max(scores))

    # ── Per-class centroids for Mahalanobis ──────────────────────────────
    class_stats = _compute_class_stats(X_scaled, verdicts, families)

    # ── Feature-level stats for z-score explanation ──────────────────────
    feature_means = scaler.mean_.tolist()
    feature_stds = scaler.scale_.tolist()

    # ── Save model ───────────────────────────────────────────────────────
    model_data = {
        "iso": iso,
        "scaler": scaler,
        "feature_names": list(NUMERIC_FEATURES),
        "class_stats": class_stats,
        "score_min": score_min,
        "score_max": score_max,
        "feature_means": feature_means,
        "feature_stds": feature_stds,
        "sample_count": len(X),
        "contamination": contamination,
        "trained_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "version": 1,
    }
    _save_model(model_data)

    n_anomalies = int(np.sum(iso.predict(X_scaled) == -1))
    logger.info(
        f"Anomaly model trained: {len(X)} samples, "
        f"{len(NUMERIC_FEATURES)} features, "
        f"{n_anomalies} flagged anomalies ({n_anomalies / len(X) * 100:.1f}%)"
    )

    return {
        "success": True,
        "sample_count": len(X),
        "feature_count": len(NUMERIC_FEATURES),
        "anomalies_in_training": n_anomalies,
        "contamination": contamination,
        "trained_at": model_data["trained_at"],
    }


# ── Inference ──────────────────────────────────────────────────────────────


def detect_anomaly(
    features: Dict[str, Any],
    z_threshold: float = 3.0,
) -> AnomalyResult:
    """Score a single sample for anomaly detection.

    Parameters
    ----------
    features : dict
        Feature dict from ``feature_extractor.extract_features()``.
    z_threshold : float
        Z-score threshold for flagging individual features as
        abnormal (default: 3.0 = 99.7th percentile).

    Returns
    -------
    AnomalyResult with score, percentile, and explanation.
    """
    result = AnomalyResult()
    if not HAS_ML:
        return result

    model = _load_model()
    if model is None:
        return result

    feature_names = model["feature_names"]
    scaler = model["scaler"]
    iso = model["iso"]

    # Build feature vector
    X_row = [float(features.get(f, 0) or 0) for f in feature_names]
    X = np.array([X_row])
    X_scaled = scaler.transform(X)

    # ── Isolation Forest score ───────────────────────────────────────────
    raw_score = float(iso.score_samples(X_scaled)[0])
    prediction = int(iso.predict(X_scaled)[0])  # -1 = anomaly, 1 = normal

    result.is_anomaly = prediction == -1
    result.anomaly_score = raw_score
    result.model_sample_count = model.get("sample_count", 0)

    # Percentile: map raw score to 0-100 (higher = more anomalous)
    score_min = model.get("score_min", -0.5)
    score_max = model.get("score_max", 0.0)
    score_range = score_max - score_min
    if score_range > 0:
        result.anomaly_percentile = max(
            0.0, min(100.0, (1.0 - (raw_score - score_min) / score_range) * 100.0)
        )

    # ── Mahalanobis distance to nearest class ────────────────────────────
    class_stats = model.get("class_stats", {})
    if class_stats:
        best_class, best_dist = _nearest_class(X_scaled[0], class_stats)
        result.mahalanobis_nearest_class = best_class
        result.mahalanobis_distance = best_dist

    # ── Feature-level z-score explanation ────────────────────────────────
    feature_means = model.get("feature_means", [])
    feature_stds = model.get("feature_stds", [])
    if feature_means and feature_stds:
        abnormals = []
        for i, fname in enumerate(feature_names):
            if i < len(feature_means) and i < len(feature_stds):
                std = feature_stds[i]
                if std > 0:
                    z = abs(X_row[i] - feature_means[i]) / std
                    if z >= z_threshold:
                        abnormals.append({
                            "feature": fname,
                            "value": round(X_row[i], 4),
                            "z_score": round(z, 2),
                            "mean": round(feature_means[i], 4),
                            "direction": "high" if X_row[i] > feature_means[i] else "low",
                        })
        abnormals.sort(key=lambda x: x["z_score"], reverse=True)
        result.abnormal_features = abnormals

    # ── Human-readable explanation ───────────────────────────────────────
    result.explanation = _build_explanation(result)

    return result


# ── Internal helpers ───────────────────────────────────────────────────────


def _load_features(
    feature_names: List[str],
) -> Tuple[Optional["np.ndarray"], List[str], List[str]]:
    """Load numeric features from the dataset_features table."""
    try:
        from hashguard.database import get_db_path
        import sqlite3

        db_path = get_db_path()
        if not os.path.isfile(db_path):
            return None, [], []

        conn = sqlite3.connect(db_path)
        conn.row_factory = sqlite3.Row
        cols = ", ".join(feature_names + ["label_verdict", "label_family"])
        rows = conn.execute(f"SELECT {cols} FROM dataset_features").fetchall()
        conn.close()

        if not rows:
            return None, [], []

        X = []
        verdicts = []
        families = []
        for row in rows:
            vals = [float(row[f] or 0) for f in feature_names]
            if any(np.isnan(v) or np.isinf(v) for v in vals):
                continue
            X.append(vals)
            verdicts.append(row["label_verdict"] or "unknown")
            families.append(row["label_family"] or "")

        if not X:
            return None, [], []

        return np.array(X), verdicts, families

    except Exception as e:
        logger.warning(f"Failed to load features for anomaly training: {e}")
        return None, [], []


def _compute_class_stats(
    X_scaled: "np.ndarray",
    verdicts: List[str],
    families: List[str],
) -> Dict[str, Dict[str, Any]]:
    """Compute per-class centroid and covariance for Mahalanobis distance."""
    stats: Dict[str, Dict[str, Any]] = {}

    # Group by verdict (clean/malicious) and top families
    labels = []
    for v, f in zip(verdicts, families):
        if f:
            labels.append(f)
        else:
            labels.append(v)

    unique_labels = set(labels)
    for label in unique_labels:
        mask = np.array([l == label for l in labels])
        X_class = X_scaled[mask]
        if len(X_class) < 5:
            continue

        centroid = np.mean(X_class, axis=0)
        # Use diagonal covariance (faster, more stable for high-dim)
        variances = np.var(X_class, axis=0) + 1e-8
        stats[label] = {
            "centroid": centroid.tolist(),
            "inv_var": (1.0 / variances).tolist(),
            "count": int(len(X_class)),
        }

    return stats


def _nearest_class(
    x: "np.ndarray", class_stats: Dict[str, Dict[str, Any]]
) -> Tuple[str, float]:
    """Find the nearest class by Mahalanobis distance (diagonal approximation)."""
    best_class = ""
    best_dist = float("inf")

    for cls_name, stats in class_stats.items():
        centroid = np.array(stats["centroid"])
        inv_var = np.array(stats["inv_var"])
        diff = x - centroid
        dist = float(np.sqrt(np.sum(diff ** 2 * inv_var)))
        if dist < best_dist:
            best_dist = dist
            best_class = cls_name

    return best_class, best_dist


def _build_explanation(result: AnomalyResult) -> str:
    """Generate a human-readable explanation of the anomaly result."""
    if not result.is_anomaly:
        if result.mahalanobis_nearest_class:
            return (
                f"Normal — closest to '{result.mahalanobis_nearest_class}' "
                f"(distance {result.mahalanobis_distance:.1f})"
            )
        return "Normal — within expected distribution"

    parts = [f"ANOMALY detected (score percentile: {result.anomaly_percentile:.0f}%)"]

    if result.mahalanobis_nearest_class:
        parts.append(
            f"Nearest known class: '{result.mahalanobis_nearest_class}' "
            f"(distance {result.mahalanobis_distance:.1f})"
        )

    if result.abnormal_features:
        top = result.abnormal_features[:3]
        feat_str = ", ".join(
            f"{f['feature']} ({f['direction']}, z={f['z_score']})" for f in top
        )
        parts.append(f"Abnormal features: {feat_str}")

    return ". ".join(parts)


# ── Model persistence ─────────────────────────────────────────────────────


def _compute_file_hmac(path: str) -> str:
    h = hmac.new(_HMAC_KEY, digestmod=hashlib.sha256)
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


def _save_model(model_data: dict) -> None:
    try:
        import joblib
    except ImportError:
        logger.warning("joblib not installed, cannot save anomaly model")
        return

    os.makedirs(MODEL_DIR, exist_ok=True)
    path = os.path.join(MODEL_DIR, _ANOMALY_MODEL_NAME)
    joblib.dump(model_data, path)
    hmac_path = path + ".hmac"
    Path(hmac_path).write_text(_compute_file_hmac(path))
    logger.info(f"Anomaly model saved: {path}")


def _load_model() -> Optional[dict]:
    try:
        import joblib
    except ImportError:
        return None

    path = os.path.join(MODEL_DIR, _ANOMALY_MODEL_NAME)
    hmac_path = path + ".hmac"

    if not os.path.isfile(path):
        return None

    # HMAC integrity check
    if os.path.isfile(hmac_path):
        stored = Path(hmac_path).read_text().strip()
        computed = _compute_file_hmac(path)
        if not hmac.compare_digest(stored, computed):
            logger.warning("Anomaly model integrity check FAILED — not loading")
            return None

    try:
        data = joblib.load(path)
        if isinstance(data, dict) and "iso" in data and "scaler" in data:
            return data
    except Exception as e:
        logger.debug(f"Failed to load anomaly model: {e}")

    return None
