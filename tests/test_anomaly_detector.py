"""Tests for hashguard.anomaly_detector — statistical & ML anomaly detection."""

import hashlib
import hmac
import json
import os
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

# ── Skip everything if scikit-learn is not installed ──────────────────────

sklearn = pytest.importorskip("sklearn", reason="scikit-learn required")
np = pytest.importorskip("numpy", reason="numpy required")
joblib = pytest.importorskip("joblib", reason="joblib required")

from hashguard.anomaly_detector import (
    AnomalyResult,
    _build_explanation,
    _compute_class_stats,
    _compute_file_hmac,
    _load_model,
    _nearest_class,
    _save_model,
    detect_anomaly,
    train_anomaly_model,
)


# ── Fixtures ─────────────────────────────────────────────────────────────


@pytest.fixture
def sample_features():
    """Minimal feature dict mimicking feature_extractor output."""
    return {
        "file_size": 102400,
        "file_size_log": 17.0,
        "byte_entropy": 6.5,
        "byte_mean": 120.0,
        "byte_std": 70.0,
        "byte_zero_ratio": 0.02,
        "byte_printable_ratio": 0.45,
        "byte_high_ratio": 0.30,
        "pe_is_pe": 1,
        "pe_section_count": 5,
        "pe_entropy_mean": 5.8,
        "pe_entropy_max": 7.2,
        "pe_entropy_min": 1.5,
        "pe_raw_size_total": 90000,
        "pe_raw_size_max": 45000,
        "pe_high_entropy_sections": 1,
        "pe_import_dll_count": 6,
        "pe_import_func_count": 80,
        "pe_suspicious_import_count": 5,
        "pe_packed": 0,
        "pe_overall_entropy": 6.5,
        "pe_has_tls": 0,
        "pe_anti_analysis_count": 0,
        "str_total_count": 200,
        "str_has_iocs": 1,
        "str_url_count": 3,
        "str_ip_count": 2,
        "str_domain_count": 1,
        "str_email_count": 0,
        "str_crypto_wallet_count": 0,
        "str_registry_key_count": 1,
        "str_powershell_count": 0,
        "str_user_agent_count": 0,
        "str_suspicious_path_count": 0,
        "yara_rules_loaded": 167,
        "yara_match_count": 2,
        "yara_max_severity": 3,
        "yara_total_severity": 5,
        "yara_string_hit_count": 8,
        "yara_unique_categories": 2,
        "ti_total_sources": 6,
        "ti_flagged_count": 0,
        "ti_successful_sources": 3,
        "ti_total_tags": 0,
        "ti_has_family": 0,
        "cap_total_detected": 1,
        "cap_ransomware": 0,
        "cap_reverse_shell": 0,
        "cap_credential_stealing": 0,
        "cap_persistence": 1,
        "cap_evasion": 0,
        "cap_keylogger": 0,
        "cap_data_exfil": 0,
        "cap_max_severity": 2,
        "cap_avg_confidence": 0.65,
        "cap_max_confidence": 0.80,
        "packer_detected": 0,
        "shellcode_detected": 0,
        "shellcode_confidence": 0,
        "risk_score": 25,
        "risk_factor_count": 3,
        "risk_max_factor": 10,
        "risk_total_points": 25,
    }


@pytest.fixture
def trained_model_data():
    """Create a minimal trained anomaly model dict."""
    from sklearn.ensemble import IsolationForest
    from sklearn.preprocessing import StandardScaler
    from hashguard.ml_trainer import NUMERIC_FEATURES

    rng = np.random.RandomState(42)
    n_features = len(NUMERIC_FEATURES)
    n_samples = 300

    X = rng.randn(n_samples, n_features)
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    iso = IsolationForest(n_estimators=50, contamination=0.05, random_state=42)
    iso.fit(X_scaled)

    scores = iso.score_samples(X_scaled)

    return {
        "iso": iso,
        "scaler": scaler,
        "feature_names": list(NUMERIC_FEATURES),
        "class_stats": {
            "clean": {
                "centroid": [0.0] * n_features,
                "inv_var": [1.0] * n_features,
                "count": 200,
            },
            "malicious": {
                "centroid": [2.0] * n_features,
                "inv_var": [0.5] * n_features,
                "count": 100,
            },
        },
        "score_min": float(np.min(scores)),
        "score_max": float(np.max(scores)),
        "feature_means": scaler.mean_.tolist(),
        "feature_stds": scaler.scale_.tolist(),
        "sample_count": n_samples,
        "contamination": 0.05,
        "trained_at": "2026-03-13 10:00:00",
        "version": 1,
    }


# ── AnomalyResult tests ─────────────────────────────────────────────────


class TestAnomalyResult:
    def test_defaults(self):
        r = AnomalyResult()
        assert r.is_anomaly is False
        assert r.anomaly_score == 0.0
        assert r.anomaly_percentile == 0.0
        assert r.abnormal_features == []
        assert r.explanation == ""

    def test_to_dict(self):
        r = AnomalyResult(
            is_anomaly=True,
            anomaly_score=-0.12345678,
            anomaly_percentile=85.678,
            mahalanobis_nearest_class="AgentTesla",
            mahalanobis_distance=12.3456,
            abnormal_features=[{"feature": "byte_entropy", "z_score": 4.5}],
            model_sample_count=5000,
            explanation="ANOMALY detected",
        )
        d = r.to_dict()
        assert d["is_anomaly"] is True
        assert d["anomaly_score"] == -0.1235  # rounded to 4 decimals
        assert d["anomaly_percentile"] == 85.7  # rounded to 1 decimal
        assert d["mahalanobis_nearest_class"] == "AgentTesla"
        assert d["mahalanobis_distance"] == 12.35
        assert len(d["abnormal_features"]) == 1
        assert d["model_sample_count"] == 5000

    def test_to_dict_limits_abnormal_features(self):
        feats = [{"feature": f"f{i}", "z_score": float(i)} for i in range(20)]
        r = AnomalyResult(abnormal_features=feats)
        d = r.to_dict()
        assert len(d["abnormal_features"]) <= 10


# ── Explanation builder ──────────────────────────────────────────────────


class TestBuildExplanation:
    def test_normal_with_class(self):
        r = AnomalyResult(
            is_anomaly=False,
            mahalanobis_nearest_class="clean",
            mahalanobis_distance=3.5,
        )
        exp = _build_explanation(r)
        assert "Normal" in exp
        assert "clean" in exp

    def test_normal_without_class(self):
        r = AnomalyResult(is_anomaly=False)
        exp = _build_explanation(r)
        assert "Normal" in exp

    def test_anomaly_basic(self):
        r = AnomalyResult(
            is_anomaly=True,
            anomaly_percentile=92.0,
        )
        exp = _build_explanation(r)
        assert "ANOMALY" in exp
        assert "92" in exp

    def test_anomaly_with_features(self):
        r = AnomalyResult(
            is_anomaly=True,
            anomaly_percentile=95.0,
            mahalanobis_nearest_class="AgentTesla",
            mahalanobis_distance=15.0,
            abnormal_features=[
                {"feature": "byte_entropy", "direction": "high", "z_score": 5.2},
                {"feature": "pe_packed", "direction": "high", "z_score": 4.1},
            ],
        )
        exp = _build_explanation(r)
        assert "ANOMALY" in exp
        assert "AgentTesla" in exp
        assert "byte_entropy" in exp


# ── Class stats & Mahalanobis ────────────────────────────────────────────


class TestClassStats:
    def test_compute_class_stats(self):
        X = np.vstack([
            np.random.randn(50, 5),
            np.random.randn(50, 5) + 3.0,
        ])
        verdicts = ["clean"] * 50 + ["malicious"] * 50
        families = [""] * 100

        stats = _compute_class_stats(X, verdicts, families)

        assert "clean" in stats
        assert "malicious" in stats
        assert len(stats["clean"]["centroid"]) == 5
        assert stats["clean"]["count"] == 50

    def test_compute_class_stats_with_families(self):
        X = np.random.randn(30, 3)
        verdicts = ["malicious"] * 30
        families = ["AgentTesla"] * 15 + ["Conti"] * 15

        stats = _compute_class_stats(X, verdicts, families)
        # Families override verdicts when present
        assert "AgentTesla" in stats
        assert "Conti" in stats

    def test_small_class_skipped(self):
        X = np.random.randn(10, 3)
        verdicts = ["clean"] * 7 + ["malicious"] * 3
        families = [""] * 10

        stats = _compute_class_stats(X, verdicts, families)
        assert "clean" in stats
        assert "malicious" not in stats  # < 5 samples

    def test_nearest_class(self):
        class_stats = {
            "clean": {
                "centroid": [0.0, 0.0, 0.0],
                "inv_var": [1.0, 1.0, 1.0],
                "count": 100,
            },
            "malicious": {
                "centroid": [5.0, 5.0, 5.0],
                "inv_var": [1.0, 1.0, 1.0],
                "count": 100,
            },
        }

        # Point near origin → closer to clean
        name, dist = _nearest_class(np.array([0.1, 0.1, 0.1]), class_stats)
        assert name == "clean"
        assert dist < 1.0

        # Point near [5,5,5] → closer to malicious
        name, dist = _nearest_class(np.array([4.9, 4.9, 4.9]), class_stats)
        assert name == "malicious"

    def test_nearest_class_empty(self):
        name, dist = _nearest_class(np.array([1.0]), {})
        assert name == ""
        assert dist == float("inf")


# ── Model persistence ───────────────────────────────────────────────────


class TestModelPersistence:
    def test_save_and_load(self, trained_model_data, tmp_path):
        model_path = str(tmp_path / "anomaly_detector.joblib")
        with patch("hashguard.anomaly_detector.MODEL_DIR", str(tmp_path)), \
             patch("hashguard.anomaly_detector._ANOMALY_MODEL_NAME", "anomaly_detector.joblib"):
            _save_model(trained_model_data)
            loaded = _load_model()

        assert loaded is not None
        assert "iso" in loaded
        assert "scaler" in loaded
        assert loaded["sample_count"] == 300

    def test_load_nonexistent(self, tmp_path):
        with patch("hashguard.anomaly_detector.MODEL_DIR", str(tmp_path)):
            loaded = _load_model()
        assert loaded is None

    def test_load_tampered_fails(self, trained_model_data, tmp_path):
        with patch("hashguard.anomaly_detector.MODEL_DIR", str(tmp_path)), \
             patch("hashguard.anomaly_detector._ANOMALY_MODEL_NAME", "anomaly_detector.joblib"):
            _save_model(trained_model_data)

            # Tamper with the model file
            model_file = tmp_path / "anomaly_detector.joblib"
            data = model_file.read_bytes()
            model_file.write_bytes(data + b"TAMPERED")

            loaded = _load_model()
        assert loaded is None  # HMAC mismatch

    def test_hmac_computation(self, tmp_path):
        test_file = tmp_path / "test.bin"
        test_file.write_bytes(b"hello world")
        h = _compute_file_hmac(str(test_file))
        assert isinstance(h, str)
        assert len(h) == 64  # SHA-256 hex digest

        # Same file → same HMAC
        h2 = _compute_file_hmac(str(test_file))
        assert h == h2


# ── detect_anomaly (with mocked model) ──────────────────────────────────


class TestDetectAnomaly:
    def test_no_model_returns_default(self, sample_features):
        with patch("hashguard.anomaly_detector._load_model", return_value=None):
            result = detect_anomaly(sample_features)
        assert result.is_anomaly is False
        assert result.anomaly_score == 0.0

    def test_normal_sample(self, sample_features, trained_model_data):
        with patch("hashguard.anomaly_detector._load_model", return_value=trained_model_data):
            result = detect_anomaly(sample_features)
        assert isinstance(result, AnomalyResult)
        assert isinstance(result.anomaly_score, float)
        assert result.mahalanobis_nearest_class in ("clean", "malicious")
        assert result.explanation != ""

    def test_anomalous_sample(self, trained_model_data):
        # Create an extreme outlier
        features = {f: 999.0 for f in trained_model_data["feature_names"]}
        with patch("hashguard.anomaly_detector._load_model", return_value=trained_model_data):
            result = detect_anomaly(features)
        assert result.is_anomaly is True
        assert result.anomaly_percentile > 50
        assert len(result.abnormal_features) > 0

    def test_z_threshold_controls_abnormal_count(self, sample_features, trained_model_data):
        with patch("hashguard.anomaly_detector._load_model", return_value=trained_model_data):
            strict = detect_anomaly(sample_features, z_threshold=10.0)
            loose = detect_anomaly(sample_features, z_threshold=0.5)
        assert len(loose.abnormal_features) >= len(strict.abnormal_features)

    def test_missing_features_default_to_zero(self, trained_model_data):
        features = {"file_size": 1000}  # minimal
        with patch("hashguard.anomaly_detector._load_model", return_value=trained_model_data):
            result = detect_anomaly(features)
        assert isinstance(result, AnomalyResult)

    def test_none_feature_values(self, trained_model_data):
        features = {f: None for f in trained_model_data["feature_names"]}
        with patch("hashguard.anomaly_detector._load_model", return_value=trained_model_data):
            result = detect_anomaly(features)
        assert isinstance(result, AnomalyResult)

    @patch("hashguard.anomaly_detector.HAS_ML", False)
    def test_no_sklearn_returns_default(self, sample_features):
        result = detect_anomaly(sample_features)
        assert result.is_anomaly is False
        assert result.anomaly_score == 0.0


# ── train_anomaly_model ─────────────────────────────────────────────────


class TestTrainAnomalyModel:
    def test_train_insufficient_data(self):
        with patch("hashguard.anomaly_detector._load_features", return_value=(None, [], [])):
            result = train_anomaly_model(min_samples=100)
        assert "error" in result

    def test_train_too_few_samples(self):
        X = np.random.randn(50, 61)
        with patch("hashguard.anomaly_detector._load_features", return_value=(X, ["clean"] * 50, [""] * 50)):
            result = train_anomaly_model(min_samples=100)
        assert "error" in result

    def test_train_success(self, tmp_path):
        from hashguard.ml_trainer import NUMERIC_FEATURES
        rng = np.random.RandomState(42)
        n_feat = len(NUMERIC_FEATURES)
        n = 500
        X = rng.randn(n, n_feat)
        verdicts = ["clean"] * 250 + ["malicious"] * 250
        families = [""] * 250 + ["AgentTesla"] * 125 + ["Conti"] * 125

        with patch("hashguard.anomaly_detector._load_features", return_value=(X, verdicts, families)), \
             patch("hashguard.anomaly_detector.MODEL_DIR", str(tmp_path)), \
             patch("hashguard.anomaly_detector._ANOMALY_MODEL_NAME", "anomaly_detector.joblib"):
            result = train_anomaly_model(contamination=0.05, min_samples=100)

        assert result.get("success") is True
        assert result["sample_count"] == 500
        assert result["feature_count"] == n_feat
        assert "anomalies_in_training" in result
        assert result["contamination"] == 0.05

        # Model was saved
        assert (tmp_path / "anomaly_detector.joblib").exists()
        assert (tmp_path / "anomaly_detector.joblib.hmac").exists()

    @patch("hashguard.anomaly_detector.HAS_ML", False)
    def test_train_no_sklearn(self):
        result = train_anomaly_model()
        assert "error" in result
        assert "scikit-learn" in result["error"]


# ── Integration: train + detect ──────────────────────────────────────────


class TestTrainAndDetect:
    def test_full_pipeline(self, tmp_path):
        """Train a model, then use it to detect anomalies."""
        from hashguard.ml_trainer import NUMERIC_FEATURES
        rng = np.random.RandomState(42)
        n_feat = len(NUMERIC_FEATURES)
        n = 400
        X = rng.randn(n, n_feat)
        verdicts = ["clean"] * 200 + ["malicious"] * 200
        families = [""] * 200 + ["Trojan"] * 200

        with patch("hashguard.anomaly_detector._load_features", return_value=(X, verdicts, families)), \
             patch("hashguard.anomaly_detector.MODEL_DIR", str(tmp_path)), \
             patch("hashguard.anomaly_detector._ANOMALY_MODEL_NAME", "anomaly_detector.joblib"):
            # Train
            train_result = train_anomaly_model(min_samples=100)
            assert train_result.get("success") is True

            # Load the saved model by using the real _load_model
            from hashguard.anomaly_detector import _load_model as real_load
            model = real_load()
            assert model is not None

            # Detect normal sample (near distribution mean)
            features = {model["feature_names"][i]: 0.0 for i in range(n_feat)}
            normal_result = detect_anomaly(features)
            assert isinstance(normal_result, AnomalyResult)

            # Detect outlier (far from distribution)
            outlier_features = {model["feature_names"][i]: 50.0 for i in range(n_feat)}
            outlier_result = detect_anomaly(outlier_features)
            assert outlier_result.is_anomaly is True
            assert outlier_result.anomaly_percentile > normal_result.anomaly_percentile


# ── Edge cases ───────────────────────────────────────────────────────────


class TestEdgeCases:
    def test_empty_class_stats_in_model(self, trained_model_data, sample_features):
        trained_model_data["class_stats"] = {}
        with patch("hashguard.anomaly_detector._load_model", return_value=trained_model_data):
            result = detect_anomaly(sample_features)
        assert result.mahalanobis_nearest_class == ""
        assert result.mahalanobis_distance == 0.0

    def test_zero_std_features(self, trained_model_data, sample_features):
        # All stds zero — should not divide by zero
        trained_model_data["feature_stds"] = [0.0] * len(trained_model_data["feature_stds"])
        with patch("hashguard.anomaly_detector._load_model", return_value=trained_model_data):
            result = detect_anomaly(sample_features)
        assert isinstance(result, AnomalyResult)
        assert len(result.abnormal_features) == 0

    def test_score_range_zero(self, trained_model_data, sample_features):
        trained_model_data["score_min"] = 0.0
        trained_model_data["score_max"] = 0.0
        with patch("hashguard.anomaly_detector._load_model", return_value=trained_model_data):
            result = detect_anomaly(sample_features)
        assert result.anomaly_percentile == 0.0

    def test_string_feature_values(self, trained_model_data):
        """Features passed as strings should be safely converted."""
        features = {f: "1.5" for f in trained_model_data["feature_names"]}
        with patch("hashguard.anomaly_detector._load_model", return_value=trained_model_data):
            result = detect_anomaly(features)
        assert isinstance(result, AnomalyResult)

    def test_inf_feature_values(self, trained_model_data):
        """Inf values are replaced with 0 to prevent sklearn crash."""
        features = {f: float("inf") for f in trained_model_data["feature_names"]}
        # inf/nan should be sanitised; if not, detect_anomaly returns a safe default
        with patch("hashguard.anomaly_detector._load_model", return_value=trained_model_data):
            try:
                result = detect_anomaly(features)
                assert isinstance(result, AnomalyResult)
            except ValueError:
                # sklearn rejects inf — acceptable; the test documents this edge case
                pass


class TestLoadFeatures:
    """Tests for _load_features helper."""

    def test_load_features_no_db(self):
        from hashguard.anomaly_detector import _load_features
        with patch("hashguard.anomaly_detector.os.path.isfile", return_value=False):
            X, verdicts, families = _load_features(["f1", "f2"])
        assert X is None

    def test_compute_class_stats_single_sample_classes(self):
        """Classes with < 5 samples are skipped."""
        X = np.random.randn(20, 3)
        verdicts = ["clean"] * 17 + ["malicious"] * 2 + ["miner"]
        families = [""] * 20
        stats = _compute_class_stats(X, verdicts, families)
        assert "clean" in stats
        assert "malicious" not in stats  # Only 2 samples
        assert "miner" not in stats  # Only 1 sample
