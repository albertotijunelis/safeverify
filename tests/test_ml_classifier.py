"""Tests for ML classifier module."""

import math
from unittest.mock import patch, MagicMock, PropertyMock
from dataclasses import fields

import pytest

from hashguard.ml_classifier import (
    MLClassification,
    _entropy,
    CLASSES,
    FEATURE_NAMES,
    CRYPTO_APIS,
    NETWORK_APIS,
    INJECTION_APIS,
    SUSPICIOUS_APIS,
)


# ── Dataclass tests ──────────────────────────────────────────────────────────


class TestMLClassification:
    def test_defaults(self):
        c = MLClassification()
        assert c.predicted_class == "unknown"
        assert c.confidence == 0.0
        assert c.is_anomaly is False
        assert c.features_used == 0

    def test_to_dict(self):
        c = MLClassification(
            predicted_class="trojan",
            confidence=0.85,
            probabilities={"trojan": 0.85, "benign": 0.1},
            anomaly_score=-0.123,
            is_anomaly=False,
            features_used=22,
        )
        d = c.to_dict()
        assert d["predicted_class"] == "trojan"
        assert d["confidence"] == 85.0
        assert d["probabilities"]["trojan"] == 85.0
        assert d["anomaly_score"] == -0.123
        assert d["features_used"] == 22

    def test_to_dict_empty_probabilities(self):
        c = MLClassification()
        d = c.to_dict()
        assert d["probabilities"] == {}


# ── Entropy tests ────────────────────────────────────────────────────────────


class TestEntropy:
    def test_empty(self):
        assert _entropy(b"") == 0.0

    def test_single_byte_repeated(self):
        assert _entropy(b"\x00" * 100) == 0.0

    def test_two_equal_bytes(self):
        val = _entropy(b"\x00\xff" * 50)
        assert abs(val - 1.0) < 0.01

    def test_high_entropy(self):
        data = bytes(range(256)) * 10
        val = _entropy(data)
        assert val > 7.9

    def test_low_entropy(self):
        data = b"\x00" * 90 + b"\x01" * 10
        val = _entropy(data)
        assert val < 1.0


# ── Constants tests ──────────────────────────────────────────────────────────


class TestConstants:
    def test_classes_list(self):
        assert "benign" in CLASSES
        assert "trojan" in CLASSES
        assert "ransomware" in CLASSES
        assert len(CLASSES) == 5

    def test_feature_names_count(self):
        assert len(FEATURE_NAMES) == 22

    def test_suspicious_apis_is_union(self):
        assert CRYPTO_APIS.issubset(SUSPICIOUS_APIS)
        assert NETWORK_APIS.issubset(SUSPICIOUS_APIS)
        assert INJECTION_APIS.issubset(SUSPICIOUS_APIS)


# ── Extract features tests ───────────────────────────────────────────────────


class TestExtractFeatures:
    def test_non_pe_returns_none(self, tmp_path):
        p = tmp_path / "test.txt"
        p.write_bytes(b"Hello, this is not a PE file")
        from hashguard.ml_classifier import extract_features

        assert extract_features(str(p)) is None

    def test_missing_file(self):
        from hashguard.ml_classifier import extract_features

        assert extract_features("/no/such/file.exe") is None


# ── Model building tests ─────────────────────────────────────────────────────


class TestBuildModel:
    """Test synthetic model building (no real dataset needed)."""

    def test_build_correlated_samples_shape(self):
        try:
            import numpy as np
            from hashguard.ml_classifier import _build_correlated_samples
        except ImportError:
            pytest.skip("numpy/sklearn not available")

        rng = np.random.RandomState(42)
        samples = _build_correlated_samples("benign", 100, rng)
        assert samples.shape == (100, 22)

    def test_build_correlated_samples_clamped(self):
        try:
            import numpy as np
            from hashguard.ml_classifier import _build_correlated_samples
        except ImportError:
            pytest.skip("numpy/sklearn not available")

        rng = np.random.RandomState(42)
        for cls_name in CLASSES:
            samples = _build_correlated_samples(cls_name, 200, rng)
            # Entropy features should be in [0, 8]
            for idx in [1, 2, 3, 21]:
                assert samples[:, idx].min() >= 0.0
                assert samples[:, idx].max() <= 8.0
            # Binary features should be 0 or 1
            for idx in [8, 9, 10, 11, 12, 13, 14, 15, 16, 20]:
                uniques = set(samples[:, idx].tolist())
                assert uniques.issubset({0.0, 1.0})
            # Ratio features in [0, 1]
            assert samples[:, 7].min() >= 0.0
            assert samples[:, 7].max() <= 1.0

    def test_build_model_returns_ensemble(self):
        try:
            import numpy as np
            from hashguard.ml_classifier import _build_model
        except ImportError:
            pytest.skip("numpy/sklearn not available")

        with patch("hashguard.ml_classifier._load_real_dataset", return_value=None):
            clf, scaler, iso = _build_model()
            assert clf is not None
            assert scaler is not None
            assert iso is not None


# ── Classify tests ───────────────────────────────────────────────────────────


class TestClassify:
    def test_classify_non_pe(self, tmp_path):
        from hashguard.ml_classifier import classify

        p = tmp_path / "test.txt"
        p.write_bytes(b"Not a PE file")
        result = classify(str(p))
        assert result.predicted_class == "unknown"

    def test_classify_missing_file(self):
        from hashguard.ml_classifier import classify

        result = classify("/no/such/file.exe")
        assert result.predicted_class == "unknown"


# ── HMAC integrity tests ────────────────────────────────────────────────────


class TestModelIntegrity:
    def test_compute_file_hmac(self, tmp_path):
        from hashguard.ml_classifier import _compute_file_hmac

        p = tmp_path / "test.bin"
        p.write_bytes(b"test data")
        h1 = _compute_file_hmac(str(p))
        h2 = _compute_file_hmac(str(p))
        assert h1 == h2
        assert len(h1) == 64  # SHA256 hex

    def test_hmac_changes_with_content(self, tmp_path):
        from hashguard.ml_classifier import _compute_file_hmac

        p = tmp_path / "test.bin"
        p.write_bytes(b"data version 1")
        h1 = _compute_file_hmac(str(p))
        p.write_bytes(b"data version 2")
        h2 = _compute_file_hmac(str(p))
        assert h1 != h2


# ── Dataset loading tests ───────────────────────────────────────────────────


class TestLoadRealDataset:
    def test_no_dataset_returns_none(self, tmp_path, monkeypatch):
        try:
            from hashguard.ml_classifier import _load_real_dataset
        except ImportError:
            pytest.skip("numpy/sklearn not available")

        monkeypatch.setattr("hashguard.ml_classifier.DATASET_DIR", str(tmp_path))
        assert _load_real_dataset() is None

    def test_csv_dataset_loads(self, tmp_path, monkeypatch):
        try:
            import numpy as np
            from hashguard.ml_classifier import _load_real_dataset
        except ImportError:
            pytest.skip("numpy/sklearn not available")

        monkeypatch.setattr("hashguard.ml_classifier.DATASET_DIR", str(tmp_path))

        # Create a CSV with 60 rows (above the 50 minimum)
        header = ",".join(FEATURE_NAMES) + ",label\n"
        rows = []
        for i in range(60):
            vals = [str(float(i % 5 + j * 0.1)) for j in range(22)]
            rows.append(",".join(vals) + f",{CLASSES[i % 5]}\n")

        csv_path = tmp_path / "dataset.csv"
        csv_path.write_text(header + "".join(rows))

        result = _load_real_dataset()
        assert result is not None
        X, y = result
        assert X.shape == (60, 22)
        assert len(y) == 60

    def test_json_dataset_loads(self, tmp_path, monkeypatch):
        try:
            import json
            import numpy as np
            from hashguard.ml_classifier import _load_real_dataset
        except ImportError:
            pytest.skip("numpy/sklearn not available")

        monkeypatch.setattr("hashguard.ml_classifier.DATASET_DIR", str(tmp_path))

        data = []
        for i in range(60):
            row = {name: float(i % 5 + j * 0.1) for j, name in enumerate(FEATURE_NAMES)}
            row["label"] = CLASSES[i % 5]
            data.append(row)

        json_path = tmp_path / "dataset.json"
        json_path.write_text(json.dumps(data))

        result = _load_real_dataset()
        assert result is not None
        X, y = result
        assert X.shape == (60, 22)


# ── _get_or_build_model tests ───────────────────────────────────────────────


class TestGetOrBuildModel:
    def test_builds_when_no_cache(self, tmp_path, monkeypatch):
        try:
            from hashguard.ml_classifier import _get_or_build_model, MODEL_VERSION
        except ImportError:
            pytest.skip("ML deps not available")

        monkeypatch.setattr("hashguard.ml_classifier.MODEL_DIR", str(tmp_path))
        monkeypatch.setattr("hashguard.ml_classifier.MODEL_PATH", str(tmp_path / "model.pkl"))
        monkeypatch.setattr("hashguard.ml_classifier._MODEL_HMAC_PATH", str(tmp_path / "model.pkl.hmac"))
        monkeypatch.setattr("hashguard.ml_classifier.DATASET_DIR", str(tmp_path / "datasets"))

        clf, scaler, iso = _get_or_build_model()
        assert clf is not None
        assert scaler is not None
        assert iso is not None
        # Should have saved to disk
        assert (tmp_path / "model.pkl").exists()
        assert (tmp_path / "model.pkl.hmac").exists()

    def test_loads_from_cache(self, tmp_path, monkeypatch):
        try:
            import pickle
            from hashguard.ml_classifier import (
                _get_or_build_model,
                _build_model,
                _compute_file_hmac,
                MODEL_VERSION,
            )
        except ImportError:
            pytest.skip("ML deps not available")

        model_path = str(tmp_path / "model.pkl")
        hmac_path = model_path + ".hmac"
        monkeypatch.setattr("hashguard.ml_classifier.MODEL_DIR", str(tmp_path))
        monkeypatch.setattr("hashguard.ml_classifier.MODEL_PATH", model_path)
        monkeypatch.setattr("hashguard.ml_classifier._MODEL_HMAC_PATH", hmac_path)
        monkeypatch.setattr("hashguard.ml_classifier.DATASET_DIR", str(tmp_path / "datasets"))

        # Build and save first
        with patch("hashguard.ml_classifier._load_real_dataset", return_value=None):
            clf, scaler, iso = _build_model()
        with open(model_path, "wb") as f:
            pickle.dump({"clf": clf, "scaler": scaler, "iso": iso, "version": MODEL_VERSION}, f)
        from pathlib import Path
        Path(hmac_path).write_text(_compute_file_hmac(model_path))

        # Should load from cache without rebuilding
        clf2, scaler2, iso2 = _get_or_build_model()
        assert clf2 is not None

    def test_integrity_failure_rebuilds(self, tmp_path, monkeypatch):
        try:
            import pickle
            from hashguard.ml_classifier import _get_or_build_model, _build_model, MODEL_VERSION
        except ImportError:
            pytest.skip("ML deps not available")

        model_path = str(tmp_path / "model.pkl")
        hmac_path = model_path + ".hmac"
        monkeypatch.setattr("hashguard.ml_classifier.MODEL_DIR", str(tmp_path))
        monkeypatch.setattr("hashguard.ml_classifier.MODEL_PATH", model_path)
        monkeypatch.setattr("hashguard.ml_classifier._MODEL_HMAC_PATH", hmac_path)
        monkeypatch.setattr("hashguard.ml_classifier.DATASET_DIR", str(tmp_path / "datasets"))

        # Write model with wrong HMAC
        with patch("hashguard.ml_classifier._load_real_dataset", return_value=None):
            clf, scaler, iso = _build_model()
        with open(model_path, "wb") as f:
            pickle.dump({"clf": clf, "scaler": scaler, "iso": iso, "version": MODEL_VERSION}, f)
        from pathlib import Path
        Path(hmac_path).write_text("wrong_hmac_value")

        # Should rebuild due to HMAC mismatch
        clf2, scaler2, iso2 = _get_or_build_model()
        assert clf2 is not None

    def test_no_ml_returns_none(self, monkeypatch):
        from hashguard.ml_classifier import _get_or_build_model
        monkeypatch.setattr("hashguard.ml_classifier.HAS_ML", False)
        clf, scaler, iso = _get_or_build_model()
        assert clf is None
        assert scaler is None
        assert iso is None


# ── classify integration tests ───────────────────────────────────────────────


class TestClassifyIntegration:
    def test_classify_with_no_ml(self, monkeypatch):
        from hashguard.ml_classifier import classify
        monkeypatch.setattr("hashguard.ml_classifier.HAS_ML", False)
        result = classify("test.exe")
        assert result.predicted_class == "unknown"

    def test_classify_with_mocked_model(self, tmp_path, monkeypatch):
        try:
            import numpy as np
            from hashguard.ml_classifier import classify, CLASSES
        except ImportError:
            pytest.skip("ML deps not available")

        mock_features = [1.0] * 22
        monkeypatch.setattr("hashguard.ml_classifier.extract_features",
                            lambda *a, **kw: mock_features)

        # Mock the model
        mock_clf = MagicMock()
        mock_clf.predict_proba.return_value = np.array([[0.05, 0.7, 0.1, 0.1, 0.05]])
        mock_scaler = MagicMock()
        mock_scaler.transform.return_value = np.array([mock_features])
        mock_iso = MagicMock()
        mock_iso.predict.return_value = np.array([1])
        mock_iso.score_samples.return_value = np.array([0.1])

        monkeypatch.setattr("hashguard.ml_classifier._get_or_build_model",
                            lambda: (mock_clf, mock_scaler, mock_iso))

        result = classify("test.exe")
        assert result.predicted_class == "trojan"
        assert result.confidence > 0.5
        assert result.features_used == 22
        assert result.is_anomaly is False
