"""Tests for ml_trainer module."""

import json
import os
import shutil
import tempfile
import unittest
from unittest.mock import MagicMock, patch

# Ensure HAS_ML is True for testing
import numpy as np
from sklearn.ensemble import RandomForestClassifier

from hashguard import ml_trainer


class TestNumericFeatures(unittest.TestCase):
    """Validate NUMERIC_FEATURES list."""

    def test_all_features_are_strings(self):
        for f in ml_trainer.NUMERIC_FEATURES:
            self.assertIsInstance(f, str)

    def test_no_label_columns(self):
        for f in ml_trainer.NUMERIC_FEATURES:
            self.assertFalse(f.startswith("label_"), f"Label column in NUMERIC_FEATURES: {f}")

    def test_feature_count(self):
        # Should have 63 numeric features (67 total - 4 label columns)
        self.assertEqual(len(ml_trainer.NUMERIC_FEATURES), 63)


class TestTrainingMetrics(unittest.TestCase):
    """Test TrainingMetrics dataclass."""

    def test_default_values(self):
        m = ml_trainer.TrainingMetrics()
        self.assertEqual(m.accuracy, 0.0)
        self.assertEqual(m.f1, 0.0)
        self.assertEqual(m.confusion_matrix, [])
        self.assertEqual(m.feature_importance, [])

    def test_to_dict(self):
        m = ml_trainer.TrainingMetrics(accuracy=0.95, f1=0.93, roc_auc=0.98)
        d = m.to_dict()
        self.assertEqual(d["accuracy"], 0.95)
        self.assertEqual(d["f1"], 0.93)
        self.assertIn("confusion_matrix", d)
        self.assertIn("feature_importance", d)

    def test_feature_importance_truncated(self):
        m = ml_trainer.TrainingMetrics()
        m.feature_importance = [{"feature": f"f{i}", "importance": 0.01} for i in range(50)]
        d = m.to_dict()
        self.assertEqual(len(d["feature_importance"]), 20)


class TestTrainedModel(unittest.TestCase):
    """Test TrainedModel dataclass."""

    def test_to_dict(self):
        m = ml_trainer.TrainedModel(
            model_id="test_123",
            mode="binary",
            algorithm="random_forest",
            sample_count=100,
            feature_count=63,
            classes=["benign", "malicious"],
        )
        d = m.to_dict()
        self.assertEqual(d["model_id"], "test_123")
        self.assertEqual(d["mode"], "binary")
        self.assertEqual(d["sample_count"], 100)
        self.assertIn("metrics", d)


class TestTrainingJob(unittest.TestCase):
    """Test TrainingJob dataclass."""

    def test_default_status(self):
        j = ml_trainer.TrainingJob()
        self.assertEqual(j.status, "idle")

    def test_to_dict_without_model(self):
        j = ml_trainer.TrainingJob(status="running", progress=50.0, message="Training...")
        d = j.to_dict()
        self.assertEqual(d["status"], "running")
        self.assertEqual(d["progress"], 50.0)
        self.assertNotIn("model", d)

    def test_to_dict_with_error(self):
        j = ml_trainer.TrainingJob(status="error", error="Boom")
        d = j.to_dict()
        self.assertEqual(d["error"], "Boom")


class TestGetTrainingStatus(unittest.TestCase):
    """Test get_training_status function."""

    def test_returns_dict(self):
        status = ml_trainer.get_training_status()
        self.assertIsInstance(status, dict)
        self.assertIn("status", status)


class TestGenerateSyntheticBenign(unittest.TestCase):
    """Test synthetic benign sample generation."""

    def test_shape(self):
        rng = np.random.default_rng(42)
        X = ml_trainer._generate_synthetic_benign(50, len(ml_trainer.NUMERIC_FEATURES), rng)
        self.assertEqual(X.shape, (50, len(ml_trainer.NUMERIC_FEATURES)))

    def test_non_negative(self):
        rng = np.random.default_rng(42)
        X = ml_trainer._generate_synthetic_benign(100, len(ml_trainer.NUMERIC_FEATURES), rng)
        # Most features should be non-negative
        self.assertTrue((X >= 0).mean() > 0.95)

    def test_yara_ti_cap_zero(self):
        """Benign samples should have zero YARA/TI/capability features."""
        rng = np.random.default_rng(42)
        X = ml_trainer._generate_synthetic_benign(50, len(ml_trainer.NUMERIC_FEATURES), rng)
        for i, name in enumerate(ml_trainer.NUMERIC_FEATURES):
            if name.startswith(("yara_", "ti_", "cap_")):
                self.assertTrue(
                    np.all(X[:, i] == 0),
                    f"Feature {name} should be 0 for benign samples",
                )


class TestBuildClassifier(unittest.TestCase):
    """Test classifier construction."""

    def test_random_forest(self):
        clf = ml_trainer._build_classifier("random_forest", 2)
        self.assertIsInstance(clf, RandomForestClassifier)

    def test_gradient_boosting(self):
        from sklearn.ensemble import GradientBoostingClassifier
        clf = ml_trainer._build_classifier("gradient_boosting", 2)
        self.assertIsInstance(clf, GradientBoostingClassifier)

    def test_ensemble(self):
        from sklearn.ensemble import VotingClassifier
        clf = ml_trainer._build_classifier("ensemble", 2)
        self.assertIsInstance(clf, VotingClassifier)


class TestComputeMetrics(unittest.TestCase):
    """Test metrics computation."""

    def setUp(self):
        rng = np.random.default_rng(42)
        self.X_train = rng.standard_normal((100, 10))
        self.y_train = np.array([0] * 50 + [1] * 50)
        self.X_test = rng.standard_normal((20, 10))
        self.y_test = np.array([0] * 10 + [1] * 10)
        self.clf = RandomForestClassifier(n_estimators=10, random_state=42)
        self.clf.fit(self.X_train, self.y_train)

    def test_returns_training_metrics(self):
        m = ml_trainer._compute_metrics(
            self.clf, self.X_train, self.y_train,
            self.X_test, self.y_test,
            ["benign", "malicious"],
            [f"f{i}" for i in range(10)],
        )
        self.assertIsInstance(m, ml_trainer.TrainingMetrics)
        self.assertGreater(m.accuracy, 0)
        self.assertGreater(m.f1, 0)

    def test_feature_importance_populated(self):
        m = ml_trainer._compute_metrics(
            self.clf, self.X_train, self.y_train,
            self.X_test, self.y_test,
            ["benign", "malicious"],
            [f"f{i}" for i in range(10)],
        )
        self.assertGreater(len(m.feature_importance), 0)
        self.assertIn("feature", m.feature_importance[0])
        self.assertIn("importance", m.feature_importance[0])

    def test_confusion_matrix_shape(self):
        m = ml_trainer._compute_metrics(
            self.clf, self.X_train, self.y_train,
            self.X_test, self.y_test,
            ["benign", "malicious"],
            [f"f{i}" for i in range(10)],
        )
        self.assertEqual(len(m.confusion_matrix), 2)
        self.assertEqual(len(m.confusion_matrix[0]), 2)


class TestLoadDatasetFromDB(unittest.TestCase):
    """Test loading dataset from database."""

    @patch("hashguard.ml_trainer.HAS_ML", False)
    def test_returns_none_without_ml(self):
        X, y, fam, feat = ml_trainer._load_dataset_from_db()
        self.assertIsNone(X)

    @patch("hashguard.database.get_connection")
    @patch("hashguard.database.init_db")
    @patch("hashguard.database._ensure_dataset_table")
    def test_returns_none_for_empty_db(self, mock_ensure, mock_init, mock_conn):
        conn = MagicMock()
        conn.execute.return_value.fetchall.return_value = []
        mock_conn.return_value = conn
        X, y, fam, feat = ml_trainer._load_dataset_from_db()
        self.assertIsNone(X)

    @patch("hashguard.database.get_connection")
    @patch("hashguard.database.init_db")
    @patch("hashguard.database._ensure_dataset_table")
    def test_loads_rows(self, mock_ensure, mock_init, mock_conn):
        # Build a fake row dict
        row = {col: float(i) for i, col in enumerate(ml_trainer.NUMERIC_FEATURES)}
        row["label_is_malicious"] = 1
        row["label_family"] = "TestFamily"

        conn = MagicMock()
        conn.execute.return_value.fetchall.return_value = [row]
        mock_conn.return_value = conn

        X, y, fam, feat = ml_trainer._load_dataset_from_db()
        self.assertEqual(X.shape, (1, len(ml_trainer.NUMERIC_FEATURES)))
        self.assertEqual(y[0], 1)
        self.assertEqual(fam[0], "TestFamily")


class TestStartTraining(unittest.TestCase):
    """Test start_training validation."""

    def test_invalid_mode(self):
        result = ml_trainer.start_training(mode="invalid")
        self.assertIn("error", result)

    def test_invalid_algorithm(self):
        result = ml_trainer.start_training(algorithm="invalid")
        self.assertIn("error", result)

    def test_invalid_test_size(self):
        result = ml_trainer.start_training(test_size=0.99)
        self.assertIn("error", result)

    @patch.object(ml_trainer, "_current_job", ml_trainer.TrainingJob(status="running"))
    def test_already_running(self):
        result = ml_trainer.start_training()
        self.assertIn("error", result)
        self.assertIn("already running", result["error"])


class TestListModels(unittest.TestCase):
    """Test list_models function."""

    def test_returns_list(self):
        models = ml_trainer.list_models()
        self.assertIsInstance(models, list)

    def test_reads_json_files(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            with patch.object(ml_trainer, "MODEL_DIR", tmpdir):
                meta = {"model_id": "test_1", "mode": "binary", "metrics": {}}
                with open(os.path.join(tmpdir, "test_1.json"), "w") as f:
                    json.dump(meta, f)
                models = ml_trainer.list_models()
                self.assertEqual(len(models), 1)
                self.assertEqual(models[0]["model_id"], "test_1")


class TestGetModelMetrics(unittest.TestCase):
    """Test get_model_metrics function."""

    def test_returns_none_for_missing(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            with patch.object(ml_trainer, "MODEL_DIR", tmpdir):
                result = ml_trainer.get_model_metrics("nonexistent")
                self.assertIsNone(result)

    def test_returns_metrics(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            with patch.object(ml_trainer, "MODEL_DIR", tmpdir):
                meta = {"model_id": "test_1", "metrics": {"accuracy": 0.95}}
                with open(os.path.join(tmpdir, "test_1.json"), "w") as f:
                    json.dump(meta, f)
                result = ml_trainer.get_model_metrics("test_1")
                self.assertEqual(result["metrics"]["accuracy"], 0.95)


class TestDeleteModel(unittest.TestCase):
    """Test delete_model function."""

    def test_delete_existing(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            with patch.object(ml_trainer, "MODEL_DIR", tmpdir):
                # Create files
                for ext in (".joblib", ".json"):
                    with open(os.path.join(tmpdir, f"test_1{ext}"), "w") as f:
                        f.write("{}")
                result = ml_trainer.delete_model("test_1")
                self.assertTrue(result)
                self.assertFalse(os.path.exists(os.path.join(tmpdir, "test_1.joblib")))
                self.assertFalse(os.path.exists(os.path.join(tmpdir, "test_1.json")))

    def test_delete_nonexistent(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            with patch.object(ml_trainer, "MODEL_DIR", tmpdir):
                result = ml_trainer.delete_model("nonexistent")
                self.assertFalse(result)


class TestPredictSample(unittest.TestCase):
    """Test predict_sample function."""

    def test_no_models_returns_error(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            with patch.object(ml_trainer, "MODEL_DIR", tmpdir):
                result = ml_trainer.predict_sample({})
                self.assertIn("error", result)

    def test_missing_model_id(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            with patch.object(ml_trainer, "MODEL_DIR", tmpdir):
                result = ml_trainer.predict_sample({}, model_id="nonexistent")
                self.assertIn("error", result)

    @patch.object(ml_trainer, "HAS_ML", False)
    def test_no_ml_returns_error(self):
        result = ml_trainer.predict_sample({})
        self.assertIn("error", result)


class TestTrainModelIntegration(unittest.TestCase):
    """Integration test: train on synthetic data (no DB needed)."""

    @patch("hashguard.ml_trainer._load_dataset_from_db")
    def test_binary_training(self, mock_load):
        """Train binary model on synthetic malicious + benign."""
        rng = np.random.default_rng(42)
        n_features = len(ml_trainer.NUMERIC_FEATURES)
        # 30 malicious + 0 benign → trainer will generate synthetic benign
        X_mal = rng.standard_normal((30, n_features)) + 2
        y_mal = np.ones(30, dtype=int)
        families = ["TestFamily"] * 30

        mock_load.return_value = (X_mal, y_mal, families, ml_trainer.NUMERIC_FEATURES)

        with tempfile.TemporaryDirectory() as tmpdir:
            with patch.object(ml_trainer, "MODEL_DIR", tmpdir):
                model = ml_trainer._train_model(mode="binary", algorithm="random_forest")
                self.assertIsInstance(model, ml_trainer.TrainedModel)
                self.assertEqual(model.mode, "binary")
                self.assertGreater(model.metrics.accuracy, 0.5)
                self.assertTrue(os.path.exists(model.path))
                # Check JSON metadata was saved
                json_path = os.path.join(tmpdir, f"{model.model_id}.json")
                self.assertTrue(os.path.exists(json_path))

    @patch("hashguard.ml_trainer._load_dataset_from_db")
    def test_family_training(self, mock_load):
        """Train multi-family classifier."""
        rng = np.random.default_rng(42)
        n_features = len(ml_trainer.NUMERIC_FEATURES)
        X = rng.standard_normal((60, n_features))
        X[:20] += 2  # family A
        X[20:40] -= 2  # family B
        # family C stays at 0
        y_binary = np.ones(60, dtype=int)
        families = ["FamilyA"] * 20 + ["FamilyB"] * 20 + ["FamilyC"] * 20

        mock_load.return_value = (X, y_binary, families, ml_trainer.NUMERIC_FEATURES)

        with tempfile.TemporaryDirectory() as tmpdir:
            with patch.object(ml_trainer, "MODEL_DIR", tmpdir):
                model = ml_trainer._train_model(mode="family", algorithm="gradient_boosting")
                self.assertEqual(model.mode, "family")
                self.assertEqual(len(model.classes), 3)
                self.assertGreater(model.metrics.accuracy, 0.3)

    @patch("hashguard.ml_trainer._load_dataset_from_db")
    def test_ensemble_training(self, mock_load):
        """Train ensemble model."""
        rng = np.random.default_rng(42)
        n_features = len(ml_trainer.NUMERIC_FEATURES)
        X = rng.standard_normal((40, n_features))
        y = np.array([0] * 20 + [1] * 20)
        families = ["clean"] * 20 + ["malware"] * 20

        mock_load.return_value = (X, y, families, ml_trainer.NUMERIC_FEATURES)

        with tempfile.TemporaryDirectory() as tmpdir:
            with patch.object(ml_trainer, "MODEL_DIR", tmpdir):
                model = ml_trainer._train_model(mode="binary", algorithm="ensemble")
                self.assertEqual(model.algorithm, "ensemble")
                self.assertGreater(model.metrics.accuracy, 0)

    @patch("hashguard.ml_trainer._load_dataset_from_db")
    def test_predict_after_train(self, mock_load):
        """Train then predict."""
        rng = np.random.default_rng(42)
        n_features = len(ml_trainer.NUMERIC_FEATURES)
        X = np.vstack([
            rng.standard_normal((30, n_features)) + 3,
            rng.standard_normal((30, n_features)) - 3,
        ])
        y = np.array([1] * 30 + [0] * 30)
        families = ["malware"] * 30 + ["clean"] * 30

        mock_load.return_value = (X, y, families, ml_trainer.NUMERIC_FEATURES)

        with tempfile.TemporaryDirectory() as tmpdir:
            with patch.object(ml_trainer, "MODEL_DIR", tmpdir):
                model = ml_trainer._train_model(mode="binary", algorithm="random_forest")
                # Predict
                features = {f: 3.0 for f in ml_trainer.NUMERIC_FEATURES}
                result = ml_trainer.predict_sample(features)
                self.assertIn("predicted_class", result)
                self.assertIn("confidence", result)
                self.assertIn("probabilities", result)

    @patch("hashguard.ml_trainer._load_dataset_from_db")
    def test_empty_dataset_raises(self, mock_load):
        mock_load.return_value = (None, None, None, [])
        with self.assertRaises(ValueError):
            ml_trainer._train_model()

    @patch("hashguard.ml_trainer._load_dataset_from_db")
    def test_single_family_raises(self, mock_load):
        rng = np.random.default_rng(42)
        n_features = len(ml_trainer.NUMERIC_FEATURES)
        X = rng.standard_normal((20, n_features))
        y = np.ones(20, dtype=int)
        families = ["OnlyFamily"] * 20

        mock_load.return_value = (X, y, families, ml_trainer.NUMERIC_FEATURES)

        with tempfile.TemporaryDirectory() as tmpdir:
            with patch.object(ml_trainer, "MODEL_DIR", tmpdir):
                with self.assertRaises(ValueError):
                    ml_trainer._train_model(mode="family")


if __name__ == "__main__":
    unittest.main()
