"""Tests for HashGuard Web API module."""

import json
import os
import threading
from unittest.mock import MagicMock, patch

import pytest

from hashguard.web.api import (
    HAS_FASTAPI,
    _get_static_dir,
    _get_template_dir,
    _sanitize_for_json,
    app,
)

# Skip all tests if FastAPI is not installed
pytestmark = pytest.mark.skipif(not HAS_FASTAPI, reason="FastAPI not installed")


@pytest.fixture
def client():
    """Create a test client for the API."""
    from starlette.testclient import TestClient

    return TestClient(app)


# ── Helpers ──────────────────────────────────────────────────────────────────


class TestSanitizeForJSON:
    def test_plain_dict(self):
        assert _sanitize_for_json({"a": 1}) == {"a": 1}

    def test_nested(self):
        data = {"a": {"b": [1, 2, {"c": "x"}]}}
        assert _sanitize_for_json(data) == data

    def test_nan_becomes_none(self):
        assert _sanitize_for_json(float("nan")) is None

    def test_numpy_scalar(self):
        try:
            import numpy as np

            val = np.int64(42)
            assert _sanitize_for_json(val) == 42
        except ImportError:
            pytest.skip("numpy not available")


class TestTemplateDirs:
    def test_template_dir_exists(self):
        d = _get_template_dir()
        assert d is not None

    def test_static_dir(self):
        # May or may not exist depending on install
        _get_static_dir()


# ── API Endpoints ────────────────────────────────────────────────────────────


class TestDashboard:
    def test_get_root(self, client):
        resp = client.get("/")
        assert resp.status_code == 200
        assert "HashGuard" in resp.text


class TestStatsEndpoint:
    @patch(
        "hashguard.database.get_stats",
        return_value={
            "total_samples": 5,
            "malicious": 2,
            "clean": 3,
            "detection_rate": 40.0,
            "top_families": [],
            "recent_samples": [],
            "verdict_distribution": {},
        },
    )
    def test_get_stats(self, mock_stats, client):
        resp = client.get("/api/stats")
        assert resp.status_code == 200
        data = resp.json()
        assert data["total_samples"] == 5

    def test_stats_fallback_on_error(self, client):
        with patch("hashguard.database.get_stats", side_effect=Exception("db error")):
            resp = client.get("/api/stats")
            assert resp.status_code == 200
            data = resp.json()
            assert data["total_samples"] == 0


class TestSamplesEndpoint:
    @patch(
        "hashguard.database.get_all_samples",
        return_value=[{"id": 1, "filename": "test.exe", "sha256": "a" * 64}],
    )
    def test_list_samples(self, mock_samples, client):
        resp = client.get("/api/samples")
        assert resp.status_code == 200
        data = resp.json()
        assert len(data["samples"]) == 1


class TestSampleDetailEndpoint:
    @patch("hashguard.database.get_timeline", return_value=[])
    @patch("hashguard.database.get_sample_behaviors", return_value=[])
    @patch("hashguard.database.get_sample_iocs", return_value=[])
    @patch("hashguard.database.get_sample_by_id")
    def test_get_sample(self, mock_get, mock_iocs, mock_beh, mock_tl, client):
        mock_get.return_value = {
            "id": 1,
            "filename": "test.exe",
            "sha256": "a" * 64,
            "full_result": "{}",
            "capabilities": None,
            "advanced_pe": None,
            "ml_classification": None,
        }
        resp = client.get("/api/samples/1")
        assert resp.status_code == 200

    @patch("hashguard.database.get_sample_by_id", return_value=None)
    def test_sample_not_found(self, mock_get, client):
        resp = client.get("/api/samples/99999")
        assert resp.status_code == 404


class TestAnalyzeEndpoint:
    @patch("hashguard.web.api._run_full_analysis")
    def test_upload_file(self, mock_analysis, client):
        mock_analysis.return_value = {
            "hashes": {"sha256": "a" * 64},
            "malicious": False,
        }
        resp = client.post(
            "/api/analyze",
            files={"file": ("test.txt", b"hello world", "text/plain")},
            data={"use_vt": "false"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert "hashes" in data


class TestAnalyzeURLEndpoint:
    @patch("hashguard.scanner.analyze_url")
    def test_analyze_url(self, mock_analyze, client):
        mock_result = MagicMock()
        mock_result.to_dict.return_value = {
            "path": "http://example.com/file",
            "malicious": False,
        }
        mock_analyze.return_value = mock_result
        resp = client.post(
            "/api/analyze-url",
            data={"url": "http://example.com/file", "use_vt": "false"},
        )
        assert resp.status_code == 200

    def test_analyze_url_ssrf_block(self, client):
        with patch(
            "hashguard.scanner.analyze_url",
            side_effect=ValueError("Private/reserved IP blocked"),
        ):
            resp = client.post(
                "/api/analyze-url",
                data={"url": "http://192.168.1.1/file", "use_vt": "false"},
            )
            assert resp.status_code == 400


class TestSearchEndpoint:
    @patch("hashguard.database.search_iocs", return_value=[])
    @patch("hashguard.database.search_samples", return_value=[])
    def test_search(self, mock_samples, mock_iocs, client):
        resp = client.get("/api/search", params={"q": "test"})
        assert resp.status_code == 200
        data = resp.json()
        assert "samples" in data
        assert "iocs" in data


class TestClustersEndpoint:
    @patch("hashguard.malware_cluster.get_all_clusters", return_value=[])
    @patch("hashguard.database.get_all_samples", return_value=[])
    def test_get_clusters(self, mock_samples, mock_clusters, client):
        resp = client.get("/api/clusters")
        assert resp.status_code == 200
        data = resp.json()
        assert "clusters" in data


class TestRunFullAnalysisPrediction:
    """Tests for trained model prediction integration in _run_full_analysis."""

    def test_prediction_added_when_model_exists(self):
        from hashguard.web.api import _run_full_analysis

        mock_result = MagicMock()
        mock_result.to_dict.return_value = {
            "hashes": {"sha256": "a" * 64},
            "malicious": True,
        }

        fake_feats = {"entropy": 7.5, "file_size": 1024}
        fake_prediction = {
            "predicted_class": "malicious",
            "confidence": 95.0,
            "model_id": "test_model",
            "probabilities": {"malicious": 0.95, "benign": 0.05},
        }

        with (
            patch("hashguard.scanner.analyze", return_value=mock_result),
            patch("hashguard.config.get_default_config", return_value={}),
            patch("hashguard.feature_extractor.extract_features", return_value=fake_feats),
            patch("hashguard.database.store_sample", return_value=1),
            patch("hashguard.database.store_timeline_event"),
            patch("hashguard.database.store_dataset_features"),
            patch("hashguard.ml_trainer.predict_sample", return_value=fake_prediction),
            patch("hashguard.ioc_graph.build_graph", side_effect=ImportError),
            patch("hashguard.malware_timeline.build_timeline", side_effect=ImportError),
            patch("hashguard.unpacker.auto_unpack", side_effect=ImportError),
        ):
            result = _run_full_analysis("/fake/path.exe")
            assert "trained_model_prediction" in result
            assert result["trained_model_prediction"]["predicted_class"] == "malicious"
            assert result["trained_model_prediction"]["confidence"] == 95.0

    def test_prediction_skipped_when_no_model(self):
        from hashguard.web.api import _run_full_analysis

        mock_result = MagicMock()
        mock_result.to_dict.return_value = {
            "hashes": {"sha256": "b" * 64},
            "malicious": False,
        }

        fake_feats = {"entropy": 3.0, "file_size": 512}
        error_prediction = {"error": "No trained models found"}

        with (
            patch("hashguard.scanner.analyze", return_value=mock_result),
            patch("hashguard.config.get_default_config", return_value={}),
            patch("hashguard.feature_extractor.extract_features", return_value=fake_feats),
            patch("hashguard.database.store_sample", return_value=2),
            patch("hashguard.database.store_timeline_event"),
            patch("hashguard.database.store_dataset_features"),
            patch("hashguard.ml_trainer.predict_sample", return_value=error_prediction),
            patch("hashguard.ioc_graph.build_graph", side_effect=ImportError),
            patch("hashguard.malware_timeline.build_timeline", side_effect=ImportError),
            patch("hashguard.unpacker.auto_unpack", side_effect=ImportError),
        ):
            result = _run_full_analysis("/fake/path.exe")
            assert "trained_model_prediction" not in result

    def test_prediction_skipped_when_no_features(self):
        from hashguard.web.api import _run_full_analysis

        mock_result = MagicMock()
        mock_result.to_dict.return_value = {
            "hashes": {"sha256": "c" * 64},
            "malicious": False,
        }

        with (
            patch("hashguard.scanner.analyze", return_value=mock_result),
            patch("hashguard.config.get_default_config", return_value={}),
            patch("hashguard.feature_extractor.extract_features", side_effect=Exception("fail")),
            patch("hashguard.database.store_sample", return_value=3),
            patch("hashguard.database.store_timeline_event"),
            patch("hashguard.ioc_graph.build_graph", side_effect=ImportError),
            patch("hashguard.malware_timeline.build_timeline", side_effect=ImportError),
            patch("hashguard.unpacker.auto_unpack", side_effect=ImportError),
        ):
            result = _run_full_analysis("/fake/path.exe")
            assert "trained_model_prediction" not in result

    def test_prediction_exception_handled_gracefully(self):
        from hashguard.web.api import _run_full_analysis

        mock_result = MagicMock()
        mock_result.to_dict.return_value = {
            "hashes": {"sha256": "d" * 64},
            "malicious": True,
        }

        fake_feats = {"entropy": 6.0}

        with (
            patch("hashguard.scanner.analyze", return_value=mock_result),
            patch("hashguard.config.get_default_config", return_value={}),
            patch("hashguard.feature_extractor.extract_features", return_value=fake_feats),
            patch("hashguard.database.store_sample", return_value=4),
            patch("hashguard.database.store_timeline_event"),
            patch("hashguard.database.store_dataset_features"),
            patch("hashguard.ml_trainer.predict_sample", side_effect=RuntimeError("model corrupt")),
            patch("hashguard.ioc_graph.build_graph", side_effect=ImportError),
            patch("hashguard.malware_timeline.build_timeline", side_effect=ImportError),
            patch("hashguard.unpacker.auto_unpack", side_effect=ImportError),
        ):
            # Should not raise — error is caught and logged
            result = _run_full_analysis("/fake/path.exe")
            assert "trained_model_prediction" not in result


class TestSandboxEndpoint:
    def test_sandbox_status(self, client):
        resp = client.get("/api/sandbox/status")
        assert resp.status_code == 200
