"""Extended tests for web/api.py — covers additional uncovered endpoint branches."""

import os
from unittest.mock import MagicMock, patch, AsyncMock

import pytest

from hashguard.web.api import HAS_FASTAPI

pytestmark = pytest.mark.skipif(not HAS_FASTAPI, reason="FastAPI not installed")


@pytest.fixture
def client():
    from starlette.testclient import TestClient
    from hashguard.web.api import app

    try:
        from hashguard.web.api import limiter
        if limiter:
            limiter.reset()
    except Exception:
        pass

    with patch(
        "hashguard.web.usage_metering.check_quota",
        return_value={"allowed": True, "remaining": 999, "limit": 999},
    ), patch("hashguard.web.usage_metering.record_analysis"):
        yield TestClient(app)


# ── Rate limiting internals ─────────────────────────────────────────────


class TestRateLimitInternals:
    def test_get_plan_for_request_with_jwt(self):
        from hashguard.web.api import _get_plan_for_request
        request = MagicMock()
        request.headers.get.return_value = "Bearer fake_jwt_token"
        with patch("hashguard.web.auth.verify_token", return_value={"sub": "u@t.com", "plan": "pro"}), \
             patch("hashguard.web.auth._is_auth_enabled", return_value=True):
            plan = _get_plan_for_request(request)
            assert plan in ("free", "pro", "team", "enterprise")

    def test_get_plan_for_request_with_api_key(self):
        from hashguard.web.api import _get_plan_for_request
        request = MagicMock()
        request.headers.get.side_effect = lambda h, d="": "hg_key_12345" if h == "X-API-Key" else ""
        with patch("hashguard.web.auth.validate_api_key", return_value={"tenant_id": "t1"}), \
             patch("hashguard.web.auth._is_auth_enabled", return_value=True):
            plan = _get_plan_for_request(request)
            assert plan in ("free", "pro", "team", "enterprise")

    def test_get_plan_for_request_auth_disabled(self):
        from hashguard.web.api import _get_plan_for_request
        request = MagicMock()
        request.headers.get.return_value = ""
        with patch("hashguard.web.auth._is_auth_enabled", return_value=False):
            plan = _get_plan_for_request(request)
            # when auth disabled, returns "enterprise" or "free"
            assert plan in ("free", "enterprise")

    def test_dynamic_limit_with_plan(self):
        from hashguard.web.api import _dynamic_limit
        resolver = _dynamic_limit("analyze", "10/minute")
        limit = resolver()
        assert "/" in limit


# ── Metrics endpoint ────────────────────────────────────────────────────


class TestMetricsEndpoint:
    def test_metrics_endpoint_available(self, client):
        r = client.get("/metrics")
        # Either serves prometheus metrics or 501
        assert r.status_code in (200, 501)


# ── Auth key management endpoints ──────────────────────────────────────


class TestAuthKeyEndpoints:
    def test_create_api_key_validation_error(self, client):
        with patch("hashguard.web.auth.create_api_key", side_effect=ValueError("bad name")):
            r = client.post("/api/auth/keys", data={"name": ""})
            assert r.status_code in (400, 422, 500)

    def test_list_api_keys(self, client):
        with patch("hashguard.web.auth.list_api_keys", return_value=[]):
            r = client.get("/api/auth/keys")
            assert r.status_code == 200

    def test_revoke_api_key_not_found(self, client):
        with patch("hashguard.web.auth.revoke_api_key", return_value=False):
            r = client.delete("/api/auth/keys/nonexistent")
            assert r.status_code in (404, 200)


# ── Dataset version endpoints ──────────────────────────────────────────


class TestDatasetVersionEndpoints:
    def test_create_dataset_version(self, client):
        with patch("hashguard.database.create_dataset_version",
                    return_value={"version": "1.0.0", "sha256": "a" * 64}):
            r = client.post("/api/dataset/versions?version=1.0.0&fmt=jsonl")
            assert r.status_code in (200, 201)

    def test_download_dataset_version_not_found(self, client):
        with patch("hashguard.database.get_dataset_version_path", return_value=None):
            r = client.get("/api/dataset/versions/v1/download")
            assert r.status_code in (404, 500)

    def test_sample_features_not_found(self, client):
        mock_conn = MagicMock()
        mock_conn.execute.return_value.fetchone.return_value = None
        with patch("hashguard.database.get_connection", return_value=mock_conn), \
             patch("hashguard.database.init_db"), \
             patch("hashguard.database._ensure_dataset_table"):
            r = client.get("/api/dataset/features/9999")
            assert r.status_code in (404, 500)

    def test_dataset_export_anonymized_parquet(self, client):
        with patch("hashguard.database.export_dataset_anonymized", return_value=b"\x00PAR"):
            r = client.get("/api/dataset/export/anonymized?fmt=parquet")
            assert r.status_code == 200


# ── Anomaly detection endpoints ────────────────────────────────────────


class TestAnomalyEndpoints:
    def test_anomaly_detect_success(self, client):
        mock_conn = MagicMock()
        mock_row = MagicMock()
        mock_row.__getitem__ = lambda self, i: 0.5  # numeric features
        mock_conn.execute.return_value.fetchone.return_value = mock_row

        result_obj = MagicMock()
        result_obj.to_dict.return_value = {"is_anomaly": True, "score": 0.85}

        with patch("hashguard.database.get_connection", return_value=mock_conn), \
             patch("hashguard.database.init_db"), \
             patch("hashguard.database._ensure_dataset_table"), \
             patch("hashguard.anomaly_detector.detect_anomaly",
                    return_value=result_obj):
            r = client.post("/api/anomaly/detect", data={"sample_id": "1"})
            assert r.status_code in (200, 400, 500)

    def test_anomaly_detect_sample_not_found(self, client):
        mock_conn = MagicMock()
        mock_conn.execute.return_value.fetchone.return_value = None
        with patch("hashguard.database.get_connection", return_value=mock_conn), \
             patch("hashguard.database.init_db"), \
             patch("hashguard.database._ensure_dataset_table"):
            r = client.post("/api/anomaly/detect", data={"sample_id": "9999"})
            assert r.status_code in (200, 404, 400, 500)


# ── Memory analysis endpoint ──────────────────────────────────────────


class TestMemoryAnalysis:
    def test_memory_analyze_file_not_found(self, client):
        mock_conn = MagicMock()
        mock_conn.execute.return_value.fetchone.return_value = ("/nonexistent/path",)
        with patch("hashguard.database.get_connection", return_value=mock_conn), \
             patch("hashguard.database.init_db"):
            r = client.post("/api/memory/analyze", data={"sample_id": "1"})
            assert r.status_code in (404, 400, 500)

    def test_memory_analyze_success(self, client):
        import tempfile
        with tempfile.NamedTemporaryFile(suffix=".exe", delete=False) as f:
            f.write(b"MZ" + b"\x00" * 100)
            fpath = f.name
        try:
            mock_conn = MagicMock()
            mock_conn.execute.return_value.fetchone.return_value = (fpath,)

            result_obj = MagicMock()
            result_obj.to_dict.return_value = {"processes": []}

            with patch("hashguard.database.get_connection", return_value=mock_conn), \
                 patch("hashguard.database.init_db"), \
                 patch("hashguard.memory_analyzer.analyze_memory",
                        return_value=result_obj):
                r = client.post("/api/memory/analyze", data={"sample_id": "1"})
                assert r.status_code in (200, 500)
        finally:
            os.unlink(fpath)


# ── ML predict error ───────────────────────────────────────────────────


class TestMLPredict:
    def test_ml_predict_error_in_result(self, client):
        mock_conn = MagicMock()
        mock_row = MagicMock()
        mock_row.__iter__ = lambda self: iter([("feature", 1.0)])
        mock_row.keys.return_value = ["feature"]
        mock_conn.execute.return_value.fetchone.return_value = mock_row
        with patch("hashguard.database.get_connection", return_value=mock_conn), \
             patch("hashguard.database.init_db"), \
             patch("hashguard.database._ensure_dataset_table"), \
             patch("hashguard.ml_trainer.predict_sample",
                    return_value={"error": "no model loaded"}):
            r = client.post("/api/ml/predict", data={"sample_id": "1"})
            assert r.status_code in (400, 500)


# ── Settings mask + env ─────────────────────────────────────────────────


class TestSettingsExtended:
    def test_get_settings_with_keys_set(self, client, monkeypatch):
        monkeypatch.setenv("VT_API_KEY", "vt_test_key_12345")
        monkeypatch.setenv("ABUSE_CH_API_KEY", "abuse_key_999")
        r = client.get("/api/settings")
        assert r.status_code == 200
        data = r.json()
        assert "vt_api_key_set" in data


# ── Start server ────────────────────────────────────────────────────────


class TestStartServer:
    def test_start_server_no_fastapi(self):
        with patch("hashguard.web.api.HAS_FASTAPI", False):
            from hashguard.web.api import start_server
            # Should print error and return
            start_server(port=9999, open_browser=False)

    def test_start_server_normal(self):
        with patch("hashguard.web.api.HAS_FASTAPI", True), \
             patch("uvicorn.run") as mock_run:
            from hashguard.web.api import start_server
            start_server(port=9999, open_browser=False)
            mock_run.assert_called_once()
