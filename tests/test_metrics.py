"""Tests for HashGuard Prometheus metrics module."""

import time
import pytest
from unittest.mock import patch, MagicMock


class TestMetricsImport:
    def test_has_prometheus_flag(self):
        from hashguard.web.metrics import HAS_PROMETHEUS
        assert isinstance(HAS_PROMETHEUS, bool)


class TestNormalizeEndpoint:
    def test_plain_path(self):
        from hashguard.web.metrics import _normalize_endpoint
        assert _normalize_endpoint("/api/stats") == "/api/stats"

    def test_numeric_id(self):
        from hashguard.web.metrics import _normalize_endpoint
        assert _normalize_endpoint("/api/samples/123") == "/api/samples/{id}"

    def test_sha256_hash(self):
        from hashguard.web.metrics import _normalize_endpoint
        h = "a" * 64
        assert _normalize_endpoint(f"/api/samples/{h}") == "/api/samples/{id}"

    def test_root_path(self):
        from hashguard.web.metrics import _normalize_endpoint
        assert _normalize_endpoint("/") == "/"

    def test_multiple_ids(self):
        from hashguard.web.metrics import _normalize_endpoint
        assert _normalize_endpoint("/api/tenants/42/samples/99") == "/api/tenants/{id}/samples/{id}"

    def test_non_numeric_preserved(self):
        from hashguard.web.metrics import _normalize_endpoint
        assert _normalize_endpoint("/api/users/edit") == "/api/users/edit"

    def test_mixed_path(self):
        from hashguard.web.metrics import _normalize_endpoint
        h = "abcdef0123456789" * 4  # 64 hex chars
        assert _normalize_endpoint(f"/api/reports/{h}/details") == "/api/reports/{id}/details"

    def test_trailing_slash(self):
        from hashguard.web.metrics import _normalize_endpoint
        result = _normalize_endpoint("/api/stats/")
        assert "stats" in result

    def test_short_hex_not_id(self):
        from hashguard.web.metrics import _normalize_endpoint
        # 32 chars is NOT 64, should not be normalized
        h = "a" * 32
        result = _normalize_endpoint(f"/api/samples/{h}")
        assert "{id}" not in result


class TestTrackRequest:
    def test_track_request_no_crash(self):
        from hashguard.web.metrics import track_request
        track_request("GET", "/api/stats", 200, 0.05)

    def test_track_multiple_methods(self):
        from hashguard.web.metrics import track_request
        track_request("GET", "/api/stats", 200, 0.01)
        track_request("POST", "/api/analyze", 201, 1.5)
        track_request("DELETE", "/api/samples/1", 204, 0.2)

    def test_track_error_status(self):
        from hashguard.web.metrics import track_request
        track_request("GET", "/api/missing", 404, 0.01)
        track_request("POST", "/api/analyze", 500, 5.0)


class TestTrackAnalysis:
    def test_track_malicious(self):
        from hashguard.web.metrics import track_analysis
        track_analysis("malicious")

    def test_track_clean(self):
        from hashguard.web.metrics import track_analysis
        track_analysis("clean")

    def test_track_unknown(self):
        from hashguard.web.metrics import track_analysis
        track_analysis("unknown")

    def test_track_suspicious(self):
        from hashguard.web.metrics import track_analysis
        track_analysis("suspicious")


class TestUpdateGauges:
    def test_update_gauges(self):
        from hashguard.web.metrics import update_gauges
        update_gauges(1000, active_users=5, ingest_jobs=2)

    def test_update_gauges_zeros(self):
        from hashguard.web.metrics import update_gauges
        update_gauges(0, active_users=0, ingest_jobs=0)

    def test_update_gauges_defaults(self):
        from hashguard.web.metrics import update_gauges
        update_gauges(500)


class TestGetMetricsResponse:
    def test_returns_tuple(self):
        from hashguard.web.metrics import get_metrics_response
        data, content_type = get_metrics_response()
        if data is not None:
            assert isinstance(data, bytes)
            assert content_type is not None

    def test_metrics_contain_app_info(self):
        from hashguard.web.metrics import get_metrics_response, HAS_PROMETHEUS
        if HAS_PROMETHEUS:
            data, _ = get_metrics_response()
            text = data.decode("utf-8")
            assert "hashguard" in text


class TestWithoutPrometheus:
    def test_track_request_graceful(self):
        with patch("hashguard.web.metrics.HAS_PROMETHEUS", False):
            from hashguard.web.metrics import track_request
            track_request("GET", "/test", 200, 0.01)

    def test_track_analysis_graceful(self):
        with patch("hashguard.web.metrics.HAS_PROMETHEUS", False):
            from hashguard.web.metrics import track_analysis
            track_analysis("malicious")

    def test_update_gauges_graceful(self):
        with patch("hashguard.web.metrics.HAS_PROMETHEUS", False):
            from hashguard.web.metrics import update_gauges
            update_gauges(100)

    def test_get_metrics_returns_none(self):
        with patch("hashguard.web.metrics.HAS_PROMETHEUS", False):
            from hashguard.web.metrics import get_metrics_response
            data, ct = get_metrics_response()
            assert data is None
