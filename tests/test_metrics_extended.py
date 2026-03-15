"""Tests for Prometheus metrics module."""

import pytest
from unittest.mock import patch, MagicMock


class TestGetMetricsResponse:
    def test_no_prometheus(self):
        with patch("hashguard.web.metrics.HAS_PROMETHEUS", False):
            from hashguard.web.metrics import get_metrics_response
            content, ctype = get_metrics_response()
            assert content is None
            assert ctype is None

    def test_with_prometheus(self):
        from hashguard.web.metrics import get_metrics_response, HAS_PROMETHEUS
        if not HAS_PROMETHEUS:
            pytest.skip("prometheus_client not installed")
        content, ctype = get_metrics_response()
        assert content is not None
        assert ctype is not None


class TestTrackRequest:
    def test_no_prometheus_noop(self):
        with patch("hashguard.web.metrics.HAS_PROMETHEUS", False):
            from hashguard.web.metrics import track_request
            track_request("GET", "/api/stats", 200, 0.01)  # Should not raise

    def test_with_prometheus(self):
        from hashguard.web.metrics import track_request, HAS_PROMETHEUS
        if not HAS_PROMETHEUS:
            pytest.skip("prometheus_client not installed")
        # Should not raise
        track_request("GET", "/api/stats", 200, 0.05)
        track_request("POST", "/api/analyze", 200, 1.5)


class TestTrackAnalysis:
    def test_no_prometheus_noop(self):
        with patch("hashguard.web.metrics.HAS_PROMETHEUS", False):
            from hashguard.web.metrics import track_analysis
            track_analysis("malicious")

    def test_with_prometheus(self):
        from hashguard.web.metrics import track_analysis, HAS_PROMETHEUS
        if not HAS_PROMETHEUS:
            pytest.skip("prometheus_client not installed")
        track_analysis("malicious")
        track_analysis("clean")


class TestUpdateGauges:
    def test_no_prometheus_noop(self):
        with patch("hashguard.web.metrics.HAS_PROMETHEUS", False):
            from hashguard.web.metrics import update_gauges
            update_gauges(100, 5, 2)

    def test_with_prometheus(self):
        from hashguard.web.metrics import update_gauges, HAS_PROMETHEUS
        if not HAS_PROMETHEUS:
            pytest.skip("prometheus_client not installed")
        update_gauges(500, active_users=10, ingest_jobs=3)


class TestNormalizeEndpoint:
    def test_plain_path(self):
        from hashguard.web.metrics import _normalize_endpoint
        assert _normalize_endpoint("/api/stats") == "/api/stats"

    def test_numeric_id(self):
        from hashguard.web.metrics import _normalize_endpoint
        assert _normalize_endpoint("/api/samples/123") == "/api/samples/{id}"

    def test_sha256_hash(self):
        from hashguard.web.metrics import _normalize_endpoint
        sha = "a" * 64
        result = _normalize_endpoint(f"/api/samples/{sha}")
        assert "{id}" in result

    def test_mixed_path(self):
        from hashguard.web.metrics import _normalize_endpoint
        result = _normalize_endpoint("/api/graph/42")
        assert result == "/api/graph/{id}"

    def test_root_path(self):
        from hashguard.web.metrics import _normalize_endpoint
        result = _normalize_endpoint("/")
        assert result == "/"

    def test_no_ids(self):
        from hashguard.web.metrics import _normalize_endpoint
        result = _normalize_endpoint("/api/feeds/recent")
        assert result == "/api/feeds/recent"
