"""Prometheus metrics for HashGuard SaaS.

Exposes /metrics endpoint with application metrics:
- HTTP request count/duration by endpoint and status
- Active analyses, queue depth
- System resource usage (CPU, memory, disk)
- Business metrics (samples total, analyses today, active users)
"""

import time
from typing import Optional

from hashguard.logger import get_logger

logger = get_logger(__name__)

try:
    from prometheus_client import (
        Counter,
        Gauge,
        Histogram,
        Info,
        generate_latest,
        CONTENT_TYPE_LATEST,
        CollectorRegistry,
        REGISTRY,
    )

    HAS_PROMETHEUS = True
except ImportError:
    HAS_PROMETHEUS = False

# ── Metrics definitions ────────────────────────────────────────────────────

if HAS_PROMETHEUS:
    REQUEST_COUNT = Counter(
        "hashguard_http_requests_total",
        "Total HTTP requests",
        ["method", "endpoint", "status"],
    )

    REQUEST_DURATION = Histogram(
        "hashguard_http_request_duration_seconds",
        "HTTP request duration in seconds",
        ["method", "endpoint"],
        buckets=[0.01, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0, 60.0],
    )

    ANALYSES_TOTAL = Counter(
        "hashguard_analyses_total",
        "Total analyses performed",
        ["verdict"],
    )

    ANALYSES_IN_PROGRESS = Gauge(
        "hashguard_analyses_in_progress",
        "Currently running analyses",
    )

    SAMPLES_TOTAL = Gauge(
        "hashguard_samples_total",
        "Total samples in database",
    )

    ACTIVE_USERS = Gauge(
        "hashguard_active_users",
        "Users active in the last 24 hours",
    )

    INGEST_JOBS = Gauge(
        "hashguard_ingest_jobs_active",
        "Currently running ingest jobs",
    )

    DB_QUERY_DURATION = Histogram(
        "hashguard_db_query_duration_seconds",
        "Database query duration",
        ["operation"],
        buckets=[0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1.0],
    )

    APP_INFO = Info("hashguard", "HashGuard application info")
    APP_INFO.info({"version": "1.1.4", "environment": "production"})


def get_metrics_response():
    """Generate Prometheus metrics response."""
    if not HAS_PROMETHEUS:
        return None, None
    return generate_latest(REGISTRY), CONTENT_TYPE_LATEST


def track_request(method: str, endpoint: str, status: int, duration: float):
    """Record an HTTP request metric."""
    if not HAS_PROMETHEUS:
        return
    # Normalize endpoint to avoid high cardinality
    normalized = _normalize_endpoint(endpoint)
    REQUEST_COUNT.labels(method=method, endpoint=normalized, status=str(status)).inc()
    REQUEST_DURATION.labels(method=method, endpoint=normalized).observe(duration)


def track_analysis(verdict: str):
    """Record a completed analysis."""
    if not HAS_PROMETHEUS:
        return
    ANALYSES_TOTAL.labels(verdict=verdict).inc()


def update_gauges(samples: int, active_users: int = 0, ingest_jobs: int = 0):
    """Update gauge metrics with current values."""
    if not HAS_PROMETHEUS:
        return
    SAMPLES_TOTAL.set(samples)
    ACTIVE_USERS.set(active_users)
    INGEST_JOBS.set(ingest_jobs)


def _normalize_endpoint(path: str) -> str:
    """Normalize URL paths to prevent metric cardinality explosion."""
    parts = path.strip("/").split("/")
    normalized = []
    for i, part in enumerate(parts):
        # Replace IDs with placeholder
        if part.isdigit() or (len(part) == 64 and all(c in "0123456789abcdef" for c in part)):
            normalized.append("{id}")
        else:
            normalized.append(part)
    return "/" + "/".join(normalized)
