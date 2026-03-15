"""Tests for multi-tenancy support in HashGuard database."""

import os
import sqlite3
import tempfile
import threading
from unittest.mock import patch

import pytest

from hashguard import database


@pytest.fixture(autouse=True)
def isolate_db(tmp_path, monkeypatch):
    """Use a temp database for every test."""
    db_path = str(tmp_path / "test.db")
    monkeypatch.setattr(database, "_DB_DIR", str(tmp_path))
    monkeypatch.setattr(database, "_DB_PATH", db_path)
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{db_path}")
    from hashguard import models
    models.reset_engine()
    database._local = threading.local()
    database._DATASET_SCHEMA_APPLIED = False
    database.init_db()
    yield db_path


def _insert_sample(sha256, tenant_id="default", is_malicious=0, family=""):
    """Helper to insert a minimal sample row."""
    conn = database.get_connection()
    conn.execute(
        """INSERT INTO samples (filename, sha256, analysis_date, risk_score, verdict, is_malicious, family, tenant_id)
           VALUES (?, ?, datetime('now'), ?, ?, ?, ?, ?)""",
        (f"sample_{sha256[:8]}", sha256, 0, "clean" if not is_malicious else "malicious", is_malicious, family, tenant_id),
    )
    conn.commit()


class TestTenantIdMigration:
    def test_tenant_id_column_exists(self):
        conn = database.get_connection()
        columns = {row[1] for row in conn.execute("PRAGMA table_info(samples)").fetchall()}
        assert "tenant_id" in columns

    def test_new_samples_get_default_tenant(self):
        _insert_sample("a" * 64)
        conn = database.get_connection()
        row = conn.execute("SELECT tenant_id FROM samples WHERE sha256 = ?", ("a" * 64,)).fetchone()
        assert row["tenant_id"] == "default"

    def test_tenant_index_exists(self):
        conn = database.get_connection()
        indexes = conn.execute("SELECT name FROM sqlite_master WHERE type='index'").fetchall()
        index_names = {row[0] for row in indexes}
        assert "idx_samples_tenant" in index_names


class TestGetAllSamplesMultiTenant:
    def test_no_tenant_returns_all(self):
        _insert_sample("a" * 64, tenant_id="tenant_a")
        _insert_sample("b" * 64, tenant_id="tenant_b")
        _insert_sample("c" * 64, tenant_id="default")
        samples = database.get_all_samples()
        assert len(samples) == 3

    def test_filter_by_tenant(self):
        _insert_sample("a" * 64, tenant_id="acme")
        _insert_sample("b" * 64, tenant_id="acme")
        _insert_sample("c" * 64, tenant_id="other")
        samples = database.get_all_samples(tenant_id="acme")
        assert len(samples) == 2
        assert all(s["tenant_id"] == "acme" for s in samples)

    def test_filter_nonexistent_tenant(self):
        _insert_sample("a" * 64, tenant_id="acme")
        samples = database.get_all_samples(tenant_id="nobody")
        assert len(samples) == 0

    def test_tenant_with_limit(self):
        for i in range(10):
            _insert_sample(f"{i:064d}", tenant_id="big")
        samples = database.get_all_samples(limit=5, tenant_id="big")
        assert len(samples) == 5


class TestGetStatsMultiTenant:
    def test_stats_no_tenant(self):
        _insert_sample("a" * 64, is_malicious=1)
        _insert_sample("b" * 64, is_malicious=0)
        stats = database.get_stats()
        assert stats["total_samples"] == 2
        assert stats["malicious"] == 1
        assert stats["clean"] == 1

    def test_stats_with_tenant(self):
        _insert_sample("a" * 64, tenant_id="t1", is_malicious=1)
        _insert_sample("b" * 64, tenant_id="t1", is_malicious=0)
        _insert_sample("c" * 64, tenant_id="t2", is_malicious=1)
        stats = database.get_stats(tenant_id="t1")
        assert stats["total_samples"] == 2
        assert stats["malicious"] == 1

    def test_stats_tenant_families(self):
        _insert_sample("a" * 64, tenant_id="t1", is_malicious=1, family="emotet")
        _insert_sample("b" * 64, tenant_id="t2", is_malicious=1, family="trickbot")
        stats = database.get_stats(tenant_id="t1")
        families = [f["name"] for f in stats["top_families"]]
        assert "emotet" in families
        assert "trickbot" not in families

    def test_stats_empty_tenant(self):
        stats = database.get_stats(tenant_id="empty")
        assert stats["total_samples"] == 0
        assert stats["malicious"] == 0
        assert stats["detection_rate"] == 0


class TestSearchSamplesMultiTenant:
    def test_search_no_tenant(self):
        _insert_sample("a" * 64, family="emotet")
        _insert_sample("b" * 64, family="trickbot")
        results = database.search_samples("emotet")
        assert len(results) == 1

    def test_search_with_tenant(self):
        _insert_sample("a" * 64, tenant_id="t1", family="emotet")
        _insert_sample("b" * 64, tenant_id="t2", family="emotet")
        results = database.search_samples("emotet", tenant_id="t1")
        assert len(results) == 1
        assert results[0]["tenant_id"] == "t1"

    def test_search_tenant_no_results(self):
        _insert_sample("a" * 64, tenant_id="t1", family="emotet")
        results = database.search_samples("emotet", tenant_id="t2")
        assert len(results) == 0
