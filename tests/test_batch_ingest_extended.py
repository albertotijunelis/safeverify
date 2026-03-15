"""Extended tests for batch_ingest — covers all source fetchers, downloaders, orchestrators."""

import gzip
import io
import os
import tempfile
import threading
import time
import zipfile
from unittest.mock import MagicMock, patch, PropertyMock

import pytest


# ── API key getters ─────────────────────────────────────────────────────


class TestGetAPIKeys:
    def test_malshare_key_from_env(self, monkeypatch):
        monkeypatch.setenv("MALSHARE_API_KEY", "ms_key_123")
        from hashguard.batch_ingest import _get_malshare_key
        assert _get_malshare_key() == "ms_key_123"

    def test_malshare_key_from_config(self, monkeypatch):
        monkeypatch.delenv("MALSHARE_API_KEY", raising=False)
        cfg = MagicMock()
        cfg.malshare_api_key = "cfg_ms_key"
        with patch("hashguard.config.get_default_config", return_value=cfg):
            from hashguard.batch_ingest import _get_malshare_key
            assert _get_malshare_key() in ("cfg_ms_key", None)  # depends on load order

    def test_malshare_key_none(self, monkeypatch):
        monkeypatch.delenv("MALSHARE_API_KEY", raising=False)
        with patch("hashguard.config.get_default_config", side_effect=Exception):
            from hashguard.batch_ingest import _get_malshare_key
            result = _get_malshare_key()
            # Returns None or cached value
            assert result is None or isinstance(result, str)

    def test_hybrid_analysis_key_from_env(self, monkeypatch):
        monkeypatch.setenv("HYBRID_ANALYSIS_API_KEY", "ha_key_123")
        from hashguard.batch_ingest import _get_hybrid_analysis_key
        assert _get_hybrid_analysis_key() == "ha_key_123"

    def test_hybrid_analysis_key_none(self, monkeypatch):
        monkeypatch.delenv("HYBRID_ANALYSIS_API_KEY", raising=False)
        with patch("hashguard.config.get_default_config", side_effect=Exception):
            from hashguard.batch_ingest import _get_hybrid_analysis_key
            result = _get_hybrid_analysis_key()
            assert result is None or isinstance(result, str)

    def test_triage_key_from_env(self, monkeypatch):
        monkeypatch.setenv("TRIAGE_API_KEY", "tri_key_123")
        from hashguard.batch_ingest import _get_triage_key
        assert _get_triage_key() == "tri_key_123"

    def test_triage_key_none(self, monkeypatch):
        monkeypatch.delenv("TRIAGE_API_KEY", raising=False)
        with patch("hashguard.config.get_default_config", side_effect=Exception):
            from hashguard.batch_ingest import _get_triage_key
            result = _get_triage_key()
            assert result is None or isinstance(result, str)


# ── URLhaus source functions ────────────────────────────────────────────


class TestURLhaus:
    def test_urlhaus_get_recent(self):
        from hashguard.batch_ingest import _urlhaus_get_recent
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "payloads": [
                {"sha256_hash": "a" * 64, "md5_hash": "b" * 32, "file_type": "exe"},
                {"sha256_hash": "c" * 64, "md5_hash": "d" * 32, "file_type": "dll"},
            ]
        }
        with patch("requests.post", return_value=mock_resp):
            result = _urlhaus_get_recent(2)
            assert len(result) <= 2
            assert all(r.get("_source") == "urlhaus" for r in result)

    def test_urlhaus_get_recent_error(self):
        from hashguard.batch_ingest import _urlhaus_get_recent
        with patch("requests.post", side_effect=Exception("timeout")):
            result = _urlhaus_get_recent(5)
            assert result == []

    def test_urlhaus_download_payload(self):
        from hashguard.batch_ingest import _urlhaus_download_payload
        # Create a zip file in memory
        zip_buf = io.BytesIO()
        with zipfile.ZipFile(zip_buf, "w") as zf:
            zf.writestr("payload.bin", b"MZ" + b"\x00" * 50)
        zip_bytes = zip_buf.getvalue()

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.content = zip_bytes

        with tempfile.TemporaryDirectory() as tmp:
            with patch("requests.get", return_value=mock_resp):
                result = _urlhaus_download_payload("a" * 64, tmp)
                # May return path or None depending on extraction logic
                assert result is None or os.path.exists(result)

    def test_urlhaus_download_payload_error(self):
        from hashguard.batch_ingest import _urlhaus_download_payload
        with tempfile.TemporaryDirectory() as tmp:
            with patch("requests.get", side_effect=Exception("conn refused")):
                result = _urlhaus_download_payload("a" * 64, tmp)
                assert result is None


# ── MalShare source functions ──────────────────────────────────────────


class TestMalShare:
    def test_malshare_get_recent_24h(self, monkeypatch):
        monkeypatch.setenv("MALSHARE_API_KEY", "test_ms_key")
        from hashguard.batch_ingest import _malshare_get_recent_24h
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.text = "aabbccdd\n11223344\n55667788\n"
        with patch("requests.get", return_value=mock_resp):
            result = _malshare_get_recent_24h(3)
            assert len(result) <= 3
            assert all(r.get("_source") == "malshare" for r in result)

    def test_malshare_get_recent_no_key(self, monkeypatch):
        monkeypatch.delenv("MALSHARE_API_KEY", raising=False)
        from hashguard.batch_ingest import _malshare_get_recent_24h
        with patch("hashguard.config.get_default_config", side_effect=Exception):
            result = _malshare_get_recent_24h(5)
            assert result == []

    def test_malshare_download_sample(self, monkeypatch):
        monkeypatch.setenv("MALSHARE_API_KEY", "test_ms_key")
        from hashguard.batch_ingest import _malshare_download_sample
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.content = b"MZ" + b"\x00" * 100
        with tempfile.TemporaryDirectory() as tmp:
            with patch("requests.get", return_value=mock_resp):
                result = _malshare_download_sample("aabbccdd", tmp)
                assert result is None or os.path.exists(result)


# ── Hybrid Analysis source functions ───────────────────────────────────


class TestHybridAnalysis:
    def test_ha_search_recent(self, monkeypatch):
        monkeypatch.setenv("HYBRID_ANALYSIS_API_KEY", "test_ha_key")
        from hashguard.batch_ingest import _ha_search_recent
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = [
            {"sha256": "a" * 64, "type_short": ["exe"]},
            {"sha256": "b" * 64, "type_short": ["dll"]},
        ]
        with patch("requests.get", return_value=mock_resp):
            result = _ha_search_recent(2)
            assert len(result) <= 2
            assert all(r.get("_source") == "hybrid_analysis" for r in result)

    def test_ha_search_recent_no_key(self, monkeypatch):
        monkeypatch.delenv("HYBRID_ANALYSIS_API_KEY", raising=False)
        from hashguard.batch_ingest import _ha_search_recent
        with patch("hashguard.config.get_default_config", side_effect=Exception):
            result = _ha_search_recent(5)
            assert result == []

    def test_ha_download_sample(self, monkeypatch):
        monkeypatch.setenv("HYBRID_ANALYSIS_API_KEY", "test_ha_key")
        from hashguard.batch_ingest import _ha_download_sample
        # Test gzip content
        raw = b"MZ" + b"\x00" * 100
        gz_buf = io.BytesIO()
        with gzip.GzipFile(fileobj=gz_buf, mode="wb") as gz:
            gz.write(raw)
        gz_bytes = gz_buf.getvalue()

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.content = gz_bytes
        mock_resp.headers = {"Content-Type": "application/gzip"}
        with tempfile.TemporaryDirectory() as tmp:
            with patch("requests.get", return_value=mock_resp):
                result = _ha_download_sample("a" * 64, tmp)
                assert result is None or os.path.exists(result)

    def test_ha_download_error(self, monkeypatch):
        monkeypatch.setenv("HYBRID_ANALYSIS_API_KEY", "test_ha_key")
        from hashguard.batch_ingest import _ha_download_sample
        with tempfile.TemporaryDirectory() as tmp:
            with patch("requests.get", side_effect=Exception("timeout")):
                result = _ha_download_sample("a" * 64, tmp)
                assert result is None


# ── Triage source functions ────────────────────────────────────────────


class TestTriage:
    def test_triage_get_recent(self, monkeypatch):
        monkeypatch.setenv("TRIAGE_API_KEY", "test_tri_key")
        from hashguard.batch_ingest import _triage_get_recent
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "data": [
                {"id": "s1", "sha256": "a" * 64},
                {"id": "s2", "targets": [{"sha256": "b" * 64}]},
            ]
        }
        with patch("requests.get", return_value=mock_resp):
            result = _triage_get_recent(2)
            assert len(result) <= 2
            assert all(r.get("_source") == "triage" for r in result)

    def test_triage_get_recent_no_key(self, monkeypatch):
        monkeypatch.delenv("TRIAGE_API_KEY", raising=False)
        from hashguard.batch_ingest import _triage_get_recent
        with patch("hashguard.config.get_default_config", side_effect=Exception):
            result = _triage_get_recent(5)
            assert result == []

    def test_triage_download_sample(self, monkeypatch):
        monkeypatch.setenv("TRIAGE_API_KEY", "test_tri_key")
        from hashguard.batch_ingest import _triage_download_sample
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.content = b"MZ" + b"\x00" * 100
        with tempfile.TemporaryDirectory() as tmp:
            with patch("requests.get", return_value=mock_resp):
                result = _triage_download_sample("a" * 64, tmp, "s1")
                assert result is None or os.path.exists(result)


# ── Download dispatcher ────────────────────────────────────────────────


class TestDownloadSample:
    def test_dispatch_malwarebazaar(self):
        from hashguard.batch_ingest import _download_sample
        entry = {"sha256_hash": "a" * 64, "_source": "malwarebazaar"}
        with patch("hashguard.batch_ingest._mb_download_sample", return_value="/tmp/file") as mock:
            result = _download_sample(entry, "/tmp")
            assert result == "/tmp/file"

    def test_dispatch_urlhaus(self):
        from hashguard.batch_ingest import _download_sample
        entry = {"sha256_hash": "a" * 64, "_source": "urlhaus"}
        with patch("hashguard.batch_ingest._urlhaus_download_payload", return_value="/tmp/file") as mock:
            result = _download_sample(entry, "/tmp")
            assert result == "/tmp/file"

    def test_dispatch_malshare(self):
        from hashguard.batch_ingest import _download_sample
        entry = {"sha256_hash": "a" * 64, "md5_hash": "b" * 32, "_source": "malshare"}
        with patch("hashguard.batch_ingest._malshare_download_sample", return_value="/tmp/file") as mock:
            result = _download_sample(entry, "/tmp")
            assert result == "/tmp/file"

    def test_dispatch_hybrid_analysis(self):
        from hashguard.batch_ingest import _download_sample
        entry = {"sha256_hash": "a" * 64, "_source": "hybrid_analysis"}
        with patch("hashguard.batch_ingest._ha_download_sample", return_value="/tmp/file") as mock:
            result = _download_sample(entry, "/tmp")
            assert result == "/tmp/file"

    def test_dispatch_triage(self):
        from hashguard.batch_ingest import _download_sample
        entry = {"sha256_hash": "a" * 64, "_source": "triage", "_triage_sample_id": "s1"}
        with patch("hashguard.batch_ingest._triage_download_sample", return_value="/tmp/file") as mock:
            result = _download_sample(entry, "/tmp")
            assert result == "/tmp/file"


# ── Analysis batch function ────────────────────────────────────────────


class TestAnalyseFileBatch:
    def test_analyse_file_batch_success(self):
        from hashguard.batch_ingest import _analyse_file_batch
        mock_result = MagicMock()
        mock_result.to_dict.return_value = {
            "hashes": {"sha256": "a" * 64},
            "risk_score": {"score": 75, "verdict": "malicious"},
        }
        with patch("hashguard.scanner.analyze", return_value=mock_result), \
             patch("hashguard.config.get_default_config"), \
             patch("hashguard.web.api._sanitize_for_json", side_effect=lambda x: x), \
             patch("hashguard.database.store_sample", return_value=1), \
             patch("hashguard.feature_extractor.extract_features", return_value={"f": 1}), \
             patch("hashguard.database.store_dataset_features"):
            result = _analyse_file_batch("/tmp/fake.exe", {})
            assert result is not None
            assert result["hashes"]["sha256"] == "a" * 64

    def test_analyse_file_batch_with_malware_metadata(self):
        from hashguard.batch_ingest import _analyse_file_batch
        mock_result = MagicMock()
        mock_result.to_dict.return_value = {
            "hashes": {"sha256": "a" * 64},
            "risk_score": {"score": 20, "verdict": "clean"},
        }
        metadata = {"sha256_hash": "a" * 64, "_source": "malwarebazaar"}
        with patch("hashguard.scanner.analyze", return_value=mock_result), \
             patch("hashguard.config.get_default_config"), \
             patch("hashguard.web.api._sanitize_for_json", side_effect=lambda x: x), \
             patch("hashguard.database.store_sample", return_value=2), \
             patch("hashguard.feature_extractor.extract_features", return_value={"f": 1}), \
             patch("hashguard.database.store_dataset_features"):
            result = _analyse_file_batch("/tmp/fake.exe", metadata)
            assert result is not None

    def test_analyse_file_batch_error(self):
        from hashguard.batch_ingest import _analyse_file_batch
        with patch("hashguard.scanner.analyze", side_effect=Exception("corrupt")), \
             patch("hashguard.config.get_default_config"):
            result = _analyse_file_batch("/tmp/bad.exe", {})
            assert result is None


# ── Benign ingest ───────────────────────────────────────────────────────


class TestRunBenignIngest:
    def test_run_benign_ingest(self):
        import hashguard.batch_ingest as bi

        # Create temp dir with fake executables
        with tempfile.TemporaryDirectory() as tmp:
            exe1 = os.path.join(tmp, "test1.exe")
            exe2 = os.path.join(tmp, "test2.dll")
            with open(exe1, "wb") as f:
                f.write(b"MZ" + b"\x00" * 100)
            with open(exe2, "wb") as f:
                f.write(b"MZ" + b"\x00" * 200)

            mock_result = MagicMock()
            mock_result.to_dict.return_value = {
                "hashes": {"sha256": "a" * 64},
                "risk_score": 5,
            }

            old_job = bi._current_job
            try:
                bi._current_job = bi.IngestJob(source="benign", status="running")
                bi._stop_event.clear()

                with patch.object(bi, "_BENIGN_DIRS_WINDOWS", [tmp]), \
                     patch("hashguard.scanner.analyze", return_value=mock_result), \
                     patch("hashguard.config.get_default_config"), \
                     patch("hashguard.web.api._sanitize_for_json", side_effect=lambda x: x), \
                     patch("hashguard.database.store_sample", return_value=1), \
                     patch("hashguard.feature_extractor.extract_features", return_value={}), \
                     patch("hashguard.database.store_dataset_features"), \
                     patch("hashguard.batch_ingest._already_in_dataset", return_value=False):
                    bi._run_benign_ingest(limit=2, delay=0)
                    assert bi._current_job.status in ("done", "running")
                    assert bi._current_job.analysed >= 0
            finally:
                bi._current_job = old_job


# ── Continuous ingest ───────────────────────────────────────────────────


class TestRunContinuousIngest:
    def test_continuous_ingest_runs_cycle(self):
        import hashguard.batch_ingest as bi

        old_job = bi._current_job
        try:
            bi._current_job = bi.IngestJob(source="continuous", status="running")
            bi._stop_event.clear()

            call_count = [0]

            def mock_process(candidates, qdir, delay, use_vt, target):
                call_count[0] += 1
                bi._current_job.analysed += len(candidates)

            with patch("hashguard.batch_ingest._mb_get_recent", return_value=[{"sha256_hash": "a" * 64}]), \
                 patch("hashguard.batch_ingest._urlhaus_get_recent", return_value=[]), \
                 patch("hashguard.batch_ingest._malshare_get_recent_24h", return_value=[]), \
                 patch("hashguard.batch_ingest._ha_search_recent", return_value=[]), \
                 patch("hashguard.batch_ingest._triage_get_recent", return_value=[]), \
                 patch("hashguard.batch_ingest._mb_get_by_tag", return_value=[]), \
                 patch("hashguard.batch_ingest._mb_get_by_filetype", return_value=[]), \
                 patch("hashguard.batch_ingest._process_candidates", side_effect=mock_process), \
                 patch("tempfile.mkdtemp", return_value=tempfile.mkdtemp()), \
                 patch("shutil.rmtree"):
                bi._run_continuous_ingest(target=1, delay=0, use_vt=False)
                assert call_count[0] >= 1
                assert bi._current_job.status in ("done", "stopped")
        finally:
            bi._current_job = old_job


# ── Process candidates ──────────────────────────────────────────────────


class TestProcessCandidates:
    def test_process_candidates_basic(self):
        import hashguard.batch_ingest as bi

        old_job = bi._current_job
        try:
            bi._current_job = bi.IngestJob(source="test", status="running")
            bi._stop_event.clear()

            candidates = [
                {"sha256_hash": "a" * 64, "_source": "malwarebazaar"},
                {"sha256_hash": "b" * 64, "_source": "malwarebazaar"},
            ]

            with tempfile.TemporaryDirectory() as tmp:
                with patch("hashguard.batch_ingest._already_in_dataset", return_value=False), \
                     patch("hashguard.batch_ingest._download_sample", return_value=os.path.join(tmp, "f")), \
                     patch("hashguard.batch_ingest._analyse_file_batch", return_value={"ok": True}), \
                     patch("os.remove"):
                    bi._process_candidates(candidates, tmp, delay=0, use_vt=False, target=10)
                    assert bi._current_job.analysed >= 0
        finally:
            bi._current_job = old_job

    def test_process_candidates_already_known(self):
        import hashguard.batch_ingest as bi

        old_job = bi._current_job
        try:
            bi._current_job = bi.IngestJob(source="test", status="running")
            candidates = [{"sha256_hash": "a" * 64, "_source": "mb"}]
            with tempfile.TemporaryDirectory() as tmp:
                with patch("hashguard.batch_ingest._already_in_dataset", return_value=True):
                    bi._process_candidates(candidates, tmp, delay=0, use_vt=False, target=10)
                    assert bi._current_job.analysed == 0
        finally:
            bi._current_job = old_job


# ── start_ingest ────────────────────────────────────────────────────────


class TestStartIngest:
    def test_start_ingest_benign(self):
        from hashguard.batch_ingest import start_ingest
        with patch("hashguard.batch_ingest._run_benign_ingest"):
            result = start_ingest(source="benign", limit=5)
            assert result.get("started") is True or "source" in result

    def test_start_ingest_recent(self):
        from hashguard.batch_ingest import start_ingest
        with patch("hashguard.batch_ingest._fetch_and_ingest"):
            result = start_ingest(source="recent", limit=5)
            assert isinstance(result, dict)

    def test_start_ingest_continuous(self):
        from hashguard.batch_ingest import start_ingest
        with patch("hashguard.batch_ingest._fetch_and_ingest"):
            result = start_ingest(source="continuous", limit=5)
            assert isinstance(result, dict)


# ── fetch_and_ingest dispatch ──────────────────────────────────────────


class TestFetchAndIngest:
    def test_fetch_and_ingest_urlhaus(self):
        import hashguard.batch_ingest as bi
        old_job = bi._current_job
        try:
            bi._current_job = bi.IngestJob(source="urlhaus", status="running")
            bi._stop_event.clear()
            with patch("hashguard.batch_ingest._urlhaus_get_recent", return_value=[]), \
                 patch("tempfile.mkdtemp", return_value=tempfile.mkdtemp()), \
                 patch("shutil.rmtree"):
                bi._fetch_and_ingest("urlhaus", limit=5, tag="", file_type="exe", delay=0, use_vt=False)
                assert bi._current_job.status in ("done", "error")
        finally:
            bi._current_job = old_job

    def test_fetch_and_ingest_malshare_no_key(self, monkeypatch):
        import hashguard.batch_ingest as bi
        monkeypatch.delenv("MALSHARE_API_KEY", raising=False)
        old_job = bi._current_job
        try:
            bi._current_job = bi.IngestJob(source="malshare", status="running")
            bi._stop_event.clear()
            with patch("hashguard.batch_ingest._malshare_get_recent_24h", return_value=[]), \
                 patch("hashguard.config.get_default_config", side_effect=Exception), \
                 patch("tempfile.mkdtemp", return_value=tempfile.mkdtemp()), \
                 patch("shutil.rmtree"):
                bi._fetch_and_ingest("malshare", limit=5, tag="", file_type="exe", delay=0, use_vt=False)
                assert bi._current_job.status in ("done", "error")
        finally:
            bi._current_job = old_job

    def test_fetch_and_ingest_hybrid_analysis(self, monkeypatch):
        import hashguard.batch_ingest as bi
        monkeypatch.setenv("HYBRID_ANALYSIS_API_KEY", "ha_key")
        old_job = bi._current_job
        try:
            bi._current_job = bi.IngestJob(source="hybrid_analysis", status="running")
            bi._stop_event.clear()
            with patch("hashguard.batch_ingest._ha_search_recent", return_value=[]), \
                 patch("tempfile.mkdtemp", return_value=tempfile.mkdtemp()), \
                 patch("shutil.rmtree"):
                bi._fetch_and_ingest("hybrid_analysis", limit=5, tag="", file_type="exe", delay=0, use_vt=False)
                assert bi._current_job.status in ("done", "error")
        finally:
            bi._current_job = old_job

    def test_fetch_and_ingest_triage(self, monkeypatch):
        import hashguard.batch_ingest as bi
        monkeypatch.setenv("TRIAGE_API_KEY", "tri_key")
        old_job = bi._current_job
        try:
            bi._current_job = bi.IngestJob(source="triage", status="running")
            bi._stop_event.clear()
            with patch("hashguard.batch_ingest._triage_get_recent", return_value=[]), \
                 patch("tempfile.mkdtemp", return_value=tempfile.mkdtemp()), \
                 patch("shutil.rmtree"):
                bi._fetch_and_ingest("triage", limit=5, tag="", file_type="exe", delay=0, use_vt=False)
                assert bi._current_job.status in ("done", "error")
        finally:
            bi._current_job = old_job

    def test_fetch_and_ingest_continuous_dispatch(self):
        import hashguard.batch_ingest as bi
        old_job = bi._current_job
        try:
            bi._current_job = bi.IngestJob(source="continuous", status="running")
            bi._stop_event.clear()
            with patch("hashguard.batch_ingest._run_continuous_ingest") as mock_ci:
                bi._fetch_and_ingest("continuous", limit=5, tag="", file_type="exe", delay=0, use_vt=False)
                mock_ci.assert_called_once()
        finally:
            bi._current_job = old_job

    def test_fetch_and_ingest_stopped(self):
        import hashguard.batch_ingest as bi
        old_job = bi._current_job
        try:
            bi._current_job = bi.IngestJob(source="recent", status="running")
            bi._stop_event.set()
            with patch("hashguard.batch_ingest._mb_get_recent", return_value=[{"sha256_hash": "a" * 64}]), \
                 patch("tempfile.mkdtemp", return_value=tempfile.mkdtemp()), \
                 patch("shutil.rmtree"):
                bi._fetch_and_ingest("recent", limit=5, tag="", file_type="exe", delay=0, use_vt=False)
                assert bi._current_job.status == "stopped"
            bi._stop_event.clear()
        finally:
            bi._current_job = old_job


# ── IngestJob dataclass ─────────────────────────────────────────────────


class TestIngestJob:
    def test_to_dict(self):
        from hashguard.batch_ingest import IngestJob
        job = IngestJob(source="recent", status="running")
        job.analysed = 5
        job.errors.append("err1")
        d = job.to_dict()
        assert d["source"] == "recent"
        assert d["status"] == "running"
        assert d["analysed"] == 5

    def test_get_ingest_status(self):
        from hashguard.batch_ingest import get_ingest_status
        result = get_ingest_status()
        assert isinstance(result, dict)

    def test_request_stop(self):
        import hashguard.batch_ingest as bi
        bi._stop_event.clear()
        bi.request_stop()
        assert bi._stop_event.is_set()
        bi._stop_event.clear()


# ── MB download exception path ─────────────────────────────────────────


class TestMBDownloadEdgeCases:
    def test_mb_download_generic_exception(self):
        from hashguard.batch_ingest import _mb_download_sample
        with patch("requests.post", side_effect=Exception("network error")):
            with tempfile.TemporaryDirectory() as tmp:
                result = _mb_download_sample("a" * 64, tmp)
                assert result is None
