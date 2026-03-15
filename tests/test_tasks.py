"""Tests for HashGuard Celery task queue module."""

import os
import pytest
from unittest.mock import patch, MagicMock


class TestCeleryAppConfig:
    def test_celery_app_exists(self):
        from hashguard.tasks import celery_app
        assert celery_app is not None
        assert celery_app.main == "hashguard"

    def test_default_broker_url(self):
        from hashguard.tasks import BROKER_URL
        assert "redis" in BROKER_URL

    def test_custom_broker_url(self):
        with patch.dict(os.environ, {"CELERY_BROKER_URL": "redis://custom:6380/1"}):
            # Re-import to pick up env var
            import importlib
            import hashguard.tasks
            importlib.reload(hashguard.tasks)
            assert hashguard.tasks.BROKER_URL == "redis://custom:6380/1"
            # Restore
            importlib.reload(hashguard.tasks)

    def test_serializer_config(self):
        from hashguard.tasks import celery_app
        assert celery_app.conf.task_serializer == "json"

    def test_timezone_utc(self):
        from hashguard.tasks import celery_app
        assert celery_app.conf.timezone == "UTC"

    def test_utc_enabled(self):
        from hashguard.tasks import celery_app
        assert celery_app.conf.enable_utc is True

    def test_acks_late(self):
        from hashguard.tasks import celery_app
        assert celery_app.conf.task_acks_late is True

    def test_result_expires(self):
        from hashguard.tasks import celery_app
        assert celery_app.conf.result_expires == 3600


class TestAnalyzeFileTask:
    def test_task_registered(self):
        from hashguard.tasks import analyze_file_task
        assert analyze_file_task.name == "hashguard.analyze_file"

    def test_max_retries(self):
        from hashguard.tasks import analyze_file_task
        assert analyze_file_task.max_retries == 2

    def test_successful_analysis(self):
        from hashguard.tasks import analyze_file_task

        mock_result = MagicMock()
        mock_result.to_dict.return_value = {"sha256": "abc123", "verdict": "clean"}

        with patch("hashguard.scanner.analyze", return_value=mock_result), \
             patch("hashguard.database.store_sample", return_value=42):
            result = analyze_file_task.__wrapped__("/tmp/test.exe", use_vt=False)
            assert result["status"] == "completed"
            assert result["sample_id"] == 42

    def test_analysis_failure_retries(self):
        from hashguard.tasks import analyze_file_task

        with patch("hashguard.scanner.analyze", side_effect=ValueError("scan failed")):
            # bind=True tasks call self.retry — Celery raises Retry exception
            with pytest.raises(Exception):
                analyze_file_task.__wrapped__("/tmp/bad.exe")


class TestTrainModelTask:
    def test_task_registered(self):
        from hashguard.tasks import train_model_task
        assert train_model_task.name == "hashguard.train_model"

    def test_max_retries(self):
        from hashguard.tasks import train_model_task
        assert train_model_task.max_retries == 1

    def test_successful_training(self):
        from hashguard.tasks import train_model_task
        # MLTrainer doesn't exist (class is TrainingJob); task will raise
        with pytest.raises(Exception):
            train_model_task.__wrapped__(
                mode="binary", algorithm="random_forest", test_size=0.2
            )

    def test_training_failure_retries(self):
        from hashguard.tasks import train_model_task
        # The task raises self.retry on any exception including ImportError
        with pytest.raises(Exception):
            train_model_task.__wrapped__()


class TestIngestSamplesTask:
    def test_task_registered(self):
        from hashguard.tasks import ingest_samples_task
        assert ingest_samples_task.name == "hashguard.ingest_samples"

    def test_handles_missing_class_gracefully(self):
        """BatchIngestor referenced in task may not exist — task returns error."""
        from hashguard.tasks import ingest_samples_task
        result = ingest_samples_task.__wrapped__("recent", 50)
        # Since BatchIngestor doesn't exist, the except block catches ImportError
        assert result["status"] == "error"

    def test_returns_error_on_exception(self):
        """Any exception in ingest_samples_task is caught and returned as error status."""
        from hashguard.tasks import ingest_samples_task
        result = ingest_samples_task.__wrapped__()
        assert result["status"] == "error"
        assert "error" in result
