"""Celery task queue for HashGuard SaaS.

Offloads heavy work (file analysis, ML training, ingest) to background workers.

Usage:
    # Start worker:
    celery -A hashguard.tasks worker --loglevel=info

    # Start beat (scheduled tasks):
    celery -A hashguard.tasks beat --loglevel=info

Configuration via environment variables:
    CELERY_BROKER_URL   — Redis URL (default: redis://localhost:6379/0)
    CELERY_RESULT_BACKEND — Result backend (default: same as broker)
"""

import os

from celery import Celery

from hashguard.logger import get_logger

logger = get_logger(__name__)

BROKER_URL = os.environ.get("CELERY_BROKER_URL", "redis://localhost:6379/0")
RESULT_BACKEND = os.environ.get("CELERY_RESULT_BACKEND", BROKER_URL)

celery_app = Celery(
    "hashguard",
    broker=BROKER_URL,
    backend=RESULT_BACKEND,
)

celery_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
    task_track_started=True,
    task_acks_late=True,
    worker_prefetch_multiplier=1,
    result_expires=3600,
)


@celery_app.task(bind=True, name="hashguard.analyze_file", max_retries=2)
def analyze_file_task(self, file_path: str, use_vt: bool = False) -> dict:
    """Run full analysis pipeline on a file (background)."""
    try:
        from hashguard.scanner import analyze
        from hashguard.config import get_default_config
        from hashguard.database import store_sample

        config = get_default_config()
        result = analyze(file_path, vt=use_vt, config=config)
        result_dict = result.to_dict()

        sample_id = store_sample(result_dict)
        result_dict["sample_id"] = sample_id

        logger.info("Background analysis complete: %s (id=%d)", file_path, sample_id)
        return {"status": "completed", "sample_id": sample_id}
    except Exception as exc:
        logger.error("Background analysis failed: %s", exc)
        raise self.retry(exc=exc, countdown=30)


@celery_app.task(bind=True, name="hashguard.train_model", max_retries=1)
def train_model_task(self, mode: str = "binary", algorithm: str = "random_forest", test_size: float = 0.2) -> dict:
    """Train ML model in background."""
    try:
        from hashguard.ml_trainer import MLTrainer

        trainer = MLTrainer()
        result = trainer.train(mode=mode, algorithm=algorithm, test_size=test_size)
        logger.info("Background ML training complete: mode=%s", mode)
        return {"status": "completed", "result": str(result)}
    except Exception as exc:
        logger.error("Background ML training failed: %s", exc)
        raise self.retry(exc=exc, countdown=60)


@celery_app.task(name="hashguard.ingest_samples")
def ingest_samples_task(mode: str = "recent", limit: int = 50) -> dict:
    """Run sample ingestion from MalwareBazaar in background."""
    try:
        from hashguard.batch_ingest import BatchIngestor

        ingestor = BatchIngestor()
        result = ingestor.ingest(mode=mode, limit=limit)
        logger.info("Background ingest complete: mode=%s", mode)
        return {"status": "completed", "result": str(result)}
    except Exception as exc:
        logger.error("Background ingest failed: %s", exc)
        return {"status": "error", "error": str(exc)}
