"""Cloud object storage abstraction for HashGuard.

Supports:
- AWS S3 (production)
- S3-compatible (MinIO, DigitalOcean Spaces, etc.)
- Local filesystem (development/testing fallback)

Configure via environment variables:
  HG_STORAGE_BACKEND  = s3 | local   (default: local)
  HG_S3_BUCKET        = hashguard-samples
  HG_S3_REGION        = us-east-1
  HG_S3_ENDPOINT      = https://s3.amazonaws.com  (optional, for S3-compat)
  HG_S3_ACCESS_KEY    = AKIA...       (optional if using IAM roles)
  HG_S3_SECRET_KEY    = ...           (optional if using IAM roles)
  HG_LOCAL_STORAGE    = /path/to/storage  (for local backend)
"""

import hashlib
import os
import shutil
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from hashguard.logger import get_logger

logger = get_logger(__name__)


def _default_local_root() -> str:
    app_data = os.environ.get("APPDATA") or os.path.expanduser("~")
    return os.path.join(app_data, "HashGuard", "storage")


class StorageBackend:
    """Abstract storage interface."""

    def put(self, key: str, data: bytes, content_type: str = "application/octet-stream", metadata: Optional[dict] = None) -> str:
        raise NotImplementedError

    def get(self, key: str) -> bytes:
        raise NotImplementedError

    def delete(self, key: str) -> bool:
        raise NotImplementedError

    def exists(self, key: str) -> bool:
        raise NotImplementedError

    def get_url(self, key: str, expires: int = 3600) -> str:
        raise NotImplementedError

    def list_keys(self, prefix: str = "") -> list[str]:
        raise NotImplementedError

    def size(self, key: str) -> int:
        raise NotImplementedError


class LocalStorage(StorageBackend):
    """Filesystem-based storage for development."""

    def __init__(self, root: Optional[str] = None):
        self.root = Path(root or _default_local_root())
        self.root.mkdir(parents=True, exist_ok=True)

    def _resolve(self, key: str) -> Path:
        safe = Path(key)
        if safe.is_absolute() or ".." in safe.parts:
            raise ValueError(f"Invalid storage key: {key}")
        return self.root / safe

    def put(self, key: str, data: bytes, content_type: str = "application/octet-stream", metadata: Optional[dict] = None) -> str:
        path = self._resolve(key)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        return key

    def get(self, key: str) -> bytes:
        path = self._resolve(key)
        if not path.exists():
            raise FileNotFoundError(f"Object not found: {key}")
        return path.read_bytes()

    def delete(self, key: str) -> bool:
        path = self._resolve(key)
        if path.exists():
            path.unlink()
            return True
        return False

    def exists(self, key: str) -> bool:
        return self._resolve(key).exists()

    def get_url(self, key: str, expires: int = 3600) -> str:
        return f"/api/storage/{key}"

    def list_keys(self, prefix: str = "") -> list[str]:
        base = self._resolve(prefix) if prefix else self.root
        if not base.exists():
            return []
        return [
            str(p.relative_to(self.root)).replace("\\", "/")
            for p in base.rglob("*")
            if p.is_file()
        ]

    def size(self, key: str) -> int:
        path = self._resolve(key)
        return path.stat().st_size if path.exists() else 0


class S3Storage(StorageBackend):
    """AWS S3 / S3-compatible storage."""

    def __init__(self):
        try:
            import boto3
        except ImportError:
            raise ImportError("boto3 required for S3 storage: pip install boto3")

        self.bucket = os.environ.get("HG_S3_BUCKET", "hashguard-samples")
        region = os.environ.get("HG_S3_REGION", "us-east-1")
        endpoint = os.environ.get("HG_S3_ENDPOINT")
        access_key = os.environ.get("HG_S3_ACCESS_KEY")
        secret_key = os.environ.get("HG_S3_SECRET_KEY")

        kwargs = {"region_name": region}
        if endpoint:
            kwargs["endpoint_url"] = endpoint
        if access_key and secret_key:
            kwargs["aws_access_key_id"] = access_key
            kwargs["aws_secret_access_key"] = secret_key

        self._client = boto3.client("s3", **kwargs)
        logger.info("S3 storage initialized: bucket=%s region=%s", self.bucket, region)

    def put(self, key: str, data: bytes, content_type: str = "application/octet-stream", metadata: Optional[dict] = None) -> str:
        params = {
            "Bucket": self.bucket,
            "Key": key,
            "Body": data,
            "ContentType": content_type,
        }
        if metadata:
            params["Metadata"] = {k: str(v) for k, v in metadata.items()}
        self._client.put_object(**params)
        return key

    def get(self, key: str) -> bytes:
        resp = self._client.get_object(Bucket=self.bucket, Key=key)
        return resp["Body"].read()

    def delete(self, key: str) -> bool:
        self._client.delete_object(Bucket=self.bucket, Key=key)
        return True

    def exists(self, key: str) -> bool:
        try:
            self._client.head_object(Bucket=self.bucket, Key=key)
            return True
        except Exception:
            return False

    def get_url(self, key: str, expires: int = 3600) -> str:
        return self._client.generate_presigned_url(
            "get_object",
            Params={"Bucket": self.bucket, "Key": key},
            ExpiresIn=expires,
        )

    def list_keys(self, prefix: str = "") -> list[str]:
        keys = []
        params = {"Bucket": self.bucket, "Prefix": prefix}
        while True:
            resp = self._client.list_objects_v2(**params)
            for obj in resp.get("Contents", []):
                keys.append(obj["Key"])
            if not resp.get("IsTruncated"):
                break
            params["ContinuationToken"] = resp["NextContinuationToken"]
        return keys

    def size(self, key: str) -> int:
        try:
            resp = self._client.head_object(Bucket=self.bucket, Key=key)
            return resp.get("ContentLength", 0)
        except Exception:
            return 0


# ── Singleton ───────────────────────────────────────────────────────────────

_storage: Optional[StorageBackend] = None


def get_storage() -> StorageBackend:
    """Get the configured storage backend (singleton)."""
    global _storage
    if _storage is not None:
        return _storage

    backend = os.environ.get("HG_STORAGE_BACKEND", "local").lower()
    if backend == "s3":
        _storage = S3Storage()
    else:
        _storage = LocalStorage()
    logger.info("Storage backend: %s", backend)
    return _storage


def sample_storage_key(sha256: str) -> str:
    """Generate a sharded storage key for a sample binary.

    Uses first 2 hex chars for sharding: samples/ab/abcdef...
    """
    prefix = sha256[:2].lower()
    return f"samples/{prefix}/{sha256.lower()}"


def dataset_storage_key(dataset_id: str, version: str, fmt: str = "csv") -> str:
    """Generate storage key for a dataset export."""
    return f"datasets/{dataset_id}/v{version}/dataset.{fmt}"


def store_sample_binary(sha256: str, data: bytes) -> str:
    """Store a sample binary, return storage key."""
    key = sample_storage_key(sha256)
    storage = get_storage()
    if not storage.exists(key):
        storage.put(key, data, content_type="application/octet-stream",
                    metadata={"sha256": sha256, "uploaded": datetime.now(timezone.utc).isoformat()})
        logger.info("Stored sample binary: %s (%d bytes)", sha256[:16], len(data))
    return key
