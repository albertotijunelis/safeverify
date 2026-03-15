"""Tests for the cloud_storage module."""

import os
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from hashguard.cloud_storage import (
    LocalStorage,
    StorageBackend,
    get_storage,
    sample_storage_key,
    dataset_storage_key,
    store_sample_binary,
)


# ── StorageBackend abstract ─────────────────────────────────────────────────


class TestStorageBackend:
    def test_put_raises(self):
        with pytest.raises(NotImplementedError):
            StorageBackend().put("k", b"v")

    def test_get_raises(self):
        with pytest.raises(NotImplementedError):
            StorageBackend().get("k")

    def test_delete_raises(self):
        with pytest.raises(NotImplementedError):
            StorageBackend().delete("k")

    def test_exists_raises(self):
        with pytest.raises(NotImplementedError):
            StorageBackend().exists("k")

    def test_get_url_raises(self):
        with pytest.raises(NotImplementedError):
            StorageBackend().get_url("k")

    def test_list_keys_raises(self):
        with pytest.raises(NotImplementedError):
            StorageBackend().list_keys()

    def test_size_raises(self):
        with pytest.raises(NotImplementedError):
            StorageBackend().size("k")


# ── LocalStorage ─────────────────────────────────────────────────────────────


class TestLocalStorage:
    @pytest.fixture
    def storage(self, tmp_path):
        return LocalStorage(root=str(tmp_path))

    def test_put_and_get(self, storage):
        storage.put("test/file.bin", b"hello world")
        assert storage.get("test/file.bin") == b"hello world"

    def test_put_returns_key(self, storage):
        key = storage.put("mykey.bin", b"data")
        assert key == "mykey.bin"

    def test_get_missing_raises(self, storage):
        with pytest.raises(FileNotFoundError):
            storage.get("nonexistent")

    def test_exists_true(self, storage):
        storage.put("exists.txt", b"y")
        assert storage.exists("exists.txt") is True

    def test_exists_false(self, storage):
        assert storage.exists("nope.txt") is False

    def test_delete_existing(self, storage):
        storage.put("del.txt", b"x")
        assert storage.delete("del.txt") is True
        assert storage.exists("del.txt") is False

    def test_delete_missing(self, storage):
        assert storage.delete("nope.txt") is False

    def test_list_keys_empty(self, storage):
        assert storage.list_keys() == []

    def test_list_keys(self, storage):
        storage.put("a/1.bin", b"x")
        storage.put("a/2.bin", b"y")
        storage.put("b/3.bin", b"z")
        keys = storage.list_keys()
        assert len(keys) == 3
        assert "a/1.bin" in keys

    def test_list_keys_prefix(self, storage):
        storage.put("samples/aa/f1.bin", b"x")
        storage.put("samples/bb/f2.bin", b"y")
        storage.put("datasets/d1.csv", b"z")
        keys = storage.list_keys(prefix="samples")
        assert len(keys) == 2

    def test_size(self, storage):
        storage.put("sized.bin", b"12345")
        assert storage.size("sized.bin") == 5

    def test_size_missing(self, storage):
        assert storage.size("nope") == 0

    def test_get_url(self, storage):
        url = storage.get_url("test/key")
        assert url == "/api/storage/test/key"

    def test_creates_subdirs(self, storage):
        storage.put("deep/nested/dir/file.bin", b"x")
        assert storage.get("deep/nested/dir/file.bin") == b"x"

    def test_rejects_absolute_path(self, storage):
        with pytest.raises(ValueError, match="Invalid storage key"):
            storage.put("C:/etc/passwd" if os.name == "nt" else "/etc/passwd", b"bad")

    def test_rejects_traversal(self, storage):
        with pytest.raises(ValueError, match="Invalid storage key"):
            storage.put("../escape.txt", b"bad")


# ── S3Storage (mocked) ──────────────────────────────────────────────────────


try:
    import boto3
    HAS_BOTO3 = True
except ImportError:
    HAS_BOTO3 = False


@pytest.mark.skipif(not HAS_BOTO3, reason="boto3 not installed")
class TestS3Storage:
    @patch.dict(os.environ, {
        "HG_S3_BUCKET": "test-bucket",
        "HG_S3_REGION": "us-west-2",
        "HG_S3_ACCESS_KEY": "TESTKEY",
        "HG_S3_SECRET_KEY": "TESTSECRET",
    })
    @patch("boto3.client")
    def test_init(self, mock_boto):
        from hashguard.cloud_storage import S3Storage
        s3 = S3Storage()
        assert s3.bucket == "test-bucket"
        mock_boto.assert_called_once()

    @patch.dict(os.environ, {
        "HG_S3_BUCKET": "b",
        "HG_S3_ACCESS_KEY": "K",
        "HG_S3_SECRET_KEY": "S",
    })
    @patch("boto3.client")
    def test_put(self, mock_boto):
        from hashguard.cloud_storage import S3Storage
        s3 = S3Storage()
        key = s3.put("test.bin", b"data", metadata={"sha256": "abc"})
        assert key == "test.bin"
        s3._client.put_object.assert_called_once()

    @patch.dict(os.environ, {
        "HG_S3_BUCKET": "b",
        "HG_S3_ACCESS_KEY": "K",
        "HG_S3_SECRET_KEY": "S",
    })
    @patch("boto3.client")
    def test_get(self, mock_boto):
        from hashguard.cloud_storage import S3Storage
        s3 = S3Storage()
        body_mock = MagicMock()
        body_mock.read.return_value = b"content"
        s3._client.get_object.return_value = {"Body": body_mock}
        assert s3.get("key") == b"content"

    @patch.dict(os.environ, {
        "HG_S3_BUCKET": "b",
        "HG_S3_ACCESS_KEY": "K",
        "HG_S3_SECRET_KEY": "S",
    })
    @patch("boto3.client")
    def test_exists_true(self, mock_boto):
        from hashguard.cloud_storage import S3Storage
        s3 = S3Storage()
        s3._client.head_object.return_value = {}
        assert s3.exists("k") is True

    @patch.dict(os.environ, {
        "HG_S3_BUCKET": "b",
        "HG_S3_ACCESS_KEY": "K",
        "HG_S3_SECRET_KEY": "S",
    })
    @patch("boto3.client")
    def test_exists_false(self, mock_boto):
        from hashguard.cloud_storage import S3Storage
        s3 = S3Storage()
        s3._client.head_object.side_effect = Exception("404")
        assert s3.exists("k") is False

    @patch.dict(os.environ, {
        "HG_S3_BUCKET": "b",
        "HG_S3_ACCESS_KEY": "K",
        "HG_S3_SECRET_KEY": "S",
    })
    @patch("boto3.client")
    def test_delete(self, mock_boto):
        from hashguard.cloud_storage import S3Storage
        s3 = S3Storage()
        assert s3.delete("k") is True
        s3._client.delete_object.assert_called_once()

    @patch.dict(os.environ, {
        "HG_S3_BUCKET": "b",
        "HG_S3_ACCESS_KEY": "K",
        "HG_S3_SECRET_KEY": "S",
    })
    @patch("boto3.client")
    def test_get_url(self, mock_boto):
        from hashguard.cloud_storage import S3Storage
        s3 = S3Storage()
        s3._client.generate_presigned_url.return_value = "https://s3/signed"
        url = s3.get_url("key", expires=600)
        assert url == "https://s3/signed"

    @patch.dict(os.environ, {
        "HG_S3_BUCKET": "b",
        "HG_S3_ACCESS_KEY": "K",
        "HG_S3_SECRET_KEY": "S",
    })
    @patch("boto3.client")
    def test_list_keys(self, mock_boto):
        from hashguard.cloud_storage import S3Storage
        s3 = S3Storage()
        s3._client.list_objects_v2.return_value = {
            "Contents": [{"Key": "a"}, {"Key": "b"}],
            "IsTruncated": False,
        }
        keys = s3.list_keys(prefix="samples")
        assert keys == ["a", "b"]

    @patch.dict(os.environ, {
        "HG_S3_BUCKET": "b",
        "HG_S3_ACCESS_KEY": "K",
        "HG_S3_SECRET_KEY": "S",
    })
    @patch("boto3.client")
    def test_list_keys_paginated(self, mock_boto):
        from hashguard.cloud_storage import S3Storage
        s3 = S3Storage()
        s3._client.list_objects_v2.side_effect = [
            {"Contents": [{"Key": "a"}], "IsTruncated": True, "NextContinuationToken": "tok"},
            {"Contents": [{"Key": "b"}], "IsTruncated": False},
        ]
        assert s3.list_keys() == ["a", "b"]

    @patch.dict(os.environ, {
        "HG_S3_BUCKET": "b",
        "HG_S3_ACCESS_KEY": "K",
        "HG_S3_SECRET_KEY": "S",
    })
    @patch("boto3.client")
    def test_size(self, mock_boto):
        from hashguard.cloud_storage import S3Storage
        s3 = S3Storage()
        s3._client.head_object.return_value = {"ContentLength": 1024}
        assert s3.size("k") == 1024

    @patch.dict(os.environ, {
        "HG_S3_BUCKET": "b",
        "HG_S3_ACCESS_KEY": "K",
        "HG_S3_SECRET_KEY": "S",
    })
    @patch("boto3.client")
    def test_size_missing(self, mock_boto):
        from hashguard.cloud_storage import S3Storage
        s3 = S3Storage()
        s3._client.head_object.side_effect = Exception("404")
        assert s3.size("k") == 0


# ── Helper functions ─────────────────────────────────────────────────────────


class TestHelpers:
    def test_sample_storage_key_format(self):
        sha = "ab" + "c" * 62
        key = sample_storage_key(sha)
        assert key.startswith("samples/ab/")
        assert sha.lower() in key

    def test_sample_key_sharding(self):
        key1 = sample_storage_key("aa" + "0" * 62)
        key2 = sample_storage_key("ff" + "0" * 62)
        assert key1.split("/")[1] == "aa"
        assert key2.split("/")[1] == "ff"

    def test_dataset_storage_key(self):
        key = dataset_storage_key("ds1", "2.0", fmt="jsonl")
        assert key == "datasets/ds1/v2.0/dataset.jsonl"

    def test_dataset_key_default_csv(self):
        key = dataset_storage_key("ds1", "1")
        assert key.endswith(".csv")


# ── get_storage singleton ────────────────────────────────────────────────────


class TestGetStorage:
    def test_local_default(self):
        import hashguard.cloud_storage as cs
        cs._storage = None
        with patch.dict(os.environ, {"HG_STORAGE_BACKEND": "local"}, clear=False):
            storage = get_storage()
            assert isinstance(storage, LocalStorage)
        cs._storage = None

    @pytest.mark.skipif(not HAS_BOTO3, reason="boto3 not installed")
    def test_s3_backend(self):
        import hashguard.cloud_storage as cs
        cs._storage = None
        with patch.dict(os.environ, {
            "HG_STORAGE_BACKEND": "s3",
            "HG_S3_BUCKET": "b",
            "HG_S3_ACCESS_KEY": "K",
            "HG_S3_SECRET_KEY": "S",
        }, clear=False):
            with patch("boto3.client"):
                from hashguard.cloud_storage import S3Storage
                storage = get_storage()
                assert isinstance(storage, S3Storage)
        cs._storage = None

    def test_singleton_returns_same(self):
        import hashguard.cloud_storage as cs
        cs._storage = None
        with patch.dict(os.environ, {"HG_STORAGE_BACKEND": "local"}, clear=False):
            s1 = get_storage()
            s2 = get_storage()
            assert s1 is s2
        cs._storage = None


# ── store_sample_binary ──────────────────────────────────────────────────────


class TestStoreSampleBinary:
    def test_stores_new_sample(self, tmp_path):
        import hashguard.cloud_storage as cs
        cs._storage = None
        storage = LocalStorage(root=str(tmp_path))
        cs._storage = storage
        sha = "ab" + "cd" * 31
        key = store_sample_binary(sha, b"MZ binary data")
        assert storage.exists(key)
        assert storage.get(key) == b"MZ binary data"
        cs._storage = None

    def test_skips_existing(self, tmp_path):
        import hashguard.cloud_storage as cs
        cs._storage = None
        storage = LocalStorage(root=str(tmp_path))
        cs._storage = storage
        sha = "ab" + "cd" * 31
        store_sample_binary(sha, b"first")
        store_sample_binary(sha, b"second")  # should not overwrite
        key = sample_storage_key(sha)
        assert storage.get(key) == b"first"
        cs._storage = None
