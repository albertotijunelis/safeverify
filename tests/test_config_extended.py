"""Extended tests for HashGuard config module — covers remaining branches."""

import json
import os
import sys
from unittest.mock import patch

import pytest

from hashguard.config import HashGuardConfig, get_default_config, _default_signatures_path


# ── _default_signatures_path ─────────────────────────────────────────────────

class TestDefaultSignaturesPath:
    def test_env_var_override(self, monkeypatch):
        monkeypatch.setenv("HASHGUARD_SIGNATURES", "/custom/path/sigs.json")
        result = _default_signatures_path()
        assert result == "/custom/path/sigs.json"

    def test_frozen_path(self, monkeypatch, tmp_path):
        monkeypatch.delenv("HASHGUARD_SIGNATURES", raising=False)
        # Create the expected data/signatures.json inside the fake _MEIPASS
        data_dir = tmp_path / "data"
        data_dir.mkdir()
        sig_file = data_dir / "signatures.json"
        sig_file.write_text("{}")
        sys.frozen = True
        sys._MEIPASS = str(tmp_path)
        try:
            result = _default_signatures_path()
        finally:
            del sys.frozen
            del sys._MEIPASS
        assert "signatures.json" in result
        assert str(tmp_path) in result

    def test_package_path(self, monkeypatch):
        monkeypatch.delenv("HASHGUARD_SIGNATURES", raising=False)
        if hasattr(sys, "frozen"):
            monkeypatch.delattr(sys, "frozen")
        result = _default_signatures_path()
        assert "signatures.json" in result

    def test_no_env_no_frozen(self, monkeypatch):
        monkeypatch.delenv("HASHGUARD_SIGNATURES", raising=False)
        if hasattr(sys, "frozen"):
            monkeypatch.delattr(sys, "frozen")
        result = _default_signatures_path()
        assert isinstance(result, str)
        assert result.endswith("signatures.json")


# ── HashGuardConfig ──────────────────────────────────────────────────────────

class TestHashGuardConfigExtended:
    def test_default_hash_algorithms(self):
        config = HashGuardConfig()
        assert config.hash_algorithms == ["md5", "sha1", "sha256"]

    def test_default_chunk_size(self):
        config = HashGuardConfig()
        assert config.chunk_size == 65536

    def test_default_max_file_size(self):
        config = HashGuardConfig()
        assert config.max_file_size == 0

    def test_default_log_level(self):
        config = HashGuardConfig()
        assert config.log_level == "INFO"

    def test_vt_key_from_env(self, monkeypatch):
        monkeypatch.setenv("VT_API_KEY", "test-vt-key-123")
        config = HashGuardConfig()
        assert config.vt_api_key == "test-vt-key-123"

    def test_abuse_ch_key_from_env(self, monkeypatch):
        monkeypatch.setenv("ABUSE_CH_API_KEY", "abuse-key-456")
        config = HashGuardConfig()
        assert config.abuse_ch_api_key == "abuse-key-456"

    def test_to_dict_redacts_abuse_ch(self):
        config = HashGuardConfig(abuse_ch_api_key="secret")
        d = config.to_dict()
        assert d["abuse_ch_api_key"] == "***REDACTED***"

    def test_to_dict_none_keys(self):
        config = HashGuardConfig(vt_api_key=None, abuse_ch_api_key=None)
        d = config.to_dict()
        assert d["vt_api_key"] is None
        assert d["abuse_ch_api_key"] is None

    def test_from_file_invalid_json(self, tmp_path):
        cfg_path = tmp_path / "bad.json"
        cfg_path.write_text("NOT JSON{{{")
        config = HashGuardConfig.from_file(str(cfg_path))
        # Should return defaults
        assert config.log_level == "INFO"

    def test_from_file_ignores_unknown_keys(self, tmp_path):
        cfg_path = tmp_path / "extra.json"
        cfg_path.write_text('{"log_level": "WARNING", "unknown_key": "value"}')
        config = HashGuardConfig.from_file(str(cfg_path))
        assert config.log_level == "WARNING"
        assert not hasattr(config, "unknown_key")

    def test_from_file_custom_chunk_size(self, tmp_path):
        cfg_path = tmp_path / "chunk.json"
        cfg_path.write_text('{"chunk_size": 4096}')
        config = HashGuardConfig.from_file(str(cfg_path))
        assert config.chunk_size == 4096

    def test_save_creates_dirs(self, tmp_path):
        cfg_path = str(tmp_path / "sub" / "dir" / "config.json")
        config = HashGuardConfig(log_level="DEBUG")
        config.save(cfg_path)
        assert os.path.exists(cfg_path)
        loaded = HashGuardConfig.from_file(cfg_path)
        assert loaded.log_level == "DEBUG"

    def test_save_excludes_both_api_keys(self, tmp_path):
        cfg_path = str(tmp_path / "keys.json")
        config = HashGuardConfig(vt_api_key="vt_secret", abuse_ch_api_key="abuse_secret")
        config.save(cfg_path)
        with open(cfg_path) as f:
            data = json.load(f)
        assert "vt_api_key" not in data
        assert "abuse_ch_api_key" not in data

    def test_save_preserves_algorithms(self, tmp_path):
        cfg_path = str(tmp_path / "algo.json")
        config = HashGuardConfig(hash_algorithms=["sha256", "sha512"])
        config.save(cfg_path)
        loaded = HashGuardConfig.from_file(cfg_path)
        assert loaded.hash_algorithms == ["sha256", "sha512"]

    def test_save_max_file_size(self, tmp_path):
        cfg_path = str(tmp_path / "maxsize.json")
        config = HashGuardConfig(max_file_size=1000000)
        config.save(cfg_path)
        loaded = HashGuardConfig.from_file(cfg_path)
        assert loaded.max_file_size == 1000000


# ── get_default_config ───────────────────────────────────────────────────────

class TestGetDefaultConfig:
    def test_returns_config(self):
        config = get_default_config()
        assert isinstance(config, HashGuardConfig)

    def test_returns_new_instance(self):
        c1 = get_default_config()
        c2 = get_default_config()
        assert c1 is not c2

    def test_default_signatures_file_set(self):
        config = get_default_config()
        assert config.signatures_file.endswith("signatures.json")
