"""Configuration management for HashGuard."""

import json
import os
import sys
from dataclasses import asdict, dataclass, field, fields
from pathlib import Path
from typing import Dict, Any, Optional


def _default_signatures_path() -> str:
    """Resolve signatures.json: env var > frozen > package data > project root."""
    env = os.getenv("HASHGUARD_SIGNATURES")
    if env:
        return env
    base = getattr(sys, "_MEIPASS", None)
    if base:
        return os.path.join(base, "signatures.json")
    # Package data (pip install)
    pkg = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data", "signatures.json")
    if os.path.isfile(pkg):
        return pkg
    # Development fallback (editable install / project root)
    return os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "signatures.json")


@dataclass
class HashGuardConfig:
    """
    Master configuration for HashGuard.

    Attributes:
        signatures_file: Path to malware signature database
        vt_api_key: VirusTotal API key
        hash_algorithms: Hash algorithms to compute
        chunk_size: File read buffer size in bytes
        max_file_size: Maximum file size to analyze (0 = unlimited)
        log_level: Logging level
    """

    signatures_file: str = field(default_factory=_default_signatures_path)
    vt_api_key: Optional[str] = field(default_factory=lambda: os.getenv("VT_API_KEY"))
    hash_algorithms: list = field(default_factory=lambda: ["md5", "sha1", "sha256"])
    chunk_size: int = 65536  # 64KB chunks for faster I/O
    max_file_size: int = 0  # 0 = unlimited
    log_level: str = "INFO"

    def to_dict(self) -> Dict[str, Any]:
        """Convert config to dictionary."""
        data = asdict(self)
        # Don't expose API key in exported config
        data["vt_api_key"] = "***REDACTED***" if self.vt_api_key else None
        return data

    @classmethod
    def from_file(cls, config_path: str) -> "HashGuardConfig":
        """Load configuration from JSON file."""
        if not os.path.exists(config_path):
            return cls()

        try:
            with open(config_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            allowed = {f.name for f in fields(cls)}
            filtered = {k: v for k, v in data.items() if k in allowed}
            return cls(**filtered)
        except Exception:
            return cls()

    def save(self, config_path: str) -> None:
        """Save configuration to JSON file."""
        os.makedirs(os.path.dirname(config_path) or ".", exist_ok=True)
        data = asdict(self)
        # Never persist API keys to disk — read from env at runtime
        data.pop("vt_api_key", None)
        with open(config_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)


def get_default_config() -> HashGuardConfig:
    """Get default configuration instance."""
    return HashGuardConfig()
