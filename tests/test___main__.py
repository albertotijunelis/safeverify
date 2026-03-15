"""Tests for HashGuard __main__ module."""

import subprocess
import sys
import pytest
from unittest.mock import patch


class TestMainEntry:
    def test_import_main_module_calls_main(self):
        """Importing __main__ calls main(), which parses sys.argv and may exit."""
        with patch("hashguard.cli.main") as mock_main:
            import importlib
            import hashguard.__main__ as m
            importlib.reload(m)
            mock_main.assert_called()

    def test_main_callable(self):
        from hashguard.cli import main
        assert callable(main)

    def test_main_help_via_subprocess(self):
        result = subprocess.run(
            [sys.executable, "-m", "hashguard", "--help"],
            capture_output=True, text=True, timeout=30,
        )
        assert result.returncode == 0
        assert "hashguard" in result.stdout.lower()

    def test_main_version_via_subprocess(self):
        result = subprocess.run(
            [sys.executable, "-m", "hashguard", "--version"],
            capture_output=True, text=True, timeout=30,
        )
        assert result.returncode == 0
        assert "hashguard" in result.stdout.lower()

    def test_run_as_module(self):
        result = subprocess.run(
            [sys.executable, "-m", "hashguard", "--help"],
            capture_output=True, text=True, timeout=30,
        )
        assert result.returncode == 0
        assert "usage" in result.stdout.lower() or "hashguard" in result.stdout.lower()
