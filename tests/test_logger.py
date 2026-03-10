"""Tests for HashGuard logger module."""

import logging

from hashguard.logger import get_logger


class TestGetLogger:
    def test_returns_logger(self):
        log = get_logger("test_module")
        assert isinstance(log, logging.Logger)
        assert log.name == "test_module"

    def test_has_handler(self):
        log = get_logger("test_handler")
        assert len(log.handlers) >= 1

    def test_default_level(self):
        log = get_logger("test_level")
        assert log.level == logging.INFO

    def test_custom_level(self):
        log = get_logger("test_custom", level=logging.DEBUG)
        assert log.level == logging.DEBUG

    def test_no_duplicate_handlers(self):
        """Calling get_logger twice should not add duplicate handlers."""
        name = "test_no_dup"
        log1 = get_logger(name)
        n = len(log1.handlers)
        log2 = get_logger(name)
        assert len(log2.handlers) == n
        assert log1 is log2
