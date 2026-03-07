"""Smoke tests for HashGuard GUI module."""

import pytest


def test_import_gui():
    """The GUI module should import without raising exceptions."""
    from hashguard import gui

    assert hasattr(gui, "main")
    assert hasattr(gui, "HashGuardGUI")
