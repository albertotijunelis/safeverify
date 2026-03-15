"""Shared test fixtures for HashGuard test suite."""

import os

import pytest


@pytest.fixture(autouse=True)
def _unlock_all_plans(monkeypatch):
    """Grant enterprise-level access in tests so plan gating doesn't block
    endpoint tests.  Production defaults to 'free' when HASHGUARD_AUTH=0."""
    monkeypatch.setenv("HASHGUARD_DEFAULT_PLAN", "enterprise")
