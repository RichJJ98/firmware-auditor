"""Shared pytest fixtures for firmware-auditor."""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest


@pytest.fixture
def fixture_root(request: pytest.FixtureRequest) -> Path:
    """Create a per-test rootfs under the workspace and remove it afterwards."""
    root = Path(__file__).resolve().parent.parent / ".tmp_test_fixtures" / request.node.name
    if root.exists():
        shutil.rmtree(root)
    root.mkdir(parents=True)
    try:
        yield root
    finally:
        if root.exists():
            shutil.rmtree(root)


@pytest.fixture
def rootfs(fixture_root: Path) -> Path:
    """Return an empty temporary rootfs fixture."""
    return fixture_root
