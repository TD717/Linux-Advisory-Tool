"""Pytest fixtures and path helpers."""

from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def rules_examples_dir() -> Path:
    return PROJECT_ROOT / "rules" / "examples"


@pytest.fixture
def rules_cis_dir() -> Path:
    return PROJECT_ROOT / "rules" / "cis"


@pytest.fixture
def project_root() -> Path:
    return PROJECT_ROOT
