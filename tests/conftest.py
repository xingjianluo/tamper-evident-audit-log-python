"""Shared fixtures + structured test logging (input / evidence / verdict)."""

from __future__ import annotations

import logging
import sys

import pytest

from audit.config import Settings
from audit.service import AuditService

logger = logging.getLogger("audit.tests")


@pytest.fixture
def settings(tmp_path):
    return Settings(data_dir=str(tmp_path / "data"), retention_days=90)


@pytest.fixture
def service(settings):
    return AuditService(settings)


def log_case(case: str, payload: object, evidence: object, verdict: object) -> None:
    logger.info("[CASE] %s\n  input=%s\n  evidence=%s\n  verdict=%s",
                case, payload, evidence, verdict)


def pytest_configure(config):
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(logging.Formatter("%(levelname)s %(name)s: %(message)s"))
    root = logging.getLogger("audit.tests")
    root.setLevel(logging.INFO)
    root.addHandler(handler)
