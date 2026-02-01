"""Integration test that runs a full scan against LocalStack.

Requires LocalStack running on localhost:4566 with vulnerable resources provisioned.
Skip if LOCALSTACK_ENDPOINT is not set.
"""

import os

import pytest

from cspm.config import Config
from cspm.scanner import run_scan
from cspm.models import Status


LOCALSTACK_ENDPOINT = os.environ.get("LOCALSTACK_ENDPOINT")

pytestmark = pytest.mark.skipif(
    not LOCALSTACK_ENDPOINT,
    reason="LOCALSTACK_ENDPOINT not set — skipping integration tests",
)


@pytest.fixture
def localstack_config():
    return Config(
        regions=["us-east-1"],
        endpoint_url=LOCALSTACK_ENDPOINT,
        checks=["all"],
    )


def test_scan_returns_findings(localstack_config):
    result = run_scan(localstack_config)
    assert len(result.findings) > 0, "Scan should return at least one finding"


def test_scan_detects_failures(localstack_config):
    result = run_scan(localstack_config)
    failures = [f for f in result.findings if f.status == Status.FAIL]
    assert len(failures) > 0, "Scan should detect at least one misconfiguration"


def test_scan_result_has_scan_id(localstack_config):
    result = run_scan(localstack_config)
    assert result.scan_id is not None
    assert len(result.scan_id) > 0
