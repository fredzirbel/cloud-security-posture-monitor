"""Scanner orchestrator — discovers and runs all security checks."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

import boto3

from cspm.config import Config
from cspm.models import ScanResult
from cspm.checks import ALL_CHECKS


def run_scan(config: Config) -> ScanResult:
    """Execute all enabled checks across configured regions and return a ScanResult."""
    session = boto3.Session()
    scan_id = str(uuid.uuid4())[:8]
    all_findings = []

    for region in config.regions:
        for check_cls in ALL_CHECKS:
            if config.checks != ["all"] and check_cls.id not in config.checks:
                continue

            try:
                check = check_cls(
                    session=session,
                    region=region,
                    endpoint_url=config.endpoint_url,
                )
                findings = check.run()
                all_findings.extend(findings)
            except Exception as e:
                print(f"[ERROR] Check {check_cls.id} in {region} failed: {e}")

    return ScanResult(
        scan_id=scan_id,
        timestamp=datetime.now(timezone.utc),
        region=",".join(config.regions),
        findings=all_findings,
    )
