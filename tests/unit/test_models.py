"""Tests for data models."""

from datetime import datetime, timezone

from cspm.models import Finding, Severity, Status, ScanResult


def test_finding_to_dict():
    f = Finding(
        check_id="s3-public-access-block",
        cis_id="2.1.4",
        title="S3 Bucket Public Access Block",
        severity=Severity.CRITICAL,
        status=Status.FAIL,
        resource_arn="arn:aws:s3:::test-bucket",
        region="us-east-1",
        description="No public access block configured.",
        remediation="Enable public access block.",
    )
    d = f.to_dict()
    assert d["check_id"] == "s3-public-access-block"
    assert d["severity"] == "CRITICAL"
    assert d["status"] == "FAIL"
    assert "timestamp" in d


def test_severity_ordering():
    assert Severity.CRITICAL < Severity.HIGH
    assert Severity.HIGH < Severity.MEDIUM
    assert Severity.MEDIUM < Severity.LOW
    assert Severity.LOW < Severity.INFO


def test_scan_result_counts():
    findings = [
        Finding(
            check_id="c1", cis_id="1.1", title="T", severity=Severity.CRITICAL,
            status=Status.FAIL, resource_arn="arn:1", region="us-east-1",
            description="D", remediation="R",
        ),
        Finding(
            check_id="c2", cis_id="1.2", title="T", severity=Severity.HIGH,
            status=Status.FAIL, resource_arn="arn:2", region="us-east-1",
            description="D", remediation="R",
        ),
        Finding(
            check_id="c3", cis_id="1.3", title="T", severity=Severity.LOW,
            status=Status.PASS, resource_arn="arn:3", region="us-east-1",
            description="D", remediation="R",
        ),
    ]
    result = ScanResult(
        scan_id="test-001",
        timestamp=datetime.now(timezone.utc),
        region="us-east-1",
        findings=findings,
    )
    assert result.critical_count == 1
    assert result.high_count == 1
    assert result.fail_count == 2
    assert result.pass_count == 1


def test_scan_result_to_dict():
    result = ScanResult(
        scan_id="test-002",
        timestamp=datetime.now(timezone.utc),
        region="us-east-1",
        findings=[],
    )
    d = result.to_dict()
    assert d["scan_id"] == "test-002"
    assert d["summary"]["total"] == 0
    assert d["summary"]["fail"] == 0
