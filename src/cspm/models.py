"""Data models for CSPM findings."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum


class Severity(Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

    @property
    def rank(self) -> int:
        return {
            Severity.CRITICAL: 0,
            Severity.HIGH: 1,
            Severity.MEDIUM: 2,
            Severity.LOW: 3,
            Severity.INFO: 4,
        }[self]

    def __lt__(self, other: Severity) -> bool:
        return self.rank < other.rank


class Status(Enum):
    FAIL = "FAIL"
    PASS = "PASS"
    ERROR = "ERROR"


@dataclass
class Finding:
    check_id: str
    cis_id: str
    title: str
    severity: Severity
    status: Status
    resource_arn: str
    region: str
    description: str
    remediation: str
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def to_dict(self) -> dict:
        return {
            "check_id": self.check_id,
            "cis_id": self.cis_id,
            "title": self.title,
            "severity": self.severity.value,
            "status": self.status.value,
            "resource_arn": self.resource_arn,
            "region": self.region,
            "description": self.description,
            "remediation": self.remediation,
            "timestamp": self.timestamp.isoformat(),
        }


@dataclass
class ScanResult:
    scan_id: str
    timestamp: datetime
    region: str
    findings: list[Finding] = field(default_factory=list)

    @property
    def critical_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.CRITICAL and f.status == Status.FAIL)

    @property
    def high_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.HIGH and f.status == Status.FAIL)

    @property
    def fail_count(self) -> int:
        return sum(1 for f in self.findings if f.status == Status.FAIL)

    @property
    def pass_count(self) -> int:
        return sum(1 for f in self.findings if f.status == Status.PASS)

    def to_dict(self) -> dict:
        return {
            "scan_id": self.scan_id,
            "timestamp": self.timestamp.isoformat(),
            "region": self.region,
            "summary": {
                "total": len(self.findings),
                "fail": self.fail_count,
                "pass": self.pass_count,
                "critical": self.critical_count,
                "high": self.high_count,
            },
            "findings": [f.to_dict() for f in self.findings],
        }
