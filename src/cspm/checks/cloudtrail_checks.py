"""CloudTrail security checks."""

from __future__ import annotations

from botocore.exceptions import ClientError

from cspm.checks.base import BaseCheck
from cspm.models import Finding, Severity, Status


class CloudTrailEnabledCheck(BaseCheck):
    id = "cloudtrail-enabled"
    title = "CloudTrail Is Enabled in All Regions"
    cis_id = "3.1"
    service = "cloudtrail"

    def run(self) -> list[Finding]:
        ct = self._get_client("cloudtrail")
        findings = []

        try:
            trails = ct.describe_trails().get("trailList", [])

            if not trails:
                findings.append(Finding(
                    check_id=self.id,
                    cis_id=self.cis_id,
                    title=self.title,
                    severity=Severity.CRITICAL,
                    status=Status.FAIL,
                    resource_arn=f"arn:aws:cloudtrail:{self.region}::trail/none",
                    region=self.region,
                    description="No CloudTrail trails are configured.",
                    remediation="aws cloudtrail create-trail --name main-trail --s3-bucket-name <bucket> --is-multi-region-trail",
                ))
                return findings

            for trail in trails:
                name = trail.get("Name", "unknown")
                arn = trail.get("TrailARN", f"arn:aws:cloudtrail:{self.region}::trail/{name}")
                is_multi_region = trail.get("IsMultiRegionTrail", False)
                is_logging = False

                try:
                    status_resp = ct.get_trail_status(Name=arn)
                    is_logging = status_resp.get("IsLogging", False)
                except ClientError:
                    pass

                if is_logging and is_multi_region:
                    status = Status.PASS
                    desc = f"Trail {name} is logging and is multi-region."
                elif is_logging:
                    status = Status.FAIL
                    desc = f"Trail {name} is logging but is NOT multi-region."
                else:
                    status = Status.FAIL
                    desc = f"Trail {name} is not currently logging."

                findings.append(Finding(
                    check_id=self.id,
                    cis_id=self.cis_id,
                    title=self.title,
                    severity=Severity.CRITICAL,
                    status=status,
                    resource_arn=arn,
                    region=self.region,
                    description=desc,
                    remediation=f"aws cloudtrail start-logging --name {name} && aws cloudtrail update-trail --name {name} --is-multi-region-trail",
                ))

        except ClientError:
            pass

        return findings


class CloudTrailLogValidationCheck(BaseCheck):
    id = "cloudtrail-log-validation"
    title = "CloudTrail Log File Validation Enabled"
    cis_id = "3.2"
    service = "cloudtrail"

    def run(self) -> list[Finding]:
        ct = self._get_client("cloudtrail")
        findings = []

        try:
            trails = ct.describe_trails().get("trailList", [])

            for trail in trails:
                name = trail.get("Name", "unknown")
                arn = trail.get("TrailARN", f"arn:aws:cloudtrail:{self.region}::trail/{name}")
                validation = trail.get("LogFileValidationEnabled", False)

                status = Status.PASS if validation else Status.FAIL
                desc = (
                    f"Trail {name} has log file validation enabled."
                    if validation
                    else f"Trail {name} does not have log file validation enabled."
                )

                findings.append(Finding(
                    check_id=self.id,
                    cis_id=self.cis_id,
                    title=self.title,
                    severity=Severity.MEDIUM,
                    status=status,
                    resource_arn=arn,
                    region=self.region,
                    description=desc,
                    remediation=f"aws cloudtrail update-trail --name {name} --enable-log-file-validation",
                ))

        except ClientError:
            pass

        return findings
