"""S3 bucket security checks."""

from __future__ import annotations

from botocore.exceptions import ClientError

from cspm.checks.base import BaseCheck
from cspm.models import Finding, Severity, Status


class S3PublicAccessCheck(BaseCheck):
    id = "s3-public-access-block"
    title = "S3 Bucket Public Access Block"
    cis_id = "2.1.4"
    service = "s3"

    def run(self) -> list[Finding]:
        s3 = self._get_client("s3")
        findings = []

        try:
            buckets = s3.list_buckets().get("Buckets", [])
        except ClientError:
            return findings

        for bucket in buckets:
            name = bucket["Name"]
            arn = f"arn:aws:s3:::{name}"

            try:
                resp = s3.get_public_access_block(Bucket=name)
                config = resp["PublicAccessBlockConfiguration"]
                all_blocked = all([
                    config.get("BlockPublicAcls", False),
                    config.get("IgnorePublicAcls", False),
                    config.get("BlockPublicPolicy", False),
                    config.get("RestrictPublicBuckets", False),
                ])
                status = Status.PASS if all_blocked else Status.FAIL
                desc = (
                    "All public access is blocked."
                    if all_blocked
                    else f"Public access block is incomplete: {config}"
                )
            except ClientError as e:
                if e.response["Error"]["Code"] == "NoSuchPublicAccessBlockConfiguration":
                    status = Status.FAIL
                    desc = "No public access block configuration found."
                else:
                    status = Status.ERROR
                    desc = f"Error checking public access block: {e}"

            findings.append(Finding(
                check_id=self.id,
                cis_id=self.cis_id,
                title=self.title,
                severity=Severity.CRITICAL,
                status=status,
                resource_arn=arn,
                region=self.region,
                description=desc,
                remediation=(
                    f"aws s3api put-public-access-block --bucket {name} "
                    "--public-access-block-configuration "
                    "BlockPublicAcls=true,IgnorePublicAcls=true,"
                    "BlockPublicPolicy=true,RestrictPublicBuckets=true"
                ),
            ))

        return findings


class S3EncryptionCheck(BaseCheck):
    id = "s3-default-encryption"
    title = "S3 Bucket Default Encryption"
    cis_id = "2.1.1"
    service = "s3"

    def run(self) -> list[Finding]:
        s3 = self._get_client("s3")
        findings = []

        try:
            buckets = s3.list_buckets().get("Buckets", [])
        except ClientError:
            return findings

        for bucket in buckets:
            name = bucket["Name"]
            arn = f"arn:aws:s3:::{name}"

            try:
                resp = s3.get_bucket_encryption(Bucket=name)
                rules = resp.get("ServerSideEncryptionConfiguration", {}).get("Rules", [])
                if rules:
                    status = Status.PASS
                    algo = rules[0].get("ApplyServerSideEncryptionByDefault", {}).get(
                        "SSEAlgorithm", "unknown"
                    )
                    desc = f"Default encryption enabled with {algo}."
                else:
                    status = Status.FAIL
                    desc = "No encryption rules configured."
            except ClientError as e:
                if "ServerSideEncryptionConfigurationNotFoundError" in str(e):
                    status = Status.FAIL
                    desc = "Default encryption is not enabled."
                else:
                    status = Status.ERROR
                    desc = f"Error checking encryption: {e}"

            findings.append(Finding(
                check_id=self.id,
                cis_id=self.cis_id,
                title=self.title,
                severity=Severity.HIGH,
                status=status,
                resource_arn=arn,
                region=self.region,
                description=desc,
                remediation=(
                    f"aws s3api put-bucket-encryption --bucket {name} "
                    "--server-side-encryption-configuration "
                    "'{\"Rules\":[{\"ApplyServerSideEncryptionByDefault\":"
                    "{\"SSEAlgorithm\":\"AES256\"}}]}'"
                ),
            ))

        return findings


class S3VersioningCheck(BaseCheck):
    id = "s3-versioning"
    title = "S3 Bucket Versioning"
    cis_id = "2.1.3"
    service = "s3"

    def run(self) -> list[Finding]:
        s3 = self._get_client("s3")
        findings = []

        try:
            buckets = s3.list_buckets().get("Buckets", [])
        except ClientError:
            return findings

        for bucket in buckets:
            name = bucket["Name"]
            arn = f"arn:aws:s3:::{name}"

            try:
                resp = s3.get_bucket_versioning(Bucket=name)
                enabled = resp.get("Status") == "Enabled"
                status = Status.PASS if enabled else Status.FAIL
                desc = "Versioning is enabled." if enabled else "Versioning is not enabled."
            except ClientError as e:
                status = Status.ERROR
                desc = f"Error checking versioning: {e}"

            findings.append(Finding(
                check_id=self.id,
                cis_id=self.cis_id,
                title=self.title,
                severity=Severity.MEDIUM,
                status=status,
                resource_arn=arn,
                region=self.region,
                description=desc,
                remediation=f"aws s3api put-bucket-versioning --bucket {name} --versioning-configuration Status=Enabled",
            ))

        return findings


class S3LoggingCheck(BaseCheck):
    id = "s3-access-logging"
    title = "S3 Bucket Server Access Logging"
    cis_id = "2.1.2"
    service = "s3"

    def run(self) -> list[Finding]:
        s3 = self._get_client("s3")
        findings = []

        try:
            buckets = s3.list_buckets().get("Buckets", [])
        except ClientError:
            return findings

        for bucket in buckets:
            name = bucket["Name"]
            arn = f"arn:aws:s3:::{name}"

            try:
                resp = s3.get_bucket_logging(Bucket=name)
                enabled = "LoggingEnabled" in resp
                status = Status.PASS if enabled else Status.FAIL
                desc = (
                    "Server access logging is enabled."
                    if enabled
                    else "Server access logging is not enabled."
                )
            except ClientError as e:
                status = Status.ERROR
                desc = f"Error checking logging: {e}"

            findings.append(Finding(
                check_id=self.id,
                cis_id=self.cis_id,
                title=self.title,
                severity=Severity.MEDIUM,
                status=status,
                resource_arn=arn,
                region=self.region,
                description=desc,
                remediation=(
                    f"aws s3api put-bucket-logging --bucket {name} "
                    "--bucket-logging-status '{\"LoggingEnabled\":"
                    "{\"TargetBucket\":\"<logging-bucket>\",\"TargetPrefix\":\"logs/\"}}'"
                ),
            ))

        return findings
