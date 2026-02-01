"""RDS security checks."""

from __future__ import annotations

from botocore.exceptions import ClientError

from cspm.checks.base import BaseCheck
from cspm.models import Finding, Severity, Status


class RDSPublicAccessCheck(BaseCheck):
    id = "rds-public-access"
    title = "RDS Instance Public Accessibility"
    cis_id = "2.3.1"
    service = "rds"

    def run(self) -> list[Finding]:
        rds = self._get_client("rds")
        findings = []

        try:
            paginator = rds.get_paginator("describe_db_instances")
            for page in paginator.paginate():
                for db in page.get("DBInstances", []):
                    db_id = db["DBInstanceIdentifier"]
                    arn = db.get("DBInstanceArn", f"arn:aws:rds:{self.region}::db:{db_id}")
                    public = db.get("PubliclyAccessible", False)

                    status = Status.FAIL if public else Status.PASS
                    desc = (
                        f"RDS instance {db_id} is publicly accessible."
                        if public
                        else f"RDS instance {db_id} is not publicly accessible."
                    )

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
                            f"aws rds modify-db-instance --db-instance-identifier {db_id} "
                            "--no-publicly-accessible"
                        ),
                    ))
        except ClientError:
            pass

        return findings


class RDSEncryptionCheck(BaseCheck):
    id = "rds-encryption"
    title = "RDS Instance Storage Encryption"
    cis_id = "2.3.1"
    service = "rds"

    def run(self) -> list[Finding]:
        rds = self._get_client("rds")
        findings = []

        try:
            paginator = rds.get_paginator("describe_db_instances")
            for page in paginator.paginate():
                for db in page.get("DBInstances", []):
                    db_id = db["DBInstanceIdentifier"]
                    arn = db.get("DBInstanceArn", f"arn:aws:rds:{self.region}::db:{db_id}")
                    encrypted = db.get("StorageEncrypted", False)

                    status = Status.PASS if encrypted else Status.FAIL
                    desc = (
                        f"RDS instance {db_id} has storage encryption enabled."
                        if encrypted
                        else f"RDS instance {db_id} does not have storage encryption enabled."
                    )

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
                            f"Encryption must be enabled at creation time. Create an encrypted "
                            f"snapshot of {db_id} and restore to a new encrypted instance."
                        ),
                    ))
        except ClientError:
            pass

        return findings


class RDSBackupCheck(BaseCheck):
    id = "rds-backup"
    title = "RDS Instance Automated Backups"
    cis_id = "2.3.1"
    service = "rds"

    def run(self) -> list[Finding]:
        rds = self._get_client("rds")
        findings = []

        try:
            paginator = rds.get_paginator("describe_db_instances")
            for page in paginator.paginate():
                for db in page.get("DBInstances", []):
                    db_id = db["DBInstanceIdentifier"]
                    arn = db.get("DBInstanceArn", f"arn:aws:rds:{self.region}::db:{db_id}")
                    retention = db.get("BackupRetentionPeriod", 0)

                    status = Status.PASS if retention > 0 else Status.FAIL
                    desc = (
                        f"RDS instance {db_id} has automated backups with {retention}-day retention."
                        if retention > 0
                        else f"RDS instance {db_id} has no automated backups configured."
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
                        remediation=(
                            f"aws rds modify-db-instance --db-instance-identifier {db_id} "
                            "--backup-retention-period 7"
                        ),
                    ))
        except ClientError:
            pass

        return findings
