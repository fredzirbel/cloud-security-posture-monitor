"""IAM security checks."""

from __future__ import annotations

import json
from datetime import datetime, timezone, timedelta
from urllib.parse import unquote

from botocore.exceptions import ClientError

from cspm.checks.base import BaseCheck
from cspm.models import Finding, Severity, Status


class IAMWildcardPolicyCheck(BaseCheck):
    id = "iam-wildcard-policy"
    title = "IAM Policy Allows Wildcard Actions"
    cis_id = "1.16"
    service = "iam"

    def run(self) -> list[Finding]:
        iam = self._get_client("iam")
        findings = []

        try:
            paginator = iam.get_paginator("list_policies")
            for page in paginator.paginate(Scope="Local"):
                for policy in page.get("Policies", []):
                    arn = policy["Arn"]
                    version_id = policy["DefaultVersionId"]

                    try:
                        version = iam.get_policy_version(
                            PolicyArn=arn, VersionId=version_id
                        )
                        doc = version["PolicyVersion"]["Document"]
                        if isinstance(doc, str):
                            doc = json.loads(unquote(doc))

                        statements = doc.get("Statement", [])
                        if isinstance(statements, dict):
                            statements = [statements]

                        has_wildcard = False
                        for stmt in statements:
                            if stmt.get("Effect") == "Allow":
                                actions = stmt.get("Action", [])
                                resources = stmt.get("Resource", [])
                                if isinstance(actions, str):
                                    actions = [actions]
                                if isinstance(resources, str):
                                    resources = [resources]
                                if "*" in actions and "*" in resources:
                                    has_wildcard = True

                        status = Status.FAIL if has_wildcard else Status.PASS
                        desc = (
                            f"Policy {policy['PolicyName']} allows Action:* on Resource:*."
                            if has_wildcard
                            else f"Policy {policy['PolicyName']} does not grant full wildcard access."
                        )

                        findings.append(Finding(
                            check_id=self.id,
                            cis_id=self.cis_id,
                            title=self.title,
                            severity=Severity.CRITICAL,
                            status=status,
                            resource_arn=arn,
                            region="global",
                            description=desc,
                            remediation=f"Review and scope down policy {policy['PolicyName']} to least-privilege.",
                        ))

                    except ClientError:
                        continue

        except ClientError:
            pass

        return findings


class IAMRootUsageCheck(BaseCheck):
    id = "iam-root-usage"
    title = "Root Account Usage"
    cis_id = "1.7"
    service = "iam"

    def run(self) -> list[Finding]:
        iam = self._get_client("iam")
        findings = []

        try:
            summary = iam.get_account_summary().get("SummaryMap", {})
            access_keys = summary.get("AccountAccessKeysPresent", 0)

            status = Status.FAIL if access_keys > 0 else Status.PASS
            desc = (
                f"Root account has {access_keys} active access key(s)."
                if access_keys > 0
                else "Root account has no active access keys."
            )

            findings.append(Finding(
                check_id=self.id,
                cis_id=self.cis_id,
                title=self.title,
                severity=Severity.CRITICAL,
                status=status,
                resource_arn="arn:aws:iam::root",
                region="global",
                description=desc,
                remediation="Delete root account access keys and use IAM users instead.",
            ))
        except ClientError:
            pass

        return findings


class IAMMFACheck(BaseCheck):
    id = "iam-user-mfa"
    title = "IAM Users Have MFA Enabled"
    cis_id = "1.4"
    service = "iam"

    def run(self) -> list[Finding]:
        iam = self._get_client("iam")
        findings = []

        try:
            paginator = iam.get_paginator("list_users")
            for page in paginator.paginate():
                for user in page.get("Users", []):
                    username = user["UserName"]
                    arn = user["Arn"]

                    try:
                        mfa_devices = iam.list_mfa_devices(UserName=username).get(
                            "MFADevices", []
                        )
                        has_mfa = len(mfa_devices) > 0
                        status = Status.PASS if has_mfa else Status.FAIL
                        desc = (
                            f"User {username} has MFA enabled."
                            if has_mfa
                            else f"User {username} does not have MFA enabled."
                        )
                    except ClientError:
                        status = Status.ERROR
                        desc = f"Error checking MFA for user {username}."

                    findings.append(Finding(
                        check_id=self.id,
                        cis_id=self.cis_id,
                        title=self.title,
                        severity=Severity.HIGH,
                        status=status,
                        resource_arn=arn,
                        region="global",
                        description=desc,
                        remediation=f"Enable MFA for IAM user {username}.",
                    ))
        except ClientError:
            pass

        return findings


class IAMStaleKeysCheck(BaseCheck):
    id = "iam-stale-access-keys"
    title = "IAM Access Keys Rotated Within 90 Days"
    cis_id = "1.14"
    service = "iam"

    def run(self) -> list[Finding]:
        iam = self._get_client("iam")
        findings = []
        max_age = timedelta(days=90)

        try:
            paginator = iam.get_paginator("list_users")
            for page in paginator.paginate():
                for user in page.get("Users", []):
                    username = user["UserName"]
                    arn = user["Arn"]

                    try:
                        keys = iam.list_access_keys(UserName=username).get(
                            "AccessKeyMetadata", []
                        )
                        for key in keys:
                            if key["Status"] != "Active":
                                continue
                            created = key["CreateDate"]
                            if isinstance(created, str):
                                created = datetime.fromisoformat(created)
                            if created.tzinfo is None:
                                created = created.replace(tzinfo=timezone.utc)
                            age = datetime.now(timezone.utc) - created
                            stale = age > max_age

                            status = Status.FAIL if stale else Status.PASS
                            desc = (
                                f"Access key {key['AccessKeyId']} for {username} is {age.days} days old."
                                if stale
                                else f"Access key {key['AccessKeyId']} for {username} is within 90-day rotation window."
                            )

                            findings.append(Finding(
                                check_id=self.id,
                                cis_id=self.cis_id,
                                title=self.title,
                                severity=Severity.MEDIUM,
                                status=status,
                                resource_arn=arn,
                                region="global",
                                description=desc,
                                remediation=f"Rotate access key {key['AccessKeyId']} for user {username}.",
                            ))
                    except ClientError:
                        continue
        except ClientError:
            pass

        return findings
