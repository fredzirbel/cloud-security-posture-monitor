"""IAM account password policy check."""

from __future__ import annotations

from botocore.exceptions import ClientError

from cspm.checks.base import BaseCheck
from cspm.models import Finding, Severity, Status


class PasswordPolicyCheck(BaseCheck):
    id = "iam-password-policy"
    title = "IAM Password Policy Meets CIS Requirements"
    cis_id = "1.8"
    service = "iam"

    REQUIRED_SETTINGS = {
        "MinimumPasswordLength": (14, ">="),
        "RequireSymbols": (True, "=="),
        "RequireNumbers": (True, "=="),
        "RequireUppercaseCharacters": (True, "=="),
        "RequireLowercaseCharacters": (True, "=="),
        "MaxPasswordAge": (90, "<="),
        "PasswordReusePrevention": (24, ">="),
    }

    def run(self) -> list[Finding]:
        iam = self._get_client("iam")
        findings = []

        try:
            policy = iam.get_account_password_policy().get("PasswordPolicy", {})
        except ClientError as e:
            if "NoSuchEntity" in str(e):
                findings.append(Finding(
                    check_id=self.id,
                    cis_id=self.cis_id,
                    title=self.title,
                    severity=Severity.HIGH,
                    status=Status.FAIL,
                    resource_arn="arn:aws:iam::account/password-policy",
                    region="global",
                    description="No account password policy is configured.",
                    remediation=(
                        "aws iam update-account-password-policy "
                        "--minimum-password-length 14 "
                        "--require-symbols --require-numbers "
                        "--require-uppercase-characters --require-lowercase-characters "
                        "--max-password-age 90 --password-reuse-prevention 24"
                    ),
                ))
                return findings
            return findings

        violations = []
        for setting, (expected, op) in self.REQUIRED_SETTINGS.items():
            actual = policy.get(setting)
            if actual is None:
                violations.append(f"{setting}: not set (expected {op} {expected})")
                continue
            if op == ">=" and actual < expected:
                violations.append(f"{setting}: {actual} (expected >= {expected})")
            elif op == "<=" and actual > expected:
                violations.append(f"{setting}: {actual} (expected <= {expected})")
            elif op == "==" and actual != expected:
                violations.append(f"{setting}: {actual} (expected {expected})")

        if violations:
            status = Status.FAIL
            desc = "Password policy violations: " + "; ".join(violations)
        else:
            status = Status.PASS
            desc = "Password policy meets all CIS requirements."

        findings.append(Finding(
            check_id=self.id,
            cis_id=self.cis_id,
            title=self.title,
            severity=Severity.HIGH,
            status=status,
            resource_arn="arn:aws:iam::account/password-policy",
            region="global",
            description=desc,
            remediation=(
                "aws iam update-account-password-policy "
                "--minimum-password-length 14 "
                "--require-symbols --require-numbers "
                "--require-uppercase-characters --require-lowercase-characters "
                "--max-password-age 90 --password-reuse-prevention 24"
            ),
        ))

        return findings
