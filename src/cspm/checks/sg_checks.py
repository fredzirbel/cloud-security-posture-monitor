"""Security Group checks."""

from __future__ import annotations

from botocore.exceptions import ClientError

from cspm.checks.base import BaseCheck
from cspm.models import Finding, Severity, Status


class _SGPortCheck(BaseCheck):
    """Base class for security group port checks."""

    port: int = 0
    protocol_label: str = ""

    def run(self) -> list[Finding]:
        ec2 = self._get_client("ec2")
        findings = []

        try:
            sgs = ec2.describe_security_groups().get("SecurityGroups", [])
        except ClientError:
            return findings

        for sg in sgs:
            sg_id = sg["GroupId"]
            sg_name = sg.get("GroupName", "")
            vpc_id = sg.get("VpcId", "N/A")
            arn = f"arn:aws:ec2:{self.region}::security-group/{sg_id}"

            unrestricted = False
            for rule in sg.get("IpPermissions", []):
                from_port = rule.get("FromPort", 0)
                to_port = rule.get("ToPort", 0)

                if self.port == 0 or (from_port <= self.port <= to_port):
                    for ip_range in rule.get("IpRanges", []):
                        if ip_range.get("CidrIp") == "0.0.0.0/0":
                            unrestricted = True
                    for ip_range in rule.get("Ipv6Ranges", []):
                        if ip_range.get("CidrIpv6") == "::/0":
                            unrestricted = True

            status = Status.FAIL if unrestricted else Status.PASS
            desc = (
                f"Security group {sg_id} ({sg_name}) in VPC {vpc_id} allows "
                f"unrestricted {self.protocol_label} access from 0.0.0.0/0."
                if unrestricted
                else f"Security group {sg_id} ({sg_name}) does not allow unrestricted {self.protocol_label} access."
            )

            findings.append(Finding(
                check_id=self.id,
                cis_id=self.cis_id,
                title=self.title,
                severity=self.severity_level,
                status=status,
                resource_arn=arn,
                region=self.region,
                description=desc,
                remediation=(
                    f"aws ec2 revoke-security-group-ingress --group-id {sg_id} "
                    f"--protocol tcp --port {self.port} --cidr 0.0.0.0/0"
                    if self.port > 0
                    else f"Review and restrict ingress rules for security group {sg_id}."
                ),
            ))

        return findings

    @property
    def severity_level(self) -> Severity:
        return Severity.CRITICAL


class SGUnrestrictedSSHCheck(_SGPortCheck):
    id = "sg-unrestricted-ssh"
    title = "Security Group Unrestricted SSH"
    cis_id = "5.2"
    service = "ec2"
    port = 22
    protocol_label = "SSH (port 22)"


class SGUnrestrictedRDPCheck(_SGPortCheck):
    id = "sg-unrestricted-rdp"
    title = "Security Group Unrestricted RDP"
    cis_id = "5.3"
    service = "ec2"
    port = 3389
    protocol_label = "RDP (port 3389)"


class SGUnrestrictedAllTrafficCheck(_SGPortCheck):
    id = "sg-unrestricted-all-traffic"
    title = "Security Group Unrestricted All Traffic"
    cis_id = "5.1"
    service = "ec2"
    port = 0
    protocol_label = "all traffic"

    def run(self) -> list[Finding]:
        ec2 = self._get_client("ec2")
        findings = []

        try:
            sgs = ec2.describe_security_groups().get("SecurityGroups", [])
        except ClientError:
            return findings

        for sg in sgs:
            sg_id = sg["GroupId"]
            sg_name = sg.get("GroupName", "")
            arn = f"arn:aws:ec2:{self.region}::security-group/{sg_id}"

            unrestricted = False
            for rule in sg.get("IpPermissions", []):
                ip_protocol = rule.get("IpProtocol", "")
                if ip_protocol == "-1":
                    for ip_range in rule.get("IpRanges", []):
                        if ip_range.get("CidrIp") == "0.0.0.0/0":
                            unrestricted = True
                    for ip_range in rule.get("Ipv6Ranges", []):
                        if ip_range.get("CidrIpv6") == "::/0":
                            unrestricted = True

            status = Status.FAIL if unrestricted else Status.PASS
            desc = (
                f"Security group {sg_id} ({sg_name}) allows ALL inbound traffic from 0.0.0.0/0."
                if unrestricted
                else f"Security group {sg_id} ({sg_name}) does not allow unrestricted all-traffic ingress."
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
                remediation=f"Review and restrict all ingress rules for security group {sg_id}.",
            ))

        return findings
