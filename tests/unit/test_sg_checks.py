"""Tests for Security Group checks using moto mocks."""

import boto3
import pytest
from moto import mock_aws

from cspm.checks.sg_checks import SGUnrestrictedSSHCheck, SGUnrestrictedRDPCheck
from cspm.models import Status


@pytest.fixture
def aws_session():
    with mock_aws():
        session = boto3.Session(region_name="us-east-1")
        ec2 = session.client("ec2", region_name="us-east-1")
        vpc = ec2.create_vpc(CidrBlock="10.0.0.0/16")
        yield session, vpc["Vpc"]["VpcId"]


class TestSGUnrestrictedSSH:
    def test_fail_ssh_open_to_world(self, aws_session):
        session, vpc_id = aws_session
        ec2 = session.client("ec2", region_name="us-east-1")
        sg = ec2.create_security_group(
            GroupName="open-ssh", Description="test", VpcId=vpc_id
        )
        ec2.authorize_security_group_ingress(
            GroupId=sg["GroupId"],
            IpPermissions=[{
                "IpProtocol": "tcp",
                "FromPort": 22,
                "ToPort": 22,
                "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
            }],
        )
        check = SGUnrestrictedSSHCheck(session=session, region="us-east-1")
        findings = check.run()

        open_findings = [f for f in findings if f.status == Status.FAIL and sg["GroupId"] in f.resource_arn]
        assert len(open_findings) >= 1

    def test_pass_ssh_restricted(self, aws_session):
        session, vpc_id = aws_session
        ec2 = session.client("ec2", region_name="us-east-1")
        sg = ec2.create_security_group(
            GroupName="restricted-ssh", Description="test", VpcId=vpc_id
        )
        ec2.authorize_security_group_ingress(
            GroupId=sg["GroupId"],
            IpPermissions=[{
                "IpProtocol": "tcp",
                "FromPort": 22,
                "ToPort": 22,
                "IpRanges": [{"CidrIp": "10.0.0.0/16"}],
            }],
        )
        check = SGUnrestrictedSSHCheck(session=session, region="us-east-1")
        findings = check.run()

        sg_findings = [f for f in findings if sg["GroupId"] in f.resource_arn]
        assert all(f.status == Status.PASS for f in sg_findings)


class TestSGUnrestrictedRDP:
    def test_fail_rdp_open_to_world(self, aws_session):
        session, vpc_id = aws_session
        ec2 = session.client("ec2", region_name="us-east-1")
        sg = ec2.create_security_group(
            GroupName="open-rdp", Description="test", VpcId=vpc_id
        )
        ec2.authorize_security_group_ingress(
            GroupId=sg["GroupId"],
            IpPermissions=[{
                "IpProtocol": "tcp",
                "FromPort": 3389,
                "ToPort": 3389,
                "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
            }],
        )
        check = SGUnrestrictedRDPCheck(session=session, region="us-east-1")
        findings = check.run()

        open_findings = [f for f in findings if f.status == Status.FAIL and sg["GroupId"] in f.resource_arn]
        assert len(open_findings) >= 1
