"""Tests for IAM checks using moto mocks."""

import json

import boto3
import pytest
from moto import mock_aws

from cspm.checks.iam_checks import IAMWildcardPolicyCheck, IAMMFACheck
from cspm.models import Status


@pytest.fixture
def aws_session():
    with mock_aws():
        session = boto3.Session(region_name="us-east-1")
        yield session


class TestIAMWildcardPolicy:
    def test_fail_wildcard_policy(self, aws_session):
        iam = aws_session.client("iam", region_name="us-east-1")
        iam.create_policy(
            PolicyName="admin-all",
            PolicyDocument=json.dumps({
                "Version": "2012-10-17",
                "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}],
            }),
        )
        check = IAMWildcardPolicyCheck(session=aws_session, region="us-east-1")
        findings = check.run()
        fail_findings = [f for f in findings if f.status == Status.FAIL]
        assert len(fail_findings) >= 1

    def test_pass_scoped_policy(self, aws_session):
        iam = aws_session.client("iam", region_name="us-east-1")
        iam.create_policy(
            PolicyName="s3-read",
            PolicyDocument=json.dumps({
                "Version": "2012-10-17",
                "Statement": [{
                    "Effect": "Allow",
                    "Action": ["s3:GetObject"],
                    "Resource": "arn:aws:s3:::my-bucket/*",
                }],
            }),
        )
        check = IAMWildcardPolicyCheck(session=aws_session, region="us-east-1")
        findings = check.run()
        assert all(f.status == Status.PASS for f in findings)


class TestIAMMFA:
    def test_fail_no_mfa(self, aws_session):
        iam = aws_session.client("iam", region_name="us-east-1")
        iam.create_user(UserName="no-mfa-user")
        check = IAMMFACheck(session=aws_session, region="us-east-1")
        findings = check.run()
        user_findings = [f for f in findings if "no-mfa-user" in f.description]
        assert len(user_findings) == 1
        assert user_findings[0].status == Status.FAIL
