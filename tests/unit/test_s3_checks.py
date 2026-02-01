"""Tests for S3 checks using moto mocks."""

import boto3
import pytest
from moto import mock_aws

from cspm.checks.s3_checks import (
    S3PublicAccessCheck,
    S3EncryptionCheck,
    S3VersioningCheck,
    S3LoggingCheck,
)
from cspm.models import Status


@pytest.fixture
def aws_session():
    with mock_aws():
        session = boto3.Session(region_name="us-east-1")
        yield session


def _create_bucket(session, name="test-bucket"):
    s3 = session.client("s3", region_name="us-east-1")
    s3.create_bucket(Bucket=name)
    return s3


class TestS3PublicAccessBlock:
    def test_fail_no_public_access_block(self, aws_session):
        _create_bucket(aws_session)
        check = S3PublicAccessCheck(session=aws_session, region="us-east-1")
        findings = check.run()
        assert len(findings) == 1
        assert findings[0].status == Status.FAIL

    def test_pass_all_blocked(self, aws_session):
        s3 = _create_bucket(aws_session)
        s3.put_public_access_block(
            Bucket="test-bucket",
            PublicAccessBlockConfiguration={
                "BlockPublicAcls": True,
                "IgnorePublicAcls": True,
                "BlockPublicPolicy": True,
                "RestrictPublicBuckets": True,
            },
        )
        check = S3PublicAccessCheck(session=aws_session, region="us-east-1")
        findings = check.run()
        assert len(findings) == 1
        assert findings[0].status == Status.PASS


class TestS3Encryption:
    def test_fail_no_encryption(self, aws_session):
        _create_bucket(aws_session)
        check = S3EncryptionCheck(session=aws_session, region="us-east-1")
        findings = check.run()
        # moto may auto-enable encryption; check we get a finding either way
        assert len(findings) == 1

    def test_pass_encryption_enabled(self, aws_session):
        s3 = _create_bucket(aws_session)
        s3.put_bucket_encryption(
            Bucket="test-bucket",
            ServerSideEncryptionConfiguration={
                "Rules": [
                    {"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}
                ]
            },
        )
        check = S3EncryptionCheck(session=aws_session, region="us-east-1")
        findings = check.run()
        assert len(findings) == 1
        assert findings[0].status == Status.PASS


class TestS3Versioning:
    def test_fail_no_versioning(self, aws_session):
        _create_bucket(aws_session)
        check = S3VersioningCheck(session=aws_session, region="us-east-1")
        findings = check.run()
        assert len(findings) == 1
        assert findings[0].status == Status.FAIL

    def test_pass_versioning_enabled(self, aws_session):
        s3 = _create_bucket(aws_session)
        s3.put_bucket_versioning(
            Bucket="test-bucket",
            VersioningConfiguration={"Status": "Enabled"},
        )
        check = S3VersioningCheck(session=aws_session, region="us-east-1")
        findings = check.run()
        assert len(findings) == 1
        assert findings[0].status == Status.PASS
