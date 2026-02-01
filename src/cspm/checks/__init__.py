"""Security check modules."""

from cspm.checks.s3_checks import S3PublicAccessCheck, S3EncryptionCheck, S3VersioningCheck, S3LoggingCheck
from cspm.checks.sg_checks import SGUnrestrictedSSHCheck, SGUnrestrictedRDPCheck, SGUnrestrictedAllTrafficCheck
from cspm.checks.iam_checks import (
    IAMWildcardPolicyCheck,
    IAMRootUsageCheck,
    IAMMFACheck,
    IAMStaleKeysCheck,
)
from cspm.checks.rds_checks import RDSPublicAccessCheck, RDSEncryptionCheck, RDSBackupCheck
from cspm.checks.cloudtrail_checks import CloudTrailEnabledCheck, CloudTrailLogValidationCheck
from cspm.checks.password_policy import PasswordPolicyCheck

ALL_CHECKS: list[type] = [
    S3PublicAccessCheck,
    S3EncryptionCheck,
    S3VersioningCheck,
    S3LoggingCheck,
    SGUnrestrictedSSHCheck,
    SGUnrestrictedRDPCheck,
    SGUnrestrictedAllTrafficCheck,
    IAMWildcardPolicyCheck,
    IAMRootUsageCheck,
    IAMMFACheck,
    IAMStaleKeysCheck,
    RDSPublicAccessCheck,
    RDSEncryptionCheck,
    RDSBackupCheck,
    CloudTrailEnabledCheck,
    CloudTrailLogValidationCheck,
    PasswordPolicyCheck,
]
