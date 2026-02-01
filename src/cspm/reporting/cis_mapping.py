"""CIS AWS Foundations Benchmark v3.0 control mapping."""

CIS_MAP: dict[str, dict[str, str]] = {
    "s3-public-access-block": {
        "cis_id": "2.1.4",
        "title": "Ensure S3 bucket public access is blocked",
        "description": (
            "Amazon S3 Block Public Access provides settings for access points, buckets, "
            "and accounts to help manage public access to S3 resources."
        ),
        "level": "1",
    },
    "s3-default-encryption": {
        "cis_id": "2.1.1",
        "title": "Ensure S3 bucket default encryption is enabled",
        "description": (
            "Amazon S3 default encryption provides a way to set the default encryption "
            "behavior for an S3 bucket."
        ),
        "level": "2",
    },
    "s3-versioning": {
        "cis_id": "2.1.3",
        "title": "Ensure S3 bucket versioning is enabled",
        "description": (
            "Versioning is a means of keeping multiple variants of an object in the same bucket."
        ),
        "level": "1",
    },
    "s3-access-logging": {
        "cis_id": "2.1.2",
        "title": "Ensure S3 bucket server access logging is enabled",
        "description": (
            "Server access logging provides detailed records for the requests made to a bucket."
        ),
        "level": "1",
    },
    "sg-unrestricted-ssh": {
        "cis_id": "5.2",
        "title": "Ensure no security groups allow ingress from 0.0.0.0/0 to port 22",
        "description": (
            "Security groups should not allow unrestricted ingress to SSH (port 22) from the internet."
        ),
        "level": "1",
    },
    "sg-unrestricted-rdp": {
        "cis_id": "5.3",
        "title": "Ensure no security groups allow ingress from 0.0.0.0/0 to port 3389",
        "description": (
            "Security groups should not allow unrestricted ingress to RDP (port 3389) from the internet."
        ),
        "level": "1",
    },
    "sg-unrestricted-all-traffic": {
        "cis_id": "5.1",
        "title": "Ensure no security groups allow ingress from 0.0.0.0/0 to all ports",
        "description": (
            "Security groups should not allow unrestricted ingress of all traffic from the internet."
        ),
        "level": "1",
    },
    "iam-wildcard-policy": {
        "cis_id": "1.16",
        "title": "Ensure IAM policies that allow full '*:*' administrative privileges are not attached",
        "description": (
            "IAM policies should not allow full administrative access with Action:* and Resource:*."
        ),
        "level": "1",
    },
    "iam-root-usage": {
        "cis_id": "1.7",
        "title": "Eliminate use of the root user for administrative and daily tasks",
        "description": (
            "The root account has unrestricted access. Avoid using root for daily tasks."
        ),
        "level": "1",
    },
    "iam-user-mfa": {
        "cis_id": "1.4",
        "title": "Ensure MFA is enabled for all IAM users that have a console password",
        "description": (
            "Multi-Factor Authentication adds an extra layer of protection on top of a username and password."
        ),
        "level": "1",
    },
    "iam-stale-access-keys": {
        "cis_id": "1.14",
        "title": "Ensure access keys are rotated every 90 days or less",
        "description": (
            "Access keys should be rotated regularly to reduce the window of opportunity for compromised keys."
        ),
        "level": "1",
    },
    "rds-public-access": {
        "cis_id": "2.3.1",
        "title": "Ensure RDS instances are not publicly accessible",
        "description": (
            "RDS database instances should not be configured for public accessibility."
        ),
        "level": "1",
    },
    "rds-encryption": {
        "cis_id": "2.3.1",
        "title": "Ensure RDS instance storage is encrypted",
        "description": (
            "RDS instances should use encrypted storage to protect data at rest."
        ),
        "level": "1",
    },
    "rds-backup": {
        "cis_id": "2.3.1",
        "title": "Ensure RDS instances have automated backups enabled",
        "description": (
            "Automated backups help ensure point-in-time recovery for RDS instances."
        ),
        "level": "1",
    },
    "cloudtrail-enabled": {
        "cis_id": "3.1",
        "title": "Ensure CloudTrail is enabled in all regions",
        "description": (
            "AWS CloudTrail records API calls and delivers log files for auditing."
        ),
        "level": "1",
    },
    "cloudtrail-log-validation": {
        "cis_id": "3.2",
        "title": "Ensure CloudTrail log file validation is enabled",
        "description": (
            "Log file validation creates a digitally signed digest file for validating log integrity."
        ),
        "level": "2",
    },
    "iam-password-policy": {
        "cis_id": "1.8",
        "title": "Ensure IAM password policy meets CIS requirements",
        "description": (
            "Password policies enforce complexity, rotation, and reuse prevention requirements."
        ),
        "level": "1",
    },
}
