# CIS AWS Foundations Benchmark v3.0 Coverage

This document maps the CSPM checks to their corresponding CIS controls.

## Coverage Summary

| Section | Controls Covered | Check IDs |
|---|---|---|
| 1 - Identity and Access Management | 5 | iam-wildcard-policy, iam-root-usage, iam-user-mfa, iam-stale-access-keys, iam-password-policy |
| 2 - Storage | 7 | s3-public-access-block, s3-default-encryption, s3-versioning, s3-access-logging, rds-public-access, rds-encryption, rds-backup |
| 3 - Logging | 2 | cloudtrail-enabled, cloudtrail-log-validation |
| 5 - Networking | 3 | sg-unrestricted-all-traffic, sg-unrestricted-ssh, sg-unrestricted-rdp |

**Total: 17 checks across 4 CIS sections**

## Detailed Mapping

### Section 1: Identity and Access Management

| CIS ID | Level | Check ID | Description |
|---|---|---|---|
| 1.4 | 1 | iam-user-mfa | Ensure MFA is enabled for all IAM users |
| 1.7 | 1 | iam-root-usage | Eliminate use of the root user |
| 1.8 | 1 | iam-password-policy | Ensure IAM password policy meets requirements |
| 1.14 | 1 | iam-stale-access-keys | Ensure access keys rotated every 90 days |
| 1.16 | 1 | iam-wildcard-policy | Ensure no full admin wildcard policies |

### Section 2: Storage

| CIS ID | Level | Check ID | Description |
|---|---|---|---|
| 2.1.1 | 2 | s3-default-encryption | Ensure S3 default encryption enabled |
| 2.1.2 | 1 | s3-access-logging | Ensure S3 server access logging enabled |
| 2.1.3 | 1 | s3-versioning | Ensure S3 versioning enabled |
| 2.1.4 | 1 | s3-public-access-block | Ensure S3 public access blocked |
| 2.3.1 | 1 | rds-public-access | Ensure RDS not publicly accessible |
| 2.3.1 | 1 | rds-encryption | Ensure RDS storage encrypted |
| 2.3.1 | 1 | rds-backup | Ensure RDS automated backups enabled |

### Section 3: Logging

| CIS ID | Level | Check ID | Description |
|---|---|---|---|
| 3.1 | 1 | cloudtrail-enabled | Ensure CloudTrail enabled in all regions |
| 3.2 | 2 | cloudtrail-log-validation | Ensure log file validation enabled |

### Section 5: Networking

| CIS ID | Level | Check ID | Description |
|---|---|---|---|
| 5.1 | 1 | sg-unrestricted-all-traffic | Ensure no SG allows all inbound from 0.0.0.0/0 |
| 5.2 | 1 | sg-unrestricted-ssh | Ensure no SG allows SSH from 0.0.0.0/0 |
| 5.3 | 1 | sg-unrestricted-rdp | Ensure no SG allows RDP from 0.0.0.0/0 |
