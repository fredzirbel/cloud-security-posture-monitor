# Cloud Security Posture Monitor (CSPM)

A from-scratch Python tool that scans AWS environments for security misconfigurations, maps findings to CIS AWS Foundations Benchmark v3.0 controls, and provides alerting with trend analysis.

Built as a portfolio project to demonstrate cloud security engineering skills. Uses LocalStack for fully reproducible demos without an AWS account.

## Features

- **17 automated security checks** across S3, IAM, Security Groups, RDS, CloudTrail, and password policy
- **CIS Benchmark mapping** — every finding references its CIS AWS Foundations v3.0 control
- **Severity classification** — CRITICAL / HIGH / MEDIUM / LOW with consistent logic
- **Multi-format output** — colored terminal (Rich), JSON, and HTML reports
- **Slack alerting** — webhook integration with configurable severity thresholds
- **Trend analysis** — SQLite persistence with scan-over-scan delta comparison
- **LocalStack demo** — full end-to-end demo without an AWS account
- **Terraform IaC** — both intentionally vulnerable and CIS-compliant baseline configs
- **CI/CD** — GitHub Actions runs lint, unit tests, and integration tests on every push

## Quick Start

### Prerequisites
- Python 3.11+
- Docker and Docker Compose

### Demo (LocalStack)
```bash
# Clone and install
git clone https://github.com/fredzirbel/cloud-security-posture-monitor.git
cd cloud-security-posture-monitor
pip install -e ".[dev]"

# Full demo: start LocalStack, provision vulnerable resources, scan
make demo
```

### Manual Steps
```bash
# Start LocalStack
make localstack-up

# Provision intentionally misconfigured resources
make terraform-up

# Run the scan
cspm scan --config config/default.yaml --output console --remediation

# Run with all output formats + delta comparison
cspm scan --config config/default.yaml --output all --compare-previous

# Clean up
make clean
```

## CLI Usage

```
cspm scan [OPTIONS]

Options:
  --config, -c PATH      Config file (default: config/default.yaml)
  --output, -o FORMAT     Output format: console, json, html, all
  --output-file PATH      Output file for json/html
  --compare-previous      Show delta from last scan
  --remediation           Show remediation commands
```

## Checks Implemented

| Check ID | CIS Control | Severity | Description |
|---|---|---|---|
| s3-public-access-block | 2.1.4 | CRITICAL | S3 bucket public access not blocked |
| s3-default-encryption | 2.1.1 | HIGH | S3 bucket default encryption disabled |
| s3-versioning | 2.1.3 | MEDIUM | S3 bucket versioning disabled |
| s3-access-logging | 2.1.2 | MEDIUM | S3 server access logging disabled |
| sg-unrestricted-all-traffic | 5.1 | CRITICAL | Security group allows all inbound from 0.0.0.0/0 |
| sg-unrestricted-ssh | 5.2 | CRITICAL | Security group allows SSH from 0.0.0.0/0 |
| sg-unrestricted-rdp | 5.3 | CRITICAL | Security group allows RDP from 0.0.0.0/0 |
| iam-wildcard-policy | 1.16 | CRITICAL | IAM policy grants Action:\* on Resource:\* |
| iam-root-usage | 1.7 | CRITICAL | Root account has active access keys |
| iam-user-mfa | 1.4 | HIGH | IAM user without MFA |
| iam-stale-access-keys | 1.14 | MEDIUM | Access key not rotated in 90+ days |
| rds-public-access | 2.3.1 | CRITICAL | RDS instance publicly accessible |
| rds-encryption | 2.3.1 | HIGH | RDS storage encryption disabled |
| rds-backup | 2.3.1 | MEDIUM | RDS automated backups disabled |
| cloudtrail-enabled | 3.1 | CRITICAL | CloudTrail not enabled in all regions |
| cloudtrail-log-validation | 3.2 | MEDIUM | CloudTrail log file validation disabled |
| iam-password-policy | 1.8 | HIGH | Password policy doesn't meet CIS requirements |

## Architecture

```
cspm scan --config config.yaml
       │
       ▼
   ┌──────────┐     ┌─────────────────────┐
   │  Config   │────▶│   Scanner           │
   │  Loader   │     │   (orchestrator)    │
   └──────────┘     └────────┬────────────┘
                             │
              ┌──────────────┼──────────────┐
              ▼              ▼              ▼
        ┌──────────┐  ┌──────────┐  ┌──────────┐
        │ S3 Checks│  │IAM Checks│  │ SG Checks│  ...
        └────┬─────┘  └────┬─────┘  └────┬─────┘
             │              │              │
             └──────────────┼──────────────┘
                            ▼
                     ┌─────────────┐
                     │  Findings   │
                     └──────┬──────┘
              ┌─────────────┼─────────────┐
              ▼             ▼             ▼
        ┌──────────┐ ┌──────────┐ ┌──────────┐
        │ Console  │ │  Report  │ │  SQLite  │
        │ (Rich)   │ │ HTML/JSON│ │  Store   │
        └──────────┘ └──────────┘ └────┬─────┘
                                       │
                            ┌──────────┼──────────┐
                            ▼                     ▼
                     ┌─────────────┐       ┌──────────┐
                     │ Delta Query │       │  Slack   │
                     └─────────────┘       │  Alert   │
                                           └──────────┘
```

## Testing

```bash
# All tests
make test

# Unit tests only (uses moto for AWS mocking)
make test-unit

# Integration tests (requires LocalStack)
make test-integration

# Lint
make lint
```

## Project Structure

```
cloud-security-posture-monitor/
├── src/cspm/
│   ├── cli.py              # CLI entry point
│   ├── scanner.py          # Check orchestrator
│   ├── config.py           # YAML config loader
│   ├── models.py           # Finding/ScanResult dataclasses
│   ├── checks/             # All 17 security checks
│   ├── alerting/           # Console (Rich) + Slack output
│   ├── reporting/          # CIS mapping, HTML, JSON reports
│   └── storage/            # SQLite persistence + delta queries
├── terraform/
│   └── modules/
│       ├── vulnerable/     # Intentionally misconfigured resources
│       └── secure_baseline/# CIS-compliant reference configs
├── tests/
│   ├── unit/               # Moto-mocked unit tests
│   └── integration/        # LocalStack integration tests
├── config/default.yaml
├── docker-compose.yml      # LocalStack
├── Makefile
└── .github/workflows/ci.yml
```

## Acknowledgements

This tool was built from scratch for learning and demonstration. For production CSPM needs, see established tools like [Prowler](https://github.com/prowler-cloud/prowler) and [ScoutSuite](https://github.com/nccgroup/ScoutSuite).
