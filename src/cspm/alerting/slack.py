"""Slack webhook alerting for scan results."""

from __future__ import annotations

import requests

from cspm.config import SlackConfig
from cspm.models import ScanResult, Severity, Status


SEVERITY_EMOJI = {
    Severity.CRITICAL: ":rotating_light:",
    Severity.HIGH: ":warning:",
    Severity.MEDIUM: ":large_yellow_circle:",
    Severity.LOW: ":information_source:",
    Severity.INFO: ":white_circle:",
}


def send_slack_alert(config: SlackConfig, result: ScanResult) -> bool:
    if not config.webhook_url:
        return False

    failures = [f for f in result.findings if f.status == Status.FAIL]
    if not failures:
        return False

    min_sev = Severity[config.min_severity]

    severity_counts = {}
    for f in failures:
        severity_counts[f.severity.value] = severity_counts.get(f.severity.value, 0) + 1

    summary_lines = [f"*{sev}*: {count}" for sev, count in sorted(severity_counts.items())]

    blocks = [
        {
            "type": "header",
            "text": {"type": "plain_text", "text": f"CSPM Scan Results — {result.scan_id}"},
        },
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": (
                    f"*Region:* {result.region}\n"
                    f"*Timestamp:* {result.timestamp.isoformat()}\n"
                    f"*Total findings:* {len(result.findings)} | *Failures:* {len(failures)}\n\n"
                    + "\n".join(summary_lines)
                ),
            },
        },
    ]

    # Individual blocks for critical findings
    critical_findings = [
        f for f in failures if f.severity.rank <= min_sev.rank
    ]

    for finding in critical_findings[:10]:
        emoji = SEVERITY_EMOJI.get(finding.severity, "")
        blocks.append({
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": (
                    f"{emoji} *[{finding.severity.value}] {finding.title}*\n"
                    f"Resource: `{finding.resource_arn}`\n"
                    f"CIS: {finding.cis_id} | {finding.description}"
                ),
            },
        })

    if len(critical_findings) > 10:
        blocks.append({
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": f"_...and {len(critical_findings) - 10} more findings above threshold._",
            },
        })

    payload = {"blocks": blocks}

    try:
        resp = requests.post(config.webhook_url, json=payload, timeout=10)
        return resp.status_code == 200
    except requests.RequestException:
        return False
