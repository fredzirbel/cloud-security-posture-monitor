"""CLI entry point for the CSPM scanner."""

from __future__ import annotations

import argparse
import json
import sys

from cspm.config import Config
from cspm.scanner import run_scan
from cspm.reporting.json_report import write_json_report
from cspm.reporting.html_report import write_html_report
from cspm.reporting.cis_mapping import CIS_MAP
from cspm.alerting.console import print_findings
from cspm.alerting.slack import send_slack_alert
from cspm.storage.sqlite_store import SQLiteStore
from cspm.models import Status


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="cspm",
        description="Cloud Security Posture Monitor — scan AWS for misconfigurations",
    )
    sub = parser.add_subparsers(dest="command")

    scan_parser = sub.add_parser("scan", help="Run a security scan")
    scan_parser.add_argument(
        "--config", "-c", default="config/default.yaml", help="Path to config YAML"
    )
    scan_parser.add_argument(
        "--output", "-o", choices=["console", "json", "html", "all"], default="console"
    )
    scan_parser.add_argument("--output-file", help="Output file path (for json/html)")
    scan_parser.add_argument("--compare-previous", action="store_true", help="Show delta from last scan")
    scan_parser.add_argument("--remediation", action="store_true", help="Show remediation commands")

    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)

    if not args.command:
        parse_args(["--help"])
        return 1

    config = Config.from_yaml(args.config)
    result = run_scan(config)

    failures = [f for f in result.findings if f.status == Status.FAIL]

    # Console output
    if args.output in ("console", "all"):
        print_findings(result, show_remediation=args.remediation)

    # JSON output
    if args.output in ("json", "all"):
        path = args.output_file or f"cspm_report_{result.scan_id}.json"
        write_json_report(result, path)
        print(f"\nJSON report written to {path}")

    # HTML output
    if args.output in ("html", "all"):
        path = args.output_file or f"cspm_report_{result.scan_id}.html"
        write_html_report(result, path)
        print(f"\nHTML report written to {path}")

    # Persist to SQLite
    store = SQLiteStore(config.db_path)
    store.save_scan(result)

    # Delta comparison
    if args.compare_previous:
        delta = store.get_delta(result.scan_id)
        if delta:
            print(f"\n--- Delta from previous scan ---")
            print(f"  New findings:      {len(delta['new'])}")
            print(f"  Resolved findings: {len(delta['resolved'])}")
            for f in delta["new"]:
                print(f"    [NEW]      [{f['severity']}] {f['check_id']}: {f['resource_arn']}")
            for f in delta["resolved"]:
                print(f"    [RESOLVED] [{f['severity']}] {f['check_id']}: {f['resource_arn']}")

    # Slack alerting
    if config.slack.enabled and failures:
        send_slack_alert(config.slack, result)

    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
