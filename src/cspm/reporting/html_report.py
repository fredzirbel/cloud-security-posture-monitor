"""HTML report generator using Jinja2 templates."""

from __future__ import annotations

from pathlib import Path

from jinja2 import Environment, FileSystemLoader

from cspm.models import ScanResult, Status, Severity
from cspm.reporting.cis_mapping import CIS_MAP

TEMPLATE_DIR = Path(__file__).resolve().parent.parent.parent.parent / "templates"


def write_html_report(result: ScanResult, path: str) -> None:
    env = Environment(loader=FileSystemLoader(str(TEMPLATE_DIR)), autoescape=True)
    template = env.get_template("report.html.j2")

    failures = [f for f in result.findings if f.status == Status.FAIL]
    passes = [f for f in result.findings if f.status == Status.PASS]

    severity_counts = {}
    for f in failures:
        severity_counts[f.severity.value] = severity_counts.get(f.severity.value, 0) + 1

    sorted_failures = sorted(failures, key=lambda f: f.severity)

    html = template.render(
        scan_id=result.scan_id,
        timestamp=result.timestamp.isoformat(),
        region=result.region,
        total=len(result.findings),
        pass_count=len(passes),
        fail_count=len(failures),
        severity_counts=severity_counts,
        failures=sorted_failures,
        cis_map=CIS_MAP,
    )

    with open(path, "w") as f:
        f.write(html)
