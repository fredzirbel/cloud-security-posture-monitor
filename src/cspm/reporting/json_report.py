"""JSON report writer."""

from __future__ import annotations

import json

from cspm.models import ScanResult


def write_json_report(result: ScanResult, path: str) -> None:
    with open(path, "w") as f:
        json.dump(result.to_dict(), f, indent=2)
