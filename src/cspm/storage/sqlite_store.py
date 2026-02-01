"""SQLite storage for scan results and delta analysis."""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

from cspm.models import ScanResult, Finding, Status


class SQLiteStore:
    def __init__(self, db_path: str = "cspm_findings.db"):
        self.db_path = db_path
        self._init_db()

    def _init_db(self) -> None:
        with self._connect() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS scans (
                    scan_id TEXT PRIMARY KEY,
                    timestamp TEXT NOT NULL,
                    region TEXT NOT NULL,
                    total_findings INTEGER,
                    fail_count INTEGER,
                    pass_count INTEGER
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS findings (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id TEXT NOT NULL,
                    check_id TEXT NOT NULL,
                    cis_id TEXT,
                    title TEXT,
                    severity TEXT NOT NULL,
                    status TEXT NOT NULL,
                    resource_arn TEXT NOT NULL,
                    region TEXT,
                    description TEXT,
                    remediation TEXT,
                    timestamp TEXT,
                    FOREIGN KEY (scan_id) REFERENCES scans(scan_id)
                )
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_findings_scan ON findings(scan_id)
            """)

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def save_scan(self, result: ScanResult) -> None:
        with self._connect() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO scans (scan_id, timestamp, region, total_findings, fail_count, pass_count) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (
                    result.scan_id,
                    result.timestamp.isoformat(),
                    result.region,
                    len(result.findings),
                    result.fail_count,
                    result.pass_count,
                ),
            )
            for f in result.findings:
                conn.execute(
                    "INSERT INTO findings (scan_id, check_id, cis_id, title, severity, status, resource_arn, region, description, remediation, timestamp) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        result.scan_id,
                        f.check_id,
                        f.cis_id,
                        f.title,
                        f.severity.value,
                        f.status.value,
                        f.resource_arn,
                        f.region,
                        f.description,
                        f.remediation,
                        f.timestamp.isoformat(),
                    ),
                )

    def get_delta(self, current_scan_id: str) -> dict | None:
        """Compare current scan to the most recent previous scan and return new/resolved findings."""
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT scan_id FROM scans WHERE scan_id != ? ORDER BY timestamp DESC LIMIT 1",
                (current_scan_id,),
            ).fetchall()

            if not rows:
                return None

            prev_scan_id = rows[0]["scan_id"]

            current_failures = set()
            for row in conn.execute(
                "SELECT check_id, resource_arn, severity FROM findings WHERE scan_id = ? AND status = 'FAIL'",
                (current_scan_id,),
            ):
                current_failures.add((row["check_id"], row["resource_arn"]))

            prev_failures = set()
            prev_details = {}
            for row in conn.execute(
                "SELECT check_id, resource_arn, severity FROM findings WHERE scan_id = ? AND status = 'FAIL'",
                (prev_scan_id,),
            ):
                key = (row["check_id"], row["resource_arn"])
                prev_failures.add(key)
                prev_details[key] = dict(row)

            current_details = {}
            for row in conn.execute(
                "SELECT check_id, resource_arn, severity FROM findings WHERE scan_id = ? AND status = 'FAIL'",
                (current_scan_id,),
            ):
                key = (row["check_id"], row["resource_arn"])
                current_details[key] = dict(row)

            new_keys = current_failures - prev_failures
            resolved_keys = prev_failures - current_failures

            return {
                "new": [current_details[k] for k in new_keys],
                "resolved": [prev_details[k] for k in resolved_keys],
                "previous_scan_id": prev_scan_id,
            }

    def get_scan_history(self, limit: int = 10) -> list[dict]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM scans ORDER BY timestamp DESC LIMIT ?", (limit,)
            ).fetchall()
            return [dict(r) for r in rows]
