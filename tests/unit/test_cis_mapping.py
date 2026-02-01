"""Tests for CIS benchmark mapping completeness."""

from cspm.reporting.cis_mapping import CIS_MAP
from cspm.checks import ALL_CHECKS


def test_all_checks_have_cis_mapping():
    """Every check class should have a corresponding entry in CIS_MAP."""
    for check_cls in ALL_CHECKS:
        assert check_cls.id in CIS_MAP, f"Check {check_cls.id} missing from CIS_MAP"


def test_cis_map_entries_have_required_fields():
    for check_id, entry in CIS_MAP.items():
        assert "cis_id" in entry, f"{check_id} missing cis_id"
        assert "title" in entry, f"{check_id} missing title"
        assert "description" in entry, f"{check_id} missing description"
