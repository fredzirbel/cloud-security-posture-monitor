"""Configuration loader for CSPM scanner."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

import yaml


@dataclass
class SlackConfig:
    enabled: bool = False
    webhook_url: str = ""
    min_severity: str = "HIGH"


@dataclass
class Config:
    regions: list[str] = field(default_factory=lambda: ["us-east-1"])
    endpoint_url: str | None = None
    checks: list[str] = field(default_factory=lambda: ["all"])
    slack: SlackConfig = field(default_factory=SlackConfig)
    output_format: str = "console"
    output_file: str | None = None
    db_path: str = "cspm_findings.db"

    @classmethod
    def from_yaml(cls, path: str | Path) -> Config:
        path = Path(path)
        if not path.exists():
            return cls()

        with open(path) as f:
            data = yaml.safe_load(f) or {}

        slack_data = data.pop("slack", {})
        slack_config = SlackConfig(**slack_data) if slack_data else SlackConfig()

        config = cls(slack=slack_config, **data)

        # Resolve db_path relative to the config file's parent directory
        db_path = Path(config.db_path)
        if not db_path.is_absolute():
            config.db_path = str(path.resolve().parent / db_path)

        return config
