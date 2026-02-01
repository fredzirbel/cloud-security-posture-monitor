"""Abstract base class for all security checks."""

from __future__ import annotations

from abc import ABC, abstractmethod

import boto3

from cspm.models import Finding


class BaseCheck(ABC):
    """Base class that all security checks must inherit from."""

    id: str = ""
    title: str = ""
    cis_id: str = ""
    service: str = ""

    def __init__(self, session: boto3.Session, region: str, endpoint_url: str | None = None):
        self.session = session
        self.region = region
        self.endpoint_url = endpoint_url

    def _get_client(self, service_name: str):
        kwargs = {"region_name": self.region}
        if self.endpoint_url:
            kwargs["endpoint_url"] = self.endpoint_url
        return self.session.client(service_name, **kwargs)

    @abstractmethod
    def run(self) -> list[Finding]:
        """Execute the check and return a list of findings."""
        ...
