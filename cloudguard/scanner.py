"""Scanner orchestration engine for CloudGuard.

Coordinates collectors and checks across specified regions and services,
aggregating findings and gracefully recording skipped checks when access is denied.
"""

from typing import List, Optional
import boto3
from cloudguard.config import Config
from cloudguard.models import Finding
from cloudguard.session import get_session


class CloudGuardScanner:
    """Orchestrates configuration collection and security checks."""

    def __init__(self, session: Optional[boto3.Session] = None, config: Optional[Config] = None):
        """Initialize scanner with AWS session and runtime configuration."""
        self.config = config or Config.load()
        self.session = session or get_session(self.config.aws_profile)

    def scan(self) -> List[Finding]:
        """Execute all registered security checks and return aggregated findings.

        Returns:
            List of Finding instances (including FAIL and SKIPPED status).
        """
        findings: List[Finding] = []
        # Stub: will iterate over collectors, pass data to checks, and collect findings
        return findings

