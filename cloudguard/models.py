"""Data models and enums for CloudGuard findings and compliance state."""

from dataclasses import asdict, dataclass
from enum import Enum
from typing import Any, Dict


class Severity(str, Enum):
    """Severity classification for a misconfiguration finding."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


class FindingStatus(str, Enum):
    """Evaluation status of a security check finding."""

    FAIL = "FAIL"
    SKIPPED = "SKIPPED"


@dataclass
class Finding:
    """Represents an individual evaluation finding from an AWS check.

    Attributes:
        id: Unique identifier for the specific finding instance.
        check_id: Identifier of the check that produced this finding (e.g., 'S3_PUBLIC_READ').
        title: Short human-readable title describing the issue.
        description: Detailed explanation of the misconfiguration or skipped reason.
        resource_id: Identifier of the evaluated AWS resource (e.g., ARN, bucket name, user name).
        resource_type: Resource category (e.g., 'AWS::S3::Bucket', 'AWS::IAM::User').
        region: AWS region where the resource resides or 'global'.
        severity: Severity level (CRITICAL, HIGH, MEDIUM, LOW).
        risk_score: Normalized numerical risk score (0.0 to 10.0).
        cis_reference: Associated CIS control title and/or reference marker.
        remediation: Actionable guidance on how to fix or mitigate the finding.
        status: Finding outcome status, strictly FAIL or SKIPPED.
    """

    id: str
    check_id: str
    title: str
    description: str
    resource_id: str
    resource_type: str
    region: str
    severity: Severity
    risk_score: float
    cis_reference: str
    remediation: str
    status: FindingStatus = FindingStatus.FAIL

    def to_dict(self) -> Dict[str, Any]:
        """Convert finding instance to a dictionary representation."""
        data = asdict(self)
        data["severity"] = self.severity.value if isinstance(self.severity, Severity) else str(self.severity)
        data["status"] = self.status.value if isinstance(self.status, FindingStatus) else str(self.status)
        return data

