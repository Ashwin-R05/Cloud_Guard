"""Data models and enums for CloudGuard findings and compliance state."""

from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any, Dict, List


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


@dataclass
class ScanResult:
    """Aggregated output of a CloudGuard assessment execution.

    Attributes:
        account_id: AWS account ID where the scan executed.
        account_arn: Caller ARN used for the scan.
        scan_timestamp: ISO-8601 formatted UTC timestamp when scan ran.
        findings: Complete list of evaluated Finding objects (FAIL and SKIPPED).
        severity_counts: Summary breakdown of findings by severity and status.
        total_findings: Count of total findings evaluated.
    """

    account_id: str
    account_arn: str
    scan_timestamp: str
    findings: List[Finding] = field(default_factory=list)
    severity_counts: Dict[str, int] = field(default_factory=dict)
    total_findings: int = 0

    def to_dict(self) -> Dict[str, Any]:
        """Convert scan result to a dictionary representation."""
        return {
            "account_id": self.account_id,
            "account_arn": self.account_arn,
            "scan_timestamp": self.scan_timestamp,
            "severity_counts": self.severity_counts,
            "total_findings": self.total_findings,
            "findings": [f.to_dict() for f in self.findings],
        }
