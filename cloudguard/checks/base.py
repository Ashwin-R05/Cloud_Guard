"""Base classes and utilities for CloudGuard security and compliance checks."""

from abc import ABC, abstractmethod
from contextlib import contextmanager
from typing import Any, Callable, Generator, List, Optional
import boto3
from botocore.exceptions import ClientError, EndpointConnectionError
from cloudguard.models import Finding, FindingStatus, Severity

# Common AWS error codes indicating permission denials or unauthorized access
ACCESS_DENIED_CODES = {
    "AccessDenied",
    "AccessDeniedException",
    "UnauthorizedOperation",
    "AuthFailure",
    "AuthorizationError",
    "Client.UnauthorizedOperation",
    "OptInRequired",
    "InvalidAction",
    "SubscriptionRequiredException",
}


def is_permission_error(error: Exception) -> bool:
    """Determine if an exception represents an AWS permissions denial or missing service authorization."""
    if isinstance(error, ClientError):
        code = error.response.get("Error", {}).get("Code", "")
        return code in ACCESS_DENIED_CODES or "AccessDenied" in code or "Unauthorized" in code
    return False


class BaseCheck(ABC):
    """Abstract base class for all CloudGuard compliance checks.

    Attributes:
        check_id: Unique string identifying the check (e.g. 'S3_BLOCK_PUBLIC_ACCESS').
        title: Short descriptive title of the check.
        module: AWS domain or service module name (e.g. 's3', 'iam', 'cloudtrail').
        base_severity: Baseline severity level if a violation is detected.
        cis_reference: Related CIS AWS Foundations Benchmark reference or title.
    """

    check_id: str
    title: str
    module: str
    base_severity: Severity
    cis_reference: str

    def __init__(self) -> None:
        if not getattr(self, "check_id", None):
            raise ValueError(f"Check class {self.__class__.__name__} must define 'check_id'")
        if not getattr(self, "title", None):
            raise ValueError(f"Check class {self.__class__.__name__} must define 'title'")
        if not getattr(self, "module", None):
            raise ValueError(f"Check class {self.__class__.__name__} must define 'module'")
        if not getattr(self, "base_severity", None):
            raise ValueError(f"Check class {self.__class__.__name__} must define 'base_severity'")
        if not getattr(self, "cis_reference", None):
            raise ValueError(f"Check class {self.__class__.__name__} must define 'cis_reference'")

    @abstractmethod
    def run(self, session: boto3.Session, regions: List[str]) -> List[Finding]:
        """Execute the check logic across the specified AWS session and regions.

        Args:
            session: Read-only boto3.Session for AWS interactions.
            regions: List of AWS region strings to evaluate.

        Returns:
            List of Finding instances representing failures or skipped evaluations.
        """
        raise NotImplementedError

    def create_skipped_finding(
        self,
        reason: str,
        resource_id: str = "N/A",
        resource_type: str = "AWS::Service",
        region: str = "global",
    ) -> Finding:
        """Create a Finding with SKIPPED status and 0.0 risk score.

        Args:
            reason: Explanation of why the check was skipped (e.g. AccessDenied).
            resource_id: Resource identifier or 'N/A'.
            resource_type: Resource category or 'AWS::Service'.
            region: AWS region or 'global'.

        Returns:
            Finding with status FindingStatus.SKIPPED.
        """
        finding_id = f"{self.check_id}-{region}-{resource_id}-skipped".replace("::", "-").replace("/", "-")
        return Finding(
            id=finding_id,
            check_id=self.check_id,
            title=f"[SKIPPED] {self.title}",
            description=reason,
            resource_id=resource_id,
            resource_type=resource_type,
            region=region,
            severity=self.base_severity,
            risk_score=0.0,
            cis_reference=self.cis_reference,
            remediation="Ensure the IAM execution role has permissions to perform read-only describe/get calls.",
            status=FindingStatus.SKIPPED,
        )

    def handle_client_error(
        self,
        error: ClientError,
        resource_id: str = "N/A",
        resource_type: str = "AWS::Service",
        region: str = "global",
    ) -> Finding:
        """Wrap a boto3 ClientError into a SKIPPED finding if AccessDenied, or re-raise if unhandled.

        Args:
            error: Caught botocore.exceptions.ClientError.
            resource_id: Resource identifier.
            resource_type: Resource type.
            region: AWS region.

        Returns:
            Finding representing the skipped check.

        Raises:
            ClientError: If error is not a permissions or authorization issue.
        """
        if is_permission_error(error):
            code = error.response.get("Error", {}).get("Code", "AccessDenied")
            msg = error.response.get("Error", {}).get("Message", str(error))
            reason = f"Check skipped due to AWS permission error [{code}]: {msg}"
            return self.create_skipped_finding(
                reason=reason,
                resource_id=resource_id,
                resource_type=resource_type,
                region=region,
            )
        raise error

    @contextmanager
    def catch_access_denied(
        self,
        findings_sink: List[Finding],
        resource_id: str = "N/A",
        resource_type: str = "AWS::Service",
        region: str = "global",
    ) -> Generator[None, None, None]:
        """Context manager to safely catch AccessDenied ClientErrors and record a SKIPPED finding.

        Usage:
            with self.catch_access_denied(findings, region=region):
                client.describe_something()
        """
        try:
            yield
        except ClientError as exc:
            if is_permission_error(exc):
                findings_sink.append(
                    self.handle_client_error(
                        error=exc,
                        resource_id=resource_id,
                        resource_type=resource_type,
                        region=region,
                    )
                )
            else:
                raise

