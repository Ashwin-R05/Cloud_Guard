"""Unit tests for BaseCheck and error-wrapping helpers."""

from typing import List
import boto3
import pytest
from botocore.exceptions import ClientError
from cloudguard.checks.base import BaseCheck, is_permission_error
from cloudguard.models import Finding, FindingStatus, Severity


class DummyValidCheck(BaseCheck):
    check_id = "DUMMY_CHECK"
    title = "Dummy Check Title"
    module = "test"
    base_severity = Severity.HIGH
    cis_reference = "CIS 1.0 Dummy"

    def run(self, session: boto3.Session, regions: List[str]) -> List[Finding]:
        return []


def test_base_check_subclass_initialization():
    """Verify concrete BaseCheck subclass instantiates properly."""
    check = DummyValidCheck()
    assert check.check_id == "DUMMY_CHECK"
    assert check.title == "Dummy Check Title"
    assert check.base_severity == Severity.HIGH


def test_base_check_missing_attributes():
    """Verify BaseCheck raises ValueError if required class attributes are omitted."""
    class IncompleteCheck(BaseCheck):
        check_id = "INCOMPLETE"
        # title, module, base_severity, cis_reference are missing

        def run(self, session: boto3.Session, regions: List[str]) -> List[Finding]:
            return []

    with pytest.raises(ValueError) as exc_info:
        IncompleteCheck()
    assert "must define" in str(exc_info.value)


def test_create_skipped_finding():
    """Verify skipped finding creation format."""
    check = DummyValidCheck()
    skipped = check.create_skipped_finding(
        reason="AccessDenied when calling DescribeBuckets",
        resource_id="all-buckets",
        resource_type="AWS::S3::Bucket",
        region="us-east-1",
    )
    assert skipped.status == FindingStatus.SKIPPED
    assert skipped.risk_score == 0.0
    assert skipped.severity == Severity.HIGH
    assert "[SKIPPED]" in skipped.title
    assert "AccessDenied" in skipped.description


def test_handle_client_error_access_denied():
    """Verify handle_client_error converts AccessDenied ClientError to SKIPPED finding."""
    check = DummyValidCheck()
    error_response = {
        "Error": {
            "Code": "AccessDenied",
            "Message": "User is not authorized to perform: s3:ListAllMyBuckets",
        }
    }
    client_error = ClientError(error_response, "ListAllMyBuckets")

    assert is_permission_error(client_error) is True

    finding = check.handle_client_error(
        error=client_error,
        resource_id="s3-service",
        region="us-east-1",
    )
    assert finding.status == FindingStatus.SKIPPED
    assert finding.check_id == "DUMMY_CHECK"
    assert "AccessDenied" in finding.description


def test_handle_client_error_non_permission_error():
    """Verify handle_client_error re-raises non-permission errors."""
    check = DummyValidCheck()
    error_response = {
        "Error": {
            "Code": "InvalidParameterValue",
            "Message": "The parameter is invalid.",
        }
    }
    client_error = ClientError(error_response, "DescribeSomething")

    assert is_permission_error(client_error) is False

    with pytest.raises(ClientError):
        check.handle_client_error(client_error)


def test_catch_access_denied_context_manager():
    """Verify catch_access_denied context manager captures AccessDenied without raising."""
    check = DummyValidCheck()
    findings: List[Finding] = []

    error_response = {
        "Error": {
            "Code": "UnauthorizedOperation",
            "Message": "You are not authorized to perform this operation.",
        }
    }
    client_error = ClientError(error_response, "DescribeInstances")

    with check.catch_access_denied(findings, region="us-east-1"):
        raise client_error

    assert len(findings) == 1
    assert findings[0].status == FindingStatus.SKIPPED
    assert "UnauthorizedOperation" in findings[0].description


def test_catch_access_denied_reraises_other_errors():
    """Verify catch_access_denied re-raises unexpected exceptions."""
    check = DummyValidCheck()
    findings: List[Finding] = []

    error_response = {
        "Error": {
            "Code": "InternalError",
            "Message": "Internal service failure.",
        }
    }
    client_error = ClientError(error_response, "DescribeInstances")

    with pytest.raises(ClientError):
        with check.catch_access_denied(findings, region="us-east-1"):
            raise client_error

    assert len(findings) == 0

