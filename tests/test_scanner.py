"""Unit tests for CloudGuard Scanner orchestration."""

from typing import List
import boto3
import pytest
from botocore.exceptions import ClientError
from moto import mock_aws
from cloudguard.checks.base import BaseCheck
from cloudguard.checks.registry import clear_registry, register_check
from cloudguard.models import Finding, FindingStatus, Severity
from cloudguard.scanner import Scanner


@pytest.fixture(autouse=True)
def clean_registry():
    clear_registry()
    yield
    clear_registry()


class MockFailingCheck(BaseCheck):
    check_id = "MOCK_FAIL_CHECK"
    title = "Mock Failing Security Check"
    module = "s3"
    base_severity = Severity.HIGH
    cis_reference = "CIS 2.1 Mock"

    def run(self, session: boto3.Session, regions: List[str]) -> List[Finding]:
        return [
            Finding(
                id="mock-fail-1",
                check_id=self.check_id,
                title=self.title,
                description="Mock bucket is publicly accessible",
                resource_id="arn:aws:s3:::vulnerable-bucket",
                resource_type="AWS::S3::Bucket",
                region="us-east-1",
                severity=self.base_severity,
                risk_score=7.5,
                cis_reference=self.cis_reference,
                remediation="Enable Block Public Access",
                status=FindingStatus.FAIL,
            )
        ]


class MockAccessDeniedCheck(BaseCheck):
    check_id = "MOCK_DENIED_CHECK"
    title = "Mock Denied Check"
    module = "iam"
    base_severity = Severity.CRITICAL
    cis_reference = "CIS 1.2 Mock"

    def run(self, session: boto3.Session, regions: List[str]) -> List[Finding]:
        error_response = {
            "Error": {
                "Code": "AccessDenied",
                "Message": "User is not authorized to call iam:GetAccountSummary",
            }
        }
        raise ClientError(error_response, "GetAccountSummary")


@mock_aws
def test_scanner_executes_checks_and_compiles_results():
    """Verify scanner runs registered checks and computes severity counts."""
    register_check(MockFailingCheck)
    session = boto3.Session(region_name="us-east-1")
    scanner = Scanner(session=session, regions=["us-east-1"])

    result = scanner.scan(check_ids=["MOCK_FAIL_CHECK"])

    assert result.account_id is not None
    assert len(result.account_id) == 12
    assert result.total_findings == 1
    assert result.findings[0].id == "mock-fail-1"
    assert result.severity_counts[Severity.HIGH.value] == 1
    assert result.severity_counts[FindingStatus.SKIPPED.value] == 0


@mock_aws
def test_scanner_handles_access_denied_gracefully():
    """Verify scanner catches AccessDenied from check and outputs SKIPPED finding."""
    register_check(MockAccessDeniedCheck)
    session = boto3.Session(region_name="us-east-1")
    scanner = Scanner(session=session, regions=["us-east-1"])

    result = scanner.scan(check_ids=["MOCK_DENIED_CHECK"])

    assert result.total_findings == 1
    finding = result.findings[0]
    assert finding.status == FindingStatus.SKIPPED
    assert finding.severity == Severity.CRITICAL
    assert finding.risk_score == 0.0
    assert "AccessDenied" in finding.description
    assert result.severity_counts[FindingStatus.SKIPPED.value] == 1


@mock_aws
def test_scanner_check_id_filtering():
    """Verify running only selected checks via check_ids parameter."""
    register_check(MockFailingCheck)
    register_check(MockAccessDeniedCheck)
    session = boto3.Session(region_name="us-east-1")
    scanner = Scanner(session=session, regions=["us-east-1"])

    result = scanner.scan(check_ids=["MOCK_FAIL_CHECK"])
    assert result.total_findings == 1
    assert result.findings[0].check_id == "MOCK_FAIL_CHECK"

