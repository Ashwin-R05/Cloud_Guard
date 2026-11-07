"""Unit tests for HTML and JSON report generation."""

import json
from pathlib import Path
import pytest
from cloudguard.models import Finding, FindingStatus, ScanResult, Severity
from cloudguard.report import ReportGenerator


@pytest.fixture
def sample_scan_result() -> ScanResult:
    """Fixture providing a realistic ScanResult with diverse findings."""
    f1 = Finding(
        id="S3-01-us-east-1-public-bucket",
        check_id="S3-01",
        title="S3 bucket is publicly accessible",
        description="Bucket 'public-bucket' allows public read access.",
        resource_id="public-bucket",
        resource_type="AWS::S3::Bucket",
        region="us-east-1",
        severity=Severity.CRITICAL,
        risk_score=25.0,
        cis_reference="Ensure S3 Buckets are not publicly accessible",
        remediation="Enable S3 Block Public Access on the bucket.",
        status=FindingStatus.FAIL,
        impact=5,
        exposure=5,
        exposure_reason="Bucket is open to AllUsers",
    )
    f2 = Finding(
        id="DATA-01-us-east-1-vol-12345",
        check_id="DATA-01",
        title="EBS volume is not encrypted",
        description="EBS volume 'vol-12345' is not encrypted at rest.",
        resource_id="vol-12345",
        resource_type="AWS::EC2::Volume",
        region="us-east-1",
        severity=Severity.MEDIUM,
        risk_score=9.0,
        cis_reference="Ensure EBS volume encryption is enabled",
        remediation="Create snapshot and copy with KMS encryption.",
        status=FindingStatus.FAIL,
        impact=3,
        exposure=3,
        exposure_reason="Block storage unencrypted at rest",
    )
    f3 = Finding(
        id="IAM-01-global-N-A-skipped",
        check_id="IAM-01",
        title="[SKIPPED] Console user without MFA",
        description="AccessDenied when calling iam:GetLoginProfile",
        resource_id="N/A",
        resource_type="AWS::IAM::User",
        region="global",
        severity=Severity.HIGH,
        risk_score=0.0,
        cis_reference="Ensure MFA is enabled for console users",
        remediation="Grant IAM read permissions.",
        status=FindingStatus.SKIPPED,
        impact=4,
        exposure=0,
        exposure_reason="Skipped check",
    )

    return ScanResult(
        account_id="123456789012",
        account_arn="arn:aws:sts::123456789012:assumed-role/CloudGuardReadOnly/scan",
        scan_timestamp="2026-11-07T12:00:00+00:00",
        findings=[f2, f1, f3],  # Purposely unordered to verify sorting
        severity_counts={
            "CRITICAL": 1,
            "HIGH": 0,
            "MEDIUM": 1,
            "LOW": 0,
            "SKIPPED": 1,
        },
        total_findings=3,
        posture_score=66.0,
    )


def test_html_report_rendering_is_self_contained(sample_scan_result: ScanResult):
    """Verify HTML report renders required sections and is completely self-contained."""
    generator = ReportGenerator()
    html = generator.render_html(sample_scan_result)

    # 1. Essential metadata and statistics
    assert "123456789012" in html
    assert "2026-11-07T12:00:00+00:00" in html
    assert "66.0" in html
    assert "public-bucket" in html
    assert "vol-12345" in html

    # 2. Score breakdown and remediation
    assert "Impact: 5 &times; Exposure: 5 = Score: 25.0" in html or "Impact: 5" in html
    assert "Enable S3 Block Public Access on the bucket." in html
    assert "Bucket is open to AllUsers" in html

    # 3. Sorted by risk score: Critical (25.0) appears before Medium (9.0)
    pos_crit = html.find("public-bucket")
    pos_med = html.find("vol-12345")
    assert pos_crit != -1 and pos_med != -1
    assert pos_crit < pos_med

    # 4. Strictly self-contained: No external HTTP/HTTPS scripts, fonts, or stylesheets
    assert "http://" not in html
    assert "https://" not in html
    assert "<link rel=\"stylesheet\"" not in html
    assert "<script src=" not in html


def test_json_report_schema_compliance(sample_scan_result: ScanResult):
    """Verify JSON export matches schema and preserves sorted findings without leaking credentials."""
    generator = ReportGenerator()
    json_str = generator.generate_json(sample_scan_result)
    data = json.loads(json_str)

    # Root fields
    assert data["account_id"] == "123456789012"
    assert data["account_arn"] == "arn:aws:sts::123456789012:assumed-role/CloudGuardReadOnly/scan"
    assert data["scan_timestamp"] == "2026-11-07T12:00:00+00:00"
    assert data["posture_score"] == 66.0
    assert data["total_findings"] == 3

    # Findings array sorted by risk score descending
    findings = data["findings"]
    assert len(findings) == 3
    assert findings[0]["risk_score"] == 25.0
    assert findings[1]["risk_score"] == 9.0
    assert findings[2]["risk_score"] == 0.0

    # Ensure required finding keys are present
    first = findings[0]
    required_keys = [
        "id", "check_id", "title", "description", "resource_id",
        "resource_type", "region", "severity", "risk_score",
        "cis_reference", "remediation", "status", "impact",
        "exposure", "exposure_reason",
    ]
    for key in required_keys:
        assert key in first

    # Zero credential leakage check
    sensitive_keywords = ["secret", "password", "token", "access_key_secret"]
    for keyword in sensitive_keywords:
        assert keyword not in json_str.lower()


def test_generate_reports_disk_output(tmp_path: Path, sample_scan_result: ScanResult):
    """Verify saving reports to disk produces timestamped JSON and HTML files."""
    generator = ReportGenerator()
    created = generator.generate_reports(sample_scan_result, output_dir=tmp_path, fmt="both")

    assert "json" in created
    assert "html" in created

    json_path = Path(created["json"])
    html_path = Path(created["html"])

    assert json_path.is_file()
    assert html_path.is_file()
    assert json_path.stat().st_size > 0
    assert html_path.stat().st_size > 0
    assert "123456789012" in json_path.name

