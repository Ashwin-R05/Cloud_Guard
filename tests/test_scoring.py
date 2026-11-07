"""Unit tests for CloudGuard risk scoring and account posture calculation."""

import pytest
from cloudguard.models import Finding, FindingStatus, Severity
from cloudguard.scoring import (
    calculate_account_risk_summary,
    calculate_posture_score,
    calculate_risk,
    score_to_severity,
)


def test_severity_band_boundaries():
    """Verify exact boundary mappings between severity bands."""
    # Critical band: 20 to 25
    assert score_to_severity(25) == Severity.CRITICAL
    assert score_to_severity(20) == Severity.CRITICAL

    # High band: 12 to 19
    assert score_to_severity(19) == Severity.HIGH
    assert score_to_severity(15) == Severity.HIGH
    assert score_to_severity(12) == Severity.HIGH

    # Medium band: 6 to 11
    assert score_to_severity(11) == Severity.MEDIUM
    assert score_to_severity(8) == Severity.MEDIUM
    assert score_to_severity(6) == Severity.MEDIUM

    # Low band: 1 to 5
    assert score_to_severity(5) == Severity.LOW
    assert score_to_severity(3) == Severity.LOW
    assert score_to_severity(1) == Severity.LOW


def test_calculate_risk_defaults_and_clamping():
    """Verify calculate_risk defaults and parameter clamping."""
    # Default exposure is 3
    # Critical impact default = 5 -> 5 * 3 = 15 (High)
    score, sev, imp, exp, reason = calculate_risk(Severity.CRITICAL)
    assert score == 15.0
    assert sev == Severity.HIGH
    assert imp == 5
    assert exp == 3
    assert reason == "Standard baseline exposure"

    # Max exposure 5 with Critical impact 5 -> 25 (Critical)
    score, sev, imp, exp, reason = calculate_risk(
        Severity.CRITICAL,
        exposure=5,
        exposure_reason="Publicly accessible from 0.0.0.0/0",
    )
    assert score == 25.0
    assert sev == Severity.CRITICAL
    assert exp == 5
    assert "Publicly accessible" in reason

    # Out-of-bounds exposure values are clamped to [1, 5]
    score_low, _, _, exp_low, _ = calculate_risk(Severity.MEDIUM, exposure=-5)
    assert exp_low == 1
    assert score_low == 3.0  # 3 * 1

    score_high, _, _, exp_high, _ = calculate_risk(Severity.MEDIUM, exposure=10)
    assert exp_high == 5
    assert score_high == 15.0  # 3 * 5


def test_posture_score_calculation():
    """Verify account posture score calculations and deductions."""
    # 1. No findings -> 100.0
    assert calculate_posture_score([]) == 100.0

    # 2. Only SKIPPED findings -> 100.0 (no penalty)
    skipped_finding = Finding(
        id="f-skipped",
        check_id="TEST",
        title="Skipped Check",
        description="AccessDenied",
        resource_id="N/A",
        resource_type="AWS::Service",
        region="global",
        severity=Severity.HIGH,
        risk_score=0.0,
        cis_reference="CIS Test",
        remediation="Fix IAM",
        status=FindingStatus.SKIPPED,
    )
    assert calculate_posture_score([skipped_finding]) == 100.0

    # 3. Failed finding deductions
    crit_finding = Finding(
        id="f-crit",
        check_id="S3-01",
        title="Public Bucket",
        description="Public S3",
        resource_id="my-bkt",
        resource_type="AWS::S3::Bucket",
        region="us-east-1",
        severity=Severity.CRITICAL,
        risk_score=25.0,
        cis_reference="CIS 2.1",
        remediation="Enable BPA",
        status=FindingStatus.FAIL,
    )
    med_finding = Finding(
        id="f-med",
        check_id="DATA-01",
        title="Unencrypted EBS",
        description="EBS volume unencrypted",
        resource_id="vol-123",
        resource_type="AWS::EC2::Volume",
        region="us-east-1",
        severity=Severity.MEDIUM,
        risk_score=9.0,
        cis_reference="CIS 2.2",
        remediation="Enable KMS",
        status=FindingStatus.FAIL,
    )

    # 100.0 - 25.0 - 9.0 = 66.0
    assert calculate_posture_score([crit_finding, med_finding, skipped_finding]) == 66.0

    # 4. Saturation at 0.0 (cannot drop below zero)
    heavy_failures = [crit_finding] * 5  # 5 * 25 = 125 deduction
    assert calculate_posture_score(heavy_failures) == 0.0


def test_calculate_account_risk_summary():
    """Verify account-level summary dictionary contents."""
    finding1 = Finding(
        id="f1",
        check_id="S3-01",
        title="Public Bucket",
        description="Public S3",
        resource_id="my-bkt",
        resource_type="AWS::S3::Bucket",
        region="us-east-1",
        severity=Severity.CRITICAL,
        risk_score=25.0,
        cis_reference="CIS 2.1",
        remediation="Enable BPA",
        status=FindingStatus.FAIL,
    )
    finding2 = Finding(
        id="f2",
        check_id="IAM-01",
        title="Skipped",
        description="Skipped",
        resource_id="N/A",
        resource_type="AWS::IAM::User",
        region="global",
        severity=Severity.HIGH,
        risk_score=0.0,
        cis_reference="CIS 1.1",
        remediation="N/A",
        status=FindingStatus.SKIPPED,
    )

    summary = calculate_account_risk_summary([finding1, finding2])
    assert summary["total_findings"] == 2
    assert summary["failed_findings"] == 1
    assert summary["skipped_findings"] == 1
    assert summary["posture_score"] == 75.0
    assert summary["total_risk_score"] == 25.0
    assert summary["severity_counts"]["CRITICAL"] == 1
    assert summary["severity_counts"]["SKIPPED"] == 1

