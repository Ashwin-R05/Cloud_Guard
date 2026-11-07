"""Unit tests for the Streamlit dashboard using Streamlit AppTest."""

from pathlib import Path
import pytest
from streamlit.testing.v1 import AppTest
from cloudguard.models import Finding, FindingStatus, ScanResult, Severity


@pytest.fixture
def sample_scan_result() -> ScanResult:
    f1 = Finding(
        id="S3-01-us-east-1-public-bkt",
        check_id="S3-01",
        title="Public bucket",
        description="Bucket allows public read.",
        resource_id="public-bkt",
        resource_type="AWS::S3::Bucket",
        region="us-east-1",
        severity=Severity.CRITICAL,
        risk_score=25.0,
        cis_reference="CIS 2.1",
        remediation="Enable BPA",
        status=FindingStatus.FAIL,
        impact=5,
        exposure=5,
        exposure_reason="Public to world",
    )
    f2 = Finding(
        id="IAM-01-global-N-A-skipped",
        check_id="IAM-01",
        title="[SKIPPED] Console MFA",
        description="AccessDenied",
        resource_id="N/A",
        resource_type="AWS::IAM::User",
        region="global",
        severity=Severity.HIGH,
        risk_score=0.0,
        cis_reference="CIS 1.1",
        remediation="Check IAM",
        status=FindingStatus.SKIPPED,
        impact=4,
        exposure=0,
        exposure_reason="Skipped",
    )
    return ScanResult(
        account_id="123456789012",
        account_arn="arn:aws:iam::123456789012:role/Scanner",
        scan_timestamp="2026-11-07T12:00:00+00:00",
        findings=[f1, f2],
        severity_counts={"CRITICAL": 1, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "SKIPPED": 1},
        total_findings=2,
        posture_score=75.0,
    )


DASHBOARD_PATH = str((Path(__file__).parent.parent / "dashboard" / "app.py").resolve())


def test_dashboard_initial_state():
    """Verify dashboard loads initial view when no scan results are present."""
    at = AppTest.from_file(DASHBOARD_PATH)
    at.run()
    assert not at.exception
    # Confirm welcome banner / info is displayed
    assert len(at.info) > 0
    assert "No scan results loaded yet" in at.info[0].value


def test_dashboard_with_loaded_result(sample_scan_result: ScanResult):
    """Verify dashboard renders metrics, charts, and findings table when a result is set in session state."""
    at = AppTest.from_file(DASHBOARD_PATH)
    at.run()

    # Inject scan_result into session_state and re-run
    at.session_state["scan_result"] = sample_scan_result
    at.run()

    assert not at.exception
    # Metrics check: posture score, critical, high, medium, low
    metric_labels = [m.label for m in at.metric]
    assert "Posture Score" in metric_labels
    assert "Critical" in metric_labels

    # Posture score value
    posture_metric = next(m for m in at.metric if m.label == "Posture Score")
    assert "75.0" in posture_metric.value

    # Findings explorer section present
    assert any("Findings Explorer" in md.value for md in at.markdown)

    # Download buttons present
    assert len(at.download_button) >= 2
    dl_labels = [b.label for b in at.download_button]
    assert any("JSON" in lbl for lbl in dl_labels)
    assert any("HTML" in lbl for lbl in dl_labels)
