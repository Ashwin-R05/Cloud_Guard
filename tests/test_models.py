"""Basic tests for CloudGuard models and configuration."""

from cloudguard.config import Config
from cloudguard.models import Finding, FindingStatus, Severity


def test_finding_to_dict():
    """Verify Finding serialization to dictionary."""
    finding = Finding(
        id="test-1",
        check_id="S3_TEST",
        title="Test Finding",
        description="Test Description",
        resource_id="arn:aws:s3:::my-bucket",
        resource_type="AWS::S3::Bucket",
        region="us-east-1",
        severity=Severity.HIGH,
        risk_score=7.5,
        cis_reference="CIS 2.1.1 Ensure S3 Buckets are not public",
        remediation="Enable S3 Block Public Access.",
        status=FindingStatus.FAIL,
    )
    data = finding.to_dict()
    assert data["id"] == "test-1"
    assert data["severity"] == "HIGH"
    assert data["status"] == "FAIL"
    assert data["risk_score"] == 7.5


def test_config_defaults(monkeypatch):
    """Verify default values in Config when environment variables are unset."""
    monkeypatch.delenv("CLOUDWARD_AWS_PROFILE", raising=False)
    monkeypatch.delenv("AWS_PROFILE", raising=False)
    monkeypatch.delenv("CLOUDWARD_REGIONS", raising=False)
    monkeypatch.delenv("AWS_REGIONS", raising=False)
    monkeypatch.delenv("AWS_DEFAULT_REGION", raising=False)

    cfg = Config.load()
    assert cfg.aws_profile is None
    assert cfg.regions == ["us-east-1"]

