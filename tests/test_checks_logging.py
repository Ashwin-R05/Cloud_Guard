"""Unit tests for CloudTrail logging checks using Moto."""

import boto3
import pytest
from moto import mock_aws
from cloudguard.checks.logging_checks import CloudTrailLoggingCheck
from cloudguard.models import FindingStatus, Severity


@mock_aws
def test_log_01_no_trails_flagged():
    """Verify LOG-01 flags an account with no CloudTrail trails."""
    session = boto3.Session(region_name="us-east-1")
    check = CloudTrailLoggingCheck()
    findings = check.run(session, regions=["us-east-1"])

    assert len(findings) == 1
    f = findings[0]
    assert f.check_id == "LOG-01"
    assert f.status == FindingStatus.FAIL
    assert f.severity == Severity.HIGH
    assert f.region == "global"
    assert len(f.resource_id) == 12  # AWS 12-digit account ID
    assert "does not have an active multi-region CloudTrail" in f.description


@mock_aws
def test_log_01_single_region_trail_flagged():
    """Verify LOG-01 flags an account when trail is only single-region."""
    session = boto3.Session(region_name="us-east-1")
    ct = session.client("cloudtrail", region_name="us-east-1")
    s3 = session.client("s3", region_name="us-east-1")
    s3.create_bucket(Bucket="test-ct-bucket")

    ct.create_trail(Name="regional-trail", S3BucketName="test-ct-bucket", IsMultiRegionTrail=False)
    ct.start_logging(Name="regional-trail")

    check = CloudTrailLoggingCheck()
    findings = check.run(session, regions=["us-east-1"])

    assert len(findings) == 1
    assert findings[0].check_id == "LOG-01"


@mock_aws
def test_log_01_multi_region_trail_not_logging_flagged():
    """Verify LOG-01 flags an account when a multi-region trail is stopped/not logging."""
    session = boto3.Session(region_name="us-east-1")
    ct = session.client("cloudtrail", region_name="us-east-1")
    s3 = session.client("s3", region_name="us-east-1")
    s3.create_bucket(Bucket="test-ct-bucket-stopped")

    # Created without start_logging
    ct.create_trail(Name="stopped-trail", S3BucketName="test-ct-bucket-stopped", IsMultiRegionTrail=True)

    check = CloudTrailLoggingCheck()
    findings = check.run(session, regions=["us-east-1"])

    assert len(findings) == 1
    assert findings[0].check_id == "LOG-01"


@mock_aws
def test_log_01_compliant_active_multi_region_trail():
    """Verify LOG-01 passes when a multi-region trail is actively logging."""
    session = boto3.Session(region_name="us-east-1")
    ct = session.client("cloudtrail", region_name="us-east-1")
    s3 = session.client("s3", region_name="us-east-1")
    s3.create_bucket(Bucket="test-ct-bucket-compliant")

    ct.create_trail(Name="active-multi-trail", S3BucketName="test-ct-bucket-compliant", IsMultiRegionTrail=True)
    ct.start_logging(Name="active-multi-trail")

    check = CloudTrailLoggingCheck()
    findings = check.run(session, regions=["us-east-1"])

    assert len(findings) == 0


@mock_aws
def test_log_01_handles_access_denied(monkeypatch):
    """Verify LOG-01 produces a SKIPPED finding when describe_trails raises AccessDenied."""
    from botocore.exceptions import ClientError

    session = boto3.Session(region_name="us-east-1")
    ct_client = session.client("cloudtrail", region_name="us-east-1")

    def mock_describe_trails(*args, **kwargs):
        raise ClientError(
            {"Error": {"Code": "AccessDenied", "Message": "Not authorized to describe trails"}},
            "DescribeTrails",
        )

    monkeypatch.setattr(ct_client, "describe_trails", mock_describe_trails)
    monkeypatch.setattr(session, "client", lambda svc, **kw: ct_client if svc == "cloudtrail" else boto3.client(svc, **kw))

    check = CloudTrailLoggingCheck()
    findings = check.run(session, regions=["us-east-1"])

    assert len(findings) == 1
    assert findings[0].status == FindingStatus.SKIPPED
    assert "AccessDenied" in findings[0].description

