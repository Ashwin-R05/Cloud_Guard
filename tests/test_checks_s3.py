"""Unit tests for S3 security checks using Moto."""

import json
import boto3
import pytest
from moto import mock_aws
from cloudguard.checks.s3 import (
    S3DefaultEncryptionCheck,
    S3PublicBucketCheck,
    S3VersioningCheck,
    resolve_bucket_region,
)
from cloudguard.models import FindingStatus, Severity


@mock_aws
def test_resolve_bucket_region():
    """Verify bucket region resolution for us-east-1 and other regions."""
    s3_east = boto3.client("s3", region_name="us-east-1")
    s3_east.create_bucket(Bucket="test-east-bucket")

    s3_west = boto3.client("s3", region_name="us-west-2")
    s3_west.create_bucket(
        Bucket="test-west-bucket",
        CreateBucketConfiguration={"LocationConstraint": "us-west-2"},
    )

    assert resolve_bucket_region(s3_east, "test-east-bucket") == "us-east-1"
    assert resolve_bucket_region(s3_east, "test-west-bucket") == "us-west-2"


@mock_aws
def test_s3_01_public_bucket_acl_flagged():
    """Verify S3-01 flags a bucket with public ACL when BPA is disabled."""
    session = boto3.Session(region_name="us-east-1")
    s3 = session.client("s3", region_name="us-east-1")

    bucket_name = "vulnerable-acl-bucket"
    s3.create_bucket(Bucket=bucket_name)
    s3.put_bucket_acl(
        Bucket=bucket_name,
        AccessControlPolicy={
            "Grants": [
                {
                    "Grantee": {
                        "Type": "Group",
                        "URI": "http://acs.amazonaws.com/groups/global/AllUsers",
                    },
                    "Permission": "READ",
                }
            ],
            "Owner": {"ID": "owner-id"},
        },
    )

    check = S3PublicBucketCheck()
    findings = check.run(session, regions=["us-east-1"])

    assert len(findings) == 1
    f = findings[0]
    assert f.check_id == "S3-01"
    assert f.status == FindingStatus.FAIL
    assert f.severity == Severity.CRITICAL
    assert f.resource_id == bucket_name
    assert "AllUsers" in f.description
    assert "Block Public Access" in f.remediation


@mock_aws
def test_s3_01_public_bucket_policy_flagged():
    """Verify S3-01 flags a bucket with public policy when BPA is disabled."""
    session = boto3.Session(region_name="us-east-1")
    s3 = session.client("s3", region_name="us-east-1")

    bucket_name = "vulnerable-policy-bucket"
    s3.create_bucket(Bucket=bucket_name)

    public_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": "*",
                "Action": "s3:GetObject",
                "Resource": f"arn:aws:s3:::{bucket_name}/*",
            }
        ],
    }
    s3.put_bucket_policy(Bucket=bucket_name, Policy=json.dumps(public_policy))

    check = S3PublicBucketCheck()
    findings = check.run(session, regions=["us-east-1"])

    assert len(findings) == 1
    f = findings[0]
    assert f.check_id == "S3-01"
    assert f.status == FindingStatus.FAIL
    assert f.resource_id == bucket_name
    assert "Principal '*'" in f.description or "public" in f.description.lower()


@mock_aws
def test_s3_01_compliant_when_block_public_access_enabled():
    """Verify S3-01 does not flag a bucket if Block Public Access is fully enabled."""
    session = boto3.Session(region_name="us-east-1")
    s3 = session.client("s3", region_name="us-east-1")

    bucket_name = "protected-bucket"
    s3.create_bucket(Bucket=bucket_name)

    # Enable full Block Public Access
    s3.put_public_access_block(
        Bucket=bucket_name,
        PublicAccessBlockConfiguration={
            "BlockPublicAcls": True,
            "IgnorePublicAcls": True,
            "BlockPublicPolicy": True,
            "RestrictPublicBuckets": True,
        },
    )

    # Even if an ACL had AllUsers, BPA blocks public access
    s3.put_bucket_acl(
        Bucket=bucket_name,
        AccessControlPolicy={
            "Grants": [
                {
                    "Grantee": {
                        "Type": "Group",
                        "URI": "http://acs.amazonaws.com/groups/global/AllUsers",
                    },
                    "Permission": "READ",
                }
            ],
            "Owner": {"ID": "owner-id"},
        },
    )

    check = S3PublicBucketCheck()
    findings = check.run(session, regions=["us-east-1"])
    assert len(findings) == 0


@mock_aws
def test_s3_02_default_encryption_disabled_and_enabled():
    """Verify S3-02 identifies unencrypted buckets and ignores compliant encrypted buckets."""
    session = boto3.Session(region_name="us-east-1")
    s3 = session.client("s3", region_name="us-east-1")

    # Unencrypted bucket (non-compliant)
    s3.create_bucket(Bucket="unencrypted-bkt")

    # Encrypted bucket (compliant)
    s3.create_bucket(Bucket="encrypted-bkt")
    s3.put_bucket_encryption(
        Bucket="encrypted-bkt",
        ServerSideEncryptionConfiguration={
            "Rules": [
                {
                    "ApplyServerSideEncryptionByDefault": {
                        "SSEAlgorithm": "AES256"
                    }
                }
            ]
        },
    )

    check = S3DefaultEncryptionCheck()
    findings = check.run(session, regions=["us-east-1"])

    assert len(findings) == 1
    f = findings[0]
    assert f.check_id == "S3-02"
    assert f.resource_id == "unencrypted-bkt"
    assert f.severity == Severity.MEDIUM
    assert f.status == FindingStatus.FAIL
    assert "default server-side encryption" in f.description


@mock_aws
def test_s3_03_versioning_disabled_and_enabled():
    """Verify S3-03 flags unversioned buckets and passes versioned buckets."""
    session = boto3.Session(region_name="us-east-1")
    s3 = session.client("s3", region_name="us-east-1")

    # Unversioned bucket (non-compliant)
    s3.create_bucket(Bucket="unversioned-bkt")

    # Versioned bucket (compliant)
    s3.create_bucket(Bucket="versioned-bkt")
    s3.put_bucket_versioning(
        Bucket="versioned-bkt",
        VersioningConfiguration={"Status": "Enabled"},
    )

    check = S3VersioningCheck()
    findings = check.run(session, regions=["us-east-1"])

    assert len(findings) == 1
    f = findings[0]
    assert f.check_id == "S3-03"
    assert f.resource_id == "unversioned-bkt"
    assert f.severity == Severity.LOW
    assert f.status == FindingStatus.FAIL
    assert "versioning enabled" in f.description


@mock_aws
def test_s3_checks_handle_access_denied_on_list_buckets(monkeypatch):
    """Verify S3 checks handle AccessDenied on list_buckets gracefully by producing a SKIPPED finding."""
    from botocore.exceptions import ClientError

    session = boto3.Session(region_name="us-east-1")

    def mock_list_buckets(*args, **kwargs):
        raise ClientError(
            {"Error": {"Code": "AccessDenied", "Message": "Access Denied listing buckets"}},
            "ListBuckets",
        )

    s3_client = session.client("s3", region_name="us-east-1")
    monkeypatch.setattr(s3_client, "list_buckets", mock_list_buckets)
    monkeypatch.setattr(session, "client", lambda service, **kwargs: s3_client if service == "s3" else boto3.client(service, **kwargs))

    check = S3DefaultEncryptionCheck()
    findings = check.run(session, regions=["us-east-1"])

    assert len(findings) == 1
    assert findings[0].status == FindingStatus.SKIPPED
    assert "AccessDenied" in findings[0].description
