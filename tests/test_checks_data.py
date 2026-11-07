"""Unit tests for Data and storage encryption checks using Moto."""

import boto3
import pytest
from moto import mock_aws
from cloudguard.checks.data import RDSInstanceSecurityCheck, UnencryptedEBSVolumeCheck
from cloudguard.models import FindingStatus, Severity


# --- DATA-01: Unencrypted EBS volume ---

@mock_aws
def test_data_01_unencrypted_volume_flagged():
    """Verify DATA-01 flags unencrypted EBS volumes."""
    session = boto3.Session(region_name="us-east-1")
    ec2 = session.client("ec2", region_name="us-east-1")

    vol = ec2.create_volume(AvailabilityZone="us-east-1a", Size=10, Encrypted=False)
    vol_id = vol["VolumeId"]

    check = UnencryptedEBSVolumeCheck()
    findings = check.run(session, regions=["us-east-1"])

    assert len(findings) == 1
    f = findings[0]
    assert f.check_id == "DATA-01"
    assert f.status == FindingStatus.FAIL
    assert f.severity == Severity.MEDIUM
    assert f.resource_id == vol_id
    assert "not encrypted at rest" in f.description


@mock_aws
def test_data_01_encrypted_volume_compliant():
    """Verify DATA-01 passes when EBS volume is encrypted."""
    session = boto3.Session(region_name="us-east-1")
    ec2 = session.client("ec2", region_name="us-east-1")

    ec2.create_volume(AvailabilityZone="us-east-1a", Size=10, Encrypted=True)

    check = UnencryptedEBSVolumeCheck()
    findings = check.run(session, regions=["us-east-1"])
    assert len(findings) == 0


# --- DATA-02: RDS instance unencrypted or publicly accessible ---

@mock_aws
def test_data_02_rds_compliant():
    """Verify DATA-02 passes when RDS instance is encrypted and private."""
    session = boto3.Session(region_name="us-east-1")
    rds = session.client("rds", region_name="us-east-1")

    rds.create_db_instance(
        DBInstanceIdentifier="secure-db",
        DBInstanceClass="db.m5.large",
        Engine="postgres",
        PubliclyAccessible=False,
        StorageEncrypted=True,
    )

    check = RDSInstanceSecurityCheck()
    findings = check.run(session, regions=["us-east-1"])
    assert len(findings) == 0


@mock_aws
def test_data_02_rds_unencrypted_only_flagged():
    """Verify DATA-02 flags unencrypted private RDS instance."""
    session = boto3.Session(region_name="us-east-1")
    rds = session.client("rds", region_name="us-east-1")

    rds.create_db_instance(
        DBInstanceIdentifier="unencrypted-private-db",
        DBInstanceClass="db.m5.large",
        Engine="postgres",
        PubliclyAccessible=False,
        StorageEncrypted=False,
    )

    check = RDSInstanceSecurityCheck()
    findings = check.run(session, regions=["us-east-1"])

    assert len(findings) == 1
    f = findings[0]
    assert f.check_id == "DATA-02"
    assert f.status == FindingStatus.FAIL
    assert f.severity == Severity.HIGH
    assert f.resource_id == "unencrypted-private-db"
    assert "storage is not encrypted" in f.title


@mock_aws
def test_data_02_rds_publicly_accessible_only_flagged():
    """Verify DATA-02 flags encrypted but publicly accessible RDS instance."""
    session = boto3.Session(region_name="us-east-1")
    rds = session.client("rds", region_name="us-east-1")

    rds.create_db_instance(
        DBInstanceIdentifier="encrypted-public-db",
        DBInstanceClass="db.m5.large",
        Engine="postgres",
        PubliclyAccessible=True,
        StorageEncrypted=True,
    )

    check = RDSInstanceSecurityCheck()
    findings = check.run(session, regions=["us-east-1"])

    assert len(findings) == 1
    f = findings[0]
    assert f.check_id == "DATA-02"
    assert f.status == FindingStatus.FAIL
    assert f.resource_id == "encrypted-public-db"
    assert "publicly accessible" in f.title


@mock_aws
def test_data_02_rds_both_unencrypted_and_public_produces_separate_findings():
    """Verify DATA-02 produces two separate findings when both conditions fail on the same instance."""
    session = boto3.Session(region_name="us-east-1")
    rds = session.client("rds", region_name="us-east-1")

    rds.create_db_instance(
        DBInstanceIdentifier="worst-case-db",
        DBInstanceClass="db.m5.large",
        Engine="postgres",
        PubliclyAccessible=True,
        StorageEncrypted=False,
    )

    check = RDSInstanceSecurityCheck()
    findings = check.run(session, regions=["us-east-1"])

    # Must produce two separate findings for the same DB instance
    assert len(findings) == 2
    titles = {f.title for f in findings}
    assert "RDS database instance storage is not encrypted" in titles
    assert "RDS database instance is publicly accessible" in titles
    assert all(f.resource_id == "worst-case-db" for f in findings)


@mock_aws
def test_data_checks_multi_region_resiliency(monkeypatch):
    """Verify failure in one region does not interrupt checks in other regions."""
    from botocore.exceptions import ClientError

    session = boto3.Session()
    ec2_west = session.client("ec2", region_name="us-west-2")
    ec2_west.create_volume(AvailabilityZone="us-west-2a", Size=10, Encrypted=False)

    real_client = session.client

    def mock_client(svc, region_name=None, **kwargs):
        if svc == "ec2" and region_name == "us-east-1":
            mock_ec2 = real_client(svc, region_name=region_name, **kwargs)

            def mock_describe(*args, **kw):
                raise ClientError(
                    {"Error": {"Code": "UnauthorizedOperation", "Message": "Denied in us-east-1"}},
                    "DescribeVolumes",
                )

            monkeypatch.setattr(mock_ec2, "get_paginator", lambda name: mock_ec2)
            monkeypatch.setattr(mock_ec2, "paginate", mock_describe)
            return mock_ec2
        return real_client(svc, region_name=region_name, **kwargs)

    monkeypatch.setattr(session, "client", mock_client)

    check = UnencryptedEBSVolumeCheck()
    findings = check.run(session, regions=["us-east-1", "us-west-2"])

    assert len(findings) == 2
    status_by_region = {f.region: f.status for f in findings}
    assert status_by_region["us-east-1"] == FindingStatus.SKIPPED
    assert status_by_region["us-west-2"] == FindingStatus.FAIL

