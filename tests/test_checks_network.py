"""Unit tests for Network security checks using Moto."""

import boto3
import pytest
from moto import mock_aws
from cloudguard.checks.network import (
    AllTrafficOpenCheck,
    OpenManagementPortsCheck,
    rule_covers_all_traffic,
    rule_covers_management_ports,
)
from cloudguard.models import FindingStatus, Severity


def test_rule_covers_management_ports_logic():
    """Verify management port detection for single ports, ranges, and protocol -1."""
    # Port 22 open to 0.0.0.0/0
    rule_22 = {
        "IpProtocol": "tcp",
        "FromPort": 22,
        "ToPort": 22,
        "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
    }
    assert "SSH (port 22)" in rule_covers_management_ports(rule_22)

    # Port 3389 open to ::/0
    rule_3389 = {
        "IpProtocol": "tcp",
        "FromPort": 3389,
        "ToPort": 3389,
        "Ipv6Ranges": [{"CidrIpv6": "::/0"}],
    }
    assert "RDP (port 3389)" in rule_covers_management_ports(rule_3389)

    # Port range 20-30 covers 22
    rule_range = {
        "IpProtocol": "tcp",
        "FromPort": 20,
        "ToPort": 30,
        "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
    }
    assert "SSH (port 22)" in rule_covers_management_ports(rule_range)

    # Protocol -1 covers both
    rule_all = {
        "IpProtocol": "-1",
        "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
    }
    ports = rule_covers_management_ports(rule_all)
    assert "SSH (port 22)" in ports
    assert "RDP (port 3389)" in ports

    # Restricted CIDR (10.0.0.0/8) is not flagged
    rule_internal = {
        "IpProtocol": "tcp",
        "FromPort": 22,
        "ToPort": 22,
        "IpRanges": [{"CidrIp": "10.0.0.0/8"}],
    }
    assert len(rule_covers_management_ports(rule_internal)) == 0


@mock_aws
def test_net_01_open_ssh_flagged():
    """Verify NET-01 flags security groups with open port 22 to 0.0.0.0/0."""
    session = boto3.Session(region_name="us-east-1")
    ec2 = session.client("ec2", region_name="us-east-1")

    sg = ec2.create_security_group(GroupName="ssh-open-sg", Description="SSH open")
    sg_id = sg["GroupId"]
    ec2.authorize_security_group_ingress(
        GroupId=sg_id,
        IpPermissions=[
            {
                "IpProtocol": "tcp",
                "FromPort": 22,
                "ToPort": 22,
                "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
            }
        ],
    )

    check = OpenManagementPortsCheck()
    findings = check.run(session, regions=["us-east-1"])

    assert len(findings) == 1
    f = findings[0]
    assert f.check_id == "NET-01"
    assert f.status == FindingStatus.FAIL
    assert f.severity == Severity.HIGH
    assert f.resource_id == sg_id
    assert "SSH (port 22)" in f.description


@mock_aws
def test_net_01_compliant_when_restricted_or_other_ports():
    """Verify NET-01 passes when management ports are restricted or web ports are used."""
    session = boto3.Session(region_name="us-east-1")
    ec2 = session.client("ec2", region_name="us-east-1")

    # Group with HTTP (80) open to world, and SSH restricted to private subnet
    sg = ec2.create_security_group(GroupName="web-sg", Description="Web server")
    sg_id = sg["GroupId"]
    ec2.authorize_security_group_ingress(
        GroupId=sg_id,
        IpPermissions=[
            {
                "IpProtocol": "tcp",
                "FromPort": 80,
                "ToPort": 80,
                "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
            },
            {
                "IpProtocol": "tcp",
                "FromPort": 22,
                "ToPort": 22,
                "IpRanges": [{"CidrIp": "192.168.1.0/24"}],
            },
        ],
    )

    check = OpenManagementPortsCheck()
    findings = check.run(session, regions=["us-east-1"])
    assert len(findings) == 0


@mock_aws
def test_net_02_all_traffic_flagged():
    """Verify NET-02 flags security groups with protocol -1 open to world."""
    session = boto3.Session(region_name="us-east-1")
    ec2 = session.client("ec2", region_name="us-east-1")

    sg = ec2.create_security_group(GroupName="all-traffic-sg", Description="All traffic open")
    sg_id = sg["GroupId"]
    ec2.authorize_security_group_ingress(
        GroupId=sg_id,
        IpPermissions=[
            {
                "IpProtocol": "-1",
                "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
            }
        ],
    )

    check = AllTrafficOpenCheck()
    findings = check.run(session, regions=["us-east-1"])

    assert len(findings) == 1
    f = findings[0]
    assert f.check_id == "NET-02"
    assert f.status == FindingStatus.FAIL
    assert f.severity == Severity.CRITICAL
    assert f.resource_id == sg_id
    assert "all protocols and ports (-1)" in f.description


@mock_aws
def test_net_checks_multi_region_resiliency(monkeypatch):
    """Verify failure in one region does not stop scans in subsequent regions."""
    from botocore.exceptions import ClientError

    session = boto3.Session()
    ec2_east = session.client("ec2", region_name="us-east-1")
    ec2_west = session.client("ec2", region_name="us-west-2")

    # In us-west-2, create a vulnerable SG
    sg = ec2_west.create_security_group(GroupName="west-open-sg", Description="West SSH")
    ec2_west.authorize_security_group_ingress(
        GroupId=sg["GroupId"],
        IpPermissions=[
            {
                "IpProtocol": "tcp",
                "FromPort": 22,
                "ToPort": 22,
                "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
            }
        ],
    )

    # Monkeypatch us-east-1 to throw AccessDenied
    real_client = session.client

    def mock_client(svc, region_name=None, **kwargs):
        if svc == "ec2" and region_name == "us-east-1":
            mock_ec2 = real_client(svc, region_name=region_name, **kwargs)

            def mock_describe(*args, **kw):
                raise ClientError(
                    {"Error": {"Code": "AccessDenied", "Message": "Denied in us-east-1"}},
                    "DescribeSecurityGroups",
                )

            monkeypatch.setattr(mock_ec2, "get_paginator", lambda name: mock_ec2)
            monkeypatch.setattr(mock_ec2, "paginate", mock_describe)
            return mock_ec2
        return real_client(svc, region_name=region_name, **kwargs)

    monkeypatch.setattr(session, "client", mock_client)

    check = OpenManagementPortsCheck()
    findings = check.run(session, regions=["us-east-1", "us-west-2"])

    # Expect: 1 SKIPPED finding for us-east-1, and 1 FAIL finding for us-west-2
    assert len(findings) == 2
    status_by_region = {f.region: f.status for f in findings}
    assert status_by_region["us-east-1"] == FindingStatus.SKIPPED
    assert status_by_region["us-west-2"] == FindingStatus.FAIL

