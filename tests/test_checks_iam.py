"""Unit tests for IAM security checks using Moto and Stubber."""

from datetime import datetime, timedelta, timezone
import json
import boto3
from botocore.stub import Stubber
import pytest
from moto import mock_aws
from cloudguard.checks.iam import (
    IAMConsoleMfaCheck,
    IAMRootAccessKeysCheck,
    IAMStaleAccessKeysCheck,
    IAMWildcardPolicyCheck,
    statement_allows_full_admin,
)
from cloudguard.models import FindingStatus, Severity


# --- IAM-01: Console user without MFA ---

@mock_aws
def test_iam_01_user_with_console_and_mfa_compliant():
    """Verify IAM-01 passes when a console user has an MFA device configured."""
    session = boto3.Session(region_name="us-east-1")
    iam = session.client("iam")

    user_name = "mfa-protected-user"
    iam.create_user(UserName=user_name)
    iam.create_login_profile(UserName=user_name, Password="Password123!")
    iam.create_virtual_mfa_device(VirtualMFADeviceName="device1")
    # In moto, enable_mfa_device associates it with the user
    iam.enable_mfa_device(
        UserName=user_name,
        SerialNumber="arn:aws:iam::123456789012:mfa/device1",
        AuthenticationCode1="123456",
        AuthenticationCode2="654321",
    )

    check = IAMConsoleMfaCheck()
    findings = check.run(session, regions=["us-east-1"])

    # User has MFA enabled, so no findings should be raised
    assert len(findings) == 0


@mock_aws
def test_iam_01_user_without_console_access_compliant():
    """Verify IAM-01 ignores users without login profile (service/API users)."""
    session = boto3.Session(region_name="us-east-1")
    iam = session.client("iam")

    iam.create_user(UserName="api-service-account")

    check = IAMConsoleMfaCheck()
    findings = check.run(session, regions=["us-east-1"])
    assert len(findings) == 0


@mock_aws
def test_iam_01_user_with_console_no_mfa_flagged():
    """Verify IAM-01 flags a console user who has no MFA device configured."""
    session = boto3.Session(region_name="us-east-1")
    iam = session.client("iam")

    user_name = "vulnerable-console-user"
    iam.create_user(UserName=user_name)
    iam.create_login_profile(UserName=user_name, Password="Password123!")

    check = IAMConsoleMfaCheck()
    findings = check.run(session, regions=["us-east-1"])

    assert len(findings) == 1
    f = findings[0]
    assert f.check_id == "IAM-01"
    assert f.status == FindingStatus.FAIL
    assert f.severity == Severity.HIGH
    assert f.resource_id == user_name
    assert "no multi-factor authentication" in f.description


# --- IAM-02: Wildcard policy (*:*) ---

def test_statement_allows_full_admin_logic():
    """Verify statement_allows_full_admin accurately detects wildcard patterns."""
    # Wildcard allow
    assert statement_allows_full_admin({"Effect": "Allow", "Action": "*", "Resource": "*"}) is True
    assert statement_allows_full_admin({"Effect": "Allow", "Action": ["*"], "Resource": ["*"]}) is True
    # Deny statement with wildcard is not flagged
    assert statement_allows_full_admin({"Effect": "Deny", "Action": "*", "Resource": "*"}) is False
    # Scoped action
    assert statement_allows_full_admin({"Effect": "Allow", "Action": "s3:*", "Resource": "*"}) is False
    # Scoped resource
    assert statement_allows_full_admin({"Effect": "Allow", "Action": "*", "Resource": "arn:aws:s3:::bucket/*"}) is False


@mock_aws
def test_iam_02_customer_managed_policy_flagged():
    """Verify IAM-02 flags customer-managed policies granting full admin (*:*)."""
    session = boto3.Session(region_name="us-east-1")
    iam = session.client("iam")

    wildcard_doc = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}],
    }
    iam.create_policy(PolicyName="CustomAdminPolicy", PolicyDocument=json.dumps(wildcard_doc))

    check = IAMWildcardPolicyCheck()
    findings = check.run(session, regions=["us-east-1"])

    assert len(findings) == 1
    f = findings[0]
    assert f.check_id == "IAM-02"
    assert f.status == FindingStatus.FAIL
    assert f.severity == Severity.HIGH
    assert f.resource_id == "CustomAdminPolicy"
    assert "full administrative privileges" in f.description


@mock_aws
def test_iam_02_inline_policies_flagged():
    """Verify IAM-02 flags inline policies on users, groups, and roles."""
    session = boto3.Session(region_name="us-east-1")
    iam = session.client("iam")

    wildcard_doc = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}],
    }
    # Inline on user
    iam.create_user(UserName="admin-user")
    iam.put_user_policy(
        UserName="admin-user",
        PolicyName="UserAdminInline",
        PolicyDocument=json.dumps(wildcard_doc),
    )

    # Inline on role
    assume_role_doc = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "ec2.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    iam.create_role(RoleName="AdminRole", AssumeRolePolicyDocument=json.dumps(assume_role_doc))
    iam.put_role_policy(
        RoleName="AdminRole",
        PolicyName="RoleAdminInline",
        PolicyDocument=json.dumps(wildcard_doc),
    )

    check = IAMWildcardPolicyCheck()
    findings = check.run(session, regions=["us-east-1"])

    assert len(findings) == 2
    resource_ids = {f.resource_id for f in findings}
    assert "admin-user/UserAdminInline" in resource_ids
    assert "AdminRole/RoleAdminInline" in resource_ids


@mock_aws
def test_iam_02_scoped_policy_compliant():
    """Verify IAM-02 passes when policies are properly scoped."""
    session = boto3.Session(region_name="us-east-1")
    iam = session.client("iam")

    scoped_doc = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["s3:GetObject", "s3:ListBucket"],
                "Resource": ["arn:aws:s3:::my-bucket", "arn:aws:s3:::my-bucket/*"],
            }
        ],
    }
    iam.create_policy(PolicyName="ScopedReadPolicy", PolicyDocument=json.dumps(scoped_doc))

    check = IAMWildcardPolicyCheck()
    findings = check.run(session, regions=["us-east-1"])
    assert len(findings) == 0


# --- IAM-03: Stale or old access keys ---

@mock_aws
def test_iam_03_active_recent_key_compliant():
    """Verify IAM-03 passes for active keys created within 90 days."""
    session = boto3.Session(region_name="us-east-1")
    iam = session.client("iam")

    iam.create_user(UserName="fresh-user")
    iam.create_access_key(UserName="fresh-user")

    check = IAMStaleAccessKeysCheck()
    findings = check.run(session, regions=["us-east-1"])
    assert len(findings) == 0


@mock_aws
def test_iam_03_stale_access_key_flagged(monkeypatch):
    """Verify IAM-03 flags active keys older than 90 days."""
    session = boto3.Session(region_name="us-east-1")
    iam = session.client("iam")

    user_name = "old-key-user"
    iam.create_user(UserName=user_name)
    key_resp = iam.create_access_key(UserName=user_name)
    key_id = key_resp["AccessKey"]["AccessKeyId"]

    # Advance time 100 days into the future to simulate an old key
    future_now = datetime.now(timezone.utc) + timedelta(days=100)

    class MockDatetime:
        @classmethod
        def now(cls, tz=None):
            return future_now

    monkeypatch.setattr("cloudguard.checks.iam.datetime", MockDatetime)

    check = IAMStaleAccessKeysCheck()
    findings = check.run(session, regions=["us-east-1"])

    assert len(findings) == 1
    f = findings[0]
    assert f.check_id == "IAM-03"
    assert f.status == FindingStatus.FAIL
    assert f.severity == Severity.MEDIUM
    assert f.resource_id == f"{user_name}/{key_id}"
    assert "violates 90-day rotation policy" in f.description


# --- IAM-04: Root access keys ---

@mock_aws
def test_iam_04_root_keys_absent_compliant():
    """Verify IAM-04 passes when no root access keys are present."""
    session = boto3.Session(region_name="us-east-1")
    check = IAMRootAccessKeysCheck()
    findings = check.run(session, regions=["us-east-1"])
    assert len(findings) == 0


def test_iam_04_root_keys_present_flagged_with_stubber():
    """Verify IAM-04 flags root access keys when AccountAccessKeysPresent > 0 using Stubber.

    Moto does not expose an API to create root access keys (matching AWS API constraints),
    so botocore.stub.Stubber is used to simulate AccountAccessKeysPresent = 1.
    """
    session = boto3.Session(region_name="us-east-1")
    iam_client = session.client("iam")
    stubber = Stubber(iam_client)

    stubbed_summary = {
        "SummaryMap": {
            "AccountAccessKeysPresent": 1,
            "Users": 2,
            "Roles": 5,
        }
    }
    stubber.add_response("get_account_summary", stubbed_summary)
    stubber.activate()

    class StubbedSession:
        def client(self, service, **kwargs):
            return iam_client

    check = IAMRootAccessKeysCheck()
    findings = check.run(StubbedSession(), regions=["us-east-1"])

    assert len(findings) == 1
    f = findings[0]
    assert f.check_id == "IAM-04"
    assert f.status == FindingStatus.FAIL
    assert f.severity == Severity.CRITICAL
    assert f.resource_id == "root"
    assert "1 active access key" in f.description
    assert "Delete all root account access keys" in f.remediation

    stubber.deactivate()
