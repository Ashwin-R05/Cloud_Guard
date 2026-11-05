"""Unit tests for AWS session and credential management."""

import boto3
import pytest
from botocore.exceptions import ClientError, NoCredentialsError
from moto import mock_aws
from cloudguard.session import CredentialsError, get_session, verify_identity


def test_get_session_default():
    """Verify get_session returns a valid boto3 Session."""
    session = get_session()
    assert isinstance(session, boto3.Session)


def test_get_session_invalid_profile():
    """Verify get_session raises CredentialsError when profile is missing."""
    with pytest.raises(CredentialsError) as exc_info:
        get_session(profile="non-existent-profile-xyz-123")
    assert "not found" in str(exc_info.value)


@mock_aws
def test_verify_identity_success():
    """Verify identity extraction with mocked STS."""
    session = boto3.Session(region_name="us-east-1")
    account_id, caller_arn = verify_identity(session)

    assert account_id is not None
    assert caller_arn is not None
    assert len(account_id) == 12  # AWS 12-digit account id


def test_verify_identity_no_credentials(monkeypatch):
    """Verify verify_identity raises CredentialsError when credentials are absent."""
    # Create a mock session whose sts client raises NoCredentialsError
    session = boto3.Session(region_name="us-east-1")

    def mock_get_caller_identity(*args, **kwargs):
        raise NoCredentialsError()

    monkeypatch.setattr(
        "botocore.client.BaseClient._make_api_call",
        lambda self, operation_name, kw: mock_get_caller_identity()
        if operation_name == "GetCallerIdentity"
        else None,
    )

    with pytest.raises(CredentialsError) as exc_info:
        verify_identity(session)
    assert "No AWS credentials found" in str(exc_info.value)

