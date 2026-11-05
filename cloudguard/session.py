"""AWS Session and credential management for CloudGuard.

Provides safe, read-only boto3 session initialization using named profiles
or standard AWS credential resolution chains (environment variables, IAM roles).
"""

from typing import Optional, Tuple
import boto3
from botocore.exceptions import (
    ClientError,
    EndpointConnectionError,
    NoCredentialsError,
    ProfileNotFound,
)
from cloudguard.config import Config


class CredentialsError(Exception):
    """Raised when AWS credentials or profiles are missing or invalid."""


def get_session(profile: Optional[str] = None, region: Optional[str] = None) -> boto3.Session:
    """Create and return a boto3.Session using the profile name or default credential chain.

    Args:
        profile: Optional AWS named profile from ~/.aws/credentials.
        region: Optional default region name (e.g. 'us-east-1').

    Returns:
        boto3.Session configured for AWS interaction.

    Raises:
        CredentialsError: If the specified profile is not found.
    """
    config = Config.load()
    resolved_profile = profile if profile is not None else config.aws_profile
    resolved_region = region if region is not None else (config.regions[0] if config.regions else None)

    try:
        kwargs = {}
        if resolved_profile:
            kwargs["profile_name"] = resolved_profile
        if resolved_region:
            kwargs["region_name"] = resolved_region
        return boto3.Session(**kwargs)
    except ProfileNotFound as exc:
        raise CredentialsError(
            f"AWS profile '{resolved_profile}' not found in configuration or credentials file."
        ) from exc


def verify_identity(session: boto3.Session) -> Tuple[str, str]:
    """Verify AWS credentials by calling STS get_caller_identity.

    Args:
        session: Active boto3.Session to verify.

    Returns:
        Tuple of (account_id, caller_arn).

    Raises:
        CredentialsError: If credentials are missing, expired, or invalid.
    """
    try:
        sts = session.client("sts")
        identity = sts.get_caller_identity()
        account_id = identity.get("Account")
        arn = identity.get("Arn")
        if not account_id or not arn:
            raise CredentialsError("STS returned an empty Account ID or ARN.")
        return account_id, arn
    except NoCredentialsError as exc:
        raise CredentialsError(
            "No AWS credentials found. Configure credentials via environment variables, "
            "AWS profile, or an attached IAM role."
        ) from exc
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code", "Unknown")
        message = exc.response.get("Error", {}).get("Message", str(exc))
        raise CredentialsError(
            f"AWS authentication failed with STS error [{code}]: {message}"
        ) from exc
    except EndpointConnectionError as exc:
        raise CredentialsError(
            f"Unable to connect to AWS STS endpoint: {exc}"
        ) from exc
