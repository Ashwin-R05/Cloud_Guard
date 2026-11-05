"""AWS Session factory for CloudGuard.

Provides safe, read-only boto3 session initialization using named profiles
or standard AWS credential resolution chain (environment variables, IAM roles).
"""

from typing import Optional
import boto3
from cloudguard.config import Config


def get_session(profile_name: Optional[str] = None) -> boto3.Session:
    """Create and return a boto3.Session using the profile name or default credential chain.

    Args:
        profile_name: Optional AWS named profile from ~/.aws/credentials or config.

    Returns:
        boto3.Session configured for AWS interaction.
    """
    config = Config.load()
    resolved_profile = profile_name or config.aws_profile

    if resolved_profile:
        return boto3.Session(profile_name=resolved_profile)
    return boto3.Session()

