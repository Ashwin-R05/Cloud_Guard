"""Unit tests for CloudGuard CLI entry point."""

from pathlib import Path
import boto3
import pytest
from moto import mock_aws
from cloudguard.cli import build_parser, main
from cloudguard.session import CredentialsError


def test_build_parser_defaults_and_options():
    """Verify CLI parser parses arguments and assigns defaults."""
    parser = build_parser()

    # Default arguments
    args = parser.parse_args([])
    assert args.profile is None
    assert args.regions is None
    assert args.checks is None
    assert args.output_dir == "reports"
    assert args.format == "both"

    # Custom arguments
    args_custom = parser.parse_args([
        "--profile", "prod-audit",
        "--regions", "us-east-1,us-west-2",
        "--checks", "S3-01,IAM-01",
        "--output-dir", "custom_reports",
        "--format", "html",
    ])
    assert args_custom.profile == "prod-audit"
    assert args_custom.regions == "us-east-1,us-west-2"
    assert args_custom.checks == "S3-01,IAM-01"
    assert args_custom.output_dir == "custom_reports"
    assert args_custom.format == "html"


@mock_aws
def test_cli_execution_success(tmp_path: Path, capsys):
    """Verify successful end-to-end CLI execution with output generation and terminal summary."""
    # Create compliant environment in moto
    session = boto3.Session(region_name="us-east-1")
    s3 = session.client("s3", region_name="us-east-1")
    s3.create_bucket(Bucket="test-compliant-bucket")
    s3.put_public_access_block(
        Bucket="test-compliant-bucket",
        PublicAccessBlockConfiguration={
            "BlockPublicAcls": True,
            "IgnorePublicAcls": True,
            "BlockPublicPolicy": True,
            "RestrictPublicBuckets": True,
        },
    )

    exit_code = main([
        "--regions", "us-east-1",
        "--checks", "S3-01",
        "--output-dir", str(tmp_path),
        "--format", "both",
    ])

    assert exit_code == 0
    captured = capsys.readouterr()
    assert "CloudGuard AWS Security Assessment Summary" in captured.out
    assert "Target Account ID:" in captured.out
    assert "Security Posture:" in captured.out

    # Verify generated files
    files = list(tmp_path.glob("cloudguard_report_*"))
    assert len(files) == 2
    extensions = {f.suffix for f in files}
    assert ".json" in extensions
    assert ".html" in extensions


def test_cli_credential_error_handling(monkeypatch, capsys):
    """Verify CLI catches CredentialsError and exits cleanly with error status 1."""
    def mock_get_session(*args, **kwargs):
        raise CredentialsError("No AWS credentials found on system.")

    monkeypatch.setattr("cloudguard.cli.get_session", mock_get_session)

    exit_code = main([])
    assert exit_code == 1

    captured = capsys.readouterr()
    assert "Authentication Error: No AWS credentials found" in captured.err

