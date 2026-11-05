"""Command-line interface entry point for CloudGuard scanner."""

import argparse
import sys
from typing import List, Optional
from cloudguard.config import Config
from cloudguard.scanner import CloudGuardScanner


def build_parser() -> argparse.ArgumentParser:
    """Build and return command-line argument parser."""
    parser = argparse.ArgumentParser(
        prog="cloudguard",
        description="CloudGuard - Read-Only AWS Misconfiguration & Security Scanner",
    )
    parser.add_argument(
        "--profile",
        dest="profile",
        type=str,
        help="AWS named profile to use for authentication",
    )
    parser.add_argument(
        "--regions",
        dest="regions",
        type=str,
        help="Comma-separated AWS regions to scan (e.g., 'us-east-1,us-west-2')",
    )
    parser.add_argument(
        "--output-html",
        dest="output_html",
        type=str,
        default="reports/cloudguard_report.html",
        help="Destination path for HTML report",
    )
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    """CLI execution workflow."""
    parser = build_parser()
    args = parser.parse_args(argv or sys.argv[1:])

    config = Config.load()
    if args.profile:
        config.aws_profile = args.profile
    if args.regions:
        config.regions = [r.strip() for r in args.regions.split(",") if r.strip()]

    scanner = CloudGuardScanner(config=config)
    findings = scanner.scan()
    print(f"CloudGuard scan completed. Evaluated {len(findings)} findings.")
    return 0


if __name__ == "__main__":
    sys.exit(main())

