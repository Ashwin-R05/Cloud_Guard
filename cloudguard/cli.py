"""Command-line interface entry point for CloudGuard scanner."""

import argparse
import sys
from typing import List, Optional
from cloudguard.config import Config
from cloudguard.report import ReportGenerator
from cloudguard.scanner import Scanner
from cloudguard.session import CredentialsError, get_session, verify_identity


def build_parser() -> argparse.ArgumentParser:
    """Build and return command-line argument parser."""
    parser = argparse.ArgumentParser(
        prog="cloudguard",
        description="CloudGuard - Read-Only AWS Misconfiguration & Compliance Scanner",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "--profile",
        dest="profile",
        type=str,
        default=None,
        help="AWS named profile from ~/.aws/credentials",
    )
    parser.add_argument(
        "--regions",
        dest="regions",
        type=str,
        default=None,
        help="Comma-separated AWS regions to evaluate (e.g. 'us-east-1,us-west-2')",
    )
    parser.add_argument(
        "--checks",
        dest="checks",
        type=str,
        default=None,
        help="Comma-separated check IDs to run (e.g. 'S3-01,IAM-01,NET-01')",
    )
    parser.add_argument(
        "--output-dir",
        dest="output_dir",
        type=str,
        default="reports",
        help="Directory to save generated assessment reports",
    )
    parser.add_argument(
        "--format",
        dest="format",
        choices=["json", "html", "both"],
        default="both",
        help="Output report format",
    )
    return parser


def print_terminal_summary(result) -> None:
    """Print an executive assessment summary table to the terminal."""
    border = "=" * 64
    print(f"\n{border}")
    print("🛡️  CloudGuard AWS Security Assessment Summary")
    print(border)
    print(f"Target Account ID:    {result.account_id}")
    print(f"Evaluation Timestamp: {result.scan_timestamp}")
    print(f"Security Posture:     {result.posture_score:.1f} / 100.0")
    print(f"Total Evaluated:      {result.total_findings} findings")
    print("-" * 64)
    print("Findings Breakdown by Severity:")
    print(f"  • CRITICAL:         {result.severity_counts.get('CRITICAL', 0)}")
    print(f"  • HIGH:             {result.severity_counts.get('HIGH', 0)}")
    print(f"  • MEDIUM:           {result.severity_counts.get('MEDIUM', 0)}")
    print(f"  • LOW:              {result.severity_counts.get('LOW', 0)}")
    print(f"  • SKIPPED:          {result.severity_counts.get('SKIPPED', 0)}")
    print(border)


def main(argv: Optional[List[str]] = None) -> int:
    """CLI execution workflow."""
    parser = build_parser()
    args = parser.parse_args(argv if argv is not None else sys.argv[1:])

    # 1. Initialize AWS Session and Verify Identity
    try:
        session = get_session(profile=args.profile)
        account_id, caller_arn = verify_identity(session)
        print(f"[*] Authenticated to AWS Account: {account_id} ({caller_arn})")
    except CredentialsError as exc:
        print(f"[!] Authentication Error: {exc}", file=sys.stderr)
        return 1

    # 2. Parse target regions and selected checks
    config = Config.load()
    if args.regions:
        target_regions = [r.strip() for r in args.regions.split(",") if r.strip()]
    else:
        target_regions = config.regions

    check_ids = None
    if args.checks:
        check_ids = [c.strip() for c in args.checks.split(",") if c.strip()]

    # 3. Execute Scan
    print(f"[*] Commencing scan across regions: {', '.join(target_regions)} ...")
    scanner = Scanner(session=session, regions=target_regions, config=config)
    result = scanner.scan(check_ids=check_ids)

    # 4. Display Terminal Summary
    print_terminal_summary(result)

    # 5. Generate and Save Reports
    reporter = ReportGenerator()
    created_reports = reporter.generate_reports(
        result=result,
        output_dir=args.output_dir,
        fmt=args.format,
    )

    print("\n[*] Exported Reports:")
    for fmt, path in created_reports.items():
        print(f"  - [{fmt.upper()}] {path}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
