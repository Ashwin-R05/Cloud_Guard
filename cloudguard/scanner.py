"""Scanner orchestration engine for CloudGuard.

Coordinates collectors and checks across specified regions and services,
aggregating findings and gracefully recording skipped checks when access is denied.
"""

from datetime import datetime, timezone
from typing import Dict, List, Optional, Type
import boto3
from botocore.exceptions import ClientError
from cloudguard.checks.base import BaseCheck, is_permission_error
from cloudguard.checks.registry import discover_checks, get_all_checks
from cloudguard.config import Config
from cloudguard.models import Finding, FindingStatus, ScanResult, Severity
from cloudguard.scoring import calculate_posture_score
from cloudguard.session import get_session, verify_identity


class Scanner:
    """Orchestrates configuration collection and security check evaluations."""

    def __init__(
        self,
        session: Optional[boto3.Session] = None,
        regions: Optional[List[str]] = None,
        config: Optional[Config] = None,
    ):
        """Initialize Scanner with AWS session, target regions, and configuration.

        Args:
            session: Optional pre-configured boto3.Session. Defaults to session factory.
            regions: Optional list of AWS regions to scan. Defaults to configured regions.
            config: Optional runtime Config instance.
        """
        self.config = config or Config.load()
        self.session = session or get_session(self.config.aws_profile)
        self.regions = regions or self.config.regions

    def scan(self, check_ids: Optional[List[str]] = None) -> ScanResult:
        """Execute registered security checks and compile scan results.

        Args:
            check_ids: Optional list of specific check_ids to evaluate. If omitted,
                       all discovered checks are executed.

        Returns:
            ScanResult containing account details, timestamps, findings, and severity counts.
        """
        account_id, caller_arn = verify_identity(self.session)
        scan_timestamp = datetime.now(timezone.utc).isoformat()

        # Discover all available checks
        discover_checks()
        available_checks: List[Type[BaseCheck]] = get_all_checks()

        if check_ids:
            target_ids = set(check_ids)
            checks_to_run = [c for c in available_checks if getattr(c, "check_id", None) in target_ids]
        else:
            checks_to_run = available_checks

        findings: List[Finding] = []

        for check_cls in checks_to_run:
            check_instance = check_cls()
            try:
                check_findings = check_instance.run(self.session, self.regions)
                findings.extend(check_findings)
            except ClientError as exc:
                if is_permission_error(exc):
                    skipped = check_instance.handle_client_error(exc)
                    findings.append(skipped)
                else:
                    # Still record as skipped with error detail rather than crashing the scan
                    reason = f"Check skipped due to AWS client error: {exc}"
                    findings.append(check_instance.create_skipped_finding(reason=reason))
            except Exception as exc:
                # Top-level safeguard: ensure individual check failure cannot crash the scanner
                reason = f"Check skipped due to unexpected execution error: {type(exc).__name__}: {exc}"
                findings.append(check_instance.create_skipped_finding(reason=reason))

        # Calculate counts per severity
        severity_counts: Dict[str, int] = {
            Severity.CRITICAL.value: 0,
            Severity.HIGH.value: 0,
            Severity.MEDIUM.value: 0,
            Severity.LOW.value: 0,
            FindingStatus.SKIPPED.value: 0,
        }

        for f in findings:
            if f.status == FindingStatus.SKIPPED:
                severity_counts[FindingStatus.SKIPPED.value] += 1
            else:
                sev_key = f.severity.value if isinstance(f.severity, Severity) else str(f.severity)
                severity_counts[sev_key] = severity_counts.get(sev_key, 0) + 1

        posture_score = calculate_posture_score(findings)

        return ScanResult(
            account_id=account_id,
            account_arn=caller_arn,
            scan_timestamp=scan_timestamp,
            findings=findings,
            severity_counts=severity_counts,
            total_findings=len(findings),
            posture_score=posture_score,
        )


# Backward compatibility alias
CloudGuardScanner = Scanner
