"""Logging and auditing compliance checks aligned with CIS AWS Foundations Benchmark."""

from typing import List
import boto3
from botocore.exceptions import ClientError
from cloudguard.checks.base import BaseCheck, is_permission_error
from cloudguard.models import Finding, FindingStatus, Severity
from cloudguard.scoring import calculate_finding_score


def get_account_id(session: boto3.Session) -> str:
    """Retrieve the current AWS account ID using STS."""
    try:
        sts = session.client("sts")
        return sts.get_caller_identity().get("Account", "unknown-account")
    except Exception:
        return "unknown-account"


class CloudTrailLoggingCheck(BaseCheck):
    """LOG-01: Ensure a multi-region CloudTrail trail is enabled and actively logging."""

    check_id = "LOG-01"
    title = "No multi-region CloudTrail is actively logging"
    module = "logging"
    base_severity = Severity.HIGH
    cis_reference = "Ensure CloudTrail is enabled in all regions and actively logging"

    def run(self, session: boto3.Session, regions: List[str]) -> List[Finding]:
        account_id = get_account_id(session)
        cloudtrail = session.client("cloudtrail")

        try:
            trails_resp = cloudtrail.describe_trails(includeShadowTrails=True)
            trails = trails_resp.get("trailList", [])
        except ClientError as exc:
            if is_permission_error(exc):
                return [
                    self.handle_client_error(
                        exc,
                        resource_id=account_id,
                        resource_type="AWS::CloudTrail::Trail",
                        region="global",
                    )
                ]
            raise

        has_active_multi_region_trail = False

        for trail in trails:
            is_multi_region = trail.get("IsMultiRegionTrail", False)
            if not is_multi_region:
                continue

            trail_identifier = trail.get("TrailARN") or trail.get("Name", "")
            try:
                status_resp = cloudtrail.get_trail_status(Name=trail_identifier)
                if status_resp.get("IsLogging", False) is True:
                    has_active_multi_region_trail = True
                    break
            except ClientError as exc:
                if is_permission_error(exc):
                    # If permission to inspect status is denied on this trail, proceed to inspect others
                    continue
                raise

        if not has_active_multi_region_trail:
            return [
                Finding(
                    id=f"{self.check_id}-{account_id}",
                    check_id=self.check_id,
                    title=self.title,
                    description=(
                        f"AWS account '{account_id}' does not have an active multi-region CloudTrail trail "
                        "recording management events across all regions. Without a centralized multi-region trail, "
                        "unauthorized API activity in non-default regions may go undetected."
                    ),
                    resource_id=account_id,
                    resource_type="AWS::CloudTrail::Trail",
                    region="global",
                    severity=self.base_severity,
                    risk_score=calculate_finding_score(self.base_severity),
                    cis_reference=self.cis_reference,
                    remediation=(
                        "Create a CloudTrail trail with 'IsMultiRegionTrail' enabled, start logging, and configure "
                        "a secure S3 bucket with access logging and KMS encryption to store trail events."
                    ),
                    status=FindingStatus.FAIL,
                )
            ]

        return []

