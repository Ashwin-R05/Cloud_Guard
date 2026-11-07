"""Data protection and storage encryption checks aligned with CIS AWS Foundations Benchmark."""

from typing import List
import boto3
from botocore.exceptions import ClientError
from cloudguard.checks.base import BaseCheck, is_permission_error
from cloudguard.config import Config
from cloudguard.models import Finding, FindingStatus, Severity
from cloudguard.scoring import calculate_risk


class UnencryptedEBSVolumeCheck(BaseCheck):
    """DATA-01: Ensure EBS volumes are encrypted at rest."""

    check_id = "DATA-01"
    title = "EBS volume is not encrypted"
    module = "data"
    base_severity = Severity.MEDIUM
    cis_reference = "Ensure EBS volume encryption is enabled"

    def run(self, session: boto3.Session, regions: List[str]) -> List[Finding]:
        findings: List[Finding] = []
        target_regions = regions if regions else Config.load().regions

        for region in target_regions:
            try:
                ec2 = session.client("ec2", region_name=region)
                paginator = ec2.get_paginator("describe_volumes")

                for page in paginator.paginate():
                    for volume in page.get("Volumes", []):
                        volume_id = volume.get("VolumeId", "")
                        is_encrypted = volume.get("Encrypted", False)

                        if not is_encrypted:
                            risk_score, effective_sev, imp, exp, reason = calculate_risk(
                                self.base_severity,
                                exposure=3,
                                exposure_reason="EBS persistent block storage volume unencrypted at rest",
                            )
                            findings.append(
                                Finding(
                                    id=f"{self.check_id}-{region}-{volume_id}",
                                    check_id=self.check_id,
                                    title=self.title,
                                    description=(
                                        f"EBS volume '{volume_id}' in region '{region}' is not encrypted at rest. "
                                        "Unencrypted storage volumes risk data exposure if physical media or backups are compromised."
                                    ),
                                    resource_id=volume_id,
                                    resource_type="AWS::EC2::Volume",
                                    region=region,
                                    severity=effective_sev,
                                    risk_score=risk_score,
                                    cis_reference=self.cis_reference,
                                    remediation=(
                                        f"Encrypt EBS volume '{volume_id}' by creating a snapshot, copying the snapshot "
                                        "with AWS KMS encryption enabled, and creating a new encrypted volume."
                                    ),
                                    status=FindingStatus.FAIL,
                                    impact=imp,
                                    exposure=exp,
                                    exposure_reason=reason,
                                )
                            )
            except ClientError as exc:
                if is_permission_error(exc):
                    findings.append(
                        self.handle_client_error(
                            exc,
                            resource_id=f"ebs-volumes-{region}",
                            resource_type="AWS::EC2::Volume",
                            region=region,
                        )
                    )
                else:
                    reason = f"Check skipped for region '{region}' due to AWS error: {exc}"
                    findings.append(
                        self.create_skipped_finding(
                            reason=reason,
                            resource_id=f"ebs-volumes-{region}",
                            resource_type="AWS::EC2::Volume",
                            region=region,
                        )
                    )
            except Exception as exc:
                reason = f"Check skipped for region '{region}' due to unexpected error: {exc}"
                findings.append(
                    self.create_skipped_finding(
                        reason=reason,
                        resource_id=f"ebs-volumes-{region}",
                        resource_type="AWS::EC2::Volume",
                        region=region,
                    )
                )

        return findings


class RDSInstanceSecurityCheck(BaseCheck):
    """DATA-02: Ensure RDS instances are encrypted at rest and not publicly accessible."""

    check_id = "DATA-02"
    title = "RDS database instance has security misconfigurations"
    module = "data"
    base_severity = Severity.HIGH
    cis_reference = "Ensure RDS instances are encrypted at rest and not publicly accessible"

    def run(self, session: boto3.Session, regions: List[str]) -> List[Finding]:
        findings: List[Finding] = []
        target_regions = regions if regions else Config.load().regions

        for region in target_regions:
            try:
                rds = session.client("rds", region_name=region)
                paginator = rds.get_paginator("describe_db_instances")

                for page in paginator.paginate():
                    for db in page.get("DBInstances", []):
                        db_id = db.get("DBInstanceIdentifier", "")
                        storage_encrypted = db.get("StorageEncrypted", False)
                        publicly_accessible = db.get("PubliclyAccessible", False)

                        # Condition 1: Storage encryption disabled
                        if not storage_encrypted:
                            risk_score, effective_sev, imp, exp, reason = calculate_risk(
                                self.base_severity,
                                exposure=3,
                                exposure_reason="RDS relational database storage unencrypted at rest",
                            )
                            findings.append(
                                Finding(
                                    id=f"{self.check_id}-{region}-{db_id}-unencrypted",
                                    check_id=self.check_id,
                                    title="RDS database instance storage is not encrypted",
                                    description=(
                                        f"RDS database instance '{db_id}' in region '{region}' does not have "
                                        "storage encryption enabled."
                                    ),
                                    resource_id=db_id,
                                    resource_type="AWS::RDS::DBInstance",
                                    region=region,
                                    severity=effective_sev,
                                    risk_score=risk_score,
                                    cis_reference=self.cis_reference,
                                    remediation=(
                                        f"Enable encryption for RDS instance '{db_id}' by taking a DB snapshot, "
                                        "copying the snapshot with encryption enabled, and restoring from the encrypted snapshot."
                                    ),
                                    status=FindingStatus.FAIL,
                                    impact=imp,
                                    exposure=exp,
                                    exposure_reason=reason,
                                )
                            )

                        # Condition 2: Public accessibility enabled
                        if publicly_accessible:
                            risk_score, effective_sev, imp, exp, reason = calculate_risk(
                                self.base_severity,
                                exposure=5,
                                exposure_reason="RDS database endpoint directly reachable from public internet",
                            )
                            findings.append(
                                Finding(
                                    id=f"{self.check_id}-{region}-{db_id}-public",
                                    check_id=self.check_id,
                                    title="RDS database instance is publicly accessible",
                                    description=(
                                        f"RDS database instance '{db_id}' in region '{region}' has PubliclyAccessible "
                                        "set to True, exposing database endpoints to the public internet."
                                    ),
                                    resource_id=db_id,
                                    resource_type="AWS::RDS::DBInstance",
                                    region=region,
                                    severity=effective_sev,
                                    risk_score=risk_score,
                                    cis_reference=self.cis_reference,
                                    remediation=(
                                        f"Modify RDS instance '{db_id}' to set PubliclyAccessible to False and place it "
                                        "within isolated private subnets accessible only via application security groups."
                                    ),
                                    status=FindingStatus.FAIL,
                                    impact=imp,
                                    exposure=exp,
                                    exposure_reason=reason,
                                )
                            )
            except ClientError as exc:
                if is_permission_error(exc):
                    findings.append(
                        self.handle_client_error(
                            exc,
                            resource_id=f"rds-instances-{region}",
                            resource_type="AWS::RDS::DBInstance",
                            region=region,
                        )
                    )
                else:
                    reason = f"Check skipped for region '{region}' due to AWS error: {exc}"
                    findings.append(
                        self.create_skipped_finding(
                            reason=reason,
                            resource_id=f"rds-instances-{region}",
                            resource_type="AWS::RDS::DBInstance",
                            region=region,
                        )
                    )
            except Exception as exc:
                reason = f"Check skipped for region '{region}' due to unexpected error: {exc}"
                findings.append(
                    self.create_skipped_finding(
                        reason=reason,
                        resource_id=f"rds-instances-{region}",
                        resource_type="AWS::RDS::DBInstance",
                        region=region,
                    )
                )

        return findings

