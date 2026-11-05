"""S3 security and compliance checks aligned with CIS AWS Foundations Benchmark."""

import json
from typing import Any, Dict, List, Optional, Tuple
import boto3
from botocore.exceptions import ClientError
from cloudguard.checks.base import BaseCheck, is_permission_error
from cloudguard.models import Finding, FindingStatus, Severity
from cloudguard.scoring import calculate_finding_score

ALL_USERS_URI = "http://acs.amazonaws.com/groups/global/AllUsers"
AUTH_USERS_URI = "http://acs.amazonaws.com/groups/global/AuthenticatedUsers"


def resolve_bucket_region(s3_client: Any, bucket_name: str) -> str:
    """Resolve the AWS region where an S3 bucket is hosted.

    AWS returns None or empty string for buckets located in 'us-east-1',
    and 'EU' for 'eu-west-1'.
    """
    try:
        location = s3_client.get_bucket_location(Bucket=bucket_name).get("LocationConstraint")
        if not location:
            return "us-east-1"
        if location == "EU":
            return "eu-west-1"
        return location
    except ClientError:
        return "us-east-1"


def get_regional_s3_client(session: boto3.Session, region: str) -> Any:
    """Obtain an S3 client configured for a specific region."""
    return session.client("s3", region_name=region)


def is_block_public_access_complete(config: Dict[str, Any]) -> bool:
    """Verify whether all four Block Public Access flags are enabled."""
    return (
        config.get("BlockPublicAcls") is True
        and config.get("IgnorePublicAcls") is True
        and config.get("BlockPublicPolicy") is True
        and config.get("RestrictPublicBuckets") is True
    )


def check_account_bpa(session: boto3.Session) -> bool:
    """Check if account-level S3 Block Public Access is fully enabled."""
    try:
        sts = session.client("sts")
        account_id = sts.get_caller_identity().get("Account")
        if not account_id:
            return False
        s3control = session.client("s3control")
        resp = s3control.get_public_access_block(AccountId=account_id)
        return is_block_public_access_complete(resp.get("PublicAccessBlockConfiguration", {}))
    except Exception:
        return False


def check_bucket_bpa(s3_client: Any, bucket_name: str) -> bool:
    """Check if bucket-level S3 Block Public Access is fully enabled."""
    try:
        resp = s3_client.get_public_access_block(Bucket=bucket_name)
        return is_block_public_access_complete(resp.get("PublicAccessBlockConfiguration", {}))
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code", "")
        if code in ("NoSuchPublicAccessBlockConfiguration", "NotFound"):
            return False
        raise


def check_bucket_acl_public(s3_client: Any, bucket_name: str) -> Tuple[bool, str]:
    """Check if the bucket ACL grants permissions to AllUsers or AuthenticatedUsers."""
    try:
        acl = s3_client.get_bucket_acl(Bucket=bucket_name)
        for grant in acl.get("Grants", []):
            grantee = grant.get("Grantee", {})
            uri = grantee.get("URI", "")
            perm = grant.get("Permission", "")
            if uri == ALL_USERS_URI:
                return True, f"Bucket ACL grants {perm} to AllUsers (public internet)"
            if uri == AUTH_USERS_URI:
                return True, f"Bucket ACL grants {perm} to AuthenticatedUsers (any AWS account)"
        return False, ""
    except ClientError:
        raise


def check_bucket_policy_public(s3_client: Any, bucket_name: str) -> Tuple[bool, str]:
    """Check if bucket policy grants public access without restrictive conditions."""
    # 1. Check native PolicyStatus if reported by AWS
    try:
        status_resp = s3_client.get_bucket_policy_status(Bucket=bucket_name)
        if status_resp.get("PolicyStatus", {}).get("IsPublic") is True:
            return True, "Bucket PolicyStatus indicates the bucket is public"
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code", "")
        if code not in ("NoSuchBucketPolicy", "NotFound") and is_permission_error(exc):
            raise

    # 2. Inspect bucket policy document
    try:
        pol_resp = s3_client.get_bucket_policy(Bucket=bucket_name)
        raw_policy = pol_resp.get("Policy", "")
        if not raw_policy:
            return False, ""

        policy_doc = json.loads(raw_policy)
        statements = policy_doc.get("Statement", [])
        if isinstance(statements, dict):
            statements = [statements]

        for stmt in statements:
            if stmt.get("Effect") != "Allow":
                continue
            principal = stmt.get("Principal")
            is_wildcard = (
                principal == "*"
                or (isinstance(principal, dict) and principal.get("AWS") == "*")
                or (isinstance(principal, dict) and "*" in principal.get("AWS", []))
            )
            if is_wildcard:
                condition = stmt.get("Condition")
                # If no condition is attached, it allows unrestricted public access
                if not condition:
                    action = stmt.get("Action", "unspecified actions")
                    return True, f"Bucket policy allows Principal '*' for action '{action}' without restrictive conditions"
                # If condition dictionary is empty
                if isinstance(condition, dict) and not any(condition.values()):
                    return True, "Bucket policy allows Principal '*' with an empty condition block"
        return False, ""
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code", "")
        if code in ("NoSuchBucketPolicy", "NotFound"):
            return False, ""
        raise


class S3PublicBucketCheck(BaseCheck):
    """S3-01: Ensure S3 buckets are not publicly accessible."""

    check_id = "S3-01"
    title = "S3 bucket is publicly accessible"
    module = "s3"
    base_severity = Severity.CRITICAL
    cis_reference = "Ensure S3 Buckets are not publicly accessible"

    def run(self, session: boto3.Session, regions: List[str]) -> List[Finding]:
        findings: List[Finding] = []
        global_s3 = session.client("s3", region_name="us-east-1")

        try:
            buckets = global_s3.list_buckets().get("Buckets", [])
        except ClientError as exc:
            return [self.handle_client_error(exc, resource_id="s3-all-buckets", resource_type="AWS::S3::Bucket")]

        # Determine if account-level Block Public Access is active
        account_bpa_enabled = check_account_bpa(session)

        for bucket in buckets:
            bucket_name = bucket.get("Name", "")
            bucket_region = resolve_bucket_region(global_s3, bucket_name)

            if regions and bucket_region not in regions:
                continue

            regional_s3 = get_regional_s3_client(session, bucket_region)

            try:
                bucket_bpa_enabled = check_bucket_bpa(regional_s3, bucket_name)
            except ClientError as exc:
                if is_permission_error(exc):
                    findings.append(self.handle_client_error(exc, resource_id=bucket_name, resource_type="AWS::S3::Bucket", region=bucket_region))
                    continue
                raise

            # If BPA is fully active at either bucket or account level, public access is blocked
            if bucket_bpa_enabled or account_bpa_enabled:
                continue

            public_reasons: List[str] = []

            # Check ACL
            try:
                acl_public, acl_reason = check_bucket_acl_public(regional_s3, bucket_name)
                if acl_public:
                    public_reasons.append(acl_reason)
            except ClientError as exc:
                if is_permission_error(exc):
                    findings.append(self.handle_client_error(exc, resource_id=bucket_name, resource_type="AWS::S3::Bucket", region=bucket_region))
                    continue
                raise

            # Check Policy
            try:
                policy_public, policy_reason = check_bucket_policy_public(regional_s3, bucket_name)
                if policy_public:
                    public_reasons.append(policy_reason)
            except ClientError as exc:
                if is_permission_error(exc):
                    findings.append(self.handle_client_error(exc, resource_id=bucket_name, resource_type="AWS::S3::Bucket", region=bucket_region))
                    continue
                raise

            if public_reasons:
                reasons_str = "; ".join(public_reasons)
                findings.append(
                    Finding(
                        id=f"{self.check_id}-{bucket_region}-{bucket_name}",
                        check_id=self.check_id,
                        title=self.title,
                        description=(
                            f"S3 bucket '{bucket_name}' allows public access ({reasons_str}). "
                            "Block Public Access is not fully enabled at both bucket and account levels."
                        ),
                        resource_id=bucket_name,
                        resource_type="AWS::S3::Bucket",
                        region=bucket_region,
                        severity=self.base_severity,
                        risk_score=calculate_finding_score(self.base_severity),
                        cis_reference=self.cis_reference,
                        remediation=(
                            "Enable S3 Block Public Access on the bucket and the account, and remove "
                            "public ACL grants or unrestricted policy statements."
                        ),
                        status=FindingStatus.FAIL,
                    )
                )

        return findings


class S3DefaultEncryptionCheck(BaseCheck):
    """S3-02: Ensure default encryption is enabled for S3 buckets."""

    check_id = "S3-02"
    title = "S3 bucket default encryption disabled"
    module = "s3"
    base_severity = Severity.MEDIUM
    cis_reference = "Ensure S3 bucket default encryption is enabled"

    def run(self, session: boto3.Session, regions: List[str]) -> List[Finding]:
        findings: List[Finding] = []
        global_s3 = session.client("s3", region_name="us-east-1")

        try:
            buckets = global_s3.list_buckets().get("Buckets", [])
        except ClientError as exc:
            return [self.handle_client_error(exc, resource_id="s3-all-buckets", resource_type="AWS::S3::Bucket")]

        for bucket in buckets:
            bucket_name = bucket.get("Name", "")
            bucket_region = resolve_bucket_region(global_s3, bucket_name)

            if regions and bucket_region not in regions:
                continue

            regional_s3 = get_regional_s3_client(session, bucket_region)

            try:
                enc = regional_s3.get_bucket_encryption(Bucket=bucket_name)
                rules = enc.get("ServerSideEncryptionConfiguration", {}).get("Rules", [])
                if not rules:
                    raise ClientError(
                        {"Error": {"Code": "ServerSideEncryptionConfigurationNotFoundError", "Message": "No rules"}},
                        "GetBucketEncryption",
                    )
            except ClientError as exc:
                code = exc.response.get("Error", {}).get("Code", "")
                if code == "ServerSideEncryptionConfigurationNotFoundError":
                    findings.append(
                        Finding(
                            id=f"{self.check_id}-{bucket_region}-{bucket_name}",
                            check_id=self.check_id,
                            title=self.title,
                            description=f"S3 bucket '{bucket_name}' does not have default server-side encryption enabled.",
                            resource_id=bucket_name,
                            resource_type="AWS::S3::Bucket",
                            region=bucket_region,
                            severity=self.base_severity,
                            risk_score=calculate_finding_score(self.base_severity),
                            cis_reference=self.cis_reference,
                            remediation="Enable default encryption for the S3 bucket using SSE-S3 or AWS KMS.",
                            status=FindingStatus.FAIL,
                        )
                    )
                elif is_permission_error(exc):
                    findings.append(
                        self.handle_client_error(
                            exc,
                            resource_id=bucket_name,
                            resource_type="AWS::S3::Bucket",
                            region=bucket_region,
                        )
                    )
                else:
                    raise

        return findings


class S3VersioningCheck(BaseCheck):
    """S3-03: Ensure versioning is enabled for S3 buckets."""

    check_id = "S3-03"
    title = "S3 bucket versioning not enabled"
    module = "s3"
    base_severity = Severity.LOW
    cis_reference = "Ensure S3 bucket versioning is enabled"

    def run(self, session: boto3.Session, regions: List[str]) -> List[Finding]:
        findings: List[Finding] = []
        global_s3 = session.client("s3", region_name="us-east-1")

        try:
            buckets = global_s3.list_buckets().get("Buckets", [])
        except ClientError as exc:
            return [self.handle_client_error(exc, resource_id="s3-all-buckets", resource_type="AWS::S3::Bucket")]

        for bucket in buckets:
            bucket_name = bucket.get("Name", "")
            bucket_region = resolve_bucket_region(global_s3, bucket_name)

            if regions and bucket_region not in regions:
                continue

            regional_s3 = get_regional_s3_client(session, bucket_region)

            try:
                ver_resp = regional_s3.get_bucket_versioning(Bucket=bucket_name)
                status = ver_resp.get("Status")
                if status != "Enabled":
                    current_status = status if status else "Disabled"
                    findings.append(
                        Finding(
                            id=f"{self.check_id}-{bucket_region}-{bucket_name}",
                            check_id=self.check_id,
                            title=self.title,
                            description=(
                                f"S3 bucket '{bucket_name}' does not have versioning enabled "
                                f"(current status: {current_status})."
                            ),
                            resource_id=bucket_name,
                            resource_type="AWS::S3::Bucket",
                            region=bucket_region,
                            severity=self.base_severity,
                            risk_score=calculate_finding_score(self.base_severity),
                            cis_reference=self.cis_reference,
                            remediation="Enable versioning on the S3 bucket to preserve and recover previous versions of objects.",
                            status=FindingStatus.FAIL,
                        )
                    )
            except ClientError as exc:
                if is_permission_error(exc):
                    findings.append(
                        self.handle_client_error(
                            exc,
                            resource_id=bucket_name,
                            resource_type="AWS::S3::Bucket",
                            region=bucket_region,
                        )
                    )
                else:
                    raise

        return findings

