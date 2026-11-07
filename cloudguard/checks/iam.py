"""IAM security and compliance checks aligned with CIS AWS Foundations Benchmark."""

from datetime import datetime, timezone
import json
from typing import Any, Dict, List, Optional
import urllib.parse
import boto3
from botocore.exceptions import ClientError
from cloudguard.checks.base import BaseCheck, is_permission_error
from cloudguard.models import Finding, FindingStatus, Severity
from cloudguard.scoring import calculate_finding_score, calculate_risk


def parse_policy_document(doc: Any) -> Dict[str, Any]:
    """Parse IAM policy document from dict or URL-encoded JSON string."""
    if isinstance(doc, dict):
        return doc
    if isinstance(doc, str):
        try:
            return json.loads(urllib.parse.unquote(doc))
        except Exception:
            try:
                return json.loads(doc)
            except Exception:
                return {}
    return {}


def statement_allows_full_admin(statement: Dict[str, Any]) -> bool:
    """Check if an IAM statement allows full administrative privileges (*:*)."""
    if statement.get("Effect") != "Allow":
        return False

    # Check Resource: must be '*' or contain '*'
    resource = statement.get("Resource")
    resource_is_star = (
        resource == "*"
        or (isinstance(resource, list) and "*" in resource)
    )
    if not resource_is_star:
        return False

    # Check Action: must be '*' or contain '*'
    action = statement.get("Action")
    action_is_star = (
        action == "*"
        or (isinstance(action, list) and "*" in action)
    )

    # Check NotAction: if NotAction is empty or non-restricting
    not_action = statement.get("NotAction")
    not_action_is_star = False
    if not_action is not None:
        if not not_action or not_action == [] or not_action == "":
            not_action_is_star = True

    return action_is_star or not_action_is_star


class IAMConsoleMfaCheck(BaseCheck):
    """IAM-01: Ensure MFA is enabled for all IAM users with console access."""

    check_id = "IAM-01"
    title = "IAM user has console access without MFA"
    module = "iam"
    base_severity = Severity.HIGH
    cis_reference = "Ensure MFA is enabled for all IAM users that have a console password"

    def run(self, session: boto3.Session, regions: List[str]) -> List[Finding]:
        findings: List[Finding] = []
        iam = session.client("iam")

        try:
            paginator = iam.get_paginator("list_users")
            user_pages = paginator.paginate()
        except ClientError as exc:
            return [self.handle_client_error(exc, resource_id="iam-users", resource_type="AWS::IAM::User")]

        try:
            for page in user_pages:
                for user in page.get("Users", []):
                    user_name = user.get("UserName", "")
                    # Check if user has a login profile (console password)
                    try:
                        iam.get_login_profile(UserName=user_name)
                    except ClientError as exc:
                        code = exc.response.get("Error", {}).get("Code", "")
                        if code == "NoSuchEntity":
                            # User has no console password, compliant for this check
                            continue
                        if is_permission_error(exc):
                            findings.append(self.handle_client_error(exc, resource_id=user_name, resource_type="AWS::IAM::User"))
                            continue
                        raise

                    # User has console access; check MFA devices
                    try:
                        mfa_paginator = iam.get_paginator("list_mfa_devices")
                        mfa_devices: List[Any] = []
                        for mfa_page in mfa_paginator.paginate(UserName=user_name):
                            mfa_devices.extend(mfa_page.get("MFADevices", []))
                    except ClientError as exc:
                        if is_permission_error(exc):
                            findings.append(self.handle_client_error(exc, resource_id=user_name, resource_type="AWS::IAM::User"))
                            continue
                        raise

                    if not mfa_devices:
                        risk_score, effective_sev, imp, exp, reason = calculate_risk(
                            self.base_severity,
                            exposure=4,
                            exposure_reason="Console password active without multi-factor authentication safeguard",
                        )
                        findings.append(
                            Finding(
                                id=f"{self.check_id}-{user_name}",
                                check_id=self.check_id,
                                title=self.title,
                                description=(
                                    f"IAM user '{user_name}' has console password access enabled but no "
                                    "multi-factor authentication (MFA) devices configured."
                                ),
                                resource_id=user_name,
                                resource_type="AWS::IAM::User",
                                region="global",
                                severity=effective_sev,
                                risk_score=risk_score,
                                cis_reference=self.cis_reference,
                                remediation=(
                                    f"Enable multi-factor authentication (MFA) for IAM user '{user_name}' "
                                    "or delete their login profile if console access is not required."
                                ),
                                status=FindingStatus.FAIL,
                                impact=imp,
                                exposure=exp,
                                exposure_reason=reason,
                            )
                        )
        except ClientError as exc:
            if is_permission_error(exc):
                findings.append(self.handle_client_error(exc, resource_id="iam-users", resource_type="AWS::IAM::User"))
            else:
                raise

        return findings


class IAMWildcardPolicyCheck(BaseCheck):
    """IAM-02: Ensure no IAM policies grant full administrative privileges (*:*)."""

    check_id = "IAM-02"
    title = "IAM policy grants full administrative privileges (*:*)"
    module = "iam"
    base_severity = Severity.HIGH
    cis_reference = "Ensure no IAM policies allow full administrative privileges (*:*)"

    def run(self, session: boto3.Session, regions: List[str]) -> List[Finding]:
        findings: List[Finding] = []
        iam = session.client("iam")

        # 1. Inspect Customer-Managed Policies (Scope='Local')
        try:
            policy_paginator = iam.get_paginator("list_policies")
            for page in policy_paginator.paginate(Scope="Local"):
                for policy in page.get("Policies", []):
                    policy_arn = policy.get("Arn", "")
                    policy_name = policy.get("PolicyName", "")
                    default_version_id = policy.get("DefaultVersionId", "")

                    try:
                        version_resp = iam.get_policy_version(
                            PolicyArn=policy_arn, VersionId=default_version_id
                        )
                        doc = parse_policy_document(
                            version_resp.get("PolicyVersion", {}).get("Document", {})
                        )
                        statements = doc.get("Statement", [])
                        if isinstance(statements, dict):
                            statements = [statements]

                        for stmt in statements:
                            if statement_allows_full_admin(stmt):
                                risk_score, effective_sev, imp, exp, reason = calculate_risk(
                                    self.base_severity,
                                    exposure=4,
                                    exposure_reason="IAM policy grants unrestricted administrative permissions (*:*)",
                                )
                                findings.append(
                                    Finding(
                                        id=f"{self.check_id}-{policy_name}",
                                        check_id=self.check_id,
                                        title=self.title,
                                        description=(
                                            f"Customer-managed IAM policy '{policy_name}' contains a statement "
                                            "granting full administrative privileges with Action '*' on Resource '*'."
                                        ),
                                        resource_id=policy_name,
                                        resource_type="AWS::IAM::Policy",
                                        region="global",
                                        severity=effective_sev,
                                        risk_score=risk_score,
                                        cis_reference=self.cis_reference,
                                        remediation=(
                                            f"Restrict policy '{policy_name}' by defining explicit allowed actions "
                                            "and specific resource ARNs, adhering to the principle of least privilege."
                                        ),
                                        status=FindingStatus.FAIL,
                                        impact=imp,
                                        exposure=exp,
                                        exposure_reason=reason,
                                    )
                                )
                                break
                    except ClientError as exc:
                        if is_permission_error(exc):
                            findings.append(self.handle_client_error(exc, resource_id=policy_name, resource_type="AWS::IAM::Policy"))
                        else:
                            raise
        except ClientError as exc:
            if is_permission_error(exc):
                findings.append(self.handle_client_error(exc, resource_id="managed-policies", resource_type="AWS::IAM::Policy"))
            else:
                raise

        # 2. Inspect Inline Policies on Users
        try:
            user_paginator = iam.get_paginator("list_users")
            for page in user_paginator.paginate():
                for user in page.get("Users", []):
                    user_name = user.get("UserName", "")
                    inline_paginator = iam.get_paginator("list_user_policies")
                    for inline_page in inline_paginator.paginate(UserName=user_name):
                        for pol_name in inline_page.get("PolicyNames", []):
                            try:
                                pol_resp = iam.get_user_policy(UserName=user_name, PolicyName=pol_name)
                                doc = parse_policy_document(pol_resp.get("PolicyDocument", {}))
                                statements = doc.get("Statement", [])
                                if isinstance(statements, dict):
                                    statements = [statements]
                                for stmt in statements:
                                    if statement_allows_full_admin(stmt):
                                        risk_score, effective_sev, imp, exp, reason = calculate_risk(
                                            self.base_severity,
                                            exposure=4,
                                            exposure_reason="Inline user policy grants unrestricted administrative privileges (*:*)",
                                        )
                                        findings.append(
                                            Finding(
                                                id=f"{self.check_id}-user-{user_name}-{pol_name}",
                                                check_id=self.check_id,
                                                title=self.title,
                                                description=(
                                                    f"Inline policy '{pol_name}' on IAM user '{user_name}' grants "
                                                    "full administrative privileges (Action '*' on Resource '*')."
                                                ),
                                                resource_id=f"{user_name}/{pol_name}",
                                                resource_type="AWS::IAM::UserPolicy",
                                                region="global",
                                                severity=effective_sev,
                                                risk_score=risk_score,
                                                cis_reference=self.cis_reference,
                                                remediation=(
                                                    f"Remove or restrict inline policy '{pol_name}' on user '{user_name}' "
                                                    "and apply least-privilege permissions."
                                                ),
                                                status=FindingStatus.FAIL,
                                                impact=imp,
                                                exposure=exp,
                                                exposure_reason=reason,
                                            )
                                        )
                                        break
                            except ClientError as exc:
                                if is_permission_error(exc):
                                    findings.append(self.handle_client_error(exc, resource_id=f"{user_name}/{pol_name}", resource_type="AWS::IAM::UserPolicy"))
                                else:
                                    raise
        except ClientError as exc:
            if is_permission_error(exc):
                findings.append(self.handle_client_error(exc, resource_id="user-inline-policies", resource_type="AWS::IAM::UserPolicy"))

        # 3. Inspect Inline Policies on Groups
        try:
            group_paginator = iam.get_paginator("list_groups")
            for page in group_paginator.paginate():
                for group in page.get("Groups", []):
                    group_name = group.get("GroupName", "")
                    group_pol_paginator = iam.get_paginator("list_group_policies")
                    for grp_page in group_pol_paginator.paginate(GroupName=group_name):
                        for pol_name in grp_page.get("PolicyNames", []):
                            try:
                                pol_resp = iam.get_group_policy(GroupName=group_name, PolicyName=pol_name)
                                doc = parse_policy_document(pol_resp.get("PolicyDocument", {}))
                                statements = doc.get("Statement", [])
                                if isinstance(statements, dict):
                                    statements = [statements]
                                for stmt in statements:
                                    if statement_allows_full_admin(stmt):
                                        risk_score, effective_sev, imp, exp, reason = calculate_risk(
                                            self.base_severity,
                                            exposure=4,
                                            exposure_reason="Inline group policy grants unrestricted administrative privileges (*:*)",
                                        )
                                        findings.append(
                                            Finding(
                                                id=f"{self.check_id}-group-{group_name}-{pol_name}",
                                                check_id=self.check_id,
                                                title=self.title,
                                                description=(
                                                    f"Inline policy '{pol_name}' on IAM group '{group_name}' grants "
                                                    "full administrative privileges (Action '*' on Resource '*')."
                                                ),
                                                resource_id=f"{group_name}/{pol_name}",
                                                resource_type="AWS::IAM::GroupPolicy",
                                                region="global",
                                                severity=effective_sev,
                                                risk_score=risk_score,
                                                cis_reference=self.cis_reference,
                                                remediation=(
                                                    f"Remove or restrict inline policy '{pol_name}' on group '{group_name}'."
                                                ),
                                                status=FindingStatus.FAIL,
                                                impact=imp,
                                                exposure=exp,
                                                exposure_reason=reason,
                                            )
                                        )
                                        break
                            except ClientError as exc:
                                if is_permission_error(exc):
                                    findings.append(self.handle_client_error(exc, resource_id=f"{group_name}/{pol_name}", resource_type="AWS::IAM::GroupPolicy"))
                                else:
                                    raise
        except ClientError as exc:
            if is_permission_error(exc):
                findings.append(self.handle_client_error(exc, resource_id="group-inline-policies", resource_type="AWS::IAM::GroupPolicy"))

        # 4. Inspect Inline Policies on Roles (skipping AWS service roles)
        try:
            role_paginator = iam.get_paginator("list_roles")
            for page in role_paginator.paginate():
                for role in page.get("Roles", []):
                    role_name = role.get("RoleName", "")
                    role_path = role.get("Path", "/")
                    if role_path.startswith("/aws-service-role/"):
                        continue

                    role_pol_paginator = iam.get_paginator("list_role_policies")
                    for r_page in role_pol_paginator.paginate(RoleName=role_name):
                        for pol_name in r_page.get("PolicyNames", []):
                            try:
                                pol_resp = iam.get_role_policy(RoleName=role_name, PolicyName=pol_name)
                                doc = parse_policy_document(pol_resp.get("PolicyDocument", {}))
                                statements = doc.get("Statement", [])
                                if isinstance(statements, dict):
                                    statements = [statements]
                                for stmt in statements:
                                    if statement_allows_full_admin(stmt):
                                        risk_score, effective_sev, imp, exp, reason = calculate_risk(
                                            self.base_severity,
                                            exposure=4,
                                            exposure_reason="Inline role policy grants unrestricted administrative privileges (*:*)",
                                        )
                                        findings.append(
                                            Finding(
                                                id=f"{self.check_id}-role-{role_name}-{pol_name}",
                                                check_id=self.check_id,
                                                title=self.title,
                                                description=(
                                                    f"Inline policy '{pol_name}' on IAM role '{role_name}' grants "
                                                    "full administrative privileges (Action '*' on Resource '*')."
                                                ),
                                                resource_id=f"{role_name}/{pol_name}",
                                                resource_type="AWS::IAM::RolePolicy",
                                                region="global",
                                                severity=effective_sev,
                                                risk_score=risk_score,
                                                cis_reference=self.cis_reference,
                                                remediation=(
                                                    f"Remove or restrict inline policy '{pol_name}' on role '{role_name}'."
                                                ),
                                                status=FindingStatus.FAIL,
                                                impact=imp,
                                                exposure=exp,
                                                exposure_reason=reason,
                                            )
                                        )
                                        break
                            except ClientError as exc:
                                if is_permission_error(exc):
                                    findings.append(self.handle_client_error(exc, resource_id=f"{role_name}/{pol_name}", resource_type="AWS::IAM::RolePolicy"))
                                else:
                                    raise
        except ClientError as exc:
            if is_permission_error(exc):
                findings.append(self.handle_client_error(exc, resource_id="role-inline-policies", resource_type="AWS::IAM::RolePolicy"))

        return findings


class IAMStaleAccessKeysCheck(BaseCheck):
    """IAM-03: Ensure active access keys older than 90 days or unused for 90 days are flagged."""

    check_id = "IAM-03"
    title = "IAM access key is older than 90 days or unused"
    module = "iam"
    base_severity = Severity.MEDIUM
    cis_reference = "Ensure access keys are rotated every 90 days or less and unused keys are disabled"

    def run(self, session: boto3.Session, regions: List[str]) -> List[Finding]:
        findings: List[Finding] = []
        iam = session.client("iam")
        now = datetime.now(timezone.utc)

        try:
            user_paginator = iam.get_paginator("list_users")
            user_pages = user_paginator.paginate()
        except ClientError as exc:
            return [self.handle_client_error(exc, resource_id="iam-users", resource_type="AWS::IAM::User")]

        try:
            for page in user_pages:
                for user in page.get("Users", []):
                    user_name = user.get("UserName", "")
                    try:
                        key_paginator = iam.get_paginator("list_access_keys")
                        for key_page in key_paginator.paginate(UserName=user_name):
                            for key in key_page.get("AccessKeyMetadata", []):
                                if key.get("Status") != "Active":
                                    continue

                                key_id = key.get("AccessKeyId", "")
                                create_date = key.get("CreateDate")
                                age_days = (now - create_date).days if create_date else 0

                                # Query last used details
                                try:
                                    last_used_resp = iam.get_access_key_last_used(AccessKeyId=key_id)
                                    last_used_info = last_used_resp.get("AccessKeyLastUsed", {})
                                    last_used_date = last_used_info.get("LastUsedDate")
                                except ClientError as exc:
                                    if is_permission_error(exc):
                                        findings.append(self.handle_client_error(exc, resource_id=f"{user_name}/{key_id}", resource_type="AWS::IAM::AccessKey"))
                                        continue
                                    raise

                                reasons: List[str] = []
                                if age_days > 90:
                                    reasons.append(f"key is {age_days} days old")

                                if last_used_date:
                                    unused_days = (now - last_used_date).days
                                    if unused_days > 90:
                                        reasons.append(f"key has been unused for {unused_days} days")
                                elif age_days > 90:
                                    reasons.append("key has never been used")

                                if reasons:
                                    reasons_msg = "; ".join(reasons)
                                    risk_score, effective_sev, imp, exp, reason = calculate_risk(
                                        self.base_severity,
                                        exposure=3,
                                        exposure_reason="Programmatic access key active beyond recommended 90-day rotation interval",
                                    )
                                    findings.append(
                                        Finding(
                                            id=f"{self.check_id}-{user_name}-{key_id}",
                                            check_id=self.check_id,
                                            title=self.title,
                                            description=(
                                                f"Active access key '{key_id}' for IAM user '{user_name}' "
                                                f"violates 90-day rotation policy ({reasons_msg})."
                                            ),
                                            resource_id=f"{user_name}/{key_id}",
                                            resource_type="AWS::IAM::AccessKey",
                                            region="global",
                                            severity=effective_sev,
                                            risk_score=risk_score,
                                            cis_reference=self.cis_reference,
                                            remediation=(
                                                f"Rotate access key '{key_id}' for IAM user '{user_name}' or "
                                                "deactivate and delete the key if no longer required."
                                            ),
                                            status=FindingStatus.FAIL,
                                            impact=imp,
                                            exposure=exp,
                                            exposure_reason=reason,
                                        )
                                    )
                    except ClientError as exc:
                        if is_permission_error(exc):
                            findings.append(self.handle_client_error(exc, resource_id=user_name, resource_type="AWS::IAM::User"))
                        else:
                            raise
        except ClientError as exc:
            if is_permission_error(exc):
                findings.append(self.handle_client_error(exc, resource_id="iam-users", resource_type="AWS::IAM::User"))
            else:
                raise

        return findings


class IAMRootAccessKeysCheck(BaseCheck):
    """IAM-04: Ensure no root account access keys exist."""

    check_id = "IAM-04"
    title = "Root account has active access keys"
    module = "iam"
    base_severity = Severity.CRITICAL
    cis_reference = "Ensure no root account access keys exist"

    def run(self, session: boto3.Session, regions: List[str]) -> List[Finding]:
        findings: List[Finding] = []
        iam = session.client("iam")

        try:
            summary = iam.get_account_summary()
            summary_map = summary.get("SummaryMap", {})
            keys_present = summary_map.get("AccountAccessKeysPresent", 0)

            if keys_present > 0:
                risk_score, effective_sev, imp, exp, reason = calculate_risk(
                    self.base_severity,
                    exposure=5,
                    exposure_reason="Root account credentials active with irrevocable administrative account privileges",
                )
                findings.append(
                    Finding(
                        id=f"{self.check_id}-root",
                        check_id=self.check_id,
                        title=self.title,
                        description=(
                            f"AWS root account currently has {keys_present} active access key(s) present. "
                            "Root access keys provide unrestricted administrative access and cannot be scoped down."
                        ),
                        resource_id="root",
                        resource_type="AWS::IAM::Root",
                        region="global",
                        severity=effective_sev,
                        risk_score=risk_score,
                        cis_reference=self.cis_reference,
                        remediation=(
                            "Delete all root account access keys immediately via the AWS Management Console "
                            "and create scoped IAM users or roles with temporary credentials."
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
                        resource_id="root",
                        resource_type="AWS::IAM::Root",
                        region="global",
                    )
                )
            else:
                raise

        return findings

