# AWS Identity and Access Management (IAM) Setup Guide

This document details the IAM prerequisites, permissions, and configuration options required to run CloudGuard against an AWS account.

---

## 1. Security Architecture Principles

CloudGuard operates under the following operational security invariants:
- **Strictly Read-Only:** The scanner executes read, list, and describe API operations exclusively. It contains no implementation logic to modify, update, or delete cloud infrastructure.
- **Least Privilege:** The scanning identity requires only the read permissions necessary to evaluate the supported CIS controls.
- **Non-Intrusive Error Handling:** If the scanning identity lacks permission to inspect a specific resource (resulting in an AWS `AccessDenied` error), the scanner logs a `SKIPPED` finding rather than halting execution.

---

## 2. AWS Managed Policies

The simplest method to grant the required read-only access is attaching the AWS-managed policy provided by AWS:

### Recommended: `SecurityAudit`
- **Policy ARN:** `arn:aws:iam::aws:policy/SecurityAudit`
- **Scope:** Grants read-only access to security-relevant configuration data across AWS services, including S3, IAM, CloudTrail, EC2, EBS, and RDS.
- **Suitability:** Recommended for comprehensive assessments and enterprise environments.

### Alternative: `ViewOnlyAccess`
- **Policy ARN:** `arn:aws:iam::aws:policy/ViewOnlyAccess`
- **Scope:** Grants broad read-only access to inspect resource configurations without access to sensitive resource data payloads.

---

## 3. Minimal Custom IAM Policy

For environments requiring least-privilege scoping without attaching broad managed policies, create a custom customer-managed IAM policy containing only the exact API actions called by CloudGuard:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "CloudGuardCoreIdentityVerification",
      "Effect": "Allow",
      "Action": [
        "sts:GetCallerIdentity"
      ],
      "Resource": "*"
    },
    {
      "Sid": "CloudGuardS3Checks",
      "Effect": "Allow",
      "Action": [
        "s3:ListAllMyBuckets",
        "s3:GetBucketLocation",
        "s3:GetBucketPublicAccessBlock",
        "s3:GetBucketAcl",
        "s3:GetBucketPolicyStatus",
        "s3:GetBucketPolicy",
        "s3:GetEncryptionConfiguration",
        "s3:GetBucketVersioning",
        "s3:GetAccountPublicAccessBlock"
      ],
      "Resource": "*"
    },
    {
      "Sid": "CloudGuardIAMChecks",
      "Effect": "Allow",
      "Action": [
        "iam:ListUsers",
        "iam:GetLoginProfile",
        "iam:ListMFADevices",
        "iam:ListPolicies",
        "iam:GetPolicy",
        "iam:GetPolicyVersion",
        "iam:ListUserPolicies",
        "iam:GetUserPolicy",
        "iam:ListGroupPolicies",
        "iam:GetGroupPolicy",
        "iam:ListRolePolicies",
        "iam:GetRolePolicy",
        "iam:ListAccessKeys",
        "iam:GetAccessKeyLastUsed",
        "iam:GetAccountSummary"
      ],
      "Resource": "*"
    },
    {
      "Sid": "CloudGuardNetworkAndDataChecks",
      "Effect": "Allow",
      "Action": [
        "ec2:DescribeSecurityGroups",
        "ec2:DescribeVolumes",
        "rds:DescribeDBInstances"
      ],
      "Resource": "*"
    },
    {
      "Sid": "CloudGuardLoggingChecks",
      "Effect": "Allow",
      "Action": [
        "cloudtrail:DescribeTrails",
        "cloudtrail:GetTrailStatus"
      ],
      "Resource": "*"
    }
  ]
}
```

---

## 4. Configuring Authentication

CloudGuard resolves credentials through standard `boto3` resolution mechanisms.

### Option A: AWS CLI Named Profile (Recommended)
Configure a named profile using the AWS CLI:
```bash
aws configure --profile cloudguard-readonly
```
Specify the profile when invoking the scanner:
```bash
python -m cloudguard.cli --profile cloudguard-readonly
```

### Option B: Environment Variables
Export standard AWS environment variables in the active shell:
```bash
export AWS_ACCESS_KEY_ID="AKIAIOSFODNN7EXAMPLE"
export AWS_SECRET_ACCESS_KEY="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
export AWS_DEFAULT_REGION="us-east-1"
```

### Option C: Cross-Account IAM Role Assumption
When evaluating secondary accounts from a central security account, configure the profile in `~/.aws/config`:
```ini
[profile audit-target-account]
role_arn = arn:aws:iam::123456789012:role/CloudGuardScanningRole
source_profile = default
```
CloudGuard will automatically assume the role through standard STS credential chaining.

---

## 5. Verifying Identity and Permissions

Before initiating a full scan, verify that the configured credentials resolve correctly:

```bash
python -c "
import boto3
from cloudguard.session import get_session, verify_identity
session = get_session(profile='cloudguard-readonly')
account_id, arn = verify_identity(session)
print(f'Authenticated Account: {account_id}')
print(f'Identity ARN: {arn}')
"
```

