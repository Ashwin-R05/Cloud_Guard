# CloudGuard Testbed Environment

This directory contains standalone utility scripts for provisioning and destroying controlled, intentionally misconfigured AWS resources to benchmark CloudGuard's detection accuracy.

> **Caution:** These scripts create live AWS resources. Use exclusively in an isolated, personal test account. Never execute against production, shared, or mission-critical cloud accounts.

---

## Safety Controls

- **Name Isolation:** All resources created by `create_vulnerable.py` use a unique prefix (`cloudguard-test-<uuid>`).
- **No Database Instances:** The testbed does not provision Amazon RDS instances to avoid unnecessary provisioning delay and hourly charges.
- **Manifest Tracking:** Resource identifiers are written to `testbed/manifest.json`.
- **Scoped Teardown:** The destruction script (`destroy_vulnerable.py`) reads strictly from `manifest.json` and deletes only registered resources. It empties S3 buckets before deletion and detaches policies safely.
- **Cost Minimization:** All created resources (e.g., 1 GiB EBS volume, S3 objects, Security Groups, IAM entities) are designed to stay well within free tier limits or incur negligible cost if torn down promptly.

---

## Usage

### 1. Provision Testbed
```bash
python testbed/create_vulnerable.py --region us-east-1
```

### 2. Verify Resources
Confirm that `testbed/manifest.json` has been populated with the created resource IDs.

### 3. Teardown Testbed
```bash
python testbed/destroy_vulnerable.py --manifest testbed/manifest.json
```
Verify via AWS CLI or AWS Console that no orphaned test resources remain:
```bash
aws s3 ls | grep cloudguard-test
aws ec2 describe-security-groups --filters "Name=group-name,Values=cloudguard-test*"
aws ec2 describe-volumes --filters "Name=tag:Name,Values=cloudguard-test*"
aws iam list-users | grep cloudguard-test
```
