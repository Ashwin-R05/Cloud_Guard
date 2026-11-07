#!/usr/bin/env python3
"""CloudGuard Testbed Provisioner.

================================================================================
⚠️  CRITICAL WARNING - USE ONLY IN AN ISOLATED PERSONAL AWS TEST ACCOUNT  ⚠️
================================================================================
This script provisions intentionally vulnerable AWS resources to evaluate
security scanning tools.

DO NOT RUN THIS SCRIPT IN A PRODUCTION, STAGING, OR CORPORATE AWS ACCOUNT.
DO NOT STORE REAL, SENSITIVE, OR CONFIDENTIAL DATA IN TESTBED RESOURCES.

Expected Costs:
- IAM Users, Managed Policies, and Security Groups: FREE
- S3 Buckets (2 buckets, dummy objects): < $0.01
- EBS Volume (1 GiB gp3/gp2, unattached): ~$0.001 / day ($0.10 / month pro-rated)
- RDS Instances: EXCLUDED (not created to avoid accidental hourly charges)
Total expected cost is under $0.05 if torn down within a few hours.

Verification:
Run 'python testbed/destroy_vulnerable.py' after testing, and verify via
AWS Console that resources prefixed with 'cloudguard-test-' are removed.
================================================================================
"""

import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import sys
import uuid
from typing import Any, Dict

import boto3
from botocore.exceptions import ClientError

MANIFEST_PATH = Path(__file__).parent / "manifest.json"


def get_default_az(ec2_client: Any) -> str:
    """Retrieve the first available AZ in the region."""
    try:
        azs = ec2_client.describe_availability_zones(
            Filters=[{"Name": "state", "Values": ["available"]}]
        )
        return azs["AvailabilityZones"][0]["ZoneName"]
    except Exception:
        region = ec2_client.meta.region_name or "us-east-1"
        return f"{region}a"


def get_default_vpc(ec2_client: Any) -> str:
    """Retrieve default VPC ID if available."""
    try:
        vpcs = ec2_client.describe_vpcs(
            Filters=[{"Name": "isDefault", "Values": ["true"]}]
        )
        if vpcs.get("Vpcs"):
            return vpcs["Vpcs"][0]["VpcId"]
        # Fallback to any VPC
        all_vpcs = ec2_client.describe_vpcs()
        if all_vpcs.get("Vpcs"):
            return all_vpcs["Vpcs"][0]["VpcId"]
    except Exception:
        pass
    return ""


def main(argv: Any = None) -> int:
    parser = argparse.ArgumentParser(
        description="Provision intentionally misconfigured testbed resources for CloudGuard evaluation."
    )
    parser.add_argument("--profile", default=None, help="AWS named profile from ~/.aws/credentials")
    parser.add_argument("--region", default="us-east-1", help="Target AWS region (default: us-east-1)")
    args = parser.parse_args(argv if argv is not None else sys.argv[1:])

    session_kwargs = {}
    if args.profile:
        session_kwargs["profile_name"] = args.profile
    if args.region:
        session_kwargs["region_name"] = args.region

    session = boto3.Session(**session_kwargs)
    region = session.region_name or "us-east-1"

    # Verify identity
    sts = session.client("sts")
    try:
        caller = sts.get_caller_identity()
        account_id = caller["Account"]
        print(f"[*] Authenticated as Account: {account_id} ({caller['Arn']})")
    except Exception as exc:
        print(f"[!] STS Authentication Failed: {exc}", file=sys.stderr)
        return 1

    unique_suffix = uuid.uuid4().hex[:8]
    prefix = f"cloudguard-test-{unique_suffix}"
    print(f"[*] Provisioning testbed resources with prefix: {prefix} in region: {region} ...")

    manifest: Dict[str, Any] = {
        "created_at": datetime.now(timezone.utc).isoformat(),
        "account_id": account_id,
        "region": region,
        "prefix": prefix,
        "resources": {
            "s3_buckets": [],
            "iam_users": [],
            "iam_policies": [],
            "security_groups": [],
            "ebs_volumes": [],
        },
    }

    s3 = session.client("s3", region_name=region)
    iam = session.client("iam")
    ec2 = session.client("ec2", region_name=region)

    # 1. Non-Compliant S3 Bucket (Public, Unencrypted, No Versioning)
    vuln_bucket = f"{prefix}-vuln-bucket"
    print(f"  -> Creating vulnerable S3 bucket: {vuln_bucket}")
    bucket_kwargs: Dict[str, Any] = {"Bucket": vuln_bucket}
    if region != "us-east-1":
        bucket_kwargs["CreateBucketConfiguration"] = {"LocationConstraint": region}
    s3.create_bucket(**bucket_kwargs)

    # Disable Block Public Access on the vulnerable bucket
    s3.put_public_access_block(
        Bucket=vuln_bucket,
        PublicAccessBlockConfiguration={
            "BlockPublicAcls": False,
            "IgnorePublicAcls": False,
            "BlockPublicPolicy": False,
            "RestrictPublicBuckets": False,
        },
    )

    # Attach public read policy
    public_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "PublicReadGetObject",
                "Effect": "Allow",
                "Principal": "*",
                "Action": "s3:GetObject",
                "Resource": f"arn:aws:s3:::{vuln_bucket}/*",
            }
        ],
    }
    s3.put_bucket_policy(Bucket=vuln_bucket, Policy=json.dumps(public_policy))

    # Add harmless dummy object
    s3.put_object(
        Bucket=vuln_bucket,
        Key="dummy_sample.txt",
        Body=b"CloudGuard non-sensitive testbed dummy file for evaluation.\n",
    )
    manifest["resources"]["s3_buckets"].append({
        "name": vuln_bucket,
        "type": "vulnerable",
        "region": region,
    })

    # 2. Compliant S3 Bucket (Control)
    comp_bucket = f"{prefix}-comp-bucket"
    print(f"  -> Creating compliant S3 bucket: {comp_bucket}")
    comp_kwargs: Dict[str, Any] = {"Bucket": comp_bucket}
    if region != "us-east-1":
        comp_kwargs["CreateBucketConfiguration"] = {"LocationConstraint": region}
    s3.create_bucket(**comp_kwargs)

    # Enable full Block Public Access
    s3.put_public_access_block(
        Bucket=comp_bucket,
        PublicAccessBlockConfiguration={
            "BlockPublicAcls": True,
            "IgnorePublicAcls": True,
            "BlockPublicPolicy": True,
            "RestrictPublicBuckets": True,
        },
    )

    # Enable Default Encryption
    s3.put_bucket_encryption(
        Bucket=comp_bucket,
        ServerSideEncryptionConfiguration={
            "Rules": [
                {
                    "ApplyServerSideEncryptionByDefault": {
                        "SSEAlgorithm": "AES256"
                    }
                }
            ]
        },
    )

    # Enable Versioning
    s3.put_bucket_versioning(
        Bucket=comp_bucket,
        VersioningConfiguration={"Status": "Enabled"},
    )
    manifest["resources"]["s3_buckets"].append({
        "name": comp_bucket,
        "type": "compliant",
        "region": region,
    })

    # 3. IAM User with Console Password and No MFA
    user_name = f"{prefix}-console-user"
    print(f"  -> Creating vulnerable IAM user: {user_name}")
    iam.create_user(UserName=user_name)
    dummy_password = f"CloudGuardTest!{uuid.uuid4().hex[:12]}"
    iam.create_login_profile(
        UserName=user_name,
        Password=dummy_password,
        PasswordResetRequired=False,
    )
    manifest["resources"]["iam_users"].append({
        "name": user_name,
        "region": "global",
    })

    # 4. Customer-Managed Wildcard Admin Policy (*:*) (unattached)
    policy_name = f"{prefix}-wildcard-policy"
    print(f"  -> Creating unattached wildcard admin IAM policy: {policy_name}")
    wildcard_doc = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "*",
                "Resource": "*",
            }
        ],
    }
    policy_resp = iam.create_policy(
        PolicyName=policy_name,
        PolicyDocument=json.dumps(wildcard_doc),
        Description="CloudGuard evaluation unattached wildcard policy",
    )
    policy_arn = policy_resp["Policy"]["Arn"]
    manifest["resources"]["iam_policies"].append({
        "name": policy_name,
        "arn": policy_arn,
        "region": "global",
    })

    # 5. Security Group: SSH Open to World (22)
    vpc_id = get_default_vpc(ec2)
    sg_ssh_name = f"{prefix}-sg-ssh-open"
    print(f"  -> Creating security group with open SSH: {sg_ssh_name}")
    sg_ssh_kwargs: Dict[str, Any] = {
        "GroupName": sg_ssh_name,
        "Description": "CloudGuard evaluation open SSH security group",
    }
    if vpc_id:
        sg_ssh_kwargs["VpcId"] = vpc_id
    sg_ssh_resp = ec2.create_security_group(**sg_ssh_kwargs)
    sg_ssh_id = sg_ssh_resp["GroupId"]
    ec2.authorize_security_group_ingress(
        GroupId=sg_ssh_id,
        IpPermissions=[
            {
                "IpProtocol": "tcp",
                "FromPort": 22,
                "ToPort": 22,
                "IpRanges": [{"CidrIp": "0.0.0.0/0", "Description": "Open SSH to world"}],
            }
        ],
    )
    manifest["resources"]["security_groups"].append({
        "id": sg_ssh_id,
        "name": sg_ssh_name,
        "type": "open-ssh",
        "region": region,
    })

    # 6. Security Group: All Traffic Open to World (-1)
    sg_all_name = f"{prefix}-sg-all-traffic"
    print(f"  -> Creating security group with all traffic open: {sg_all_name}")
    sg_all_kwargs: Dict[str, Any] = {
        "GroupName": sg_all_name,
        "Description": "CloudGuard evaluation all-traffic open security group",
    }
    if vpc_id:
        sg_all_kwargs["VpcId"] = vpc_id
    sg_all_resp = ec2.create_security_group(**sg_all_kwargs)
    sg_all_id = sg_all_resp["GroupId"]
    ec2.authorize_security_group_ingress(
        GroupId=sg_all_id,
        IpPermissions=[
            {
                "IpProtocol": "-1",
                "IpRanges": [{"CidrIp": "0.0.0.0/0", "Description": "All traffic open"}],
            }
        ],
    )
    manifest["resources"]["security_groups"].append({
        "id": sg_all_id,
        "name": sg_all_name,
        "type": "all-traffic",
        "region": region,
    })

    # 7. Small Unencrypted EBS Volume (1 GiB)
    target_az = get_default_az(ec2)
    print(f"  -> Creating 1 GiB unencrypted EBS volume in {target_az}")
    vol_resp = ec2.create_volume(
        AvailabilityZone=target_az,
        Size=1,
        VolumeType="gp3",
        Encrypted=False,
        TagSpecifications=[
            {
                "ResourceType": "volume",
                "Tags": [{"Key": "Name", "Value": f"{prefix}-unencrypted-vol"}],
            }
        ],
    )
    vol_id = vol_resp["VolumeId"]
    manifest["resources"]["ebs_volumes"].append({
        "id": vol_id,
        "az": target_az,
        "region": region,
    })

    # Save manifest
    MANIFEST_PATH.parent.mkdir(parents=True, exist_ok=True)
    with open(MANIFEST_PATH, "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2)

    print(f"\n[+] Provisioning complete! Manifest written to: {MANIFEST_PATH.resolve()}")
    print("[*] Remember to run 'python testbed/destroy_vulnerable.py' when evaluation completes.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
