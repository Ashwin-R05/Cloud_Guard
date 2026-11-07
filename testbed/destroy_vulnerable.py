#!/usr/bin/env python3
"""CloudGuard Testbed Teardown Script.

================================================================================
⚠️  CRITICAL WARNING - USE ONLY IN AN ISOLATED PERSONAL AWS TEST ACCOUNT  ⚠️
================================================================================
This script tears down and deletes ONLY the testbed resources created by
'create_vulnerable.py' and listed in 'testbed/manifest.json'.

Verification after teardown:
1. S3: aws s3 ls | grep cloudguard-test-
2. IAM: aws iam list-users | grep cloudguard-test-
3. EC2 SG: aws ec2 describe-security-groups --filters Name=group-name,Values=cloudguard-test-*
4. EBS: aws ec2 describe-volumes --filters Name=tag:Name,Values=cloudguard-test-*
================================================================================
"""

import argparse
import json
from pathlib import Path
import sys
import time
from typing import Any, Dict

import boto3
from botocore.exceptions import ClientError

MANIFEST_PATH = Path(__file__).parent / "manifest.json"


def empty_and_delete_bucket(s3_client: Any, bucket_name: str) -> None:
    """Empty all objects, versions, and delete markers from an S3 bucket before deleting it."""
    print(f"  -> Emptying bucket: {bucket_name} ...")
    try:
        # Delete object versions and delete markers
        paginator = s3_client.get_paginator("list_object_versions")
        for page in paginator.paginate(Bucket=bucket_name):
            to_delete = []
            for ver in page.get("Versions", []):
                to_delete.append({"Key": ver["Key"], "VersionId": ver["VersionId"]})
            for dm in page.get("DeleteMarkers", []):
                to_delete.append({"Key": dm["Key"], "VersionId": dm["VersionId"]})
            if to_delete:
                s3_client.delete_objects(Bucket=bucket_name, Delete={"Objects": to_delete})

        # Delete any plain objects
        obj_paginator = s3_client.get_paginator("list_objects_v2")
        for page in obj_paginator.paginate(Bucket=bucket_name):
            objects = page.get("Contents", [])
            if objects:
                to_delete = [{"Key": obj["Key"]} for obj in objects]
                s3_client.delete_objects(Bucket=bucket_name, Delete={"Objects": to_delete})

        # Delete the bucket
        s3_client.delete_bucket(Bucket=bucket_name)
        print(f"     [✓] Deleted bucket: {bucket_name}")
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code", "")
        if code in ("NoSuchBucket", "NotFound"):
            print(f"     [-] Bucket {bucket_name} already deleted or not found.")
        else:
            print(f"     [!] Failed to delete bucket {bucket_name}: {exc}", file=sys.stderr)


def delete_iam_user(iam_client: Any, user_name: str) -> None:
    """Safely delete an IAM user along with attached login profile and credentials."""
    print(f"  -> Cleaning up IAM user: {user_name} ...")
    try:
        # 1. Delete login profile
        try:
            iam_client.delete_login_profile(UserName=user_name)
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "NoSuchEntity":
                raise

        # 2. Delete access keys
        try:
            keys = iam_client.list_access_keys(UserName=user_name).get("AccessKeyMetadata", [])
            for key in keys:
                iam_client.delete_access_key(UserName=user_name, AccessKeyId=key["AccessKeyId"])
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "NoSuchEntity":
                raise

        # 3. Delete inline policies
        try:
            policies = iam_client.list_user_policies(UserName=user_name).get("PolicyNames", [])
            for pol in policies:
                iam_client.delete_user_policy(UserName=user_name, PolicyName=pol)
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "NoSuchEntity":
                raise

        # 4. Detach managed policies
        try:
            attached = iam_client.list_attached_user_policies(UserName=user_name).get("AttachedPolicies", [])
            for pol in attached:
                iam_client.detach_user_policy(UserName=user_name, PolicyArn=pol["PolicyArn"])
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "NoSuchEntity":
                raise

        # 5. Delete the user
        iam_client.delete_user(UserName=user_name)
        print(f"     [✓] Deleted IAM user: {user_name}")
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code", "")
        if code == "NoSuchEntity":
            print(f"     [-] IAM user {user_name} already deleted or not found.")
        else:
            print(f"     [!] Failed to delete IAM user {user_name}: {exc}", file=sys.stderr)


def delete_iam_policy(iam_client: Any, policy_arn: str) -> None:
    """Delete a customer managed policy, removing non-default versions first."""
    print(f"  -> Deleting IAM policy: {policy_arn} ...")
    try:
        versions = iam_client.list_policy_versions(PolicyArn=policy_arn).get("Versions", [])
        for ver in versions:
            if not ver.get("IsDefaultVersion", False):
                try:
                    iam_client.delete_policy_version(PolicyArn=policy_arn, VersionId=ver["VersionId"])
                except Exception:
                    pass
        iam_client.delete_policy(PolicyArn=policy_arn)
        print(f"     [✓] Deleted IAM policy: {policy_arn}")
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code", "")
        if code == "NoSuchEntity":
            print(f"     [-] IAM policy {policy_arn} already deleted.")
        else:
            print(f"     [!] Failed to delete policy {policy_arn}: {exc}", file=sys.stderr)


def delete_security_group(ec2_client: Any, group_id: str) -> None:
    """Delete an EC2 security group."""
    print(f"  -> Deleting Security Group: {group_id} ...")
    try:
        ec2_client.delete_security_group(GroupId=group_id)
        print(f"     [✓] Deleted security group: {group_id}")
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code", "")
        if code in ("InvalidGroup.NotFound", "NoSuchEntity"):
            print(f"     [-] Security group {group_id} already deleted.")
        else:
            print(f"     [!] Failed to delete security group {group_id}: {exc}", file=sys.stderr)


def delete_ebs_volume(ec2_client: Any, volume_id: str) -> None:
    """Delete an EBS volume, waiting briefly if volume state is not yet available."""
    print(f"  -> Deleting EBS Volume: {volume_id} ...")
    for _ in range(5):
        try:
            ec2_client.delete_volume(VolumeId=volume_id)
            print(f"     [✓] Deleted EBS volume: {volume_id}")
            return
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "")
            if code in ("InvalidVolume.NotFound", "NoSuchEntity"):
                print(f"     [-] EBS volume {volume_id} already deleted.")
                return
            if "in-use" in str(exc) or "creating" in str(exc):
                time.sleep(2)
                continue
            print(f"     [!] Failed to delete EBS volume {volume_id}: {exc}", file=sys.stderr)
            return


def main(argv: Any = None) -> int:
    parser = argparse.ArgumentParser(
        description="Safely tear down resources listed in testbed/manifest.json."
    )
    parser.add_argument("--profile", default=None, help="AWS named profile from ~/.aws/credentials")
    args = parser.parse_args(argv if argv is not None else sys.argv[1:])

    if not MANIFEST_PATH.exists():
        print(f"[*] Manifest file not found at {MANIFEST_PATH.resolve()}. Nothing to destroy.")
        return 0

    with open(MANIFEST_PATH, "r", encoding="utf-8") as f:
        try:
            manifest = json.load(f)
        except Exception as exc:
            print(f"[!] Malformed manifest file: {exc}", file=sys.stderr)
            return 1

    region = manifest.get("region", "us-east-1")
    resources = manifest.get("resources", {})

    session_kwargs = {}
    if args.profile:
        session_kwargs["profile_name"] = args.profile
    if region:
        session_kwargs["region_name"] = region

    session = boto3.Session(**session_kwargs)

    print(f"[*] Starting teardown for testbed prefix: {manifest.get('prefix')} in region: {region} ...")

    s3 = session.client("s3", region_name=region)
    iam = session.client("iam")
    ec2 = session.client("ec2", region_name=region)

    # 1. Teardown S3 Buckets
    for b in resources.get("s3_buckets", []):
        empty_and_delete_bucket(s3, b["name"])

    # 2. Teardown Security Groups
    for sg in resources.get("security_groups", []):
        delete_security_group(ec2, sg["id"])

    # 3. Teardown EBS Volumes
    for vol in resources.get("ebs_volumes", []):
        delete_ebs_volume(ec2, vol["id"])

    # 4. Teardown IAM Users
    for user in resources.get("iam_users", []):
        delete_iam_user(iam, user["name"])

    # 5. Teardown IAM Policies
    for pol in resources.get("iam_policies", []):
        delete_iam_policy(iam, pol["arn"])

    # Remove manifest file
    MANIFEST_PATH.unlink(missing_ok=True)
    print(f"\n[+] Teardown complete! Manifest removed: {MANIFEST_PATH.resolve()}")
    print("[*] All testbed resources have been cleaned up.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
