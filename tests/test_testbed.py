"""Unit tests for testbed provisioning and teardown lifecycle using Moto."""

import json
from pathlib import Path
import pytest
from moto import mock_aws
import testbed.create_vulnerable as create_mod
import testbed.destroy_vulnerable as destroy_mod


@mock_aws
def test_testbed_create_and_destroy_lifecycle(tmp_path: Path, monkeypatch):
    """Verify create_vulnerable creates resources and manifest, and destroy_vulnerable tears down cleanly."""
    manifest_file = tmp_path / "manifest.json"
    monkeypatch.setattr(create_mod, "MANIFEST_PATH", manifest_file)
    monkeypatch.setattr(destroy_mod, "MANIFEST_PATH", manifest_file)

    # 1. Execute create_vulnerable
    create_exit = create_mod.main(argv=[])
    assert create_exit == 0
    assert manifest_file.exists()

    with open(manifest_file, "r", encoding="utf-8") as f:
        manifest = json.load(f)

    # Validate manifest contents
    assert "resources" in manifest
    resources = manifest["resources"]
    assert len(resources["s3_buckets"]) == 2  # 1 vulnerable, 1 compliant control
    assert len(resources["iam_users"]) == 1
    assert len(resources["iam_policies"]) == 1
    assert len(resources["security_groups"]) == 2  # 1 open-ssh, 1 all-traffic
    assert len(resources["ebs_volumes"]) == 1

    # 2. Execute destroy_vulnerable
    destroy_exit = destroy_mod.main(argv=[])
    assert destroy_exit == 0
    assert not manifest_file.exists()

    # 3. Verify destroy_vulnerable is idempotent when re-run
    re_destroy_exit = destroy_mod.main(argv=[])
    assert re_destroy_exit == 0
