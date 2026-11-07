"""Unit tests for the evaluation engine and accuracy benchmarking."""

import json
from pathlib import Path
import pytest
from evaluation.evaluate import (
    PlantedIssue,
    evaluate_scan,
    extract_planted_issues,
    generate_markdown_report,
    main,
)


@pytest.fixture
def sample_manifest_data() -> dict:
    return {
        "created_at": "2026-11-07T12:00:00+00:00",
        "account_id": "123456789012",
        "region": "us-east-1",
        "prefix": "cloudguard-test-sample1",
        "resources": {
            "s3_buckets": [
                {"name": "cloudguard-test-sample1-vuln-bucket", "type": "vulnerable", "region": "us-east-1"},
                {"name": "cloudguard-test-sample1-comp-bucket", "type": "compliant", "region": "us-east-1"},
            ],
            "iam_users": [
                {"name": "cloudguard-test-sample1-console-user", "region": "global"}
            ],
            "iam_policies": [
                {"name": "cloudguard-test-sample1-wildcard-policy", "arn": "arn:aws:iam::123:policy/p", "region": "global"}
            ],
            "security_groups": [
                {"id": "sg-ssh123", "name": "cloudguard-test-sample1-sg-ssh", "type": "open-ssh", "region": "us-east-1"},
                {"id": "sg-all123", "name": "cloudguard-test-sample1-sg-all", "type": "all-traffic", "region": "us-east-1"},
            ],
            "ebs_volumes": [
                {"id": "vol-ebs123", "az": "us-east-1a", "region": "us-east-1"}
            ],
        },
    }


def test_extract_planted_issues(sample_manifest_data):
    """Verify extract_planted_issues extracts all 8 expected planted issues and the control bucket."""
    planted, controls = extract_planted_issues(sample_manifest_data)

    # 3 on S3 + 1 on IAM user + 1 on IAM policy + 2 on SGs + 1 on EBS = 8 planted issues
    assert len(planted) == 8
    assert controls == ["cloudguard-test-sample1-comp-bucket"]

    check_ids = {p.check_id for p in planted}
    assert check_ids == {"S3-01", "S3-02", "S3-03", "IAM-01", "IAM-02", "NET-01", "NET-02", "DATA-01"}


def test_evaluate_scan_perfect_detection(sample_manifest_data):
    """Verify evaluation detects 100% recall with zero false positives on controls."""
    planted, controls = extract_planted_issues(sample_manifest_data)

    # Construct mock scan data that found all 8 planted issues
    findings = []
    for p in planted:
        findings.append({
            "check_id": p.check_id,
            "resource_id": p.resource_id,
            "title": p.title,
            "severity": "HIGH",
            "risk_score": 16.0,
            "status": "FAIL",
        })

    scan_data = {"findings": findings}
    report = evaluate_scan(planted, controls, scan_data)

    assert report.total_planted == 8
    assert len(report.true_positives) == 8
    assert len(report.missed_issues) == 0
    assert len(report.false_positives) == 0
    assert report.detection_rate == 100.0


def test_evaluate_scan_missed_issues_and_false_positives(sample_manifest_data):
    """Verify evaluation records missed issues and control false positives."""
    planted, controls = extract_planted_issues(sample_manifest_data)

    # Scan data only found 6 of the 8, and erroneously flagged the compliant control bucket
    findings = []
    for p in planted[:6]:
        findings.append({
            "check_id": p.check_id,
            "resource_id": p.resource_id,
            "title": p.title,
            "severity": "HIGH",
            "risk_score": 16.0,
            "status": "FAIL",
        })
    # Erroneous false positive finding on control resource
    findings.append({
        "check_id": "S3-01",
        "resource_id": controls[0],
        "title": "False Positive",
        "severity": "CRITICAL",
        "risk_score": 25.0,
        "status": "FAIL",
    })

    scan_data = {"findings": findings}
    report = evaluate_scan(planted, controls, scan_data)

    assert len(report.true_positives) == 6
    assert len(report.missed_issues) == 2
    assert len(report.false_positives) == 1
    assert report.false_positives[0]["resource_id"] == controls[0]
    assert report.detection_rate == 75.0  # 6 / 8 = 75%


def test_generate_markdown_report_comparison(sample_manifest_data):
    """Verify before and after comparison markdown report generation."""
    planted, controls = extract_planted_issues(sample_manifest_data)

    # Before: all 8 detected
    before_findings = [
        {"check_id": p.check_id, "resource_id": p.resource_id, "status": "FAIL"}
        for p in planted
    ]
    before_report = evaluate_scan(planted, controls, {"findings": before_findings}, label="Before")

    # After: all 8 remediated (0 remaining)
    after_findings = []
    after_report = evaluate_scan(planted, controls, {"findings": after_findings}, label="After")

    md = generate_markdown_report(before_report, after_report)

    assert "# CloudGuard Detection Accuracy & Remediation Report" in md
    assert "100.0%" in md
    assert "Remediation Success Rate:" in md
    assert "🛡️ RESOLVED" in md


def test_cli_evaluate_execution(tmp_path: Path, sample_manifest_data):
    """Verify evaluate.py CLI execution end-to-end with files on disk."""
    manifest_file = tmp_path / "manifest.json"
    manifest_file.write_text(json.dumps(sample_manifest_data), encoding="utf-8")

    planted, controls = extract_planted_issues(sample_manifest_data)
    before_file = tmp_path / "scan_before.json"
    before_data = {
        "findings": [{"check_id": p.check_id, "resource_id": p.resource_id, "status": "FAIL"} for p in planted]
    }
    before_file.write_text(json.dumps(before_data), encoding="utf-8")

    after_file = tmp_path / "scan_after.json"
    after_data = {"findings": []}
    after_file.write_text(json.dumps(after_data), encoding="utf-8")

    output_md = tmp_path / "results.md"

    exit_code = main([
        "--manifest", str(manifest_file),
        "--before", str(before_file),
        "--after", str(after_file),
        "--output", str(output_md),
    ])

    assert exit_code == 0
    assert output_md.is_file()
    content = output_md.read_text(encoding="utf-8")
    assert "Detection Performance Summary" in content
    assert "**Remediation Success Rate:** **100.0%**" in content
