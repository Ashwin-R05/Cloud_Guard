# CloudGuard JSON Report Schema

CloudGuard exports assessment results in a deterministic JSON schema.

## Root Schema Specification

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "title": "CloudGuardScanResult",
  "type": "object",
  "required": [
    "account_id",
    "account_arn",
    "scan_timestamp",
    "severity_counts",
    "total_findings",
    "posture_score",
    "findings"
  ],
  "properties": {
    "account_id": {
      "type": "string",
      "description": "AWS 12-digit account identifier."
    },
    "account_arn": {
      "type": "string",
      "description": "IAM identity ARN that executed the scan."
    },
    "scan_timestamp": {
      "type": "string",
      "format": "date-time",
      "description": "ISO-8601 UTC timestamp when scan completed."
    },
    "posture_score": {
      "type": "number",
      "minimum": 0.0,
      "maximum": 100.0,
      "description": "Overall account security posture score (0.0 to 100.0)."
    },
    "total_findings": {
      "type": "integer",
      "minimum": 0,
      "description": "Total number of findings evaluated."
    },
    "severity_counts": {
      "type": "object",
      "required": ["CRITICAL", "HIGH", "MEDIUM", "LOW", "SKIPPED"],
      "properties": {
        "CRITICAL": { "type": "integer", "minimum": 0 },
        "HIGH": { "type": "integer", "minimum": 0 },
        "MEDIUM": { "type": "integer", "minimum": 0 },
        "LOW": { "type": "integer", "minimum": 0 },
        "SKIPPED": { "type": "integer", "minimum": 0 }
      }
    },
    "findings": {
      "type": "array",
      "items": { "$ref": "#/$defs/Finding" },
      "description": "List of findings sorted descending by risk_score."
    }
  },
  "$defs": {
    "Finding": {
      "type": "object",
      "required": [
        "id",
        "check_id",
        "title",
        "description",
        "resource_id",
        "resource_type",
        "region",
        "severity",
        "risk_score",
        "cis_reference",
        "remediation",
        "status",
        "impact",
        "exposure",
        "exposure_reason"
      ],
      "properties": {
        "id": {
          "type": "string",
          "description": "Unique identifier for this finding instance."
        },
        "check_id": {
          "type": "string",
          "description": "Unique control ID (e.g., S3-01, IAM-01, NET-01)."
        },
        "title": {
          "type": "string",
          "description": "Short descriptive title of the finding."
        },
        "description": {
          "type": "string",
          "description": "Detailed explanation of the misconfiguration or skip reason."
        },
        "resource_id": {
          "type": "string",
          "description": "Identifier of the resource (bucket name, SG ID, user name, etc.)."
        },
        "resource_type": {
          "type": "string",
          "description": "CloudFormation resource type (e.g., AWS::S3::Bucket)."
        },
        "region": {
          "type": "string",
          "description": "AWS region name or 'global'."
        },
        "severity": {
          "type": "string",
          "enum": ["CRITICAL", "HIGH", "MEDIUM", "LOW"],
          "description": "Calculated effective severity classification."
        },
        "risk_score": {
          "type": "number",
          "minimum": 0.0,
          "maximum": 25.0,
          "description": "Computed risk score (impact x exposure, or 0.0 for SKIPPED)."
        },
        "cis_reference": {
          "type": "string",
          "description": "Corresponding CIS Benchmark control title."
        },
        "remediation": {
          "type": "string",
          "description": "Actionable guidance to remediate the issue."
        },
        "status": {
          "type": "string",
          "enum": ["FAIL", "SKIPPED"],
          "description": "Evaluation outcome status."
        },
        "impact": {
          "type": "integer",
          "minimum": 1,
          "maximum": 5,
          "description": "Impact factor (1 to 5) based on check baseline severity."
        },
        "exposure": {
          "type": "integer",
          "minimum": 1,
          "maximum": 5,
          "description": "Exposure factor (1 to 5) based on reachability."
        },
        "exposure_reason": {
          "type": "string",
          "description": "Contextual reason justifying the assigned exposure level."
        }
      }
    }
  }
}
```

## Credential Safety Guarantee
The report schema contains zero credential fields. AWS access keys, secret tokens, session tokens, or password strings are strictly excluded from all scan findings and serialization outputs.

