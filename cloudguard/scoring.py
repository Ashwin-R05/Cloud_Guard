"""Severity-based risk scoring engine for CloudGuard.

Implements a transparent risk scoring model:
    risk_score = impact x exposure (scale 1 to 25)

Where:
- Impact (1-5) is derived from the check's base severity (Low=2, Medium=3, High=4, Critical=5).
- Exposure (1-5) reflects contextual reachability (e.g. 5 for 0.0.0.0/0 or public buckets,
  3 for internal/default baseline, 2 for unused keys or defense-in-depth).
- The final score maps back to effective severity bands:
    20-25: Critical
    12-19: High
     6-11: Medium
      1-5: Low
"""

from typing import Any, Dict, List, Optional, Tuple
from cloudguard.models import Finding, FindingStatus, Severity

# Base severity to default impact mapping (scale 1-5)
SEVERITY_IMPACT: Dict[Severity, int] = {
    Severity.CRITICAL: 5,
    Severity.HIGH: 4,
    Severity.MEDIUM: 3,
    Severity.LOW: 2,
}


def score_to_severity(score: float | int) -> Severity:
    """Map a numerical risk score (1 to 25) to its severity classification band.

    Bands:
        20 to 25: Critical
        12 to 19: High
         6 to 11: Medium
          1 to 5: Low
    """
    if score >= 20:
        return Severity.CRITICAL
    if score >= 12:
        return Severity.HIGH
    if score >= 6:
        return Severity.MEDIUM
    return Severity.LOW


def calculate_risk(
    base_severity: Severity,
    exposure: Optional[int] = None,
    exposure_reason: Optional[str] = None,
    impact: Optional[int] = None,
) -> Tuple[float, Severity, int, int, str]:
    """Calculate the risk score, effective severity, and breakdown components.

    Args:
        base_severity: The baseline Severity of the finding.
        exposure: Contextual exposure score on 1-5 scale (defaults to 3).
        exposure_reason: Justification for the exposure score.
        impact: Optional override for impact score (1-5 scale).

    Returns:
        Tuple of (risk_score, effective_severity, impact_val, exposure_val, reason_str).
    """
    resolved_impact = impact if impact is not None else SEVERITY_IMPACT.get(base_severity, 3)
    resolved_impact = max(1, min(5, resolved_impact))

    resolved_exposure = exposure if exposure is not None else 3
    resolved_exposure = max(1, min(5, resolved_exposure))

    resolved_reason = exposure_reason or "Standard baseline exposure"

    risk_score = float(resolved_impact * resolved_exposure)
    effective_severity = score_to_severity(risk_score)

    return risk_score, effective_severity, resolved_impact, resolved_exposure, resolved_reason


def calculate_finding_score(severity: Severity) -> float:
    """Calculate baseline risk score for a finding (backward compatibility helper)."""
    score, _, _, _, _ = calculate_risk(severity, exposure=3)
    return score


def calculate_posture_score(findings: List[Finding]) -> float:
    """Calculate the overall account security posture score on a scale from 0.0 to 100.0.

    Formula:
        posture_score = max(0.0, 100.0 - sum(f.risk_score for f in failed_findings))

    A score of 100.0 represents a clean posture with no identified misconfigurations.
    Skipped checks (e.g. AccessDenied) do not deduct from the posture score.
    """
    failed_findings = [f for f in findings if f.status == FindingStatus.FAIL or f.status == "FAIL"]
    if not failed_findings:
        return 100.0

    total_deduction = sum(f.risk_score for f in failed_findings)
    posture = max(0.0, 100.0 - total_deduction)
    return round(posture, 1)


def calculate_account_risk_summary(findings: List[Finding]) -> Dict[str, Any]:
    """Generate an account-level summary of findings, severity counts, and posture score."""
    severity_counts: Dict[str, int] = {
        Severity.CRITICAL.value: 0,
        Severity.HIGH.value: 0,
        Severity.MEDIUM.value: 0,
        Severity.LOW.value: 0,
        FindingStatus.SKIPPED.value: 0,
    }

    for f in findings:
        if f.status == FindingStatus.SKIPPED or f.status == "SKIPPED":
            severity_counts[FindingStatus.SKIPPED.value] += 1
        else:
            sev_key = f.severity.value if isinstance(f.severity, Severity) else str(f.severity)
            severity_counts[sev_key] = severity_counts.get(sev_key, 0) + 1

    posture_score = calculate_posture_score(findings)
    total_risk = sum(f.risk_score for f in findings if f.status == FindingStatus.FAIL or f.status == "FAIL")

    return {
        "total_findings": len(findings),
        "failed_findings": sum(1 for f in findings if f.status == FindingStatus.FAIL or f.status == "FAIL"),
        "skipped_findings": severity_counts[FindingStatus.SKIPPED.value],
        "severity_counts": severity_counts,
        "posture_score": posture_score,
        "total_risk_score": round(total_risk, 1),
    }


# Backward compatibility alias
def calculate_account_risk_score(findings: List[Finding]) -> float:
    """Aggregate risk score of all failed findings."""
    return sum(f.risk_score for f in findings if f.status == FindingStatus.FAIL or f.status == "FAIL")
