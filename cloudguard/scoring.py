"""Severity-based risk scoring engine for CloudGuard.

Calculates normalized risk scores for individual findings and aggregate
compliance posture scores for evaluated AWS accounts.
"""

from typing import Dict, List
from cloudguard.models import Finding, Severity

# Standard severity-to-weight mapping (0.0 to 10.0 scale)
SEVERITY_WEIGHTS: Dict[Severity, float] = {
    Severity.CRITICAL: 10.0,
    Severity.HIGH: 7.5,
    Severity.MEDIUM: 5.0,
    Severity.LOW: 2.0,
}


def calculate_finding_score(severity: Severity) -> float:
    """Calculate the base risk score for a single finding based on severity.

    Args:
        severity: The severity enum of the finding.

    Returns:
        Float score representing risk weight (0.0 - 10.0).
    """
    return SEVERITY_WEIGHTS.get(severity, 1.0)


def calculate_account_risk_score(findings: List[Finding]) -> float:
    """Calculate an aggregate posture score for a collection of findings.

    Args:
        findings: List of evaluated findings.

    Returns:
        Aggregate numeric score.
    """
    # Stub implementation to be expanded
    if not findings:
        return 0.0
    return sum(f.risk_score for f in findings if f.status == "FAIL")

