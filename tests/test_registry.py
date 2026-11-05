"""Unit tests for check registry and auto-discovery."""

from typing import List
import boto3
import pytest
from cloudguard.checks.base import BaseCheck
from cloudguard.checks.registry import (
    clear_registry,
    discover_checks,
    get_all_checks,
    get_check,
    register_check,
)
from cloudguard.models import Finding, Severity


@pytest.fixture(autouse=True)
def reset_registry():
    """Reset registry before and after each test."""
    clear_registry()
    yield
    clear_registry()


class SampleCheckA(BaseCheck):
    check_id = "SAMPLE_A"
    title = "Sample Check A"
    module = "iam"
    base_severity = Severity.CRITICAL
    cis_reference = "CIS 1.1 Sample"

    def run(self, session: boto3.Session, regions: List[str]) -> List[Finding]:
        return []


class SampleCheckB(BaseCheck):
    check_id = "SAMPLE_B"
    title = "Sample Check B"
    module = "s3"
    base_severity = Severity.MEDIUM
    cis_reference = "CIS 2.1 Sample"

    def run(self, session: boto3.Session, regions: List[str]) -> List[Finding]:
        return []


def test_register_and_get_check():
    """Verify explicit registration and lookup."""
    register_check(SampleCheckA)
    assert get_check("SAMPLE_A") is SampleCheckA
    assert get_check("NON_EXISTENT") is None


def test_get_all_checks():
    """Verify get_all_checks lists registered checks."""
    register_check(SampleCheckA)
    register_check(SampleCheckB)
    all_checks = get_all_checks()
    assert SampleCheckA in all_checks
    assert SampleCheckB in all_checks
    assert len(all_checks) >= 2


def test_register_invalid_class():
    """Verify register_check rejects non-BaseCheck classes."""
    class NotACheck:
        pass

    with pytest.raises(TypeError):
        register_check(NotACheck)  # type: ignore


def test_discover_checks_auto_finds_subclasses():
    """Verify discover_checks automatically discovers concrete subclasses."""
    clear_registry()
    discovered = discover_checks("tests.test_registry")
    # SampleCheckA and SampleCheckB are in tests.test_registry
    assert "SAMPLE_A" in discovered
    assert "SAMPLE_B" in discovered
    assert discovered["SAMPLE_A"] is SampleCheckA
