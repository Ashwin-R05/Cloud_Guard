"""Network security checks aligned with CIS AWS Foundations Benchmark."""

from typing import Any, Dict, List
import boto3
from botocore.exceptions import ClientError
from cloudguard.checks.base import BaseCheck, is_permission_error
from cloudguard.config import Config
from cloudguard.models import Finding, FindingStatus, Severity
from cloudguard.scoring import calculate_finding_score


def is_cidr_world_accessible(rule: Dict[str, Any]) -> bool:
    """Check if rule CIDR ranges include 0.0.0.0/0 or ::/0."""
    has_ipv4_world = any(r.get("CidrIp") == "0.0.0.0/0" for r in rule.get("IpRanges", []))
    has_ipv6_world = any(r.get("CidrIpv6") == "::/0" for r in rule.get("Ipv6Ranges", []))
    return has_ipv4_world or has_ipv6_world


def rule_covers_management_ports(rule: Dict[str, Any]) -> List[str]:
    """Check if rule covers port 22 (SSH) or port 3389 (RDP) from the world.

    Handles specific port ranges, individual ports, and all-protocol (-1) rules.
    """
    if not is_cidr_world_accessible(rule):
        return []

    protocol = str(rule.get("IpProtocol", "")).lower()
    from_port = rule.get("FromPort")
    to_port = rule.get("ToPort")

    flagged_ports: List[str] = []

    # Protocol -1 (all protocols) covers all ports including 22 and 3389
    if protocol == "-1":
        flagged_ports.extend(["SSH (port 22)", "RDP (port 3389)"])
    elif protocol == "tcp":
        if from_port is not None and to_port is not None:
            if from_port <= 22 <= to_port:
                flagged_ports.append("SSH (port 22)")
            if from_port <= 3389 <= to_port:
                flagged_ports.append("RDP (port 3389)")

    return flagged_ports


def rule_covers_all_traffic(rule: Dict[str, Any]) -> bool:
    """Check if rule allows all traffic (all protocols and ports) from the world."""
    if not is_cidr_world_accessible(rule):
        return False

    protocol = str(rule.get("IpProtocol", "")).lower()
    return protocol == "-1"


class OpenManagementPortsCheck(BaseCheck):
    """NET-01: Ensure no security groups allow ingress from 0.0.0.0/0 or ::/0 to port 22 or 3389."""

    check_id = "NET-01"
    title = "Security group allows unrestricted ingress on SSH (port 22) or RDP (port 3389)"
    module = "network"
    base_severity = Severity.HIGH
    cis_reference = "Ensure no security groups allow ingress from 0.0.0.0/0 to remote management ports (22, 3389)"

    def run(self, session: boto3.Session, regions: List[str]) -> List[Finding]:
        findings: List[Finding] = []
        target_regions = regions if regions else Config.load().regions

        for region in target_regions:
            try:
                ec2 = session.client("ec2", region_name=region)
                paginator = ec2.get_paginator("describe_security_groups")

                for page in paginator.paginate():
                    for sg in page.get("SecurityGroups", []):
                        sg_id = sg.get("GroupId", "")
                        sg_name = sg.get("GroupName", "")
                        ip_permissions = sg.get("IpPermissions", [])

                        exposed_services: List[str] = []
                        for rule in ip_permissions:
                            services = rule_covers_management_ports(rule)
                            for s in services:
                                if s not in exposed_services:
                                    exposed_services.append(s)

                        if exposed_services:
                            services_str = ", ".join(exposed_services)
                            findings.append(
                                Finding(
                                    id=f"{self.check_id}-{region}-{sg_id}",
                                    check_id=self.check_id,
                                    title=self.title,
                                    description=(
                                        f"Security group '{sg_name}' ({sg_id}) in region '{region}' allows "
                                        f"unrestricted inbound access from 0.0.0.0/0 or ::/0 to {services_str}."
                                    ),
                                    resource_id=sg_id,
                                    resource_type="AWS::EC2::SecurityGroup",
                                    region=region,
                                    severity=self.base_severity,
                                    risk_score=calculate_finding_score(self.base_severity),
                                    cis_reference=self.cis_reference,
                                    remediation=(
                                        f"Modify security group '{sg_id}' to remove 0.0.0.0/0 and ::/0 from "
                                        "inbound rules for ports 22 and 3389, and restrict access to authorized CIDR blocks."
                                    ),
                                    status=FindingStatus.FAIL,
                                )
                            )
            except ClientError as exc:
                if is_permission_error(exc):
                    findings.append(
                        self.handle_client_error(
                            exc,
                            resource_id=f"security-groups-{region}",
                            resource_type="AWS::EC2::SecurityGroup",
                            region=region,
                        )
                    )
                else:
                    reason = f"Check skipped for region '{region}' due to AWS error: {exc}"
                    findings.append(
                        self.create_skipped_finding(
                            reason=reason,
                            resource_id=f"security-groups-{region}",
                            resource_type="AWS::EC2::SecurityGroup",
                            region=region,
                        )
                    )
            except Exception as exc:
                reason = f"Check skipped for region '{region}' due to unexpected error: {exc}"
                findings.append(
                    self.create_skipped_finding(
                        reason=reason,
                        resource_id=f"security-groups-{region}",
                        resource_type="AWS::EC2::SecurityGroup",
                        region=region,
                    )
                )

        return findings


class AllTrafficOpenCheck(BaseCheck):
    """NET-02: Ensure no security groups allow unrestricted all-traffic ingress from 0.0.0.0/0 or ::/0."""

    check_id = "NET-02"
    title = "Security group allows all ingress traffic from the world (0.0.0.0/0 or ::/0)"
    module = "network"
    base_severity = Severity.CRITICAL
    cis_reference = "Ensure no security groups allow unrestricted ingress for all protocols and ports"

    def run(self, session: boto3.Session, regions: List[str]) -> List[Finding]:
        findings: List[Finding] = []
        target_regions = regions if regions else Config.load().regions

        for region in target_regions:
            try:
                ec2 = session.client("ec2", region_name=region)
                paginator = ec2.get_paginator("describe_security_groups")

                for page in paginator.paginate():
                    for sg in page.get("SecurityGroups", []):
                        sg_id = sg.get("GroupId", "")
                        sg_name = sg.get("GroupName", "")
                        ip_permissions = sg.get("IpPermissions", [])

                        allows_all = any(rule_covers_all_traffic(rule) for rule in ip_permissions)

                        if allows_all:
                            findings.append(
                                Finding(
                                    id=f"{self.check_id}-{region}-{sg_id}",
                                    check_id=self.check_id,
                                    title=self.title,
                                    description=(
                                        f"Security group '{sg_name}' ({sg_id}) in region '{region}' allows "
                                        "unrestricted inbound access for all protocols and ports (-1) from 0.0.0.0/0 or ::/0."
                                    ),
                                    resource_id=sg_id,
                                    resource_type="AWS::EC2::SecurityGroup",
                                    region=region,
                                    severity=self.base_severity,
                                    risk_score=calculate_finding_score(self.base_severity),
                                    cis_reference=self.cis_reference,
                                    remediation=(
                                        f"Remove the all-traffic (-1) ingress rule from security group '{sg_id}' "
                                        "and specify only the explicitly required protocols, ports, and source CIDRs."
                                    ),
                                    status=FindingStatus.FAIL,
                                )
                            )
            except ClientError as exc:
                if is_permission_error(exc):
                    findings.append(
                        self.handle_client_error(
                            exc,
                            resource_id=f"security-groups-{region}",
                            resource_type="AWS::EC2::SecurityGroup",
                            region=region,
                        )
                    )
                else:
                    reason = f"Check skipped for region '{region}' due to AWS error: {exc}"
                    findings.append(
                        self.create_skipped_finding(
                            reason=reason,
                            resource_id=f"security-groups-{region}",
                            resource_type="AWS::EC2::SecurityGroup",
                            region=region,
                        )
                    )
            except Exception as exc:
                reason = f"Check skipped for region '{region}' due to unexpected error: {exc}"
                findings.append(
                    self.create_skipped_finding(
                        reason=reason,
                        resource_id=f"security-groups-{region}",
                        resource_type="AWS::EC2::SecurityGroup",
                        region=region,
                    )
                )

        return findings

