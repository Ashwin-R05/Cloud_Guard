"""Streamlit interactive dashboard for CloudGuard AWS security posture assessment."""

from datetime import datetime
import json
from typing import Any, Dict, List, Optional
import pandas as pd
import streamlit as st

from cloudguard.checks.registry import discover_checks
from cloudguard.config import Config
from cloudguard.models import Finding, FindingStatus, ScanResult, Severity
from cloudguard.report import ReportGenerator
from cloudguard.scanner import Scanner
from cloudguard.session import CredentialsError, get_session, verify_identity

COMMON_REGIONS = [
    "us-east-1",
    "us-east-2",
    "us-west-1",
    "us-west-2",
    "ca-central-1",
    "eu-west-1",
    "eu-central-1",
    "ap-southeast-1",
    "ap-northeast-1",
    "sa-east-1",
]

MODULE_MAP: Dict[str, str] = {
    "S3": "s3",
    "IAM": "iam",
    "NET": "network",
    "DATA": "data",
    "LOG": "logging",
}


def get_finding_module(check_id: str) -> str:
    """Extract standard module name from a check_id prefix."""
    prefix = check_id.split("-")[0].upper() if "-" in check_id else check_id.upper()
    return MODULE_MAP.get(prefix, prefix.lower())


def render_dashboard() -> None:
    """Render the main Streamlit application layout and reactive components."""
    st.set_page_config(
        page_title="CloudGuard - AWS Security Dashboard",
        page_icon="🛡️",
        layout="wide",
        initial_sidebar_state="expanded",
    )

    # Initialize persistent session state
    if "scan_result" not in st.session_state:
        st.session_state["scan_result"] = None
    if "scan_error" not in st.session_state:
        st.session_state["scan_error"] = None

    # Discover all registered checks
    discovered = discover_checks()
    all_check_ids = sorted(list(discovered.keys()))

    # --- SIDEBAR CONTROLS ---
    with st.sidebar:
        st.title("🛡️ CloudGuard")
        st.caption("Read-only AWS Misconfiguration Scanner")
        st.markdown("---")

        st.subheader("1. Live Scan Configuration")
        config = Config.load()
        default_profile = config.aws_profile or ""
        profile_input = st.text_input(
            "AWS Profile Name",
            value=default_profile,
            help="Named profile from ~/.aws/credentials (leave empty for default credential chain)",
        )
        resolved_profile = profile_input.strip() if profile_input.strip() else None

        # Regions multiselect
        selected_regions = st.multiselect(
            "Target AWS Regions",
            options=COMMON_REGIONS,
            default=config.regions if any(r in COMMON_REGIONS for r in config.regions) else ["us-east-1"],
            help="Select one or more AWS regions to evaluate",
        )

        # Checks multiselect
        selected_checks = st.multiselect(
            "Security Checks to Run",
            options=all_check_ids,
            default=all_check_ids,
            help="Select individual checks or run the full suite",
        )

        # Run Scan Trigger
        if st.button("🚀 Run Security Scan", type="primary", use_container_width=True):
            st.session_state["scan_error"] = None
            if not selected_regions:
                st.error("Please select at least one target region.")
            elif not selected_checks:
                st.error("Please select at least one check to execute.")
            else:
                with st.spinner("Connecting to AWS and evaluating controls..."):
                    try:
                        session = get_session(profile=resolved_profile)
                        verify_identity(session)
                        scanner = Scanner(session=session, regions=selected_regions)
                        result = scanner.scan(check_ids=selected_checks)
                        st.session_state["scan_result"] = result
                        st.success(f"Scan completed successfully for Account {result.account_id}!")
                    except CredentialsError as exc:
                        st.session_state["scan_error"] = f"Authentication Error: {exc}"
                    except Exception as exc:
                        st.session_state["scan_error"] = f"Scan Execution Failed: {type(exc).__name__}: {exc}"

        st.markdown("---")
        st.subheader("2. Load Saved Scan")
        uploaded_file = st.file_uploader(
            "Upload CloudGuard JSON Report",
            type=["json"],
            help="Load a previously generated scan result file for offline inspection",
        )
        if uploaded_file is not None:
            try:
                content = uploaded_file.read().decode("utf-8")
                loaded_result = ReportGenerator.load_from_json(content)
                st.session_state["scan_result"] = loaded_result
                st.session_state["scan_error"] = None
                st.success(f"Loaded assessment for Account {loaded_result.account_id}!")
            except Exception as exc:
                st.error(f"Failed to load JSON file: {exc}")

    # Display error banner if present
    if st.session_state["scan_error"]:
        st.error(st.session_state["scan_error"])

    result: Optional[ScanResult] = st.session_state["scan_result"]

    # --- MAIN VIEW ---
    if result is None:
        st.header("AWS Security Posture Overview")
        st.info(
            "👈 **No scan results loaded yet.**\n\n"
            "Configure your AWS credentials in the sidebar and click **Run Security Scan**, "
            "or upload a previously saved **JSON report** to analyze findings."
        )
        st.markdown(
            """
            ### Evaluated CIS AWS Foundations Benchmark Domains
            - 🗄️ **S3:** Public buckets, default server-side encryption, versioning
            - 🔑 **IAM:** Console users without MFA, wildcard policies, stale access keys, root keys
            - 🌐 **Network:** Remote management ports (22, 3389) open to world, all-traffic open rules
            - 💾 **Data:** Unencrypted EBS volumes, unencrypted or publicly accessible RDS instances
            - 📜 **Logging:** Multi-region CloudTrail auditing and active logging verification
            """
        )
        return

    # Header with Scan Metadata
    st.subheader(f"Security Posture Report &bull; Account: `{result.account_id}`")
    st.caption(f"Evaluated on {result.scan_timestamp} | Caller ARN: `{result.account_arn}`")

    # --- TOP ROW: METRIC CARDS ---
    m_col0, m_col1, m_col2, m_col3, m_col4 = st.columns(5)
    with m_col0:
        st.metric(label="Posture Score", value=f"{result.posture_score:.1f} / 100")
    with m_col1:
        st.metric(label="Critical", value=result.severity_counts.get("CRITICAL", 0))
    with m_col2:
        st.metric(label="High", value=result.severity_counts.get("HIGH", 0))
    with m_col3:
        st.metric(label="Medium", value=result.severity_counts.get("MEDIUM", 0))
    with m_col4:
        st.metric(label="Low", value=result.severity_counts.get("LOW", 0))

    st.markdown("---")

    # Separate failed vs skipped findings
    failed_findings = [f for f in result.findings if f.status == FindingStatus.FAIL or f.status == "FAIL"]
    skipped_findings = [f for f in result.findings if f.status == FindingStatus.SKIPPED or f.status == "SKIPPED"]

    # --- CHARTS ROW ---
    c_col1, c_col2 = st.columns(2)
    with c_col1:
        st.markdown("##### Findings by Severity")
        sev_data = {
            "Critical": result.severity_counts.get("CRITICAL", 0),
            "High": result.severity_counts.get("HIGH", 0),
            "Medium": result.severity_counts.get("MEDIUM", 0),
            "Low": result.severity_counts.get("LOW", 0),
        }
        df_sev = pd.DataFrame(list(sev_data.items()), columns=["Severity", "Count"]).set_index("Severity")
        st.bar_chart(df_sev, height=220, color="#dc2626")

    with c_col2:
        st.markdown("##### Findings by Module")
        mod_counts: Dict[str, int] = {}
        for f in failed_findings:
            mod = get_finding_module(f.check_id).upper()
            mod_counts[mod] = mod_counts.get(mod, 0) + 1
        if not mod_counts:
            st.info("No failed findings to display across modules.")
        else:
            df_mod = pd.DataFrame(list(mod_counts.items()), columns=["Module", "Count"]).set_index("Module")
            st.bar_chart(df_mod, height=220, color="#2563eb")

    st.markdown("---")

    # --- FILTERABLE FINDINGS TABLE ---
    st.markdown("### Findings Explorer")

    # Filter Controls
    f_col1, f_col2, f_col3, f_col4 = st.columns([2, 2, 2, 4])
    with f_col1:
        severity_options = ["All"] + [s.value for s in Severity]
        selected_sev = st.selectbox("Severity Filter", severity_options)
    with f_col2:
        available_modules = ["All"] + sorted(list({get_finding_module(f.check_id) for f in failed_findings}))
        selected_mod = st.selectbox("Module Filter", available_modules)
    with f_col3:
        available_regions = ["All"] + sorted(list({f.region for f in failed_findings}))
        selected_reg = st.selectbox("Region Filter", available_regions)
    with f_col4:
        search_query = st.text_input("🔍 Free-text Search", placeholder="Search title, resource ID, or description...")

    # Apply Filters
    filtered_findings = failed_findings
    if selected_sev != "All":
        filtered_findings = [f for f in filtered_findings if str(f.severity) == selected_sev]
    if selected_mod != "All":
        filtered_findings = [f for f in filtered_findings if get_finding_module(f.check_id) == selected_mod]
    if selected_reg != "All":
        filtered_findings = [f for f in filtered_findings if f.region == selected_reg]
    if search_query.strip():
        q = search_query.strip().lower()
        filtered_findings = [
            f for f in filtered_findings
            if q in f.title.lower()
            or q in f.resource_id.lower()
            or q in f.description.lower()
            or q in f.cis_reference.lower()
            or q in f.check_id.lower()
        ]

    # Convert to Pandas DataFrame for Tabular Display
    if filtered_findings:
        table_rows = []
        for f in filtered_findings:
            table_rows.append({
                "Check ID": f.check_id,
                "Severity": f.severity.value if isinstance(f.severity, Severity) else str(f.severity),
                "Risk Score": f.risk_score,
                "Title": f.title,
                "Module": get_finding_module(f.check_id).upper(),
                "Resource ID": f.resource_id,
                "Resource Type": f.resource_type,
                "Region": f.region,
            })
        df_table = pd.DataFrame(table_rows)
        # Default sort by Risk Score descending
        df_table = df_table.sort_values(by="Risk Score", ascending=False)
        st.dataframe(df_table, use_container_width=True, hide_index=True)
    else:
        st.info("No findings match the current filter criteria.")

    # --- DETAIL PANEL FOR SELECTED FINDING ---
    if filtered_findings:
        st.markdown("#### Finding Detail & Remediation")
        finding_options = {
            f"[{f.severity}] [{f.check_id}] {f.title} ({f.resource_id})": f
            for f in filtered_findings
        }
        chosen_key = st.selectbox("Select a finding to inspect details:", list(finding_options.keys()))
        selected_finding = finding_options[chosen_key]

        d_col1, d_col2 = st.columns([1, 1])
        with d_col1:
            st.markdown(f"**Title:** {selected_finding.title}")
            st.markdown(f"**Resource:** `{selected_finding.resource_type}` &bull; `{selected_finding.resource_id}`")
            st.markdown(f"**Region:** `{selected_finding.region}`")
            st.markdown(f"**CIS Reference:** *{selected_finding.cis_reference}*")
            st.markdown(f"**Description:**\n{selected_finding.description}")

        with d_col2:
            st.markdown("**Risk Score Breakdown:**")
            st.info(
                f"**Impact:** {selected_finding.impact} &times; **Exposure:** {selected_finding.exposure} = "
                f"**Score: {selected_finding.risk_score}**\n\n"
                f"*Exposure Context:* {selected_finding.exposure_reason}"
            )
            st.markdown("**Remediation Guidance:**")
            st.success(selected_finding.remediation)

    # --- SKIPPED CHECKS / COVERAGE GAPS ---
    if skipped_findings:
        st.markdown("---")
        with st.expander(f"⚠️ Check Coverage Gaps & Skipped Evaluations ({len(skipped_findings)})", expanded=False):
            st.caption(
                "Checks skipped due to AWS permissions limitations (AccessDenied) or missing regional service endpoints."
            )
            skipped_rows = []
            for sf in skipped_findings:
                skipped_rows.append({
                    "Check ID": sf.check_id,
                    "Title": sf.title,
                    "Region": sf.region,
                    "Resource / Scope": sf.resource_id,
                    "Reason / Error": sf.description,
                    "Suggested Action": sf.remediation,
                })
            st.dataframe(pd.DataFrame(skipped_rows), use_container_width=True, hide_index=True)

    # --- REPORT DOWNLOAD BUTTONS ---
    st.markdown("---")
    st.markdown("### Export Assessment Reports")
    reporter = ReportGenerator()
    json_bytes = reporter.generate_json(result).encode("utf-8")
    html_bytes = reporter.render_html(result).encode("utf-8")

    dl_col1, dl_col2, _ = st.columns([2, 2, 6])
    with dl_col1:
        st.download_button(
            label="📥 Download JSON Report",
            data=json_bytes,
            file_name=f"cloudguard_report_{result.account_id}.json",
            mime="application/json",
            use_container_width=True,
        )
    with dl_col2:
        st.download_button(
            label="📄 Download HTML Report",
            data=html_bytes,
            file_name=f"cloudguard_report_{result.account_id}.html",
            mime="text/html",
            use_container_width=True,
        )


if __name__ == "__main__":
    render_dashboard()
