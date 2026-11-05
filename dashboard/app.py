"""Streamlit interactive dashboard for CloudGuard scan results and posture visualization."""

import streamlit as st


def render_dashboard() -> None:
    """Render the main Streamlit application layout."""
    st.set_page_config(
        page_title="CloudGuard - AWS Security Posture Dashboard",
        page_icon="🛡️",
        layout="wide",
    )

    st.title("🛡️ CloudGuard Security Posture Dashboard")
    st.markdown(
        """
        **CloudGuard** is a read-only AWS misconfiguration scanner evaluating infrastructure
        against selected CIS AWS Foundations Benchmark controls.
        """
    )

    st.info("Scanner initialized. Run a scan via the CLI or select options in the sidebar to view findings.")


if __name__ == "__main__":
    render_dashboard()

