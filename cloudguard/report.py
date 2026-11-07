"""HTML and JSON assessment report generation."""

from datetime import datetime, timezone
import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Union
from jinja2 import Environment, FileSystemLoader, select_autoescape
from cloudguard.models import Finding, ScanResult


class ReportGenerator:
    """Renders structured assessment results into human-readable HTML and JSON reports."""

    def __init__(self, template_dir: Union[str, Path] = "templates"):
        """Initialize Jinja2 environment."""
        self.template_dir = Path(template_dir)
        self.env = Environment(
            loader=FileSystemLoader(str(self.template_dir)),
            autoescape=select_autoescape(["html", "xml"]),
        )

    def render_html(
        self,
        result: Union[ScanResult, List[Finding]],
        metadata: Optional[Dict[str, Any]] = None,
    ) -> str:
        """Render assessment findings into a self-contained HTML document.

        Args:
            result: Either a ScanResult instance or a list of Finding objects.
            metadata: Optional dictionary of metadata if result is a list of findings.

        Returns:
            Rendered self-contained HTML content.
        """
        if isinstance(result, ScanResult):
            scan_result = result
        else:
            meta = metadata or {}
            scan_result = ScanResult(
                account_id=meta.get("account_id", "N/A"),
                account_arn=meta.get("account_arn", "N/A"),
                scan_timestamp=meta.get("timestamp", datetime.now(timezone.utc).isoformat()),
                findings=result,
                severity_counts=meta.get("severity_counts", {}),
                total_findings=len(result),
                posture_score=meta.get("posture_score", 100.0),
            )

        # Sort findings descending by risk score
        sorted_findings = sorted(scan_result.findings, key=lambda f: f.risk_score, reverse=True)
        # Create a display copy with sorted findings
        display_result = ScanResult(
            account_id=scan_result.account_id,
            account_arn=scan_result.account_arn,
            scan_timestamp=scan_result.scan_timestamp,
            findings=sorted_findings,
            severity_counts=scan_result.severity_counts,
            total_findings=scan_result.total_findings,
            posture_score=scan_result.posture_score,
        )

        template = self.env.get_template("report.html.j2")
        return template.render(result=display_result, findings=sorted_findings, metadata=metadata or {})

    def generate_json(self, result: ScanResult) -> str:
        """Generate structured JSON string from ScanResult adhering to schema.md.

        Findings are sorted descending by risk score. Never includes credentials.
        """
        data = result.to_dict()
        # Sort findings descending by risk score
        data["findings"] = sorted(data["findings"], key=lambda f: f.get("risk_score", 0.0), reverse=True)
        return json.dumps(data, indent=2)

    def save_html_report(self, result: ScanResult, output_path: Union[str, Path]) -> str:
        """Render and save HTML report to file."""
        html_content = self.render_html(result)
        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(html_content, encoding="utf-8")
        return str(path.resolve())

    def save_json_report(self, result: ScanResult, output_path: Union[str, Path]) -> str:
        """Serialize and save JSON report to file."""
        json_content = self.generate_json(result)
        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json_content, encoding="utf-8")
        return str(path.resolve())

    def generate_reports(
        self,
        result: ScanResult,
        output_dir: Union[str, Path] = "reports",
        fmt: str = "both",
    ) -> Dict[str, str]:
        """Generate timestamped assessment reports in HTML and/or JSON format.

        Args:
            result: The completed ScanResult.
            output_dir: Destination folder.
            fmt: One of 'json', 'html', or 'both'.

        Returns:
            Dictionary mapping format keys to absolute file paths on disk.
        """
        out_path = Path(output_dir)
        out_path.mkdir(parents=True, exist_ok=True)

        # Standard clean timestamp for filenames: YYYYMMDD_HHMMSS
        clean_ts = (
            result.scan_timestamp.replace("-", "").replace(":", "").replace(".", "_")[:15]
            if result.scan_timestamp
            else datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        )
        base_name = f"cloudguard_report_{result.account_id}_{clean_ts}"

        created_files: Dict[str, str] = {}

        if fmt in ("json", "both"):
            json_file = out_path / f"{base_name}.json"
            created_files["json"] = self.save_json_report(result, json_file)

        if fmt in ("html", "both"):
            html_file = out_path / f"{base_name}.html"
            created_files["html"] = self.save_html_report(result, html_file)

        return created_files
