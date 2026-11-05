"""HTML and file report generation using Jinja2 templates."""

from pathlib import Path
from typing import Any, Dict, List
from jinja2 import Environment, FileSystemLoader
from cloudguard.models import Finding


class ReportGenerator:
    """Renders structured assessment results into human-readable HTML reports."""

    def __init__(self, template_dir: str = "templates"):
        """Initialize Jinja2 environment."""
        self.template_dir = Path(template_dir)
        self.env = Environment(
            loader=FileSystemLoader(str(self.template_dir)),
            autoescape=True,
        )

    def render_html(self, findings: List[Finding], metadata: Dict[str, Any]) -> str:
        """Render findings to an HTML string using report.html.j2 template.

        Args:
            findings: List of scan findings.
            metadata: Additional run metadata (account id, timestamp, summary stats).

        Returns:
            Rendered HTML content.
        """
        template = self.env.get_template("report.html.j2")
        return template.render(findings=findings, metadata=metadata)

    def save_report(self, html_content: str, output_path: str) -> None:
        """Write rendered HTML report to the specified file path."""
        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(html_content, encoding="utf-8")

