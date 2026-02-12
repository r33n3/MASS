"""Report generator module.

The ReportGenerator orchestrates report generation across
multiple formats (SARIF, HTML, JSON, PDF).
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any

from mass.core.findings import Finding
from mass.compliance.assessor import AssessmentResult
from mass.orchestration.service import ScanResult
from mass.reporting.formats.sarif import SarifFormatter
from mass.reporting.formats.html import HtmlFormatter
from mass.reporting.formats.json import JsonFormatter


class ReportFormat(str, Enum):
    """Available report formats."""

    SARIF = "sarif"
    HTML = "html"
    JSON = "json"
    PDF = "pdf"  # Placeholder for future PDF support


@dataclass
class ReportConfig:
    """Configuration for report generation."""

    title: str = "MASS Security Report"
    include_evidence: bool = True
    include_remediation: bool = True
    include_compliance: bool = True
    include_charts: bool = True
    pretty_print: bool = True

    # SARIF-specific
    tool_name: str = "MASS"
    tool_version: str = "0.1.0"
    tool_uri: str = "https://github.com/r33n3/MASS"


@dataclass
class GeneratedReport:
    """A generated report."""

    format: ReportFormat
    content: str | bytes
    filename: str
    generated_at: datetime = field(default_factory=datetime.utcnow)
    size_bytes: int = 0
    metadata: dict[str, Any] = field(default_factory=dict)

    def save(self, path: str | Path) -> Path:
        """Save report to file.

        Args:
            path: Directory or file path to save to.

        Returns:
            Path to saved file.
        """
        path = Path(path)

        if path.is_dir():
            path = path / self.filename

        if isinstance(self.content, bytes):
            path.write_bytes(self.content)
        else:
            path.write_text(self.content, encoding="utf-8")

        return path


class ReportGenerator:
    """Generates security reports in multiple formats.

    The generator creates reports from scan findings,
    optionally including compliance assessments and
    other metadata.
    """

    def __init__(self, config: ReportConfig | None = None) -> None:
        """Initialize the report generator.

        Args:
            config: Report configuration.
        """
        self.config = config or ReportConfig()

        # Initialize formatters
        self._sarif = SarifFormatter(
            tool_name=self.config.tool_name,
            tool_version=self.config.tool_version,
            tool_uri=self.config.tool_uri,
        )
        self._html = HtmlFormatter(
            title=self.config.title,
            include_charts=self.config.include_charts,
        )
        self._json = JsonFormatter(
            include_evidence=self.config.include_evidence,
            include_remediation=self.config.include_remediation,
            pretty=self.config.pretty_print,
        )

    def generate(
        self,
        format: ReportFormat,
        findings: list[Finding],
        scan_id: str = "",
        scan_result: ScanResult | None = None,
        compliance_result: AssessmentResult | None = None,
        metadata: dict[str, Any] | None = None,
        verdict: dict[str, Any] | None = None,
        threat_model: dict[str, Any] | None = None,
        report_type: str = "security",
        ai_summary: str | None = None,
    ) -> GeneratedReport:
        """Generate a report in the specified format.

        Args:
            format: Report format.
            findings: List of security findings.
            scan_id: Optional scan ID.
            scan_result: Optional scan result.
            compliance_result: Optional compliance assessment.
            metadata: Optional additional metadata.
            verdict: Optional Final Verdict Judge assessment.
            threat_model: Optional STRIDE-AI threat model.
            report_type: Report type: security, compliance, executive.
            ai_summary: Optional AI-generated project overview.

        Returns:
            GeneratedReport with content.
        """
        scan_id = scan_id or (scan_result.scan_id if scan_result else "")
        timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")

        if format == ReportFormat.SARIF:
            content = self._sarif.format_to_string(findings, scan_id)
            filename = f"mass_report_{timestamp}.sarif"
        elif format == ReportFormat.HTML:
            content = self._html.format(
                findings, scan_id, compliance_result, metadata,
                verdict=verdict, threat_model=threat_model,
                report_type=report_type,
                ai_summary=ai_summary,
            )
            filename = f"mass_report_{timestamp}.html"
        elif format == ReportFormat.JSON:
            content = self._json.format_to_string(
                findings, scan_id, scan_result, compliance_result, metadata,
                verdict=verdict, threat_model=threat_model,
            )
            filename = f"mass_report_{timestamp}.json"
        elif format == ReportFormat.PDF:
            # PDF generation placeholder
            content = self._generate_pdf_placeholder(findings)
            filename = f"mass_report_{timestamp}.pdf"
        else:
            raise ValueError(f"Unsupported format: {format}")

        report = GeneratedReport(
            format=format,
            content=content,
            filename=filename,
            size_bytes=len(content.encode() if isinstance(content, str) else content),
            metadata={
                "scan_id": scan_id,
                "findings_count": len(findings),
                "format": format.value,
            },
        )

        return report

    def generate_all(
        self,
        findings: list[Finding],
        scan_id: str = "",
        scan_result: ScanResult | None = None,
        compliance_result: AssessmentResult | None = None,
        metadata: dict[str, Any] | None = None,
        formats: list[ReportFormat] | None = None,
    ) -> dict[ReportFormat, GeneratedReport]:
        """Generate reports in all specified formats.

        Args:
            findings: List of security findings.
            scan_id: Optional scan ID.
            scan_result: Optional scan result.
            compliance_result: Optional compliance assessment.
            metadata: Optional additional metadata.
            formats: Formats to generate. Defaults to SARIF, HTML, JSON.

        Returns:
            Dictionary mapping format to GeneratedReport.
        """
        if formats is None:
            formats = [ReportFormat.SARIF, ReportFormat.HTML, ReportFormat.JSON]

        reports = {}
        for fmt in formats:
            reports[fmt] = self.generate(
                fmt, findings, scan_id, scan_result, compliance_result, metadata
            )

        return reports

    def save_all(
        self,
        reports: dict[ReportFormat, GeneratedReport],
        output_dir: str | Path,
    ) -> dict[ReportFormat, Path]:
        """Save all reports to a directory.

        Args:
            reports: Generated reports.
            output_dir: Directory to save reports.

        Returns:
            Dictionary mapping format to saved file path.
        """
        output_dir = Path(output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)

        saved = {}
        for fmt, report in reports.items():
            saved[fmt] = report.save(output_dir)

        return saved

    def _generate_pdf_placeholder(self, findings: list[Finding]) -> bytes:
        """Generate PDF placeholder.

        Note: Full PDF generation would require reportlab or similar library.
        This is a placeholder that returns empty bytes.
        """
        # In a full implementation, this would use reportlab or weasyprint
        # to generate a proper PDF from the HTML content
        return b"%PDF-1.4\n% MASS Security Report (PDF generation not implemented)\n"

    @staticmethod
    def from_scan_result(
        scan_result: ScanResult,
        format: ReportFormat = ReportFormat.JSON,
        config: ReportConfig | None = None,
    ) -> GeneratedReport:
        """Convenience method to generate report from scan result.

        Args:
            scan_result: Completed scan result.
            format: Report format.
            config: Optional report configuration.

        Returns:
            GeneratedReport.
        """
        generator = ReportGenerator(config)
        return generator.generate(
            format=format,
            findings=scan_result.findings,
            scan_id=scan_result.scan_id,
            scan_result=scan_result,
        )

    @staticmethod
    def quick_sarif(
        findings: list[Finding],
        output_path: str | Path | None = None,
    ) -> str:
        """Quick SARIF report generation.

        Args:
            findings: List of findings.
            output_path: Optional path to save report.

        Returns:
            SARIF JSON string.
        """
        formatter = SarifFormatter()
        content = formatter.format_to_string(findings)

        if output_path:
            Path(output_path).write_text(content, encoding="utf-8")

        return content

    @staticmethod
    def quick_html(
        findings: list[Finding],
        output_path: str | Path | None = None,
        title: str = "MASS Security Report",
    ) -> str:
        """Quick HTML report generation.

        Args:
            findings: List of findings.
            output_path: Optional path to save report.
            title: Report title.

        Returns:
            HTML string.
        """
        formatter = HtmlFormatter(title=title)
        content = formatter.format(findings)

        if output_path:
            Path(output_path).write_text(content, encoding="utf-8")

        return content

    @staticmethod
    def quick_json(
        findings: list[Finding],
        output_path: str | Path | None = None,
    ) -> str:
        """Quick JSON report generation.

        Args:
            findings: List of findings.
            output_path: Optional path to save report.

        Returns:
            JSON string.
        """
        formatter = JsonFormatter()
        content = formatter.format_to_string(findings)

        if output_path:
            Path(output_path).write_text(content, encoding="utf-8")

        return content
