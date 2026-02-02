"""Tests for report generation module."""

import json
import pytest
from datetime import datetime
from pathlib import Path

from mass.core.findings import Finding, Evidence, Remediation
from mass.core.types import (
    AttackCategory,
    ComponentType,
    Severity,
)
from mass.reporting.formats.sarif import SarifFormatter
from mass.reporting.formats.html import HtmlFormatter
from mass.reporting.formats.json import JsonFormatter
from mass.reporting.generator import (
    ReportGenerator,
    ReportConfig,
    ReportFormat,
    GeneratedReport,
)


def create_test_finding(
    title: str = "Test Finding",
    severity: Severity = Severity.HIGH,
    category: AttackCategory = AttackCategory.PROMPT_INJECTION,
) -> Finding:
    """Create a test finding."""
    return Finding(
        title=title,
        description="This is a test finding description",
        severity=severity,
        category=category,
        component_type=ComponentType.MODEL,
        component_name="test-model",
        file_path="src/main.py",
        line_number=42,
        cwe_ids=["CWE-74"],
        owasp_ids=["LLM01"],
        mitre_ids=["AML.T0015"],
        evidence=[
            Evidence(
                type="prompt",
                content="Malicious prompt content",
            ),
            Evidence(
                type="response",
                content="Model response",
            ),
        ],
        remediation=Remediation(
            summary="Fix the vulnerability",
            steps=["Step 1", "Step 2"],
            references=["https://example.com"],
        ),
    )


class TestSarifFormatter:
    """Tests for SarifFormatter."""

    def test_formatter_creation(self):
        """Test creating a SARIF formatter."""
        formatter = SarifFormatter()
        assert formatter.tool_name == "MASS"
        assert formatter.tool_version == "0.1.0"

    def test_formatter_custom_tool(self):
        """Test formatter with custom tool info."""
        formatter = SarifFormatter(
            tool_name="CustomTool",
            tool_version="2.0.0",
        )
        assert formatter.tool_name == "CustomTool"

    def test_format_empty_findings(self):
        """Test formatting empty findings list."""
        formatter = SarifFormatter()
        sarif = formatter.format([])

        assert sarif["version"] == "2.1.0"
        assert len(sarif["runs"]) == 1
        assert sarif["runs"][0]["results"] == []

    def test_format_single_finding(self):
        """Test formatting single finding."""
        formatter = SarifFormatter()
        finding = create_test_finding()
        sarif = formatter.format([finding])

        assert len(sarif["runs"][0]["results"]) == 1
        result = sarif["runs"][0]["results"][0]
        assert result["level"] == "error"  # HIGH maps to error
        assert "prompt_injection" in result["ruleId"]

    def test_format_with_scan_id(self):
        """Test formatting with scan ID."""
        formatter = SarifFormatter()
        sarif = formatter.format([], scan_id="test-scan-123")

        assert sarif["runs"][0]["automationDetails"]["id"] == "test-scan-123"

    def test_format_severity_levels(self):
        """Test severity to level mapping."""
        formatter = SarifFormatter()

        severities = [
            (Severity.CRITICAL, "error"),
            (Severity.HIGH, "error"),
            (Severity.MEDIUM, "warning"),
            (Severity.LOW, "note"),
            (Severity.INFO, "note"),
        ]

        for severity, expected_level in severities:
            finding = create_test_finding(severity=severity)
            sarif = formatter.format([finding])
            result = sarif["runs"][0]["results"][0]
            assert result["level"] == expected_level

    def test_format_with_location(self):
        """Test formatting finding with file location."""
        formatter = SarifFormatter()
        finding = create_test_finding()
        sarif = formatter.format([finding])

        result = sarif["runs"][0]["results"][0]
        assert "locations" in result
        location = result["locations"][0]
        assert location["physicalLocation"]["artifactLocation"]["uri"] == "src/main.py"
        assert location["physicalLocation"]["region"]["startLine"] == 42

    def test_format_rules(self):
        """Test rule generation."""
        formatter = SarifFormatter()
        finding = create_test_finding()
        sarif = formatter.format([finding])

        rules = sarif["runs"][0]["tool"]["driver"]["rules"]
        assert len(rules) == 1
        assert rules[0]["id"] == "prompt_injection"

    def test_format_to_string(self):
        """Test formatting to JSON string."""
        formatter = SarifFormatter()
        finding = create_test_finding()
        result = formatter.format_to_string([finding])

        assert isinstance(result, str)
        parsed = json.loads(result)
        assert parsed["version"] == "2.1.0"


class TestHtmlFormatter:
    """Tests for HtmlFormatter."""

    def test_formatter_creation(self):
        """Test creating HTML formatter."""
        formatter = HtmlFormatter()
        assert formatter.title == "MASS Security Report"

    def test_formatter_custom_title(self):
        """Test formatter with custom title."""
        formatter = HtmlFormatter(title="Custom Report")
        assert formatter.title == "Custom Report"

    def test_format_empty_findings(self):
        """Test formatting empty findings list."""
        formatter = HtmlFormatter()
        html = formatter.format([])

        assert "<!DOCTYPE html>" in html
        assert "MASS Security Report" in html
        assert "No findings detected" in html

    def test_format_single_finding(self):
        """Test formatting single finding."""
        formatter = HtmlFormatter()
        finding = create_test_finding()
        html = formatter.format([finding])

        assert finding.title in html
        assert "HIGH" in html
        assert "prompt_injection" in html

    def test_format_with_scan_id(self):
        """Test formatting with scan ID."""
        formatter = HtmlFormatter()
        html = formatter.format([], scan_id="test-scan-123")

        assert "test-scan-123" in html

    def test_format_severity_colors(self):
        """Test severity styling in HTML."""
        formatter = HtmlFormatter()
        finding = create_test_finding(severity=Severity.CRITICAL)
        html = formatter.format([finding])

        assert "severity-critical" in html

    def test_format_findings_table(self):
        """Test findings table generation."""
        formatter = HtmlFormatter()
        findings = [
            create_test_finding(title="Finding 1", severity=Severity.HIGH),
            create_test_finding(title="Finding 2", severity=Severity.MEDIUM),
        ]
        html = formatter.format(findings)

        assert "Finding 1" in html
        assert "Finding 2" in html
        assert "<table>" in html


class TestJsonFormatter:
    """Tests for JsonFormatter."""

    def test_formatter_creation(self):
        """Test creating JSON formatter."""
        formatter = JsonFormatter()
        assert formatter.include_evidence is True

    def test_formatter_options(self):
        """Test formatter with custom options."""
        formatter = JsonFormatter(
            include_evidence=False,
            include_remediation=False,
            pretty=False,
        )
        assert formatter.include_evidence is False
        assert formatter.include_remediation is False

    def test_format_empty_findings(self):
        """Test formatting empty findings list."""
        formatter = JsonFormatter()
        report = formatter.format([])

        assert report["version"] == "1.0"
        assert report["summary"]["total_findings"] == 0
        assert report["findings"] == []

    def test_format_single_finding(self):
        """Test formatting single finding."""
        formatter = JsonFormatter()
        finding = create_test_finding()
        report = formatter.format([finding])

        assert report["summary"]["total_findings"] == 1
        assert len(report["findings"]) == 1

        f = report["findings"][0]
        assert f["title"] == finding.title
        assert f["severity"] == "high"
        assert f["category"] == "prompt_injection"

    def test_format_with_evidence(self):
        """Test formatting includes evidence."""
        formatter = JsonFormatter(include_evidence=True)
        finding = create_test_finding()
        report = formatter.format([finding])

        f = report["findings"][0]
        assert "evidence" in f
        assert len(f["evidence"]) == 2

    def test_format_without_evidence(self):
        """Test formatting excludes evidence when disabled."""
        formatter = JsonFormatter(include_evidence=False)
        finding = create_test_finding()
        report = formatter.format([finding])

        f = report["findings"][0]
        assert "evidence" not in f

    def test_format_with_remediation(self):
        """Test formatting includes remediation."""
        formatter = JsonFormatter(include_remediation=True)
        finding = create_test_finding()
        report = formatter.format([finding])

        f = report["findings"][0]
        assert "remediation" in f
        assert f["remediation"]["summary"] == "Fix the vulnerability"

    def test_format_to_string(self):
        """Test formatting to JSON string."""
        formatter = JsonFormatter()
        finding = create_test_finding()
        result = formatter.format_to_string([finding])

        assert isinstance(result, str)
        parsed = json.loads(result)
        assert "findings" in parsed

    def test_format_findings_only(self):
        """Test formatting findings without wrapper."""
        formatter = JsonFormatter()
        finding = create_test_finding()
        result = formatter.format_findings_only([finding])

        parsed = json.loads(result)
        assert isinstance(parsed, list)
        assert len(parsed) == 1

    def test_format_severity_counts(self):
        """Test severity count in summary."""
        formatter = JsonFormatter()
        findings = [
            create_test_finding(severity=Severity.CRITICAL),
            create_test_finding(severity=Severity.HIGH),
            create_test_finding(severity=Severity.MEDIUM),
            create_test_finding(severity=Severity.LOW),
            create_test_finding(severity=Severity.INFO),
        ]
        report = formatter.format(findings)

        summary = report["summary"]
        assert summary["by_severity"]["critical"] == 1
        assert summary["by_severity"]["high"] == 1
        assert summary["by_severity"]["medium"] == 1
        assert summary["by_severity"]["low"] == 1
        assert summary["by_severity"]["info"] == 1


class TestReportConfig:
    """Tests for ReportConfig."""

    def test_default_config(self):
        """Test default report configuration."""
        config = ReportConfig()
        assert config.title == "MASS Security Report"
        assert config.include_evidence is True
        assert config.pretty_print is True

    def test_custom_config(self):
        """Test custom report configuration."""
        config = ReportConfig(
            title="Custom Report",
            include_evidence=False,
            tool_name="CustomTool",
        )
        assert config.title == "Custom Report"
        assert config.include_evidence is False
        assert config.tool_name == "CustomTool"


class TestGeneratedReport:
    """Tests for GeneratedReport."""

    def test_report_creation(self):
        """Test creating a generated report."""
        report = GeneratedReport(
            format=ReportFormat.JSON,
            content='{"test": true}',
            filename="report.json",
        )
        assert report.format == ReportFormat.JSON
        assert report.filename == "report.json"

    def test_report_save(self, tmp_path):
        """Test saving report to file."""
        report = GeneratedReport(
            format=ReportFormat.JSON,
            content='{"test": true}',
            filename="report.json",
        )
        saved_path = report.save(tmp_path)

        assert saved_path.exists()
        assert saved_path.read_text() == '{"test": true}'

    def test_report_save_with_filename(self, tmp_path):
        """Test saving report with specific filename."""
        report = GeneratedReport(
            format=ReportFormat.JSON,
            content='{"test": true}',
            filename="report.json",
        )
        saved_path = report.save(tmp_path / "custom.json")

        assert saved_path.name == "custom.json"


class TestReportGenerator:
    """Tests for ReportGenerator."""

    def test_generator_creation(self):
        """Test creating a report generator."""
        generator = ReportGenerator()
        assert generator.config.title == "MASS Security Report"

    def test_generator_with_config(self):
        """Test generator with custom config."""
        config = ReportConfig(title="Custom")
        generator = ReportGenerator(config)
        assert generator.config.title == "Custom"

    def test_generate_sarif(self):
        """Test generating SARIF report."""
        generator = ReportGenerator()
        finding = create_test_finding()
        report = generator.generate(ReportFormat.SARIF, [finding])

        assert report.format == ReportFormat.SARIF
        assert ".sarif" in report.filename
        assert "2.1.0" in report.content

    def test_generate_html(self):
        """Test generating HTML report."""
        generator = ReportGenerator()
        finding = create_test_finding()
        report = generator.generate(ReportFormat.HTML, [finding])

        assert report.format == ReportFormat.HTML
        assert ".html" in report.filename
        assert "<!DOCTYPE html>" in report.content

    def test_generate_json(self):
        """Test generating JSON report."""
        generator = ReportGenerator()
        finding = create_test_finding()
        report = generator.generate(ReportFormat.JSON, [finding])

        assert report.format == ReportFormat.JSON
        assert ".json" in report.filename
        parsed = json.loads(report.content)
        assert "findings" in parsed

    def test_generate_all(self):
        """Test generating all report formats."""
        generator = ReportGenerator()
        finding = create_test_finding()
        reports = generator.generate_all([finding])

        assert ReportFormat.SARIF in reports
        assert ReportFormat.HTML in reports
        assert ReportFormat.JSON in reports

    def test_generate_all_custom_formats(self):
        """Test generating specific formats only."""
        generator = ReportGenerator()
        finding = create_test_finding()
        reports = generator.generate_all(
            [finding],
            formats=[ReportFormat.JSON, ReportFormat.SARIF],
        )

        assert len(reports) == 2
        assert ReportFormat.JSON in reports
        assert ReportFormat.SARIF in reports
        assert ReportFormat.HTML not in reports

    def test_save_all(self, tmp_path):
        """Test saving all reports."""
        generator = ReportGenerator()
        finding = create_test_finding()
        reports = generator.generate_all([finding])
        saved = generator.save_all(reports, tmp_path)

        assert len(saved) == 3
        for path in saved.values():
            assert path.exists()

    def test_quick_sarif(self, tmp_path):
        """Test quick SARIF generation."""
        finding = create_test_finding()
        content = ReportGenerator.quick_sarif([finding])

        assert "2.1.0" in content

    def test_quick_sarif_save(self, tmp_path):
        """Test quick SARIF with save."""
        finding = create_test_finding()
        output = tmp_path / "quick.sarif"
        ReportGenerator.quick_sarif([finding], output)

        assert output.exists()

    def test_quick_html(self):
        """Test quick HTML generation."""
        finding = create_test_finding()
        content = ReportGenerator.quick_html([finding])

        assert "<!DOCTYPE html>" in content

    def test_quick_json(self):
        """Test quick JSON generation."""
        finding = create_test_finding()
        content = ReportGenerator.quick_json([finding])

        parsed = json.loads(content)
        assert "findings" in parsed


class TestIntegration:
    """Integration tests for reporting module."""

    def test_full_report_workflow(self, tmp_path):
        """Test complete report generation workflow."""
        # Create diverse findings
        findings = [
            create_test_finding(
                title="Critical Injection",
                severity=Severity.CRITICAL,
            ),
            create_test_finding(
                title="High Risk Issue",
                severity=Severity.HIGH,
            ),
            create_test_finding(
                title="Medium Finding",
                severity=Severity.MEDIUM,
            ),
        ]

        # Generate all reports
        generator = ReportGenerator()
        reports = generator.generate_all(findings, scan_id="test-scan")

        # Verify all formats
        assert len(reports) == 3

        # Save all
        saved = generator.save_all(reports, tmp_path)
        assert all(p.exists() for p in saved.values())

        # Verify SARIF content
        sarif_content = json.loads(reports[ReportFormat.SARIF].content)
        assert len(sarif_content["runs"][0]["results"]) == 3

        # Verify JSON content
        json_content = json.loads(reports[ReportFormat.JSON].content)
        assert json_content["summary"]["total_findings"] == 3
        assert json_content["summary"]["by_severity"]["critical"] == 1

        # Verify HTML content
        html_content = reports[ReportFormat.HTML].content
        assert "Critical Injection" in html_content
        assert "High Risk Issue" in html_content

    def test_report_with_compliance(self):
        """Test report generation with compliance data."""
        from mass.compliance.assessor import ComplianceAssessor
        from mass.core.types import FrameworkType

        findings = [
            create_test_finding(severity=Severity.HIGH),
        ]

        # Generate compliance assessment
        assessor = ComplianceAssessor(frameworks=[FrameworkType.OWASP_LLM])
        compliance_result = assessor.assess(findings)

        # Generate HTML report with compliance
        formatter = HtmlFormatter()
        html = formatter.format(
            findings,
            compliance_result=compliance_result,
        )

        assert "Compliance Assessment" in html
        assert "owasp_llm" in html.lower()
