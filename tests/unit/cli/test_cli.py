"""Tests for CLI module."""

import json
import pytest
from pathlib import Path
from typer.testing import CliRunner

from mass.cli.main import app


runner = CliRunner()


class TestVersionCommand:
    """Tests for version command."""

    def test_version(self):
        """Test version command output."""
        result = runner.invoke(app, ["version"])
        assert result.exit_code == 0
        assert "MASS version" in result.stdout


class TestInfoCommand:
    """Tests for info command."""

    def test_info(self):
        """Test info command output."""
        result = runner.invoke(app, ["info"])
        assert result.exit_code == 0
        assert "System Information" in result.stdout
        assert "Analyzers" in result.stdout


class TestScanCommands:
    """Tests for scan commands."""

    def test_list_profiles(self):
        """Test listing scan profiles."""
        result = runner.invoke(app, ["scan", "list-profiles"])
        assert result.exit_code == 0
        assert "quick" in result.stdout
        assert "standard" in result.stdout
        assert "comprehensive" in result.stdout

    def test_scan_run_nonexistent_path(self):
        """Test scan run with nonexistent path."""
        result = runner.invoke(app, ["scan", "run", "/nonexistent/path"])
        assert result.exit_code == 1
        assert "not found" in result.stdout.lower()


class TestAnalyzeCommands:
    """Tests for analyze commands."""

    def test_analyze_model_nonexistent(self):
        """Test analyze model with nonexistent file."""
        result = runner.invoke(app, ["analyze", "model", "/nonexistent/model.pt"])
        assert result.exit_code == 1
        assert "not found" in result.stdout.lower()

    def test_analyze_context_nonexistent(self):
        """Test analyze context with nonexistent file."""
        result = runner.invoke(app, ["analyze", "context", "/nonexistent/prompt.txt"])
        assert result.exit_code == 1
        assert "not found" in result.stdout.lower()

    def test_analyze_mcp_nonexistent(self):
        """Test analyze mcp with nonexistent file."""
        result = runner.invoke(app, ["analyze", "mcp", "/nonexistent/.mcp.json"])
        assert result.exit_code == 1
        assert "not found" in result.stdout.lower()

    def test_analyze_workflow_nonexistent(self):
        """Test analyze workflow with nonexistent file."""
        result = runner.invoke(app, ["analyze", "workflow", "/nonexistent/workflow.py"])
        assert result.exit_code == 1
        assert "not found" in result.stdout.lower()


class TestComplianceCommands:
    """Tests for compliance commands."""

    def test_list_frameworks(self):
        """Test listing compliance frameworks."""
        result = runner.invoke(app, ["compliance", "frameworks"])
        assert result.exit_code == 0
        assert "owasp_llm" in result.stdout
        assert "mitre_atlas" in result.stdout

    def test_assess_nonexistent_file(self):
        """Test assess with nonexistent findings file."""
        result = runner.invoke(app, ["compliance", "assess", "/nonexistent/findings.json"])
        assert result.exit_code == 1
        assert "not found" in result.stdout.lower()

    def test_assess_findings_file(self, tmp_path):
        """Test assess with valid findings file."""
        # Create test findings file
        findings = [
            {
                "id": "finding-1",
                "title": "Test Finding",
                "description": "A test finding",
                "severity": "high",
                "category": "prompt_injection",
                "component_type": "model",
                "component_name": "test-model",
            }
        ]
        findings_file = tmp_path / "findings.json"
        findings_file.write_text(json.dumps({"findings": findings}))

        result = runner.invoke(app, ["compliance", "assess", str(findings_file)])
        assert result.exit_code == 0
        assert "Compliance" in result.stdout


class TestReportCommands:
    """Tests for report commands."""

    def test_list_formats(self):
        """Test listing report formats."""
        result = runner.invoke(app, ["report", "formats"])
        assert result.exit_code == 0
        assert "sarif" in result.stdout
        assert "html" in result.stdout
        assert "json" in result.stdout

    def test_export_nonexistent_file(self):
        """Test export with nonexistent findings file."""
        result = runner.invoke(app, ["report", "export", "/nonexistent/findings.json"])
        assert result.exit_code == 1
        assert "not found" in result.stdout.lower()

    def test_export_sarif(self, tmp_path):
        """Test exporting SARIF report."""
        # Create test findings file
        findings = [
            {
                "id": "finding-1",
                "title": "Test Finding",
                "description": "A test finding",
                "severity": "high",
                "category": "prompt_injection",
                "component_type": "model",
                "component_name": "test-model",
            }
        ]
        findings_file = tmp_path / "findings.json"
        findings_file.write_text(json.dumps({"findings": findings}))

        output_file = tmp_path / "report.sarif"
        result = runner.invoke(
            app,
            ["report", "export", str(findings_file), "--format", "sarif", "-o", str(output_file)],
        )
        assert result.exit_code == 0
        assert output_file.exists()

    def test_export_html(self, tmp_path):
        """Test exporting HTML report."""
        findings = [
            {
                "id": "finding-1",
                "title": "Test Finding",
                "description": "A test finding",
                "severity": "high",
                "category": "prompt_injection",
                "component_type": "model",
                "component_name": "test-model",
            }
        ]
        findings_file = tmp_path / "findings.json"
        findings_file.write_text(json.dumps({"findings": findings}))

        output_file = tmp_path / "report.html"
        result = runner.invoke(
            app,
            ["report", "export", str(findings_file), "--format", "html", "-o", str(output_file)],
        )
        assert result.exit_code == 0
        assert output_file.exists()

    def test_export_json(self, tmp_path):
        """Test exporting JSON report."""
        findings = [
            {
                "id": "finding-1",
                "title": "Test Finding",
                "description": "A test finding",
                "severity": "high",
                "category": "prompt_injection",
                "component_type": "model",
                "component_name": "test-model",
            }
        ]
        findings_file = tmp_path / "findings.json"
        findings_file.write_text(json.dumps({"findings": findings}))

        output_file = tmp_path / "report.json"
        result = runner.invoke(
            app,
            ["report", "export", str(findings_file), "--format", "json", "-o", str(output_file)],
        )
        assert result.exit_code == 0
        assert output_file.exists()


class TestHelpMessages:
    """Tests for help messages."""

    def test_main_help(self):
        """Test main help message."""
        result = runner.invoke(app, ["--help"])
        assert result.exit_code == 0
        assert "MASS" in result.stdout
        assert "scan" in result.stdout
        assert "analyze" in result.stdout

    def test_scan_help(self):
        """Test scan help message."""
        result = runner.invoke(app, ["scan", "--help"])
        assert result.exit_code == 0
        assert "run" in result.stdout
        assert "list-profiles" in result.stdout

    def test_analyze_help(self):
        """Test analyze help message."""
        result = runner.invoke(app, ["analyze", "--help"])
        assert result.exit_code == 0
        assert "model" in result.stdout
        assert "context" in result.stdout
        assert "mcp" in result.stdout
        assert "workflow" in result.stdout

    def test_compliance_help(self):
        """Test compliance help message."""
        result = runner.invoke(app, ["compliance", "--help"])
        assert result.exit_code == 0
        assert "assess" in result.stdout
        assert "frameworks" in result.stdout

    def test_report_help(self):
        """Test report help message."""
        result = runner.invoke(app, ["report", "--help"])
        assert result.exit_code == 0
        assert "export" in result.stdout
        assert "formats" in result.stdout
