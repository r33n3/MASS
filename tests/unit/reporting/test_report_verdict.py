"""Tests for verdict and threat model integration in reports."""

import json
import pytest

from mass.core.findings import Finding
from mass.core.types import AttackCategory, ComponentType, Severity
from mass.reporting.generator import ReportGenerator, ReportConfig, ReportFormat
from mass.reporting.formats.json import JsonFormatter
from mass.reporting.formats.html import HtmlFormatter


def _sample_findings():
    """Create sample findings for report testing."""
    return [
        Finding(
            id="f-001",
            title="Hardcoded API Key",
            description="API key found in source code",
            severity=Severity.HIGH,
            category=AttackCategory.SENSITIVE_INFO,
            component_type=ComponentType.MODEL,
            component_name="config.py",
        ),
    ]


def _sample_verdict():
    """Create sample verdict data."""
    return {
        "risk_level": "high",
        "confidence": 0.85,
        "overall_assessment": "Significant security risks identified",
        "executive_summary": "This deployment has several critical vulnerabilities.",
        "narrative": "Detailed analysis shows prompt injection and data leakage risks.",
        "key_themes": ["prompt_injection", "data_leakage", "api_exposure"],
        "attack_chains": [
            {
                "name": "Prompt to Data Exfiltration",
                "severity": "critical",
                "steps": ["Inject prompt", "Override instructions", "Exfiltrate data"],
            },
        ],
        "recommendations": [
            {
                "title": "Implement input sanitization",
                "priority": "high",
                "description": "Sanitize user inputs before prompt construction",
            },
            {
                "title": "Add output filtering",
                "priority": "medium",
                "description": "Filter model outputs for sensitive data patterns",
            },
        ],
    }


def _sample_threat_model():
    """Create sample threat model data."""
    return {
        "name": "test-model",
        "deployment_name": "test-deployment",
        "overall_risk_level": "high",
        "data_classification": "confidential",
        "phases_completed": ["discovery", "static_analysis", "judge_verdict"],
        "threat_counts_by_stride": {
            "prompt_injection": 3,
            "data_exfiltration": 2,
            "jailbreak": 1,
        },
        "threat_counts_by_severity": {
            "critical": 2,
            "high": 3,
            "medium": 1,
        },
        "threats": [
            {
                "id": "T-001",
                "stride_category": "prompt_injection",
                "title": "User Input Prompt Injection",
                "description": "User input concatenated into prompts",
                "severity": "critical",
                "likelihood": 0.8,
                "impact": 0.9,
                "risk_score": 0.72,
            },
            {
                "id": "T-002",
                "stride_category": "data_exfiltration",
                "title": "System Prompt Leakage",
                "description": "System prompt can be extracted",
                "severity": "high",
                "likelihood": 0.6,
                "impact": 0.7,
                "risk_score": 0.42,
            },
        ],
        "recommended_mitigations": [
            {
                "title": "Input Sanitization",
                "description": "Sanitize all user inputs",
            },
        ],
        "top_risks": ["T-001", "T-002"],
    }


class TestJsonReportVerdict:
    """Tests for verdict/threat model in JSON reports."""

    def test_verdict_included_in_json(self):
        formatter = JsonFormatter()
        report = formatter.format(
            findings=_sample_findings(),
            scan_id="test-scan",
            verdict=_sample_verdict(),
        )
        assert "verdict" in report
        assert report["verdict"]["risk_level"] == "high"
        assert report["verdict"]["confidence"] == 0.85

    def test_threat_model_included_in_json(self):
        formatter = JsonFormatter()
        report = formatter.format(
            findings=_sample_findings(),
            scan_id="test-scan",
            threat_model=_sample_threat_model(),
        )
        assert "threat_model" in report
        assert report["threat_model"]["overall_risk_level"] == "high"
        assert len(report["threat_model"]["threats"]) == 2

    def test_both_included(self):
        formatter = JsonFormatter()
        report = formatter.format(
            findings=_sample_findings(),
            verdict=_sample_verdict(),
            threat_model=_sample_threat_model(),
        )
        assert "verdict" in report
        assert "threat_model" in report

    def test_none_when_not_provided(self):
        formatter = JsonFormatter()
        report = formatter.format(findings=_sample_findings())
        assert "verdict" not in report
        assert "threat_model" not in report

    def test_format_to_string_includes_verdict(self):
        formatter = JsonFormatter()
        json_str = formatter.format_to_string(
            findings=_sample_findings(),
            verdict=_sample_verdict(),
            threat_model=_sample_threat_model(),
        )
        parsed = json.loads(json_str)
        assert "verdict" in parsed
        assert "threat_model" in parsed


class TestHtmlReportVerdict:
    """Tests for verdict/threat model in HTML reports."""

    def test_verdict_section_in_html(self):
        formatter = HtmlFormatter()
        html = formatter.format(
            findings=_sample_findings(),
            verdict=_sample_verdict(),
        )
        assert "Security Verdict" in html
        assert "HIGH" in html
        assert "Significant security risks" in html

    def test_threat_model_section_in_html(self):
        formatter = HtmlFormatter()
        html = formatter.format(
            findings=_sample_findings(),
            threat_model=_sample_threat_model(),
        )
        assert "STRIDE-AI Threat Model" in html
        assert "CONFIDENTIAL" in html
        assert "prompt_injection" in html

    def test_attack_chains_in_html(self):
        formatter = HtmlFormatter()
        html = formatter.format(
            findings=_sample_findings(),
            verdict=_sample_verdict(),
        )
        assert "Attack Chains" in html
        assert "Prompt to Data Exfiltration" in html

    def test_recommendations_in_html(self):
        formatter = HtmlFormatter()
        html = formatter.format(
            findings=_sample_findings(),
            verdict=_sample_verdict(),
        )
        assert "Recommendations" in html
        assert "input sanitization" in html

    def test_no_sections_when_not_provided(self):
        formatter = HtmlFormatter()
        html = formatter.format(findings=_sample_findings())
        assert "Security Verdict" not in html
        assert "STRIDE-AI Threat Model" not in html


class TestReportGeneratorIntegration:
    """Tests for ReportGenerator passing verdict/threat_model through."""

    def test_json_generator(self):
        generator = ReportGenerator()
        report = generator.generate(
            format=ReportFormat.JSON,
            findings=_sample_findings(),
            scan_id="test",
            verdict=_sample_verdict(),
            threat_model=_sample_threat_model(),
        )
        parsed = json.loads(report.content)
        assert "verdict" in parsed
        assert "threat_model" in parsed

    def test_html_generator(self):
        generator = ReportGenerator()
        report = generator.generate(
            format=ReportFormat.HTML,
            findings=_sample_findings(),
            scan_id="test",
            verdict=_sample_verdict(),
            threat_model=_sample_threat_model(),
        )
        assert "Security Verdict" in report.content
        assert "STRIDE-AI Threat Model" in report.content
