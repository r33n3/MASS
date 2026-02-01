"""Tests for mass.core.findings module."""

from datetime import datetime
from typing import Any

import pytest

from mass.core.findings import Evidence, Finding, FindingSummary, Remediation
from mass.core.types import AttackCategory, ComponentType, Severity


class TestEvidence:
    """Tests for Evidence model."""

    def test_basic_evidence(self) -> None:
        """Test basic evidence creation."""
        evidence = Evidence(
            type="response",
            content="Model leaked system prompt",
        )
        assert evidence.type == "response"
        assert evidence.content == "Model leaked system prompt"
        assert evidence.source_file is None
        assert evidence.source_line is None
        assert isinstance(evidence.timestamp, datetime)

    def test_evidence_with_source(self) -> None:
        """Test evidence with source location."""
        evidence = Evidence(
            type="code",
            content="api_key = 'sk-xxx'",
            source_file="config.py",
            source_line=42,
        )
        assert evidence.source_file == "config.py"
        assert evidence.source_line == 42

    def test_evidence_with_metadata(self) -> None:
        """Test evidence with metadata."""
        evidence = Evidence(
            type="response",
            content="Test",
            metadata={"probe": "jailbreak", "attempt": 3},
        )
        assert evidence.metadata["probe"] == "jailbreak"
        assert evidence.metadata["attempt"] == 3


class TestRemediation:
    """Tests for Remediation model."""

    def test_basic_remediation(self) -> None:
        """Test basic remediation creation."""
        remediation = Remediation(
            summary="Add input validation",
            steps=["Step 1", "Step 2"],
        )
        assert remediation.summary == "Add input validation"
        assert len(remediation.steps) == 2
        assert remediation.references == []
        assert remediation.code_example is None

    def test_remediation_with_all_fields(self) -> None:
        """Test remediation with all fields."""
        remediation = Remediation(
            summary="Implement rate limiting",
            steps=["Add middleware", "Configure limits"],
            references=["https://example.com/docs"],
            code_example="rate_limit(100)",
            estimated_effort="medium",
        )
        assert len(remediation.references) == 1
        assert remediation.code_example == "rate_limit(100)"
        assert remediation.estimated_effort == "medium"


class TestFinding:
    """Tests for Finding model."""

    def test_basic_finding(self) -> None:
        """Test basic finding creation."""
        finding = Finding(
            title="Prompt Injection Vulnerability",
            description="Model susceptible to direct prompt injection",
            severity=Severity.HIGH,
            category=AttackCategory.PROMPT_INJECTION,
            component_type=ComponentType.MODEL,
            component_name="gpt-4",
        )
        assert finding.title == "Prompt Injection Vulnerability"
        assert finding.severity == Severity.HIGH
        assert finding.category == AttackCategory.PROMPT_INJECTION
        assert finding.component_type == ComponentType.MODEL
        assert finding.id is not None  # UUID generated

    def test_finding_with_evidence(self) -> None:
        """Test finding with evidence."""
        evidence = Evidence(type="response", content="Leaked prompt")
        finding = Finding(
            title="System Prompt Leakage",
            description="Model disclosed system prompt",
            severity=Severity.MEDIUM,
            category=AttackCategory.SYSTEM_PROMPT_LEAKAGE,
            component_type=ComponentType.MODEL,
            component_name="claude-3",
            evidence=[evidence],
        )
        assert len(finding.evidence) == 1
        assert finding.evidence[0].type == "response"

    def test_finding_with_remediation(self) -> None:
        """Test finding with remediation."""
        remediation = Remediation(
            summary="Use parameterized prompts",
            steps=["Implement template system"],
        )
        finding = Finding(
            title="Test Finding",
            description="Test description",
            severity=Severity.LOW,
            category=AttackCategory.PROMPT_INJECTION,
            component_type=ComponentType.CONTEXT,
            component_name="system_prompt.txt",
            remediation=remediation,
        )
        assert finding.remediation is not None
        assert finding.remediation.summary == "Use parameterized prompts"

    def test_finding_compliance_mapping(self) -> None:
        """Test finding with compliance IDs."""
        finding = Finding(
            title="Sensitive Data Exposure",
            description="PII leaked in responses",
            severity=Severity.HIGH,
            category=AttackCategory.SENSITIVE_INFO,
            component_type=ComponentType.MODEL,
            component_name="model",
            cwe_ids=["CWE-200", "CWE-359"],
            owasp_ids=["LLM02"],
            mitre_ids=["AML.T0048"],
        )
        assert "CWE-200" in finding.cwe_ids
        assert "LLM02" in finding.owasp_ids
        assert "AML.T0048" in finding.mitre_ids

    def test_finding_confidence(self) -> None:
        """Test finding confidence clamping."""
        finding = Finding(
            title="Test",
            description="Test",
            severity=Severity.INFO,
            category=AttackCategory.HALLUCINATION,
            component_type=ComponentType.MODEL,
            component_name="model",
            confidence=0.75,
        )
        assert finding.confidence == 0.75

    def test_finding_false_positive_and_suppressed(self) -> None:
        """Test false positive and suppressed flags."""
        finding = Finding(
            title="Test",
            description="Test",
            severity=Severity.LOW,
            category=AttackCategory.BIAS,
            component_type=ComponentType.MODEL,
            component_name="model",
            false_positive=True,
            suppressed=True,
        )
        assert finding.false_positive is True
        assert finding.suppressed is True


class TestFindingSummary:
    """Tests for FindingSummary model."""

    def test_empty_summary(self) -> None:
        """Test summary with no findings."""
        summary = FindingSummary.from_findings([])
        assert summary.total == 0
        assert summary.critical_count == 0
        assert summary.high_count == 0

    def test_summary_counts(self) -> None:
        """Test summary counts by severity."""
        findings = [
            Finding(
                title="Critical Finding",
                description="Test",
                severity=Severity.CRITICAL,
                category=AttackCategory.PROMPT_INJECTION,
                component_type=ComponentType.MODEL,
                component_name="model",
            ),
            Finding(
                title="High Finding",
                description="Test",
                severity=Severity.HIGH,
                category=AttackCategory.JAILBREAK,
                component_type=ComponentType.MODEL,
                component_name="model",
            ),
            Finding(
                title="Another High",
                description="Test",
                severity=Severity.HIGH,
                category=AttackCategory.DATA_LEAKAGE,
                component_type=ComponentType.CONTEXT,
                component_name="prompt",
            ),
        ]
        summary = FindingSummary.from_findings(findings)
        assert summary.total == 3
        assert summary.critical_count == 1
        assert summary.high_count == 2
        assert summary.by_severity["critical"] == 1
        assert summary.by_severity["high"] == 2

    def test_summary_by_category(self) -> None:
        """Test summary by category."""
        findings = [
            Finding(
                title="F1",
                description="Test",
                severity=Severity.HIGH,
                category=AttackCategory.PROMPT_INJECTION,
                component_type=ComponentType.MODEL,
                component_name="model",
            ),
            Finding(
                title="F2",
                description="Test",
                severity=Severity.HIGH,
                category=AttackCategory.PROMPT_INJECTION,
                component_type=ComponentType.MODEL,
                component_name="model",
            ),
        ]
        summary = FindingSummary.from_findings(findings)
        assert summary.by_category["prompt_injection"] == 2

    def test_summary_by_component(self) -> None:
        """Test summary by component type."""
        findings = [
            Finding(
                title="F1",
                description="Test",
                severity=Severity.MEDIUM,
                category=AttackCategory.SECRETS_EXPOSURE,
                component_type=ComponentType.CONFIG,
                component_name="config.yaml",
            ),
            Finding(
                title="F2",
                description="Test",
                severity=Severity.MEDIUM,
                category=AttackCategory.SECRETS_EXPOSURE,
                component_type=ComponentType.CODE,
                component_name="app.py",
            ),
        ]
        summary = FindingSummary.from_findings(findings)
        assert summary.by_component["config"] == 1
        assert summary.by_component["code"] == 1

    def test_summary_false_positive_count(self) -> None:
        """Test false positive counting."""
        findings = [
            Finding(
                title="Real Finding",
                description="Test",
                severity=Severity.HIGH,
                category=AttackCategory.JAILBREAK,
                component_type=ComponentType.MODEL,
                component_name="model",
                false_positive=False,
            ),
            Finding(
                title="False Positive",
                description="Test",
                severity=Severity.HIGH,
                category=AttackCategory.JAILBREAK,
                component_type=ComponentType.MODEL,
                component_name="model",
                false_positive=True,
            ),
        ]
        summary = FindingSummary.from_findings(findings)
        assert summary.false_positive_count == 1
        assert summary.suppressed_count == 0
