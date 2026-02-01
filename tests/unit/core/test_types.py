"""Tests for mass.core.types module."""

import pytest

from mass.core.types import (
    AgenticFramework,
    AttackCategory,
    ComponentType,
    FrameworkType,
    ModelProvider,
    RiskLevel,
    ScanStatus,
    Severity,
)


class TestRiskLevel:
    """Tests for RiskLevel enum."""

    def test_risk_level_values(self) -> None:
        """Test that all risk levels have expected values."""
        assert RiskLevel.CRITICAL.value == "critical"
        assert RiskLevel.HIGH.value == "high"
        assert RiskLevel.MEDIUM.value == "medium"
        assert RiskLevel.LOW.value == "low"
        assert RiskLevel.INFO.value == "info"
        assert RiskLevel.SAFE.value == "safe"

    def test_risk_level_is_string_enum(self) -> None:
        """Test that RiskLevel is a string enum."""
        assert isinstance(RiskLevel.CRITICAL, str)
        assert RiskLevel.CRITICAL == "critical"

    def test_risk_level_membership(self) -> None:
        """Test membership checks."""
        assert RiskLevel.CRITICAL in RiskLevel
        assert "invalid" not in [r.value for r in RiskLevel]


class TestSeverity:
    """Tests for Severity enum."""

    def test_severity_values(self) -> None:
        """Test that all severity levels have expected values."""
        assert Severity.CRITICAL.value == "critical"
        assert Severity.HIGH.value == "high"
        assert Severity.MEDIUM.value == "medium"
        assert Severity.LOW.value == "low"
        assert Severity.INFO.value == "info"

    def test_severity_count(self) -> None:
        """Test that we have exactly 5 severity levels."""
        assert len(Severity) == 5


class TestScanStatus:
    """Tests for ScanStatus enum."""

    def test_scan_status_values(self) -> None:
        """Test that all scan statuses have expected values."""
        assert ScanStatus.PENDING.value == "pending"
        assert ScanStatus.QUEUED.value == "queued"
        assert ScanStatus.RUNNING.value == "running"
        assert ScanStatus.COMPLETED.value == "completed"
        assert ScanStatus.FAILED.value == "failed"
        assert ScanStatus.CANCELLED.value == "cancelled"

    def test_scan_status_count(self) -> None:
        """Test that we have exactly 6 scan statuses."""
        assert len(ScanStatus) == 6


class TestComponentType:
    """Tests for ComponentType enum."""

    def test_component_type_values(self) -> None:
        """Test that all component types have expected values."""
        assert ComponentType.MODEL.value == "model"
        assert ComponentType.CONTEXT.value == "context"
        assert ComponentType.MCP_SERVER.value == "mcp_server"
        assert ComponentType.SKILL.value == "skill"
        assert ComponentType.KNOWLEDGE.value == "knowledge"
        assert ComponentType.CODE.value == "code"
        assert ComponentType.CONFIG.value == "config"
        assert ComponentType.INFRASTRUCTURE.value == "infrastructure"
        assert ComponentType.WORKFLOW.value == "workflow"

    def test_component_type_includes_guardrails(self) -> None:
        """Test that guardrails component type exists."""
        assert ComponentType.GUARDRAILS.value == "guardrails"


class TestAttackCategory:
    """Tests for AttackCategory enum."""

    def test_owasp_llm_top10_categories(self) -> None:
        """Test that OWASP LLM Top 10 2025 categories exist."""
        owasp_categories = [
            AttackCategory.PROMPT_INJECTION,
            AttackCategory.SENSITIVE_INFO,
            AttackCategory.SUPPLY_CHAIN,
            AttackCategory.DATA_MODEL_POISONING,
            AttackCategory.IMPROPER_OUTPUT,
            AttackCategory.EXCESSIVE_AGENCY,
            AttackCategory.SYSTEM_PROMPT_LEAKAGE,
            AttackCategory.VECTOR_EMBEDDING,
            AttackCategory.MISINFORMATION,
            AttackCategory.UNBOUNDED_CONSUMPTION,
        ]
        assert len(owasp_categories) == 10

    def test_extended_categories(self) -> None:
        """Test that extended categories exist."""
        assert AttackCategory.JAILBREAK.value == "jailbreak"
        assert AttackCategory.DATA_LEAKAGE.value == "data_leakage"
        assert AttackCategory.HALLUCINATION.value == "hallucination"
        assert AttackCategory.BIAS.value == "bias"
        assert AttackCategory.TOXICITY.value == "toxicity"


class TestFrameworkType:
    """Tests for FrameworkType enum."""

    def test_compliance_frameworks(self) -> None:
        """Test that major compliance frameworks exist."""
        assert FrameworkType.OWASP_LLM.value == "owasp_llm"
        assert FrameworkType.MITRE_ATLAS.value == "mitre_atlas"
        assert FrameworkType.NIST_AI_RMF.value == "nist_ai_rmf"
        assert FrameworkType.EU_AI_ACT.value == "eu_ai_act"
        assert FrameworkType.GDPR.value == "gdpr"


class TestAgenticFramework:
    """Tests for AgenticFramework enum."""

    def test_major_frameworks(self) -> None:
        """Test that major agentic frameworks exist."""
        assert AgenticFramework.LANGCHAIN.value == "langchain"
        assert AgenticFramework.LANGGRAPH.value == "langgraph"
        assert AgenticFramework.CREWAI.value == "crewai"
        assert AgenticFramework.AUTOGEN.value == "autogen"
        assert AgenticFramework.OPENAI_AGENTS.value == "openai_agents"


class TestModelProvider:
    """Tests for ModelProvider enum."""

    def test_major_providers(self) -> None:
        """Test that major model providers exist."""
        assert ModelProvider.OPENAI.value == "openai"
        assert ModelProvider.ANTHROPIC.value == "anthropic"
        assert ModelProvider.GOOGLE.value == "google"
        assert ModelProvider.XAI.value == "xai"
        assert ModelProvider.OLLAMA.value == "ollama"
        assert ModelProvider.LOCAL.value == "local"
