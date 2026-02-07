"""Tests for ThreatModelBuilder progressive construction."""

import json
import pytest

from mass.threat_model.builder import ThreatModelBuilder
from mass.threat_model.types import (
    DataClassification,
    StrideAICategory,
    ThreatModelPhase,
)


def _sample_topology():
    """Create a sample topology for testing."""
    return {
        "nodes": [
            {"id": "n1", "label": "Chat API", "type": "api_service"},
            {"id": "n2", "label": "LLM Provider", "type": "model_provider"},
            {"id": "n3", "label": "Vector DB", "type": "vector_store"},
            {"id": "n4", "label": "MCP Server", "type": "mcp_server"},
        ],
        "edges": [
            {"id": "e1", "source": "n1", "target": "n2", "type": "api_call"},
            {"id": "e2", "source": "n1", "target": "n3", "type": "data_flow"},
            {"id": "e3", "source": "n1", "target": "n4", "type": "tool_invocation"},
        ],
    }


def _sample_environment():
    """Create a sample environment for testing."""
    return {
        "cloud_provider": "aws",
        "auth_mechanisms": [{"type": "jwt", "name": "auth0"}],
        "databases": [{"type": "postgresql", "name": "main-db"}],
        "frameworks": ["langchain", "fastapi"],
    }


def _sample_findings():
    """Create sample findings for testing."""
    return [
        {
            "title": "Hardcoded API Key",
            "severity": "high",
            "category": "hardcoded_secret",
            "component_name": "config.py",
            "confidence": 0.95,
            "metadata": {},
        },
        {
            "title": "Prompt Injection Risk",
            "severity": "critical",
            "category": "prompt_injection",
            "component_name": "chat.py",
            "confidence": 0.85,
            "metadata": {},
        },
        {
            "title": "Unsafe Pickle Load",
            "severity": "high",
            "category": "unsafe_deserialization",
            "component_name": "model_loader.py",
            "confidence": 0.9,
            "metadata": {},
        },
    ]


class TestBuilderDiscovery:
    """Tests for Phase 1: Discovery ingestion."""

    def test_ingest_discovery_creates_trust_boundaries(self):
        builder = ThreatModelBuilder("test-deploy")
        builder.ingest_discovery(
            environment=_sample_environment(),
            topology=_sample_topology(),
            attack_surface=None,
            deployment_posture="production",
        )
        model = builder.build()
        assert len(model.trust_boundaries) > 0

    def test_ingest_discovery_creates_data_flows(self):
        builder = ThreatModelBuilder("test-deploy")
        builder.ingest_discovery(
            environment=_sample_environment(),
            topology=_sample_topology(),
            attack_surface=None,
            deployment_posture="staging",
        )
        model = builder.build()
        assert len(model.data_flows) > 0

    def test_ingest_discovery_creates_assets(self):
        builder = ThreatModelBuilder("test-deploy")
        builder.ingest_discovery(
            environment=_sample_environment(),
            topology=_sample_topology(),
            attack_surface=None,
            deployment_posture="unknown",
        )
        model = builder.build()
        assert len(model.assets) > 0

    def test_ingest_discovery_creates_initial_threats(self):
        builder = ThreatModelBuilder("test-deploy")
        builder.ingest_discovery(
            environment=_sample_environment(),
            topology=_sample_topology(),
            attack_surface=None,
            deployment_posture="unknown",
        )
        model = builder.build()
        assert len(model.threats) > 0

    def test_phases_tracked(self):
        builder = ThreatModelBuilder("test-deploy")
        builder.ingest_discovery(
            environment={},
            topology={"nodes": [], "edges": []},
            attack_surface=None,
            deployment_posture="unknown",
        )
        model = builder.build()
        assert ThreatModelPhase.DISCOVERY.value in model.phases_completed


class TestBuilderFindings:
    """Tests for Phase 2: Findings ingestion."""

    def test_ingest_findings_creates_threats(self):
        builder = ThreatModelBuilder("test-deploy")
        builder.ingest_findings(_sample_findings())
        model = builder.build()
        # Only categories with STRIDE mappings generate threats
        assert len(model.threats) >= 1

    def test_severity_preserved(self):
        builder = ThreatModelBuilder("test-deploy")
        builder.ingest_findings(_sample_findings())
        model = builder.build()
        severities = {t.severity for t in model.threats}
        assert "critical" in severities or "high" in severities

    def test_phases_tracked(self):
        builder = ThreatModelBuilder("test-deploy")
        builder.ingest_findings(_sample_findings())
        model = builder.build()
        assert ThreatModelPhase.STATIC_ANALYSIS.value in model.phases_completed


class TestBuilderInterrogation:
    """Tests for Phase 3: Interrogation ingestion."""

    def test_ingest_interrogation_phase_tracked(self):
        builder = ThreatModelBuilder("test-deploy")
        builder.ingest_findings(_sample_findings())
        confirmed = [
            {
                "title": "Prompt Injection Risk",
                "severity": "critical",
                "category": "prompt_injection",
                "metadata": {"confidence_level": "confirmed"},
            },
        ]
        builder.ingest_interrogation(
            risk_score={"overall": 7.5, "category_scores": {}},
            findings=confirmed,
        )
        model = builder.build()
        assert ThreatModelPhase.INTERROGATION.value in model.phases_completed


class TestBuilderVerdict:
    """Tests for Phase 4: Verdict ingestion."""

    def test_ingest_verdict_adds_mitigations(self):
        builder = ThreatModelBuilder("test-deploy")
        builder.ingest_findings(_sample_findings())
        verdict = {
            "risk_level": "high",
            "confidence": 0.85,
            "attack_chains": [
                {
                    "name": "Prompt to RCE",
                    "severity": "critical",
                    "steps": ["Inject prompt", "Execute tool", "Get shell"],
                },
            ],
            "recommendations": [
                {
                    "title": "Implement input sanitization",
                    "priority": "high",
                    "description": "Sanitize all user inputs before prompt construction",
                },
            ],
        }
        builder.ingest_verdict(verdict)
        model = builder.build()
        assert ThreatModelPhase.JUDGE_VERDICT.value in model.phases_completed
        assert len(model.recommended_mitigations) > 0


class TestBuilderBuild:
    """Tests for the build() method output."""

    def test_risk_matrix_populated(self):
        builder = ThreatModelBuilder("test-deploy")
        builder.ingest_discovery(
            environment=_sample_environment(),
            topology=_sample_topology(),
            attack_surface=None,
            deployment_posture="production",
        )
        builder.ingest_findings(_sample_findings())
        model = builder.build()
        assert len(model.risk_matrix) > 0
        for entry in model.risk_matrix:
            assert 0.0 <= entry.likelihood <= 1.0
            assert 0.0 <= entry.impact <= 1.0

    def test_summary_statistics(self):
        builder = ThreatModelBuilder("test-deploy")
        builder.ingest_findings(_sample_findings())
        model = builder.build()
        assert model.threat_counts_by_severity
        total = sum(model.threat_counts_by_severity.values())
        assert total == len(model.threats)

    def test_stride_breakdown(self):
        builder = ThreatModelBuilder("test-deploy")
        builder.ingest_findings(_sample_findings())
        model = builder.build()
        assert model.threat_counts_by_stride
        total = sum(model.threat_counts_by_stride.values())
        assert total == len(model.threats)

    def test_overall_risk_level_set(self):
        builder = ThreatModelBuilder("test-deploy")
        builder.ingest_findings(_sample_findings())
        model = builder.build()
        assert model.overall_risk_level in ("safe", "low", "medium", "high", "critical")

    def test_compliance_summary(self):
        builder = ThreatModelBuilder("test-deploy")
        builder.ingest_findings(_sample_findings())
        model = builder.build()
        assert model.compliance_summary


class TestBuilderJsonRoundTrip:
    """Tests for JSON serialization round-trip."""

    def test_full_roundtrip(self):
        builder = ThreatModelBuilder("test-deploy")
        builder.ingest_discovery(
            environment=_sample_environment(),
            topology=_sample_topology(),
            attack_surface=None,
            deployment_posture="production",
        )
        builder.ingest_findings(_sample_findings())
        model = builder.build()

        json_str = json.dumps(model.to_dict())
        from mass.threat_model.types import AIThreatModel
        restored = AIThreatModel.from_dict(json.loads(json_str))

        assert restored.name == model.name
        assert len(restored.threats) == len(model.threats)
        assert len(restored.trust_boundaries) == len(model.trust_boundaries)
        assert len(restored.data_flows) == len(model.data_flows)
        assert restored.overall_risk_level == model.overall_risk_level
        assert restored.data_classification == model.data_classification


class TestBuilderEmptyData:
    """Tests for graceful handling of empty/missing data."""

    def test_empty_topology(self):
        builder = ThreatModelBuilder("test-deploy")
        builder.ingest_discovery(
            environment={},
            topology={"nodes": [], "edges": []},
            attack_surface=None,
            deployment_posture="unknown",
        )
        model = builder.build()
        assert model.name is not None

    def test_no_ingestion(self):
        builder = ThreatModelBuilder("test-deploy")
        model = builder.build()
        assert model.deployment_name == "test-deploy"
        assert model.threats == []
        assert model.trust_boundaries == []

    def test_empty_findings(self):
        builder = ThreatModelBuilder("test-deploy")
        builder.ingest_findings([])
        model = builder.build()
        assert model.deployment_name == "test-deploy"
