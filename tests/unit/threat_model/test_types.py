"""Tests for threat model data structures."""

import pytest

from mass.threat_model.types import (
    StrideAICategory,
    STRIDE_PILLARS,
    DataClassification,
    max_classification,
    ThreatModelPhase,
    TrustBoundary,
    DataFlowAnnotation,
    StrideAIThreat,
    RiskMatrixEntry,
    AIThreatModel,
)


class TestStrideAICategory:
    """Tests for STRIDE-AI category enum."""

    def test_all_categories_present(self):
        assert len(StrideAICategory) == 16

    def test_stride_pillars_cover_all_categories(self):
        all_in_pillars = []
        for cats in STRIDE_PILLARS.values():
            all_in_pillars.extend(cats)
        assert set(all_in_pillars) == set(StrideAICategory)

    def test_category_values_are_snake_case(self):
        for cat in StrideAICategory:
            assert cat.value == cat.value.lower()
            assert " " not in cat.value


class TestDataClassification:
    """Tests for data classification levels."""

    def test_ordering(self):
        assert max_classification(DataClassification.PUBLIC, DataClassification.INTERNAL) == DataClassification.INTERNAL
        assert max_classification(DataClassification.INTERNAL, DataClassification.CONFIDENTIAL) == DataClassification.CONFIDENTIAL
        assert max_classification(DataClassification.CONFIDENTIAL, DataClassification.RESTRICTED) == DataClassification.RESTRICTED

    def test_max_classification_symmetric(self):
        assert max_classification(DataClassification.RESTRICTED, DataClassification.PUBLIC) == DataClassification.RESTRICTED
        assert max_classification(DataClassification.PUBLIC, DataClassification.RESTRICTED) == DataClassification.RESTRICTED

    def test_max_classification_same(self):
        for dc in DataClassification:
            assert max_classification(dc, dc) == dc


class TestTrustBoundary:
    """Tests for TrustBoundary serialization."""

    def test_roundtrip(self):
        tb = TrustBoundary(
            id="tb-1",
            name="API Gateway",
            description="Network boundary",
            components_inside=["api", "auth"],
            components_outside=["client"],
            crossing_edges=["e1"],
        )
        d = tb.to_dict()
        tb2 = TrustBoundary.from_dict(d)
        assert tb2.id == tb.id
        assert tb2.name == tb.name
        assert tb2.components_inside == tb.components_inside

    def test_from_dict_defaults(self):
        tb = TrustBoundary.from_dict({"id": "x", "name": "y"})
        assert tb.description == ""
        assert tb.components_inside == []


class TestDataFlowAnnotation:
    """Tests for DataFlowAnnotation serialization."""

    def test_roundtrip(self):
        df = DataFlowAnnotation(
            edge_id="e1",
            source_node="api",
            target_node="db",
            data_types=["user_data"],
            classification=DataClassification.CONFIDENTIAL,
            crosses_trust_boundary=True,
            applicable_threats=["t1"],
        )
        d = df.to_dict()
        df2 = DataFlowAnnotation.from_dict(d)
        assert df2.edge_id == df.edge_id
        assert df2.classification == DataClassification.CONFIDENTIAL
        assert df2.crosses_trust_boundary is True


class TestStrideAIThreat:
    """Tests for StrideAIThreat serialization."""

    def test_roundtrip(self):
        t = StrideAIThreat(
            id="T-001",
            stride_category=StrideAICategory.PROMPT_INJECTION,
            title="Prompt Injection via User Input",
            description="User input is concatenated into prompts",
            severity="high",
            likelihood=0.8,
            impact=0.9,
            risk_score=0.72,
            affected_components=["chat_api"],
            owasp_llm_ids=["LLM01"],
            confirmed=True,
        )
        d = t.to_dict()
        t2 = StrideAIThreat.from_dict(d)
        assert t2.id == "T-001"
        assert t2.stride_category == StrideAICategory.PROMPT_INJECTION
        assert t2.confirmed is True
        assert t2.owasp_llm_ids == ["LLM01"]

    def test_from_dict_defaults(self):
        t = StrideAIThreat.from_dict({
            "id": "T-X",
            "stride_category": "jailbreak",
            "title": "test",
        })
        assert t.severity == "medium"
        assert t.likelihood == 0.5
        assert t.confirmed is False


class TestRiskMatrixEntry:
    """Tests for RiskMatrixEntry serialization."""

    def test_roundtrip(self):
        rm = RiskMatrixEntry(
            threat_id="T-001",
            threat_title="Test Threat",
            likelihood=0.7,
            impact=0.8,
            risk_score=0.56,
            severity="high",
            stride_category="prompt_injection",
        )
        d = rm.to_dict()
        rm2 = RiskMatrixEntry.from_dict(d)
        assert rm2.threat_id == rm.threat_id
        assert rm2.risk_score == rm.risk_score


class TestAIThreatModel:
    """Tests for full AIThreatModel serialization."""

    def test_roundtrip(self):
        model = AIThreatModel(
            name="Test Model",
            deployment_name="my-deployment",
            deployment_posture="production",
            phases_completed=["discovery", "static_analysis"],
            data_classification=DataClassification.CONFIDENTIAL,
            threats=[
                StrideAIThreat(
                    id="T-001",
                    stride_category=StrideAICategory.PROMPT_INJECTION,
                    title="Test",
                    description="Desc",
                    severity="high",
                    likelihood=0.8,
                    impact=0.9,
                    risk_score=0.72,
                ),
            ],
            trust_boundaries=[
                TrustBoundary(id="tb-1", name="Gateway", description="desc"),
            ],
            overall_risk_level="high",
        )
        d = model.to_dict()
        model2 = AIThreatModel.from_dict(d)
        assert model2.name == "Test Model"
        assert model2.data_classification == DataClassification.CONFIDENTIAL
        assert len(model2.threats) == 1
        assert model2.threats[0].id == "T-001"
        assert len(model2.trust_boundaries) == 1
        assert model2.overall_risk_level == "high"

    def test_empty_model(self):
        model = AIThreatModel(name="Empty", deployment_name="x")
        d = model.to_dict()
        model2 = AIThreatModel.from_dict(d)
        assert model2.threats == []
        assert model2.trust_boundaries == []
        assert model2.overall_risk_level == "safe"
