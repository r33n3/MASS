"""AI threat model data structures.

Defines the STRIDE-AI taxonomy, data classification levels,
and all dataclasses for the progressive threat model.
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any


# ============================================================
# Enums
# ============================================================


class StrideAICategory(str, Enum):
    """STRIDE adapted for AI deployments.

    Maps the classic STRIDE threat categories to AI-specific
    threat types relevant to LLM and agentic systems.
    """

    # Spoofing
    MODEL_IMPERSONATION = "model_impersonation"
    IDENTITY_SPOOFING = "identity_spoofing"

    # Tampering
    PROMPT_INJECTION = "prompt_injection"
    DATA_POISONING = "data_poisoning"
    MODEL_MANIPULATION = "model_manipulation"
    CONTEXT_MANIPULATION = "context_manipulation"

    # Repudiation
    AUDIT_TRAIL_GAPS = "audit_trail_gaps"
    ATTRIBUTION_FAILURES = "attribution_failures"

    # Information Disclosure
    SYSTEM_PROMPT_LEAKAGE = "system_prompt_leakage"
    DATA_EXFILTRATION = "data_exfiltration"
    MODEL_EXTRACTION = "model_extraction"

    # Denial of Service
    RESOURCE_EXHAUSTION = "resource_exhaustion"
    UNBOUNDED_CONSUMPTION = "unbounded_consumption"

    # Elevation of Privilege
    JAILBREAK = "jailbreak"
    EXCESSIVE_AGENCY = "excessive_agency"
    TOOL_ABUSE = "tool_abuse"


# Group categories by STRIDE pillar for display
STRIDE_PILLARS: dict[str, list[StrideAICategory]] = {
    "Spoofing": [
        StrideAICategory.MODEL_IMPERSONATION,
        StrideAICategory.IDENTITY_SPOOFING,
    ],
    "Tampering": [
        StrideAICategory.PROMPT_INJECTION,
        StrideAICategory.DATA_POISONING,
        StrideAICategory.MODEL_MANIPULATION,
        StrideAICategory.CONTEXT_MANIPULATION,
    ],
    "Repudiation": [
        StrideAICategory.AUDIT_TRAIL_GAPS,
        StrideAICategory.ATTRIBUTION_FAILURES,
    ],
    "Information Disclosure": [
        StrideAICategory.SYSTEM_PROMPT_LEAKAGE,
        StrideAICategory.DATA_EXFILTRATION,
        StrideAICategory.MODEL_EXTRACTION,
    ],
    "Denial of Service": [
        StrideAICategory.RESOURCE_EXHAUSTION,
        StrideAICategory.UNBOUNDED_CONSUMPTION,
    ],
    "Elevation of Privilege": [
        StrideAICategory.JAILBREAK,
        StrideAICategory.EXCESSIVE_AGENCY,
        StrideAICategory.TOOL_ABUSE,
    ],
}


class DataClassification(str, Enum):
    """Inferred data sensitivity level."""

    PUBLIC = "public"
    INTERNAL = "internal"
    CONFIDENTIAL = "confidential"
    RESTRICTED = "restricted"  # PII, health, financial


# Ordering for max() comparisons
_DATA_CLASSIFICATION_ORDER = {
    DataClassification.PUBLIC: 0,
    DataClassification.INTERNAL: 1,
    DataClassification.CONFIDENTIAL: 2,
    DataClassification.RESTRICTED: 3,
}


def max_classification(
    a: DataClassification, b: DataClassification
) -> DataClassification:
    """Return the higher of two data classifications."""
    if _DATA_CLASSIFICATION_ORDER[a] >= _DATA_CLASSIFICATION_ORDER[b]:
        return a
    return b


class ThreatModelPhase(str, Enum):
    """Phases that contribute to the threat model."""

    DISCOVERY = "discovery"
    STATIC_ANALYSIS = "static_analysis"
    INTERROGATION = "interrogation"
    JUDGE_VERDICT = "judge_verdict"


# ============================================================
# Dataclasses
# ============================================================


@dataclass
class TrustBoundary:
    """A trust boundary in the deployment architecture."""

    id: str
    name: str
    description: str
    components_inside: list[str] = field(default_factory=list)
    components_outside: list[str] = field(default_factory=list)
    crossing_edges: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "components_inside": self.components_inside,
            "components_outside": self.components_outside,
            "crossing_edges": self.crossing_edges,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "TrustBoundary":
        return cls(
            id=data["id"],
            name=data["name"],
            description=data.get("description", ""),
            components_inside=data.get("components_inside", []),
            components_outside=data.get("components_outside", []),
            crossing_edges=data.get("crossing_edges", []),
        )


@dataclass
class DataFlowAnnotation:
    """Annotation on a topology edge with data classification and threats."""

    edge_id: str
    source_node: str
    target_node: str
    data_types: list[str] = field(default_factory=list)
    classification: DataClassification = DataClassification.INTERNAL
    crosses_trust_boundary: bool = False
    applicable_threats: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "edge_id": self.edge_id,
            "source_node": self.source_node,
            "target_node": self.target_node,
            "data_types": self.data_types,
            "classification": self.classification.value,
            "crosses_trust_boundary": self.crosses_trust_boundary,
            "applicable_threats": self.applicable_threats,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "DataFlowAnnotation":
        return cls(
            edge_id=data["edge_id"],
            source_node=data["source_node"],
            target_node=data["target_node"],
            data_types=data.get("data_types", []),
            classification=DataClassification(
                data.get("classification", "internal")
            ),
            crosses_trust_boundary=data.get("crosses_trust_boundary", False),
            applicable_threats=data.get("applicable_threats", []),
        )


@dataclass
class StrideAIThreat:
    """A single threat entry in the STRIDE-AI model."""

    id: str
    stride_category: StrideAICategory
    title: str
    description: str
    severity: str  # Severity value string
    likelihood: float  # 0.0-1.0
    impact: float  # 0.0-1.0
    risk_score: float  # likelihood * impact * posture_multiplier
    affected_components: list[str] = field(default_factory=list)
    data_flow_ids: list[str] = field(default_factory=list)
    evidence_phase: ThreatModelPhase = ThreatModelPhase.DISCOVERY
    evidence_sources: list[str] = field(default_factory=list)
    # Cross-framework mapping
    owasp_llm_ids: list[str] = field(default_factory=list)
    mitre_atlas_ids: list[str] = field(default_factory=list)
    nist_ai_rmf_ids: list[str] = field(default_factory=list)
    cwe_ids: list[str] = field(default_factory=list)
    # Status tracking
    confirmed: bool = False
    mitigations: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "stride_category": self.stride_category.value,
            "title": self.title,
            "description": self.description,
            "severity": self.severity,
            "likelihood": self.likelihood,
            "impact": self.impact,
            "risk_score": self.risk_score,
            "affected_components": self.affected_components,
            "data_flow_ids": self.data_flow_ids,
            "evidence_phase": self.evidence_phase.value,
            "evidence_sources": self.evidence_sources,
            "owasp_llm_ids": self.owasp_llm_ids,
            "mitre_atlas_ids": self.mitre_atlas_ids,
            "nist_ai_rmf_ids": self.nist_ai_rmf_ids,
            "cwe_ids": self.cwe_ids,
            "confirmed": self.confirmed,
            "mitigations": self.mitigations,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "StrideAIThreat":
        return cls(
            id=data["id"],
            stride_category=StrideAICategory(data["stride_category"]),
            title=data["title"],
            description=data.get("description", ""),
            severity=data.get("severity", "medium"),
            likelihood=data.get("likelihood", 0.5),
            impact=data.get("impact", 0.5),
            risk_score=data.get("risk_score", 0.0),
            affected_components=data.get("affected_components", []),
            data_flow_ids=data.get("data_flow_ids", []),
            evidence_phase=ThreatModelPhase(
                data.get("evidence_phase", "discovery")
            ),
            evidence_sources=data.get("evidence_sources", []),
            owasp_llm_ids=data.get("owasp_llm_ids", []),
            mitre_atlas_ids=data.get("mitre_atlas_ids", []),
            nist_ai_rmf_ids=data.get("nist_ai_rmf_ids", []),
            cwe_ids=data.get("cwe_ids", []),
            confirmed=data.get("confirmed", False),
            mitigations=data.get("mitigations", []),
        )


@dataclass
class RiskMatrixEntry:
    """An entry in the risk matrix (likelihood x impact)."""

    threat_id: str
    threat_title: str
    likelihood: float
    impact: float
    risk_score: float
    severity: str
    stride_category: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "threat_id": self.threat_id,
            "threat_title": self.threat_title,
            "likelihood": self.likelihood,
            "impact": self.impact,
            "risk_score": self.risk_score,
            "severity": self.severity,
            "stride_category": self.stride_category,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "RiskMatrixEntry":
        return cls(
            threat_id=data["threat_id"],
            threat_title=data["threat_title"],
            likelihood=data.get("likelihood", 0.5),
            impact=data.get("impact", 0.5),
            risk_score=data.get("risk_score", 0.0),
            severity=data.get("severity", "medium"),
            stride_category=data.get("stride_category", ""),
        )


@dataclass
class AIThreatModel:
    """Complete AI-specific threat model, progressively built."""

    name: str
    deployment_name: str
    deployment_posture: str = "unknown"
    created_at: str = ""
    last_updated_at: str = ""
    phases_completed: list[str] = field(default_factory=list)

    # Data classification
    data_classification: DataClassification = DataClassification.INTERNAL
    data_classification_signals: list[str] = field(default_factory=list)

    # Architecture elements (from topology)
    assets: list[dict[str, Any]] = field(default_factory=list)
    trust_boundaries: list[TrustBoundary] = field(default_factory=list)
    data_flows: list[DataFlowAnnotation] = field(default_factory=list)

    # Threats
    threats: list[StrideAIThreat] = field(default_factory=list)

    # Risk matrix
    risk_matrix: list[RiskMatrixEntry] = field(default_factory=list)

    # Summary statistics
    threat_counts_by_stride: dict[str, int] = field(default_factory=dict)
    threat_counts_by_severity: dict[str, int] = field(default_factory=dict)
    top_risks: list[str] = field(default_factory=list)
    overall_risk_level: str = "safe"

    # Cross-framework compliance mapping summary
    compliance_summary: dict[str, list[str]] = field(default_factory=dict)

    # Mitigations (aggregated)
    recommended_mitigations: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "deployment_name": self.deployment_name,
            "deployment_posture": self.deployment_posture,
            "created_at": self.created_at,
            "last_updated_at": self.last_updated_at,
            "phases_completed": self.phases_completed,
            "data_classification": self.data_classification.value,
            "data_classification_signals": self.data_classification_signals,
            "assets": self.assets,
            "trust_boundaries": [tb.to_dict() for tb in self.trust_boundaries],
            "data_flows": [df.to_dict() for df in self.data_flows],
            "threats": [t.to_dict() for t in self.threats],
            "risk_matrix": [rm.to_dict() for rm in self.risk_matrix],
            "threat_counts_by_stride": self.threat_counts_by_stride,
            "threat_counts_by_severity": self.threat_counts_by_severity,
            "top_risks": self.top_risks,
            "overall_risk_level": self.overall_risk_level,
            "compliance_summary": self.compliance_summary,
            "recommended_mitigations": self.recommended_mitigations,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "AIThreatModel":
        return cls(
            name=data.get("name", ""),
            deployment_name=data.get("deployment_name", ""),
            deployment_posture=data.get("deployment_posture", "unknown"),
            created_at=data.get("created_at", ""),
            last_updated_at=data.get("last_updated_at", ""),
            phases_completed=data.get("phases_completed", []),
            data_classification=DataClassification(
                data.get("data_classification", "internal")
            ),
            data_classification_signals=data.get(
                "data_classification_signals", []
            ),
            assets=data.get("assets", []),
            trust_boundaries=[
                TrustBoundary.from_dict(tb)
                for tb in data.get("trust_boundaries", [])
            ],
            data_flows=[
                DataFlowAnnotation.from_dict(df)
                for df in data.get("data_flows", [])
            ],
            threats=[
                StrideAIThreat.from_dict(t) for t in data.get("threats", [])
            ],
            risk_matrix=[
                RiskMatrixEntry.from_dict(rm)
                for rm in data.get("risk_matrix", [])
            ],
            threat_counts_by_stride=data.get("threat_counts_by_stride", {}),
            threat_counts_by_severity=data.get("threat_counts_by_severity", {}),
            top_risks=data.get("top_risks", []),
            overall_risk_level=data.get("overall_risk_level", "safe"),
            compliance_summary=data.get("compliance_summary", {}),
            recommended_mitigations=data.get("recommended_mitigations", []),
        )
