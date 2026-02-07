"""AI Threat Modeling Framework.

Provides a progressive, STRIDE-AI adapted threat model that builds
across all scan phases: discovery, static analysis, interrogation,
and judge verdict.
"""

from mass.threat_model.types import (
    AIThreatModel,
    DataClassification,
    DataFlowAnnotation,
    RiskMatrixEntry,
    StrideAICategory,
    StrideAIThreat,
    ThreatModelPhase,
    TrustBoundary,
)
from mass.threat_model.builder import ThreatModelBuilder

__all__ = [
    "AIThreatModel",
    "DataClassification",
    "DataFlowAnnotation",
    "RiskMatrixEntry",
    "StrideAICategory",
    "StrideAIThreat",
    "ThreatModelBuilder",
    "ThreatModelPhase",
    "TrustBoundary",
]
