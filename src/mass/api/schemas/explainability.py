"""Explainability schemas.

Request and response models for generating human-readable explanations
of security findings, attack chains, and remediation guidance.
Per ARCHITECTURE.md Section 8.1 — Explainability module slot.
"""

from enum import Enum

from pydantic import BaseModel, ConfigDict, Field


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class ExplainAudience(str, Enum):
    """Target audience for the explanation."""

    DEVELOPER = "developer"
    SECURITY_ENGINEER = "security_engineer"
    EXECUTIVE = "executive"
    COMPLIANCE_OFFICER = "compliance_officer"


class ExplainDepth(str, Enum):
    """Explanation detail level."""

    BRIEF = "brief"
    STANDARD = "standard"
    DETAILED = "detailed"


# ---------------------------------------------------------------------------
# Finding explanation
# ---------------------------------------------------------------------------

class ExplainFindingRequest(BaseModel):
    """Request explanation of a security finding."""

    model_config = ConfigDict(extra="forbid")

    finding_id: str = Field(..., description="Finding ID to explain")
    audience: ExplainAudience = Field(
        default=ExplainAudience.DEVELOPER,
        description="Target audience for the explanation",
    )
    depth: ExplainDepth = Field(default=ExplainDepth.STANDARD)
    include_attack_chain: bool = Field(default=True, description="Include attack chain breakdown")
    include_remediation: bool = Field(default=True, description="Include remediation steps")
    include_compliance: bool = Field(default=True, description="Include compliance context")
    include_similar: bool = Field(default=False, description="Include similar findings")


class AttackChainStep(BaseModel):
    model_config = ConfigDict(extra="forbid")

    step_number: int
    step_type: str
    description: str
    component: str = ""
    risk: str = "medium"
    indicators: list[str] = Field(default_factory=list)
    mitigations: list[str] = Field(default_factory=list)


class ComplianceContext(BaseModel):
    model_config = ConfigDict(extra="forbid")

    framework: str
    control_id: str
    control_name: str
    relevance: str = Field(default="", description="Why this finding is relevant to this control")


class ExplainFindingResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    finding_id: str
    title: str
    severity: str
    category: str

    # Natural language explanation
    summary: str = Field(default="", description="1-2 sentence executive summary")
    explanation: str = Field(default="", description="Full explanation for target audience")
    risk_description: str = Field(default="", description="What could go wrong if not addressed")
    business_impact: str = Field(default="", description="Impact in business terms")

    # Attack chain
    attack_chain: list[AttackChainStep] = Field(default_factory=list)
    attack_chain_narrative: str = Field(default="", description="Story-form attack chain explanation")

    # Remediation
    remediation_summary: str = Field(default="")
    remediation_steps: list[str] = Field(default_factory=list)
    code_example: str | None = Field(default=None, description="Code fix example")
    estimated_effort: str | None = None

    # Compliance
    compliance_context: list[ComplianceContext] = Field(default_factory=list)

    # Similar findings
    similar_findings: list[dict] = Field(default_factory=list)

    # Metadata
    audience: str = "developer"
    depth: str = "standard"
    generated_by: str = Field(default="template", description="template or llm")


# ---------------------------------------------------------------------------
# Attack chain explanation
# ---------------------------------------------------------------------------

class ExplainChainRequest(BaseModel):
    """Request explanation of an attack chain."""

    model_config = ConfigDict(extra="forbid")

    scan_id: str = Field(..., description="Scan to analyze for attack chains")
    audience: ExplainAudience = Field(default=ExplainAudience.DEVELOPER)
    max_chains: int = Field(default=5, ge=1, le=20, description="Max chains to explain")


class AttackChainExplanation(BaseModel):
    model_config = ConfigDict(extra="forbid")

    chain_id: str
    name: str
    severity: str
    risk_score: float = Field(default=0.0, ge=0, le=100)
    summary: str
    narrative: str = Field(default="", description="Story-form walkthrough")
    steps: list[AttackChainStep] = Field(default_factory=list)
    entry_point: str = ""
    final_target: str = ""
    mitre_mapping: list[str] = Field(default_factory=list)
    remediation_priority: list[str] = Field(default_factory=list)


class ExplainChainResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    scan_id: str
    chains_found: int
    chains: list[AttackChainExplanation] = Field(default_factory=list)
    overall_risk: str = "low"
    recommendations: list[str] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# Scan summary explanation
# ---------------------------------------------------------------------------

class ExplainScanRequest(BaseModel):
    """Request a human-readable explanation of scan results."""

    model_config = ConfigDict(extra="forbid")

    scan_id: str = Field(..., description="Scan to explain")
    audience: ExplainAudience = Field(default=ExplainAudience.DEVELOPER)
    depth: ExplainDepth = Field(default=ExplainDepth.STANDARD)
    max_findings: int = Field(default=10, ge=1, le=50, description="Top N findings to explain")


class ExplainScanResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    scan_id: str
    executive_summary: str = ""
    risk_overview: str = ""
    severity_breakdown: dict[str, int] = Field(default_factory=dict)
    category_breakdown: dict[str, int] = Field(default_factory=dict)
    top_findings: list[ExplainFindingResponse] = Field(default_factory=list)
    attack_chains: list[AttackChainExplanation] = Field(default_factory=list)
    key_recommendations: list[str] = Field(default_factory=list)
    compliance_summary: dict[str, str] = Field(
        default_factory=dict,
        description="Framework → status summary",
    )
    audience: str = "developer"


# ---------------------------------------------------------------------------
# Remediation plan
# ---------------------------------------------------------------------------

class RemediationPlanRequest(BaseModel):
    """Generate a prioritized remediation plan for a scan."""

    model_config = ConfigDict(extra="forbid")

    scan_id: str = Field(..., description="Scan to build plan from")
    max_items: int = Field(default=20, ge=1, le=100)
    group_by: str = Field(
        default="severity",
        description="Group plan items by: severity, category, component",
    )


class RemediationPlanItem(BaseModel):
    model_config = ConfigDict(extra="forbid")

    priority: int
    finding_ids: list[str] = Field(default_factory=list)
    title: str
    description: str
    category: str
    severity: str
    effort: str = Field(default="medium", description="low, medium, high")
    steps: list[str] = Field(default_factory=list)
    code_example: str | None = None
    dependencies: list[str] = Field(
        default_factory=list,
        description="Other plan items that should be done first",
    )


class RemediationPlanResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    scan_id: str
    total_findings: int = 0
    items: list[RemediationPlanItem] = Field(default_factory=list)
    estimated_total_effort: str = ""
    quick_wins: list[str] = Field(
        default_factory=list,
        description="Low-effort, high-impact items to do first",
    )


# ---------------------------------------------------------------------------
# Module status
# ---------------------------------------------------------------------------

class ExplainabilityStatusResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    status: str = Field(default="healthy")
    explanations_generated: int = Field(default=0)
    cache_size: int = Field(default=0)
    llm_available: bool = Field(default=False)
    supported_audiences: list[str] = Field(default_factory=list)
