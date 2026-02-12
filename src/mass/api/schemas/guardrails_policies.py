"""Guardrails and policies generation schemas."""

from pydantic import BaseModel, ConfigDict, Field


class FindingSummaryItem(BaseModel):
    """Condensed finding for guardrail matching."""

    model_config = ConfigDict(extra="forbid")

    id: str = Field(..., description="Finding ID")
    title: str = Field(..., description="Finding title")
    category: str = Field(..., description="Attack category (e.g., prompt_injection)")
    severity: str = Field(..., description="Severity: critical, high, medium, low, info")
    description: str = Field(default="", description="Finding description")
    cwe_ids: list[str] = Field(default_factory=list)
    owasp_ids: list[str] = Field(default_factory=list)


class RiskContextInput(BaseModel):
    """Deployment risk context for severity adjustment."""

    model_config = ConfigDict(extra="ignore")

    is_public_facing: bool | None = None
    deployment_environment: str | None = None
    user_count: str | None = None
    data_sensitivity: str | None = None
    handles_pii: bool | None = None
    has_payment_data: bool | None = None
    compliance_frameworks: list[str] | None = None


class GenerateGuardrailsRequest(BaseModel):
    """Request to generate guardrails and policies from findings."""

    model_config = ConfigDict(extra="forbid")

    findings: list[FindingSummaryItem] = Field(
        ..., min_length=1, description="Findings to generate guardrails/policies for"
    )
    target_name: str = Field(default="", description="Project/target name for context")
    generate_ai_guardrails: bool = Field(
        default=False,
        description="Whether to generate AI-augmented guardrails via LLM",
    )
    generate_policies: bool = Field(
        default=False,
        description="Whether to generate organizational policy recommendations via LLM",
    )
    risk_context: RiskContextInput | None = Field(
        default=None,
        description="Deployment risk context for severity adjustment",
    )
    provider: str = Field(default="ollama", description="LLM provider")
    model: str | None = Field(default=None, description="Model name")
    api_key: str | None = Field(default=None, description="Provider API key")
    endpoint: str | None = Field(default=None, description="Custom API endpoint URL")


class GuardrailItem(BaseModel):
    """A single guardrail recommendation."""

    model_config = ConfigDict(extra="ignore")

    id: str = ""
    name: str = ""
    description: str = ""
    guardrail_type: str = ""
    severity: str = "medium"
    original_severity: str = ""
    severity_adjusted: bool = False
    implementation_steps: list[str] = Field(default_factory=list)
    code_examples: dict[str, str] = Field(default_factory=dict)
    configuration_examples: dict[str, str] = Field(default_factory=dict)
    mitigates: list[str] = Field(default_factory=list)
    compliance: list[str] = Field(default_factory=list)
    effort: str = "medium"
    effectiveness: str = "high"
    source: str = "registry"


class PolicyItem(BaseModel):
    """An organizational policy recommendation."""

    model_config = ConfigDict(extra="ignore")

    name: str = ""
    owner_group: str = "Security"
    description: str = ""
    assets_covered: list[str] = Field(default_factory=list)
    violation_severity: str = "medium"
    original_severity: str = ""
    severity_adjusted: bool = False
    remediation_actions: list[str] = Field(default_factory=list)
    related_findings: list[str] = Field(default_factory=list)
    source: str = "ai_generated"


class GenerateGuardrailsResponse(BaseModel):
    """Response with guardrails and policies."""

    model_config = ConfigDict(extra="forbid")

    registry_guardrails: list[GuardrailItem] = Field(default_factory=list)
    ai_guardrails: list[GuardrailItem] = Field(default_factory=list)
    policies: list[PolicyItem] = Field(default_factory=list)
    provider: str = ""
    model_used: str = ""
    findings_analyzed: int = 0
    risk_multiplier: float | None = None
    risk_factors: list[str] | None = None
    risk_level: str | None = None
