"""Cross-model collaborative security schemas.

Request and response models for running security probes against multiple
LLM providers/models in parallel and comparing vulnerability profiles.
Per ARCHITECTURE.md Section 8.1 — Cross-Model module slot.
"""

from enum import Enum

from pydantic import BaseModel, ConfigDict, Field

from mass.api.schemas.common import PaginationMeta


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class ComparisonStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


# ---------------------------------------------------------------------------
# Model target configuration
# ---------------------------------------------------------------------------

class ModelTarget(BaseModel):
    """A model to include in the cross-model comparison."""

    model_config = ConfigDict(extra="forbid")

    provider: str = Field(..., description="Provider: openai, anthropic, ollama, gemini, grok, bedrock, azure_openai")
    model: str = Field(..., description="Model name (e.g., gpt-4o-mini, claude-sonnet-4-20250514)")
    label: str | None = Field(default=None, description="Display label (defaults to provider/model)")
    api_key: str | None = Field(default=None, description="Provider API key (uses default if omitted)")
    base_url: str | None = Field(default=None, description="Custom API endpoint")
    temperature: float = Field(default=0.7, ge=0, le=2)
    max_tokens: int = Field(default=1024, ge=1, le=16384)


# ---------------------------------------------------------------------------
# Comparison job
# ---------------------------------------------------------------------------

class ComparisonCreate(BaseModel):
    """Start a cross-model security comparison."""

    model_config = ConfigDict(extra="forbid")

    name: str = Field(default="", max_length=255, description="Comparison name")
    models: list[ModelTarget] = Field(
        ..., min_length=2, max_length=10,
        description="Models to compare (2-10)",
    )
    categories: list[str] = Field(
        default_factory=list,
        description="Attack categories to test (empty = all)",
    )
    probe_names: list[str] = Field(
        default_factory=list,
        description="Specific probes to run (overrides categories)",
    )
    max_probes: int = Field(default=0, ge=0, description="Max probes per model (0 = all)")
    max_prompts_per_probe: int = Field(default=0, ge=0, description="Max prompts per probe (0 = all)")
    system_prompt: str | None = Field(default=None, description="System prompt to inject")
    prompt_timeout: float = Field(default=30.0, ge=5, le=120)


class ModelResultSummary(BaseModel):
    model_config = ConfigDict(extra="forbid")

    provider: str
    model: str
    label: str = ""
    probes_run: int = 0
    prompts_sent: int = 0
    vulnerable_count: int = 0
    safe_count: int = 0
    uncertain_count: int = 0
    error_count: int = 0
    vulnerability_rate: float = Field(default=0.0, description="Percent of prompts that found vulnerabilities")
    findings_by_severity: dict[str, int] = Field(default_factory=dict)
    findings_by_category: dict[str, int] = Field(default_factory=dict)
    avg_latency_ms: float = 0.0
    total_tokens: int = 0


class CategoryComparison(BaseModel):
    """Per-category vulnerability comparison across models."""

    model_config = ConfigDict(extra="forbid")

    category: str
    results: dict[str, dict] = Field(
        default_factory=dict,
        description="model_label → {vulnerable, safe, uncertain, rate}",
    )
    most_vulnerable: str | None = None
    most_resilient: str | None = None


class ComparisonResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    name: str = ""
    status: ComparisonStatus
    models_count: int = 0
    model_results: list[ModelResultSummary] = Field(default_factory=list)
    category_comparisons: list[CategoryComparison] = Field(default_factory=list)
    overall_ranking: list[dict] = Field(
        default_factory=list,
        description="Models ranked by security posture (best first)",
    )
    total_probes: int = 0
    total_prompts: int = 0
    total_findings: int = 0
    duration_seconds: float = 0.0
    error: str | None = None
    created_at: str
    completed_at: str | None = None


class ComparisonListResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    items: list[ComparisonResponse]
    pagination: PaginationMeta


# ---------------------------------------------------------------------------
# Module status
# ---------------------------------------------------------------------------

class CrossModelStatusResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    status: str = Field(default="healthy")
    total_comparisons: int = Field(default=0)
    recent_comparisons: int = Field(default=0, description="Comparisons in last 24h")
    available_providers: list[str] = Field(default_factory=list)
    available_categories: list[str] = Field(default_factory=list)
