"""Threat intelligence schemas.

Request and response models for managing AI security threat feeds,
MITRE ATLAS techniques, and threat-derived attack payloads.
Per ARCHITECTURE.md Section 8.1 — Threat Intel module slot.
"""

from enum import Enum

from pydantic import BaseModel, ConfigDict, Field

from mass.api.schemas.common import PaginationMeta


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class FeedType(str, Enum):
    """Threat intelligence feed types."""

    MITRE_ATLAS = "mitre_atlas"
    AI_INCIDENT_DB = "ai_incident_db"
    NVD = "nvd"
    CUSTOM = "custom"


class ThreatSeverity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class ThreatStatus(str, Enum):
    NEW = "new"
    ANALYZED = "analyzed"
    ACTIONABLE = "actionable"
    MITIGATED = "mitigated"
    DISMISSED = "dismissed"


class TechniqueStatus(str, Enum):
    ACTIVE = "active"
    DEPRECATED = "deprecated"
    COVERED = "covered"
    NOT_COVERED = "not_covered"


# ---------------------------------------------------------------------------
# Feeds — threat intel sources
# ---------------------------------------------------------------------------

class FeedCreate(BaseModel):
    """Create a threat intel feed."""

    model_config = ConfigDict(extra="forbid")

    name: str = Field(..., min_length=1, max_length=255, description="Feed name")
    feed_type: FeedType = Field(..., description="Feed type")
    url: str | None = Field(default=None, description="Feed URL (for automated collection)")
    description: str = Field(default="", max_length=1000)
    is_active: bool = Field(default=True)
    poll_interval_minutes: int = Field(
        default=1440, ge=15,
        description="How often to poll (minutes). Default: daily.",
    )
    filters: dict | None = Field(
        default=None,
        description="Feed-specific filters (e.g., keywords, CVE prefixes)",
    )


class FeedUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str | None = None
    url: str | None = None
    description: str | None = None
    is_active: bool | None = None
    poll_interval_minutes: int | None = None
    filters: dict | None = None


class FeedResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    name: str
    feed_type: FeedType
    url: str | None = None
    description: str = ""
    is_active: bool
    poll_interval_minutes: int
    filters: dict | None = None
    items_count: int = Field(default=0, description="Total items collected")
    last_polled_at: str | None = None
    created_at: str
    updated_at: str


class FeedListResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    items: list[FeedResponse]
    pagination: PaginationMeta


# ---------------------------------------------------------------------------
# Threat items — individual threats (CVEs, advisories, attack patterns)
# ---------------------------------------------------------------------------

class ThreatItemCreate(BaseModel):
    """Create a threat item manually."""

    model_config = ConfigDict(extra="forbid")

    title: str = Field(..., min_length=1, max_length=500)
    description: str = Field(default="")
    severity: ThreatSeverity = Field(default=ThreatSeverity.MEDIUM)
    source: str = Field(default="manual", description="Source feed or 'manual'")
    source_url: str | None = Field(default=None, description="External reference URL")
    source_id: str | None = Field(default=None, description="External ID (CVE, advisory number)")
    attack_categories: list[str] = Field(
        default_factory=list,
        description="Mapped MASS AttackCategory values",
    )
    cwe_ids: list[str] = Field(default_factory=list)
    mitre_ids: list[str] = Field(default_factory=list, description="MITRE ATLAS technique IDs")
    owasp_ids: list[str] = Field(default_factory=list, description="OWASP LLM Top 10 IDs")
    tags: list[str] = Field(default_factory=list)
    affected_components: list[str] = Field(
        default_factory=list,
        description="Affected component types: llm, agent, tool, embedding, rag, etc.",
    )
    indicators: list[str] = Field(
        default_factory=list,
        description="Indicators of compromise or exploitation",
    )
    raw_data: dict | None = Field(default=None, description="Original feed data")


class ThreatItemUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    title: str | None = None
    description: str | None = None
    severity: ThreatSeverity | None = None
    status: ThreatStatus | None = None
    attack_categories: list[str] | None = None
    cwe_ids: list[str] | None = None
    mitre_ids: list[str] | None = None
    owasp_ids: list[str] | None = None
    tags: list[str] | None = None
    affected_components: list[str] | None = None
    indicators: list[str] | None = None


class ThreatItemResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    feed_id: str | None = None
    title: str
    description: str = ""
    severity: ThreatSeverity
    status: ThreatStatus
    source: str
    source_url: str | None = None
    source_id: str | None = None
    attack_categories: list[str] = Field(default_factory=list)
    cwe_ids: list[str] = Field(default_factory=list)
    mitre_ids: list[str] = Field(default_factory=list)
    owasp_ids: list[str] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)
    affected_components: list[str] = Field(default_factory=list)
    indicators: list[str] = Field(default_factory=list)
    analysis: str | None = Field(default=None, description="LLM-generated analysis")
    payloads_generated: int = Field(default=0, description="Payloads generated from this threat")
    created_at: str
    updated_at: str


class ThreatItemListResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    items: list[ThreatItemResponse]
    pagination: PaginationMeta


# ---------------------------------------------------------------------------
# MITRE ATLAS techniques
# ---------------------------------------------------------------------------

class TechniqueResponse(BaseModel):
    """A MITRE ATLAS technique with MASS coverage status."""

    model_config = ConfigDict(extra="forbid")

    id: str = Field(..., description="ATLAS technique ID (e.g., AML.T0043)")
    name: str
    tactic: str = Field(..., description="Parent tactic (e.g., Initial Access)")
    description: str = ""
    coverage_status: TechniqueStatus = Field(
        default=TechniqueStatus.NOT_COVERED,
        description="Whether MASS scanners cover this technique",
    )
    mapped_categories: list[str] = Field(
        default_factory=list,
        description="MASS AttackCategory values that cover this technique",
    )
    mapped_probes: list[str] = Field(
        default_factory=list,
        description="MASS probe names that test this technique",
    )
    threat_items_count: int = Field(default=0, description="Related threat items")
    url: str | None = None


class TechniqueListResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    items: list[TechniqueResponse]
    pagination: PaginationMeta


class CoverageResponse(BaseModel):
    """Threat technique coverage summary."""

    model_config = ConfigDict(extra="forbid")

    total_techniques: int
    covered: int
    partially_covered: int
    not_covered: int
    coverage_percent: float
    by_tactic: dict[str, dict[str, int]] = Field(
        default_factory=dict,
        description="Coverage breakdown by MITRE ATLAS tactic",
    )


# ---------------------------------------------------------------------------
# Payload generation from threat intel
# ---------------------------------------------------------------------------

class GeneratePayloadsRequest(BaseModel):
    """Request to generate attack payloads from a threat item."""

    model_config = ConfigDict(extra="forbid")

    threat_item_id: str = Field(..., description="Threat item to generate payloads from")
    count: int = Field(default=5, ge=1, le=20, description="Number of payloads to generate")
    target_categories: list[str] = Field(
        default_factory=list,
        description="Attack categories to target (empty = auto-detect)",
    )


class GeneratedPayload(BaseModel):
    model_config = ConfigDict(extra="forbid")

    text: str = Field(..., description="The attack payload text")
    category: str = Field(..., description="Attack category")
    severity: str = Field(default="medium")
    description: str = Field(default="", description="What this payload tests")
    success_indicators: list[str] = Field(default_factory=list)


class GeneratePayloadsResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    threat_item_id: str
    payloads: list[GeneratedPayload]
    generated_count: int


# ---------------------------------------------------------------------------
# Module status
# ---------------------------------------------------------------------------

class ThreatIntelStatusResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    status: str = Field(default="healthy")
    active_feeds: int = Field(default=0)
    total_items: int = Field(default=0)
    new_items_24h: int = Field(default=0)
    actionable_items: int = Field(default=0)
    technique_coverage_percent: float = Field(default=0.0)
