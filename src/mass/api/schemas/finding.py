"""Finding schemas."""

from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field

from mass.core.types import Severity, AttackCategory, ComponentType
from mass.api.schemas.common import IDMixin, TimestampMixin, PaginationMeta


class EvidenceResponse(IDMixin, TimestampMixin):
    """Evidence response schema."""

    model_config = ConfigDict(extra="forbid")

    evidence_type: str = Field(..., description="Type of evidence: prompt, response, config, code, screenshot")
    content: str = Field(..., description="Evidence content")
    source_file: str | None = Field(default=None, description="Source file path")
    source_line: int | None = Field(default=None, description="Source line number")
    prompt: str | None = Field(default=None, description="Prompt that triggered the finding")
    response: str | None = Field(default=None, description="Model response")


class RemediationInfo(BaseModel):
    """Remediation information."""

    model_config = ConfigDict(extra="forbid")

    description: str = Field(..., description="How to fix this issue")
    effort: str = Field(default="medium", description="Effort level: low, medium, high")
    references: list[str] = Field(default_factory=list, description="Reference URLs")


class ComplianceMapping(BaseModel):
    """Compliance framework mapping."""

    model_config = ConfigDict(extra="forbid")

    cwe_ids: list[str] = Field(default_factory=list, description="CWE IDs")
    owasp_ids: list[str] = Field(default_factory=list, description="OWASP LLM Top 10 IDs")
    mitre_ids: list[str] = Field(default_factory=list, description="MITRE ATLAS IDs")


class FindingResponse(IDMixin, TimestampMixin):
    """Finding response schema."""

    model_config = ConfigDict(extra="forbid")

    scan_id: str = Field(..., description="Scan ID")
    title: str = Field(..., description="Finding title")
    description: str = Field(..., description="Detailed description")
    severity: Severity = Field(..., description="Severity level")
    category: AttackCategory = Field(..., description="Attack category")
    component_type: ComponentType = Field(..., description="Affected component type")
    component_name: str = Field(..., description="Affected component name")
    file_path: str | None = Field(default=None, description="File path if applicable")
    line_number: int | None = Field(default=None, description="Line number if applicable")
    confidence: float = Field(default=1.0, description="Confidence score (0-1)")
    false_positive: bool = Field(default=False, description="Marked as false positive")
    suppressed: bool = Field(default=False, description="Suppressed from reports")
    acknowledged: bool = Field(default=False, description="Acknowledged by user")
    acknowledged_by: str | None = Field(default=None, description="User who acknowledged")
    acknowledged_at: datetime | None = Field(default=None, description="When acknowledged")
    compliance: ComplianceMapping = Field(
        default_factory=ComplianceMapping,
        description="Compliance framework mappings",
    )
    remediation: RemediationInfo | None = Field(default=None, description="Remediation guidance")
    probe_name: str | None = Field(default=None, description="Probe that discovered this")
    detector_name: str | None = Field(default=None, description="Detector that classified this")
    evidence: list[EvidenceResponse] | None = Field(default=None, description="Supporting evidence")
    tags: list[str] = Field(default_factory=list, description="Tags")


class FindingListResponse(BaseModel):
    """List of findings."""

    model_config = ConfigDict(extra="forbid")

    items: list[FindingResponse] = Field(..., description="List of findings")
    pagination: PaginationMeta = Field(..., description="Pagination metadata")


class FindingSummary(BaseModel):
    """Summary of findings for a scan."""

    model_config = ConfigDict(extra="forbid")

    total: int = Field(default=0, description="Total findings")
    by_severity: dict[str, int] = Field(default_factory=dict, description="Count by severity")
    by_category: dict[str, int] = Field(default_factory=dict, description="Count by category")
    by_component: dict[str, int] = Field(default_factory=dict, description="Count by component type")
    false_positives: int = Field(default=0, description="False positives")
    suppressed: int = Field(default=0, description="Suppressed findings")
    acknowledged: int = Field(default=0, description="Acknowledged findings")


class FindingUpdate(BaseModel):
    """Request to update a finding."""

    model_config = ConfigDict(extra="forbid")

    false_positive: bool | None = Field(default=None, description="Mark as false positive")
    suppressed: bool | None = Field(default=None, description="Suppress from reports")
    acknowledged: bool | None = Field(default=None, description="Acknowledge the finding")
    tags: list[str] | None = Field(default=None, description="Update tags")
