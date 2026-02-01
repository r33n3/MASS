"""Compliance schemas."""

from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field

from mass.api.schemas.common import IDMixin, PaginationMeta


class ControlResponse(BaseModel):
    """Compliance control response."""

    model_config = ConfigDict(extra="forbid")

    id: str = Field(..., description="Control ID (e.g., LLM01)")
    name: str = Field(..., description="Control name")
    description: str = Field(..., description="Control description")
    category: str | None = Field(default=None, description="Control category")
    severity: str = Field(default="medium", description="Default severity if violated")


class FrameworkResponse(IDMixin):
    """Compliance framework response."""

    model_config = ConfigDict(extra="forbid")

    name: str = Field(..., description="Framework name")
    short_name: str = Field(..., description="Short name (e.g., owasp:llm)")
    version: str = Field(..., description="Framework version")
    description: str = Field(..., description="Framework description")
    url: str | None = Field(default=None, description="Official URL")
    controls: list[ControlResponse] = Field(..., description="Framework controls")
    control_count: int = Field(default=0, description="Number of controls")


class FrameworkListResponse(BaseModel):
    """List of compliance frameworks."""

    model_config = ConfigDict(extra="forbid")

    items: list[FrameworkResponse] = Field(..., description="List of frameworks")
    pagination: PaginationMeta = Field(..., description="Pagination metadata")


class AssessmentRequest(BaseModel):
    """Request for compliance assessment."""

    model_config = ConfigDict(extra="forbid")

    scan_id: str = Field(..., description="Scan to assess")
    frameworks: list[str] = Field(..., description="Framework IDs to assess against")
    include_evidence: bool = Field(default=True, description="Include evidence in results")


class ControlAssessment(BaseModel):
    """Assessment result for a single control."""

    model_config = ConfigDict(extra="forbid")

    control_id: str = Field(..., description="Control ID")
    control_name: str = Field(..., description="Control name")
    status: str = Field(..., description="Status: pass, fail, partial, not_applicable")
    finding_count: int = Field(default=0, description="Number of related findings")
    finding_ids: list[str] = Field(default_factory=list, description="Related finding IDs")
    notes: str | None = Field(default=None, description="Assessment notes")


class FrameworkAssessment(BaseModel):
    """Assessment result for a single framework."""

    model_config = ConfigDict(extra="forbid")

    framework_id: str = Field(..., description="Framework ID")
    framework_name: str = Field(..., description="Framework name")
    overall_status: str = Field(..., description="Overall status")
    pass_count: int = Field(default=0, description="Controls passed")
    fail_count: int = Field(default=0, description="Controls failed")
    partial_count: int = Field(default=0, description="Partially compliant")
    not_applicable_count: int = Field(default=0, description="Not applicable")
    compliance_percentage: float = Field(default=0.0, description="Compliance percentage")
    controls: list[ControlAssessment] = Field(..., description="Control assessments")


class AssessmentResponse(BaseModel):
    """Compliance assessment response."""

    model_config = ConfigDict(extra="forbid")

    id: str = Field(..., description="Assessment ID")
    scan_id: str = Field(..., description="Scan ID")
    created_at: datetime = Field(..., description="Assessment timestamp")
    overall_compliance: float = Field(..., description="Overall compliance percentage")
    frameworks: list[FrameworkAssessment] = Field(..., description="Framework assessments")
    summary: str = Field(..., description="Assessment summary")


class PresetResponse(BaseModel):
    """Compliance preset response."""

    model_config = ConfigDict(extra="forbid")

    id: str = Field(..., description="Preset ID")
    name: str = Field(..., description="Preset name")
    description: str = Field(..., description="Preset description")
    frameworks: list[str] = Field(..., description="Included frameworks")
    categories: list[str] = Field(..., description="Attack categories covered")
