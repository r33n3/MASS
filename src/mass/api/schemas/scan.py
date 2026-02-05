"""Scan schemas."""

from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field

from mass.core.types import ScanStatus
from mass.api.schemas.common import IDMixin, TimestampMixin, PaginationMeta
from mass.api.schemas.deployment import DeploymentSummary


class ScanCreate(BaseModel):
    """Request to create a scan."""

    model_config = ConfigDict(extra="forbid")

    deployment_id: str = Field(..., description="Deployment to scan")
    name: str | None = Field(default=None, max_length=255, description="Scan name")
    profile: str = Field(default="standard", description="Scan profile: quick, standard, comprehensive, custom")
    config: dict | None = Field(default=None, description="Custom scan configuration")
    triggered_by: str | None = Field(default=None, description="What triggered the scan: user, api, webhook, scheduled")


class ScanStatusResponse(BaseModel):
    """Scan status update."""

    model_config = ConfigDict(extra="forbid")

    id: str = Field(..., description="Scan ID")
    status: ScanStatus = Field(..., description="Current status")
    progress_percent: float = Field(..., description="Progress percentage (0-100)")
    current_phase: str | None = Field(default=None, description="Current scan phase")
    status_message: str | None = Field(default=None, description="Status message")
    jobs_completed: int = Field(default=0, description="Jobs completed so far")
    jobs_total: int = Field(default=0, description="Total jobs in scan plan")


class ScanJobResponse(IDMixin, TimestampMixin):
    """Scan job response."""

    model_config = ConfigDict(extra="forbid")

    job_type: str = Field(..., description="Job type: model, context, mcp, workflow, etc.")
    component_id: str | None = Field(default=None, description="Component being analyzed")
    status: ScanStatus = Field(..., description="Job status")
    progress_percent: float = Field(default=0.0, description="Job progress")
    items_total: int = Field(default=0, description="Total items to process")
    items_completed: int = Field(default=0, description="Items completed")
    started_at: datetime | None = Field(default=None, description="Job start time")
    completed_at: datetime | None = Field(default=None, description="Job completion time")
    findings_count: int = Field(default=0, description="Findings discovered")
    error: str | None = Field(default=None, description="Error message if failed")


class ScanSeverityCounts(BaseModel):
    """Count of findings by severity."""

    model_config = ConfigDict(extra="forbid")

    critical: int = Field(default=0, description="Critical findings")
    high: int = Field(default=0, description="High findings")
    medium: int = Field(default=0, description="Medium findings")
    low: int = Field(default=0, description="Low findings")
    info: int = Field(default=0, description="Informational findings")


class ScanResponse(IDMixin, TimestampMixin):
    """Scan response schema."""

    model_config = ConfigDict(extra="forbid")

    deployment: DeploymentSummary = Field(..., description="Deployment being scanned")
    name: str | None = Field(default=None, description="Scan name")
    profile: str = Field(..., description="Scan profile")
    status: ScanStatus = Field(..., description="Scan status")
    status_message: str | None = Field(default=None, description="Status message")
    progress_percent: float = Field(default=0.0, description="Progress percentage")
    current_phase: str | None = Field(default=None, description="Current phase")
    started_at: datetime | None = Field(default=None, description="Scan start time")
    completed_at: datetime | None = Field(default=None, description="Scan completion time")
    duration_seconds: int | None = Field(default=None, description="Duration in seconds")
    findings_count: int = Field(default=0, description="Total findings")
    severity_counts: ScanSeverityCounts = Field(
        default_factory=ScanSeverityCounts,
        description="Findings by severity",
    )
    triggered_by: str | None = Field(default=None, description="What triggered the scan")
    jobs: list[ScanJobResponse] | None = Field(default=None, description="Individual scan jobs")


class ScanListResponse(BaseModel):
    """List of scans."""

    model_config = ConfigDict(extra="forbid")

    items: list[ScanResponse] = Field(..., description="List of scans")
    pagination: PaginationMeta = Field(..., description="Pagination metadata")


class ScanCancelResponse(BaseModel):
    """Response after cancelling a scan."""

    model_config = ConfigDict(extra="forbid")

    id: str = Field(..., description="Scan ID")
    status: ScanStatus = Field(..., description="New status")
    message: str = Field(default="Scan cancelled", description="Cancellation message")
