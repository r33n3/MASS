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
    target_files: list[str] | None = Field(
        default=None,
        description="Specific file paths to scan. If null, scans all files in the deployment source path.",
    )
    exclude_paths: list[str] | None = Field(
        default=None,
        description="Glob patterns or file paths to exclude (e.g. 'docs/**', 'tests/', '*.md'). "
                    "Applied after target_files or full file list using fnmatch.",
    )


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


class VerdictSummary(BaseModel):
    """Summary of the Final Verdict Judge assessment."""

    model_config = ConfigDict(extra="forbid")

    overall_assessment: str = Field(..., description="One-sentence security verdict")
    risk_level: str = Field(..., description="Overall risk level: safe, low, medium, high, critical")
    confidence: float = Field(..., description="Judge confidence (0-1)")
    narrative: str = Field(..., description="Expert security analysis narrative")
    key_themes: list[str] = Field(default_factory=list, description="Top security themes identified")
    executive_summary: str = Field(..., description="Non-technical summary")
    recommendations_count: int = Field(default=0, description="Number of recommendations")
    attack_chains_count: int = Field(default=0, description="Number of attack chains identified")


class ThreatModelSummary(BaseModel):
    """Summary of the STRIDE-AI threat model."""

    model_config = ConfigDict(extra="forbid")

    overall_risk_level: str = Field(..., description="Overall risk: safe, low, medium, high, critical")
    total_threats: int = Field(default=0, description="Total threats identified")
    threats_by_stride: dict[str, int] = Field(default_factory=dict, description="Threat counts by STRIDE-AI category")
    threats_by_severity: dict[str, int] = Field(default_factory=dict, description="Threat counts by severity")
    data_classification: str = Field(default="internal", description="Inferred data classification")
    phases_completed: list[str] = Field(default_factory=list, description="Scan phases contributing to model")
    top_risks: list[str] = Field(default_factory=list, description="Top threat IDs by risk score")


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
    verdict: VerdictSummary | None = Field(default=None, description="Final Verdict Judge assessment")
    threat_model: ThreatModelSummary | None = Field(default=None, description="STRIDE-AI threat model summary")


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
