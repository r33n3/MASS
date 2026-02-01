"""Report schemas."""

from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field

from mass.api.schemas.common import IDMixin, TimestampMixin, PaginationMeta


class ReportCreate(BaseModel):
    """Request to generate a report."""

    model_config = ConfigDict(extra="forbid")

    scan_id: str = Field(..., description="Scan to report on")
    name: str | None = Field(default=None, max_length=255, description="Report name")
    report_type: str = Field(default="security", description="Report type: security, compliance, executive")
    format: str = Field(default="html", description="Output format: html, pdf, sarif, json, markdown, csv, junit")
    include_evidence: bool = Field(default=True, description="Include evidence in report")
    include_remediation: bool = Field(default=True, description="Include remediation guidance")
    frameworks: list[str] | None = Field(default=None, description="Compliance frameworks to include")


class ReportResponse(IDMixin, TimestampMixin):
    """Report response schema."""

    model_config = ConfigDict(extra="forbid")

    scan_id: str = Field(..., description="Scan ID")
    name: str = Field(..., description="Report name")
    report_type: str = Field(..., description="Report type")
    format: str = Field(..., description="Output format")
    status: str = Field(..., description="Status: pending, generating, completed, failed")
    file_size: int | None = Field(default=None, description="File size in bytes")
    file_path: str | None = Field(default=None, description="File path or URL")
    error_message: str | None = Field(default=None, description="Error message if failed")
    generated_at: datetime | None = Field(default=None, description="Generation completion time")
    expires_at: datetime | None = Field(default=None, description="Download expiration time")


class ReportListResponse(BaseModel):
    """List of reports."""

    model_config = ConfigDict(extra="forbid")

    items: list[ReportResponse] = Field(..., description="List of reports")
    pagination: PaginationMeta = Field(..., description="Pagination metadata")


class ExportRequest(BaseModel):
    """Request to export a report."""

    model_config = ConfigDict(extra="forbid")

    format: str = Field(default="html", description="Export format")
    include_evidence: bool = Field(default=True, description="Include evidence")
    include_remediation: bool = Field(default=True, description="Include remediation")
    filter_severity: list[str] | None = Field(default=None, description="Filter by severity levels")
    filter_category: list[str] | None = Field(default=None, description="Filter by categories")


class ExportResponse(BaseModel):
    """Export response."""

    model_config = ConfigDict(extra="forbid")

    download_url: str = Field(..., description="URL to download the report")
    expires_at: datetime = Field(..., description="URL expiration time")
    format: str = Field(..., description="Export format")
    file_size: int = Field(..., description="File size in bytes")


class CompareRequest(BaseModel):
    """Request to compare two scans."""

    model_config = ConfigDict(extra="forbid")

    scan_id_1: str = Field(..., description="First scan ID")
    scan_id_2: str = Field(..., description="Second scan ID")
    format: str = Field(default="json", description="Output format")


class FindingDiff(BaseModel):
    """Difference in a finding between scans."""

    model_config = ConfigDict(extra="forbid")

    finding_id: str = Field(..., description="Finding ID")
    title: str = Field(..., description="Finding title")
    severity: str = Field(..., description="Finding severity")
    status: str = Field(..., description="Status: new, fixed, unchanged, changed")
    scan_1_state: dict | None = Field(default=None, description="State in first scan")
    scan_2_state: dict | None = Field(default=None, description="State in second scan")


class CompareResponse(BaseModel):
    """Scan comparison response."""

    model_config = ConfigDict(extra="forbid")

    scan_id_1: str = Field(..., description="First scan ID")
    scan_id_2: str = Field(..., description="Second scan ID")
    scan_1_date: datetime = Field(..., description="First scan date")
    scan_2_date: datetime = Field(..., description="Second scan date")
    new_findings: int = Field(default=0, description="New findings in scan 2")
    fixed_findings: int = Field(default=0, description="Findings fixed in scan 2")
    unchanged_findings: int = Field(default=0, description="Unchanged findings")
    changed_findings: int = Field(default=0, description="Changed findings")
    severity_trend: dict[str, int] = Field(default_factory=dict, description="Severity change (+/-)")
    differences: list[FindingDiff] = Field(..., description="Individual finding differences")


class WebhookCreate(BaseModel):
    """Request to create a webhook."""

    model_config = ConfigDict(extra="forbid")

    name: str = Field(..., min_length=1, max_length=255, description="Webhook name")
    url: str = Field(..., description="Webhook URL")
    events: list[str] = Field(..., description="Events to trigger on")
    secret: str | None = Field(default=None, description="Signing secret")
    is_active: bool = Field(default=True, description="Whether webhook is active")


class WebhookResponse(IDMixin, TimestampMixin):
    """Webhook response schema."""

    model_config = ConfigDict(extra="forbid")

    name: str = Field(..., description="Webhook name")
    url: str = Field(..., description="Webhook URL")
    events: list[str] = Field(..., description="Events that trigger this webhook")
    is_active: bool = Field(..., description="Whether webhook is active")
    last_triggered_at: datetime | None = Field(default=None, description="Last trigger time")
    failure_count: int = Field(default=0, description="Consecutive failure count")


class WebhookListResponse(BaseModel):
    """List of webhooks."""

    model_config = ConfigDict(extra="forbid")

    items: list[WebhookResponse] = Field(..., description="List of webhooks")
    pagination: PaginationMeta = Field(..., description="Pagination metadata")
