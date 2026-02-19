"""CI/CD integration schemas.

Request and response models for the CI/CD integration module.
Supports GitHub Actions, GitLab CI, and generic webhook providers.
"""

from datetime import datetime
from enum import Enum

from pydantic import BaseModel, ConfigDict, Field

from mass.api.schemas.common import IDMixin, PaginationMeta


class CICDProvider(str, Enum):
    """Supported CI/CD providers."""

    GITHUB = "github"
    GITLAB = "gitlab"
    GENERIC = "generic"


class GateVerdict(str, Enum):
    """CI/CD quality gate verdicts."""

    PASS = "pass"
    FAIL = "fail"
    WARN = "warn"
    PENDING = "pending"
    ERROR = "error"


# ---------------------------------------------------------------------------
# Integration CRUD
# ---------------------------------------------------------------------------

class CICDIntegrationCreate(BaseModel):
    """Create a new CI/CD integration."""

    model_config = ConfigDict(extra="forbid")

    name: str = Field(..., min_length=1, max_length=255, description="Integration name")
    provider: CICDProvider = Field(..., description="CI/CD provider type")
    repository: str = Field(
        ..., min_length=1, max_length=500,
        description="Repository identifier (e.g., 'owner/repo')",
    )
    webhook_secret: str | None = Field(
        default=None, description="Shared secret for HMAC webhook verification",
    )
    deployment_id: str | None = Field(
        default=None,
        description="Default deployment to scan. If not set, auto-creates deployment.",
    )
    scan_profile: str = Field(
        default="standard",
        description="Scan profile: quick, standard, comprehensive",
    )
    branch_filter: list[str] = Field(
        default_factory=lambda: ["main", "master"],
        description="Branches that trigger scans. Empty list = all branches.",
    )
    trigger_on: list[str] = Field(
        default_factory=lambda: ["push", "pull_request"],
        description="Events that trigger scans: push, pull_request, tag",
    )
    severity_threshold: str = Field(
        default="high",
        description="Minimum severity to fail the gate: critical, high, medium, low",
    )
    auto_gate: bool = Field(
        default=True,
        description="Automatically fail CI gate when findings exceed threshold",
    )
    is_active: bool = Field(default=True, description="Whether this integration is active")


class CICDIntegrationUpdate(BaseModel):
    """Update a CI/CD integration."""

    model_config = ConfigDict(extra="forbid")

    name: str | None = Field(default=None, max_length=255)
    webhook_secret: str | None = None
    deployment_id: str | None = None
    scan_profile: str | None = None
    branch_filter: list[str] | None = None
    trigger_on: list[str] | None = None
    severity_threshold: str | None = None
    auto_gate: bool | None = None
    is_active: bool | None = None


class CICDIntegrationResponse(IDMixin):
    """CI/CD integration response."""

    model_config = ConfigDict(extra="ignore")

    name: str = Field(..., description="Integration name")
    provider: CICDProvider = Field(..., description="CI/CD provider")
    repository: str = Field(..., description="Repository identifier")
    deployment_id: str | None = Field(default=None, description="Associated deployment")
    scan_profile: str = Field(..., description="Scan profile")
    branch_filter: list[str] = Field(..., description="Branch filters")
    trigger_on: list[str] = Field(..., description="Trigger events")
    severity_threshold: str = Field(..., description="Gate severity threshold")
    auto_gate: bool = Field(..., description="Auto-gate enabled")
    is_active: bool = Field(..., description="Integration active")
    total_scans: int = Field(default=0, description="Total scans triggered")
    last_scan_at: str | None = Field(default=None, description="Last scan timestamp")
    created_at: str = Field(..., description="Creation timestamp")
    updated_at: str = Field(..., description="Last update timestamp")


class CICDIntegrationListResponse(BaseModel):
    """List of CI/CD integrations."""

    model_config = ConfigDict(extra="forbid")

    items: list[CICDIntegrationResponse] = Field(..., description="Integrations")
    pagination: PaginationMeta = Field(..., description="Pagination metadata")


# ---------------------------------------------------------------------------
# Webhook payloads
# ---------------------------------------------------------------------------

class CICDWebhookResponse(BaseModel):
    """Response after receiving a CI/CD webhook."""

    model_config = ConfigDict(extra="forbid")

    accepted: bool = Field(..., description="Whether the webhook was accepted")
    scan_id: str | None = Field(default=None, description="Triggered scan ID")
    integration_id: str = Field(..., description="Matched integration ID")
    message: str = Field(..., description="Status message")


# ---------------------------------------------------------------------------
# Gate (quality gate for CI pipelines)
# ---------------------------------------------------------------------------

class GateSeverityCounts(BaseModel):
    """Finding counts by severity for gate evaluation."""

    model_config = ConfigDict(extra="forbid")

    critical: int = Field(default=0)
    high: int = Field(default=0)
    medium: int = Field(default=0)
    low: int = Field(default=0)
    info: int = Field(default=0)


class GateResponse(BaseModel):
    """CI/CD quality gate response.

    CI pipelines poll this endpoint to determine pass/fail.
    """

    model_config = ConfigDict(extra="forbid")

    scan_id: str = Field(..., description="Scan ID")
    verdict: GateVerdict = Field(..., description="Gate verdict: pass, fail, warn, pending, error")
    scan_status: str = Field(..., description="Current scan status")
    severity_threshold: str = Field(..., description="Configured severity threshold")
    findings: GateSeverityCounts = Field(
        default_factory=GateSeverityCounts, description="Finding counts",
    )
    total_findings: int = Field(default=0, description="Total findings above threshold")
    message: str = Field(..., description="Human-readable verdict message")
    scan_url: str | None = Field(default=None, description="URL to view scan results")
    sarif_url: str | None = Field(default=None, description="URL to download SARIF report")
    duration_seconds: int | None = Field(default=None, description="Scan duration")


# ---------------------------------------------------------------------------
# Build status (tracks CI/CD-triggered scans)
# ---------------------------------------------------------------------------

class CICDBuildResponse(BaseModel):
    """A CI/CD-triggered build/scan record."""

    model_config = ConfigDict(extra="ignore")

    id: str = Field(..., description="Build record ID")
    integration_id: str = Field(..., description="Integration that triggered this")
    scan_id: str | None = Field(default=None, description="Associated scan ID")
    provider: CICDProvider = Field(..., description="CI/CD provider")
    repository: str = Field(..., description="Repository")
    branch: str = Field(..., description="Branch name")
    commit_sha: str | None = Field(default=None, description="Commit SHA")
    event_type: str = Field(..., description="Trigger event: push, pull_request, tag")
    gate_verdict: GateVerdict = Field(default=GateVerdict.PENDING, description="Gate result")
    status: str = Field(..., description="Build status")
    created_at: str = Field(..., description="Timestamp")


class CICDBuildListResponse(BaseModel):
    """List of CI/CD builds."""

    model_config = ConfigDict(extra="forbid")

    items: list[CICDBuildResponse] = Field(..., description="Build records")
    pagination: PaginationMeta = Field(..., description="Pagination metadata")


# ---------------------------------------------------------------------------
# Module status
# ---------------------------------------------------------------------------

class CICDStatusResponse(BaseModel):
    """CI/CD module health / availability."""

    model_config = ConfigDict(extra="forbid")

    status: str = Field(default="healthy", description="Module status")
    active_integrations: int = Field(default=0, description="Number of active integrations")
    total_builds: int = Field(default=0, description="Total builds processed")
    recent_scans: int = Field(default=0, description="Scans in last 24h")
