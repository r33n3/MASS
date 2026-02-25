"""GitHub issue generation schemas.

Request and response models for exporting security findings as GitHub Issues.
Per ARCHITECTURE.md Section 8.1 — Issue Generation module slot.
"""

from pydantic import BaseModel, ConfigDict, Field

from mass.api.schemas.common import PaginationMeta


# ---------------------------------------------------------------------------
# GitHub integration config
# ---------------------------------------------------------------------------

class GitHubConfigCreate(BaseModel):
    """Create a GitHub issue export integration."""

    model_config = ConfigDict(extra="forbid")

    name: str = Field(..., min_length=1, max_length=255, description="Integration name")
    owner: str = Field(..., min_length=1, max_length=255, description="GitHub repo owner or org")
    repo: str = Field(..., min_length=1, max_length=255, description="GitHub repo name")
    token: str = Field(..., min_length=1, description="GitHub personal access token (PAT)")
    api_url: str = Field(
        default="https://api.github.com",
        description="GitHub API base URL (change for GitHub Enterprise)",
    )
    labels: list[str] = Field(
        default_factory=lambda: ["security", "mass-finding"],
        description="Labels to apply to created issues",
    )
    severity_labels: bool = Field(
        default=True,
        description="Add severity as a label (e.g., 'severity:critical')",
    )
    category_labels: bool = Field(
        default=True,
        description="Add finding category as a label",
    )
    auto_export: bool = Field(
        default=False,
        description="Auto-export findings when a scan completes",
    )
    auto_export_min_severity: str = Field(
        default="high",
        description="Minimum severity for auto-export: critical, high, medium, low",
    )
    deployment_id: str | None = Field(
        default=None,
        description="Scope auto-export to a specific deployment",
    )
    assignees: list[str] = Field(
        default_factory=list,
        description="GitHub usernames to assign to created issues",
    )
    is_active: bool = Field(default=True)


class GitHubConfigUpdate(BaseModel):
    """Update a GitHub integration."""

    model_config = ConfigDict(extra="forbid")

    name: str | None = None
    owner: str | None = None
    repo: str | None = None
    token: str | None = None
    api_url: str | None = None
    labels: list[str] | None = None
    severity_labels: bool | None = None
    category_labels: bool | None = None
    auto_export: bool | None = None
    auto_export_min_severity: str | None = None
    deployment_id: str | None = None
    assignees: list[str] | None = None
    is_active: bool | None = None


class GitHubConfigResponse(BaseModel):
    """GitHub integration response (token masked)."""

    model_config = ConfigDict(extra="forbid")

    id: str = Field(..., description="Integration ID")
    name: str
    owner: str
    repo: str
    token_last4: str = Field(..., description="Last 4 chars of the PAT")
    api_url: str
    labels: list[str]
    severity_labels: bool
    category_labels: bool
    auto_export: bool
    auto_export_min_severity: str
    deployment_id: str | None = None
    assignees: list[str]
    is_active: bool
    total_exported: int = Field(default=0, description="Total issues exported")
    last_export_at: str | None = None
    created_at: str
    updated_at: str


class GitHubConfigListResponse(BaseModel):
    """List of GitHub integrations."""

    model_config = ConfigDict(extra="forbid")

    items: list[GitHubConfigResponse]
    pagination: PaginationMeta


# ---------------------------------------------------------------------------
# Issue export
# ---------------------------------------------------------------------------

class ExportRequest(BaseModel):
    """Request to export findings as GitHub Issues."""

    model_config = ConfigDict(extra="forbid")

    scan_id: str = Field(..., description="Scan whose findings to export")
    min_severity: str = Field(
        default="medium",
        description="Minimum severity to export: critical, high, medium, low",
    )
    categories: list[str] | None = Field(
        default=None,
        description="Filter by finding categories (None = all)",
    )
    skip_duplicates: bool = Field(
        default=True,
        description="Skip findings whose fingerprint already has an exported issue",
    )
    dry_run: bool = Field(
        default=False,
        description="Preview issues without actually creating them on GitHub",
    )


class ExportedIssue(BaseModel):
    """A single exported GitHub Issue."""

    model_config = ConfigDict(extra="forbid")

    finding_id: str = Field(..., description="MASS finding ID")
    finding_title: str
    severity: str
    github_issue_number: int | None = Field(default=None, description="GitHub issue #")
    github_issue_url: str | None = Field(default=None, description="GitHub issue URL")
    status: str = Field(..., description="created, skipped_duplicate, failed, dry_run")
    error: str | None = None


class ExportResponse(BaseModel):
    """Response after exporting findings."""

    model_config = ConfigDict(extra="forbid")

    integration_id: str
    scan_id: str
    total_findings: int = Field(..., description="Total findings matching filters")
    exported: int = Field(default=0, description="Issues created on GitHub")
    skipped: int = Field(default=0, description="Skipped (duplicates or filtered)")
    failed: int = Field(default=0, description="Failed to create")
    dry_run: bool = False
    issues: list[ExportedIssue]


class ExportedIssueListResponse(BaseModel):
    """List of previously exported issues."""

    model_config = ConfigDict(extra="forbid")

    items: list[ExportedIssue]
    pagination: PaginationMeta


# ---------------------------------------------------------------------------
# Module status
# ---------------------------------------------------------------------------

class IntegrationsStatusResponse(BaseModel):
    """Integrations module health."""

    model_config = ConfigDict(extra="forbid")

    status: str = Field(default="healthy")
    active_github_configs: int = Field(default=0)
    total_exported: int = Field(default=0)
