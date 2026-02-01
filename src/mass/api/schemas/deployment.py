"""Deployment schemas."""

from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field

from mass.core.types import ComponentType
from mass.api.schemas.common import IDMixin, TimestampMixin, PaginationMeta


class ComponentResponse(IDMixin, TimestampMixin):
    """Component response schema."""

    model_config = ConfigDict(extra="forbid")

    name: str = Field(..., description="Component name")
    component_type: ComponentType = Field(..., description="Component type")
    description: str | None = Field(default=None, description="Component description")
    file_path: str | None = Field(default=None, description="Source file path")
    line_start: int | None = Field(default=None, description="Start line number")
    line_end: int | None = Field(default=None, description="End line number")
    model_provider: str | None = Field(default=None, description="Model provider (for model components)")
    model_name: str | None = Field(default=None, description="Model name (for model components)")
    mcp_server_url: str | None = Field(default=None, description="MCP server URL (for MCP components)")


class DeploymentCreate(BaseModel):
    """Request to create a deployment."""

    model_config = ConfigDict(extra="forbid")

    name: str = Field(..., min_length=1, max_length=255, description="Deployment name")
    description: str | None = Field(default=None, max_length=5000, description="Deployment description")
    version: str | None = Field(default=None, max_length=50, description="Version string")
    source_type: str = Field(
        default="local",
        description="Source type: local, git, s3, azure, gcs",
    )
    source_path: str | None = Field(default=None, description="Path to source")
    source_ref: str | None = Field(default=None, description="Git branch/tag reference")
    tags: list[str] | None = Field(default=None, description="Tags for categorization")


class DeploymentUpdate(BaseModel):
    """Request to update a deployment."""

    model_config = ConfigDict(extra="forbid")

    name: str | None = Field(default=None, min_length=1, max_length=255, description="Deployment name")
    description: str | None = Field(default=None, max_length=5000, description="Deployment description")
    version: str | None = Field(default=None, max_length=50, description="Version string")
    source_path: str | None = Field(default=None, description="Path to source")
    source_ref: str | None = Field(default=None, description="Git branch/tag reference")
    is_active: bool | None = Field(default=None, description="Whether deployment is active")
    tags: list[str] | None = Field(default=None, description="Tags for categorization")


class DeploymentResponse(IDMixin, TimestampMixin):
    """Deployment response schema."""

    model_config = ConfigDict(extra="forbid")

    name: str = Field(..., description="Deployment name")
    description: str | None = Field(default=None, description="Deployment description")
    version: str | None = Field(default=None, description="Version string")
    source_type: str = Field(..., description="Source type")
    source_path: str | None = Field(default=None, description="Path to source")
    source_ref: str | None = Field(default=None, description="Git branch/tag reference")
    is_active: bool = Field(..., description="Whether deployment is active")
    last_scanned_at: datetime | None = Field(default=None, description="Last scan time")
    tags: list[str] | None = Field(default=None, description="Tags")
    components: list[ComponentResponse] | None = Field(default=None, description="Deployment components")
    component_count: int = Field(default=0, description="Number of components")
    scan_count: int = Field(default=0, description="Number of scans")


class DeploymentListResponse(BaseModel):
    """List of deployments."""

    model_config = ConfigDict(extra="forbid")

    items: list[DeploymentResponse] = Field(..., description="List of deployments")
    pagination: PaginationMeta = Field(..., description="Pagination metadata")


class DeploymentSummary(IDMixin):
    """Minimal deployment reference."""

    model_config = ConfigDict(extra="forbid")

    name: str = Field(..., description="Deployment name")
    version: str | None = Field(default=None, description="Version string")
