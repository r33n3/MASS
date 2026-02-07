"""Unified target inventory schemas.

Provides a single view of all scan targets — both filesystem-discovered
and database-registered — with status enrichment.
"""

from datetime import datetime
from enum import Enum

from pydantic import BaseModel, ConfigDict, Field

from mass.api.schemas.common import IDMixin, PaginationMeta, TimestampMixin
from mass.api.schemas.deployment import MCPServerConfig, TargetType


class TargetStatus(str, Enum):
    """Target lifecycle stage — maps to the analysis pipeline progression."""

    DISCOVERED = "discovered"          # Found on filesystem, nothing else done
    PROFILED = "profiled"              # Discovery ran: files, frameworks, models identified
    SCANNED = "scanned"                # Static analysis complete
    INTERROGATED = "interrogated"      # Dynamic testing complete (probes ran)


class TargetSource(str, Enum):
    """How the target was sourced."""

    LOCAL = "local"        # Mounted filesystem directory
    GITHUB = "github"      # Cloned GitHub repository
    REMOTE = "remote"      # Remote endpoint (model/agent/MCP)


class TargetScanSummary(BaseModel):
    """Scan history summary for a target."""

    model_config = ConfigDict(extra="forbid")

    total_scans: int = Field(default=0, description="Total number of scans")
    last_scan_at: datetime | None = Field(default=None, description="Last scan timestamp")
    last_scan_status: str | None = Field(default=None, description="Last scan status")
    total_findings: int = Field(default=0, description="Total findings across scans")
    critical_findings: int = Field(default=0, description="Critical severity findings")
    high_findings: int = Field(default=0, description="High severity findings")


class TargetDiscoveryInfo(BaseModel):
    """Filesystem discovery metadata."""

    model_config = ConfigDict(extra="forbid")

    file_count: int = Field(default=0, description="Number of files")
    has_models: bool = Field(default=False, description="Contains ML model files")
    has_code: bool = Field(default=False, description="Contains source code")
    ai_frameworks: list[str] = Field(default_factory=list, description="Detected AI frameworks")
    recommended_profile: str | None = Field(default=None, description="Recommended scan profile")


class TargetCreate(BaseModel):
    """Request to manually register a target."""

    model_config = ConfigDict(extra="forbid")

    name: str = Field(..., min_length=1, max_length=255, description="Target name")
    target_type: TargetType = Field(
        default=TargetType.DEPLOYMENT,
        description="Target type: deployment, mcp_server, model_file, skill_file, instruction_file, model_endpoint, agent_endpoint",
    )
    description: str | None = Field(default=None, max_length=5000, description="Target description")
    tags: list[str] | None = Field(default=None, description="Tags for categorization")
    auto_discover: bool = Field(
        default=False,
        description="Run filesystem discovery profiling on the target",
    )

    # Source location
    source_path: str | None = Field(default=None, description="Path to directory or file")
    source_ref: str | None = Field(default=None, description="Git branch/tag reference")
    target_files: list[str] | None = Field(default=None, description="Specific files to target")

    # Inline content
    content: str | None = Field(
        default=None,
        description="Inline content: system prompt, MCP config JSON, or code",
    )

    # Model endpoint fields
    model_endpoint: str | None = Field(default=None, description="Model API endpoint URL")
    model_provider: str | None = Field(default=None, description="Model provider")
    model_name: str | None = Field(default=None, description="Model identifier")
    model_api_key: str | None = Field(default=None, description="API key for model provider")
    system_prompt: str | None = Field(default=None, description="System prompt to test")

    # MCP server fields
    mcp_servers: list[MCPServerConfig] | None = Field(default=None, description="MCP server definitions")

    # Agent endpoint fields
    agent_url: str | None = Field(default=None, description="Agent API endpoint URL")
    agent_protocol: str | None = Field(default=None, description="Protocol: rest, grpc, mcp, a2a, custom")
    agent_auth_type: str | None = Field(default=None, description="Auth: bearer, api_key, oauth2, mtls, none")
    agent_auth_token: str | None = Field(default=None, description="Auth token for agent endpoint")
    upstream_agents: list[str] | None = Field(default=None, description="Upstream agent URLs")
    downstream_agents: list[str] | None = Field(default=None, description="Downstream agent URLs")


class TargetResponse(BaseModel):
    """Unified target in inventory listing."""

    model_config = ConfigDict(extra="forbid")

    id: str = Field(..., description="Target ID (deployment UUID or synthetic filesystem ID)")
    name: str = Field(..., description="Target name")
    target_type: str = Field(default="deployment", description="Target type")
    status: TargetStatus = Field(..., description="Lifecycle status")
    source: TargetSource = Field(..., description="How the target was sourced")
    source_path: str | None = Field(default=None, description="Filesystem or remote path")
    description: str | None = Field(default=None, description="Target description")
    tags: list[str] | None = Field(default=None, description="Tags")

    # Filesystem metadata (populated for discovered/local targets)
    file_count: int | None = Field(default=None, description="Number of files")
    has_models: bool | None = Field(default=None, description="Contains ML model files")
    has_code: bool | None = Field(default=None, description="Contains source code")

    # Scan summary (populated for scanned/interrogated targets)
    scan_summary: TargetScanSummary | None = Field(default=None, description="Scan history summary")

    # Pipeline progression
    next_action: str | None = Field(
        default=None,
        description="Next pipeline step: profile, scan, interrogate, or null (complete)",
    )

    created_at: datetime | None = Field(default=None, description="Registration timestamp")
    updated_at: datetime | None = Field(default=None, description="Last update timestamp")


class TargetDetailResponse(TargetResponse):
    """Extended target detail with scan history and type-specific fields."""

    discovery_info: TargetDiscoveryInfo | None = Field(default=None, description="Discovery profiling results")
    recent_scans: list[dict] | None = Field(default=None, description="Recent scan summaries")

    # Type-specific fields
    model_endpoint: str | None = Field(default=None, description="Model API endpoint URL")
    model_provider: str | None = Field(default=None, description="Model provider")
    model_name: str | None = Field(default=None, description="Model identifier")
    system_prompt: str | None = Field(default=None, description="System prompt")
    mcp_servers: list[MCPServerConfig] | None = Field(default=None, description="MCP server configs")
    agent_url: str | None = Field(default=None, description="Agent endpoint URL")
    agent_protocol: str | None = Field(default=None, description="Agent protocol")

    # Topology from scan discovery
    topology: dict | None = Field(default=None, description="Discovered deployment topology graph (nodes/edges)")


class TargetListResponse(BaseModel):
    """Paginated list of targets."""

    model_config = ConfigDict(extra="forbid")

    items: list[TargetResponse] = Field(..., description="List of targets")
    pagination: PaginationMeta = Field(..., description="Pagination metadata")
