"""Deployment schemas."""

from datetime import datetime
from enum import Enum

from pydantic import BaseModel, ConfigDict, Field

from mass.core.types import ComponentType
from mass.api.schemas.common import IDMixin, TimestampMixin, PaginationMeta


class TargetType(str, Enum):
    """Type of scan target.

    Determines which analyzers run and how discovery works.
    """

    DEPLOYMENT = "deployment"              # Full directory (default)
    MCP_SERVER = "mcp_server"              # MCP server config (JSON/YAML)
    MODEL_FILE = "model_file"              # GGUF, safetensors, etc.
    SKILL_FILE = "skill_file"              # Python/JS file with AI logic
    INSTRUCTION_FILE = "instruction_file"  # System prompt / instruction text
    MODEL_ENDPOINT = "model_endpoint"      # Remote model API (dynamic only)
    AGENT_ENDPOINT = "agent_endpoint"      # Agent-to-agent communication endpoint


class MCPServerConfig(BaseModel):
    """MCP server configuration for a deployment."""

    model_config = ConfigDict(extra="forbid")

    name: str = Field(..., description="Server name")
    url: str | None = Field(default=None, description="Server URL (for SSE/HTTP transport)")
    command: str | None = Field(default=None, description="Server command (for stdio transport)")
    args: list[str] | None = Field(default=None, description="Command arguments")
    transport: str = Field(default="stdio", description="Transport type: stdio, sse, http")
    auth_token: str | None = Field(default=None, description="Authentication token")


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
    target_type: TargetType = Field(
        default=TargetType.DEPLOYMENT,
        description=(
            "Target type: deployment (full directory), mcp_server, model_file, "
            "skill_file, instruction_file, model_endpoint, agent_endpoint"
        ),
    )
    target_files: list[str] | None = Field(
        default=None,
        description="Specific file paths to scan (for single-target types)",
    )
    source_type: str = Field(
        default="local",
        description="Source type: local, git, s3, azure, gcs",
    )
    source_path: str | None = Field(default=None, description="Path to source")
    source_ref: str | None = Field(default=None, description="Git branch/tag reference")
    tags: list[str] | None = Field(default=None, description="Tags for categorization")

    # Model configuration (for dynamic analysis)
    model_endpoint: str | None = Field(default=None, description="Model API endpoint URL")
    model_provider: str | None = Field(
        default=None,
        description=(
            "Model provider: openai, anthropic, bedrock, azure_openai, "
            "gemini, grok, ollama, huggingface, custom"
        ),
    )
    model_name: str | None = Field(default=None, description="Model identifier (e.g. gpt-4o, claude-3-5-sonnet)")
    model_api_key: str | None = Field(default=None, description="API key for the model provider")
    system_prompt: str | None = Field(default=None, description="System prompt / context instructions to test")

    # MCP server configurations
    mcp_servers: list[MCPServerConfig] | None = Field(
        default=None,
        description="MCP tool servers the deployment uses",
    )


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

    # Model configuration
    model_endpoint: str | None = Field(default=None, description="Model API endpoint URL")
    model_provider: str | None = Field(default=None, description="Model provider")
    model_name: str | None = Field(default=None, description="Model identifier")
    model_api_key: str | None = Field(default=None, description="API key for the model provider")
    system_prompt: str | None = Field(default=None, description="System prompt / context instructions")

    # MCP server configurations
    mcp_servers: list[MCPServerConfig] | None = Field(default=None, description="MCP tool servers")


class DeploymentResponse(IDMixin, TimestampMixin):
    """Deployment response schema."""

    model_config = ConfigDict(extra="forbid")

    name: str = Field(..., description="Deployment name")
    description: str | None = Field(default=None, description="Deployment description")
    version: str | None = Field(default=None, description="Version string")
    target_type: str = Field(default="deployment", description="Target type")
    target_files: list[str] | None = Field(default=None, description="Specific target files")
    source_type: str = Field(..., description="Source type")
    source_path: str | None = Field(default=None, description="Path to source")
    source_ref: str | None = Field(default=None, description="Git branch/tag reference")
    is_active: bool = Field(..., description="Whether deployment is active")
    last_scanned_at: datetime | None = Field(default=None, description="Last scan time")
    tags: list[str] | None = Field(default=None, description="Tags")
    components: list[ComponentResponse] | None = Field(default=None, description="Deployment components")
    component_count: int = Field(default=0, description="Number of components")
    scan_count: int = Field(default=0, description="Number of scans")

    # Model configuration
    model_endpoint: str | None = Field(default=None, description="Model API endpoint URL")
    model_provider: str | None = Field(default=None, description="Model provider")
    model_name: str | None = Field(default=None, description="Model identifier")
    system_prompt: str | None = Field(default=None, description="System prompt / context instructions")

    # MCP server configurations
    mcp_servers: list[MCPServerConfig] | None = Field(default=None, description="MCP tool servers")


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
