"""Discovery schemas.

Request and response models for the deployment discovery API.
Discovery provides lightweight reconnaissance of a target before scanning,
identifying AI components, models, frameworks, and scan scope.
"""

from pydantic import BaseModel, ConfigDict, Field


class DiscoveryRequest(BaseModel):
    """Request to discover components in a deployment target."""

    model_config = ConfigDict(extra="forbid")

    path: str = Field(..., description="Local path to the deployment directory")
    include_dependencies: bool = Field(
        default=True, description="Parse and include dependency information"
    )


class DiscoveredComponent(BaseModel):
    """A component discovered during reconnaissance."""

    model_config = ConfigDict(extra="forbid")

    name: str = Field(..., description="Component name (usually filename)")
    component_type: str = Field(..., description="Type: code, config, context, infrastructure, knowledge")
    file_path: str = Field(..., description="Relative file path")
    size_bytes: int = Field(default=0, description="File size in bytes")


class DiscoveredDependency(BaseModel):
    """A dependency found in the deployment."""

    model_config = ConfigDict(extra="forbid")

    name: str = Field(..., description="Package/library name")
    version: str | None = Field(default=None, description="Version constraint")
    source: str = Field(default="unknown", description="Source file (requirements.txt, package.json, etc.)")
    is_ai_framework: bool = Field(default=False, description="Whether this is an AI/ML framework")


class ScanRecommendation(BaseModel):
    """Recommended scan configuration based on discovery."""

    model_config = ConfigDict(extra="forbid")

    recommended_profile: str = Field(..., description="Suggested scan profile: quick, standard, comprehensive")
    reason: str = Field(..., description="Why this profile is recommended")
    estimated_files: int = Field(default=0, description="Number of files that would be scanned")
    has_models: bool = Field(default=False, description="Model files detected")
    has_context: bool = Field(default=False, description="Context/prompt files detected")
    has_mcp: bool = Field(default=False, description="MCP configuration detected")
    has_workflows: bool = Field(default=False, description="Agent/workflow files detected")
    has_infrastructure: bool = Field(default=False, description="Infrastructure files detected")
    has_secrets_risk: bool = Field(default=False, description="Files that may contain secrets")


class DiscoveryResponse(BaseModel):
    """Response from deployment discovery."""

    model_config = ConfigDict(extra="forbid")

    path: str = Field(..., description="Path that was discovered")
    total_files: int = Field(default=0, description="Total files found (after exclusions)")
    total_components: int = Field(default=0, description="Components identified")
    components_by_type: dict[str, int] = Field(
        default_factory=dict, description="Component count by type"
    )
    ai_frameworks: list[str] = Field(
        default_factory=list, description="AI/ML frameworks detected"
    )
    model_files: list[str] = Field(
        default_factory=list, description="Model files found"
    )
    components: list[DiscoveredComponent] = Field(
        default_factory=list, description="All discovered components (truncated to 200)"
    )
    dependencies: list[DiscoveredDependency] = Field(
        default_factory=list, description="Dependencies found"
    )
    recommendation: ScanRecommendation = Field(
        ..., description="Scan recommendation based on discovery"
    )
