"""Topology schemas for deployment architecture graph."""

from pydantic import BaseModel, ConfigDict, Field


class TopologyNodeSchema(BaseModel):
    """A node in the deployment topology graph."""

    model_config = ConfigDict(extra="forbid")

    id: str = Field(..., description="Unique node identifier")
    type: str = Field(
        ...,
        description="Node type: ai_agent, model_provider, database, cloud_service, "
        "mcp_server, tool, trigger, api_service, memory, vector_store",
    )
    name: str = Field(..., description="Display name")
    provider: str | None = Field(default=None, description="Cloud/model provider")
    icon_hint: str = Field(default="", description="Icon hint for dashboard rendering")
    metadata: dict = Field(default_factory=dict, description="Additional node metadata")


class TopologyEdgeSchema(BaseModel):
    """An edge connecting two nodes in the topology graph."""

    model_config = ConfigDict(extra="forbid")

    id: str = Field(..., description="Unique edge identifier")
    source: str = Field(..., description="Source node ID")
    target: str = Field(..., description="Target node ID")
    edge_type: str = Field(
        ...,
        description="Edge type: data_flow, auth, tool_call, api_call, model_query",
    )
    label: str = Field(default="", description="Edge label")
    metadata: dict = Field(default_factory=dict, description="Additional edge metadata")


class TopologyResponse(BaseModel):
    """Full topology graph response."""

    model_config = ConfigDict(extra="forbid")

    nodes: list[TopologyNodeSchema] = Field(default_factory=list, description="Graph nodes")
    edges: list[TopologyEdgeSchema] = Field(default_factory=list, description="Graph edges")
    environment: dict = Field(default_factory=dict, description="Detected environment profile")


class TopologyUpdate(BaseModel):
    """Replace the entire topology graph."""

    model_config = ConfigDict(extra="forbid")

    nodes: list[TopologyNodeSchema] = Field(..., description="Graph nodes")
    edges: list[TopologyEdgeSchema] = Field(..., description="Graph edges")


class TopologyNodeUpdate(BaseModel):
    """Update a single node's metadata."""

    model_config = ConfigDict(extra="forbid")

    name: str | None = Field(default=None, description="Updated display name")
    provider: str | None = Field(default=None, description="Updated provider")
    icon_hint: str | None = Field(default=None, description="Updated icon hint")
    metadata: dict | None = Field(default=None, description="Updated metadata (merged)")


class TopologyImport(BaseModel):
    """Import topology from an external platform.

    Accepts raw JSON from automation platforms (n8n, Make, etc.)
    or a direct node/edge structure.
    """

    model_config = ConfigDict(extra="forbid")

    format: str = Field(
        default="generic",
        description="Source format: generic, n8n, make",
    )
    data: dict = Field(..., description="Raw topology data from the source platform")
