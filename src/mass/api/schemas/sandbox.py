"""Request/response schemas for sandbox API endpoints."""

from __future__ import annotations

from pydantic import BaseModel, Field


class SandboxRequest(BaseModel):
    """Request to start a sandbox run."""

    scenario: dict | None = Field(None, description="Inline scenario dict")
    scenario_name: str | None = Field(None, description="Reference a named built-in scenario")
    scenario_yaml: str | None = Field(None, description="Raw YAML string")

    # Model config overrides
    model_provider: str | None = Field(None, description="Override scenario model provider")
    model_name: str | None = Field(None, description="Override scenario model name")
    model_endpoint: str | None = Field(None, description="Override model endpoint URL")
    model_api_key: str | None = Field(None, description="Override model API key")

    # Options
    seed: int | None = Field(None, description="RNG seed for reproducibility")
    use_judge: bool = Field(False, description="Enable LLM judge scoring")

    # Tool execution mode
    tool_mode: str | None = Field(None, description="mock, live, or hybrid")
    mcp_transport: str | None = Field(None, description="stdio, http, or sse")
    mcp_command: str | None = Field(None, description="Command for stdio transport")
    mcp_args: list[str] | None = Field(None, description="Arguments for stdio command")
    mcp_url: str | None = Field(None, description="URL for http/sse transport")
    mcp_api_key: str | None = Field(None, description="API key for MCP server")
    mcp_headers: dict[str, str] | None = Field(None, description="Headers for MCP server")
    live_tools: list[str] | None = Field(None, description="Tool names to call live in hybrid mode")

    # Context
    scan_id: str | None = Field(None, description="Link to a scan")
    deployment_id: str | None = Field(None, description="Link to a deployment/target")
    target_id: str | None = Field(None, description="Alias for deployment_id")


class SandboxJobResponse(BaseModel):
    """Summary response for a sandbox job."""

    job_id: str
    status: str = "pending"
    scenario_name: str = ""
    model_used: str = ""
    provider_used: str = ""
    turns_completed: int = 0
    turns_total: int = 0
    passed_assertions: int = 0
    failed_assertions: int = 0
    findings_count: int = 0
    duration_seconds: float = 0.0
    score: float | None = None
    deployment_id: str | None = None
    created_at: str = ""


class SandboxDetailResponse(SandboxJobResponse):
    """Full detail response for a sandbox job."""

    steps: list[dict] = []
    findings: list[dict] = []
    scores: dict | None = None
    telemetry: dict | None = None
    compliance: dict | None = None
    guardrail_recommendations: list[dict] = []


class ScenarioInfo(BaseModel):
    """Summary of an available scenario."""

    name: str
    category: str = "general"
    description: str = ""
    tags: list[str] = []
    turns_count: int = 0
    source: str = "builtin"  # builtin | custom | generated
    file: str | None = None


class ScenarioUpload(BaseModel):
    """Upload a custom scenario."""

    yaml_content: str = Field(..., description="YAML content of the scenario")
    name: str | None = Field(None, description="Override scenario name")


class GenerateFromArchitectureRequest(BaseModel):
    """Request to auto-generate scenarios from a deployment's ArchitectureMap."""

    deployment_id: str
    categories: list[str] | None = Field(
        None,
        description="Categories to generate: boundary, tool, routing, memory. Default: all",
    )
    auto_execute: bool = Field(
        False,
        description="Auto-execute generated scenarios after creation",
    )
    model_provider: str | None = Field(None, description="Model provider for execution")
    model_name: str | None = Field(None, description="Model name for execution")


class GenerateFromArchitectureResponse(BaseModel):
    """Response from scenario auto-generation."""

    deployment_id: str
    scenarios_generated: int = 0
    scenarios: list[ScenarioInfo] = []
    job_ids: list[str] = []  # If auto_execute was True


# ─── MCP Server Testing ──────────────────────────────────────────────

class MCPDiscoverRequest(BaseModel):
    """Request to discover tools on an MCP server."""

    transport: str = Field("http", description="Transport type: http, sse, or stdio")
    url: str | None = Field(None, description="MCP server URL (for http/sse)")
    api_key: str | None = Field(None, description="API key for MCP server auth")
    headers: dict[str, str] | None = Field(None, description="Custom headers")
    command: str | None = Field(None, description="Command for stdio transport")
    args: list[str] | None = Field(None, description="Arguments for stdio command")


class MCPToolInfo(BaseModel):
    """Discovered MCP tool summary."""

    name: str
    description: str = ""
    parameter_count: int = 0
    parameters: list[dict] = []
    inferred_risks: list[str] = []


class MCPDiscoverResponse(BaseModel):
    """Response from MCP tool discovery."""

    tools: list[MCPToolInfo] = []
    server_info: dict = {}
    transport: str = ""
    url: str | None = None


class MCPSandboxRequest(BaseModel):
    """Request to run MCP server security tests through the sandbox."""

    # MCP Connection
    transport: str = Field("http", description="Transport type: http, sse, or stdio")
    url: str | None = Field(None, description="MCP server URL")
    api_key: str | None = Field(None, description="API key for MCP server auth")
    headers: dict[str, str] | None = Field(None, description="Custom headers")
    command: str | None = Field(None, description="Command for stdio transport")
    args: list[str] | None = Field(None, description="Arguments for stdio command")

    # Model config
    model_provider: str = Field("openai", description="Model provider for sandbox execution")
    model_name: str = Field("gpt-4o", description="Model name")
    model_api_key: str | None = Field(None, description="Model API key")

    # Test config
    attack_categories: list[str] | None = Field(
        None, description="Attack categories to test (None = all 13)"
    )
    max_payloads_per_category: int = Field(3, description="Max payloads per attack category")
    tools_to_test: list[str] | None = Field(
        None, description="Specific tool names to test (None = all discovered)"
    )

    # Options
    use_judge: bool = Field(False, description="Enable LLM judge scoring")
    deployment_id: str | None = Field(None, description="Link to a deployment/target")


class MCPSandboxResponse(BaseModel):
    """Response from MCP sandbox security test."""

    tools_discovered: int = 0
    tools_tested: int = 0
    scenarios_generated: int = 0
    scenarios: list[ScenarioInfo] = []
    job_ids: list[str] = []


# ─── Unified Corpus-Based Testing ────────────────────────────────────


class TargetTestRequest(BaseModel):
    """Unified request for corpus-based security testing against any target type."""

    target_type: str = Field(
        ...,
        description=(
            "Target type: deployment, mcp_server, model_file, skill_file, "
            "instruction_file, model_endpoint, agent_endpoint"
        ),
    )
    profile: str = Field(
        "standard",
        description="Test profile: quick, standard, or comprehensive",
    )

    # Target identification
    deployment_id: str | None = Field(None, description="Deployment ID (for deployment targets)")
    target_id: str | None = Field(None, description="Alias for deployment_id")

    # MCP config (for mcp_server, agent_endpoint)
    url: str | None = Field(None, description="MCP server URL (for http/sse)")
    transport: str = Field("http", description="Transport type: http, sse, or stdio")
    command: str | None = Field(None, description="Command for stdio transport")
    args: list[str] | None = Field(None, description="Arguments for stdio command")
    headers: dict[str, str] | None = Field(None, description="Custom headers")
    api_key: str | None = Field(None, description="API key for MCP server auth")
    env: dict[str, str] | None = Field(None, description="Environment vars for stdio")

    # File config (for model_file, skill_file, instruction_file)
    file_path: str | None = Field(None, description="Path to target file")

    # Model config (for model_endpoint, or override platform defaults)
    model_provider: str | None = Field(None, description="Model provider")
    model_name: str | None = Field(None, description="Model name")
    model_endpoint: str | None = Field(None, description="Model endpoint URL")
    model_api_key: str | None = Field(None, description="Model API key")

    # Filtering
    tools_to_test: list[str] | None = Field(
        None, description="Specific tool names to test (None = all)",
    )
    attack_categories: list[str] | None = Field(
        None, description="Attack categories to include (None = all)",
    )

    # Execution
    use_judge: bool = Field(False, description="Enable LLM judge scoring")
    scan_id: str | None = Field(None, description="Link to a scan")


class TargetTestResponse(BaseModel):
    """Response from corpus-based target security test."""

    target_type: str
    profile: str
    surface_summary: dict = {}
    scenarios_generated: int = 0
    scenarios: list[ScenarioInfo] = []
    job_ids: list[str] = []


# ─── Scenario Packs ─────────────────────────────────────────────────


class PackInfo(BaseModel):
    """Summary of a scenario pack."""

    id: str
    name: str
    description: str = ""
    domain: str = ""
    difficulty: str = "basic"
    scenario_count: int = 0
    scenario_names: list[str] = []
    tags: list[str] = []
    recommended_for: list[str] = []
    estimated_turns: int = 0
    icon: str = ""


class PackRunRequest(BaseModel):
    """Request to run all scenarios in a pack."""

    model_provider: str = Field("openai", description="Model provider")
    model_name: str = Field("gpt-4o", description="Model name")
    model_endpoint: str | None = Field(None, description="Custom model endpoint")
    model_api_key: str | None = Field(None, description="Model API key")
    use_judge: bool = Field(False, description="Enable LLM judge scoring")
    deployment_id: str | None = Field(None, description="Link to a deployment")

    # Tool execution mode
    tool_mode: str | None = Field(None, description="mock, live, or hybrid")
    mcp_transport: str | None = Field(None, description="stdio, http, or sse")
    mcp_command: str | None = Field(None, description="Command for stdio transport")
    mcp_args: list[str] | None = Field(None, description="Arguments for stdio command")
    mcp_url: str | None = Field(None, description="URL for http/sse transport")
    mcp_api_key: str | None = Field(None, description="API key for MCP server")
    mcp_headers: dict[str, str] | None = Field(None, description="Headers for MCP server")
    live_tools: list[str] | None = Field(None, description="Tool names to call live in hybrid mode")

    # Overrides
    system_prompt_override: str | None = Field(None, description="Override scenario system prompt")
    seed: int | None = Field(None, description="RNG seed for reproducibility")


class PackRunResponse(BaseModel):
    """Response from running a pack."""

    pack_id: str
    pack_name: str
    scenarios_count: int = 0
    job_ids: list[str] = []


# ─── Project Proposals ──────────────────────────────────────────────


class ProposeRequest(BaseModel):
    """Request to analyze a target and propose scenarios."""

    target_type: str = Field(
        ...,
        description="Target type: deployment, mcp_server, model_endpoint, etc.",
    )
    profile: str = Field("standard", description="Test profile: quick, standard, comprehensive")

    # Target identification
    deployment_id: str | None = None
    target_id: str | None = None

    # MCP config
    url: str | None = None
    transport: str = "http"
    command: str | None = None
    args: list[str] | None = None
    headers: dict[str, str] | None = None
    api_key: str | None = None
    env: dict[str, str] | None = None

    # File config
    file_path: str | None = None

    # Model config
    model_provider: str | None = None
    model_name: str | None = None
    model_endpoint: str | None = None
    model_api_key: str | None = None


class ScenarioProposalInfo(BaseModel):
    """A single proposed scenario."""

    id: str
    scenario_name: str
    description: str = ""
    rationale: str = ""
    priority: str = "medium"
    category: str = ""
    risk_factors: list[str] = []
    estimated_turns: int = 0
    approved: bool = False


class ProposalResponse(BaseModel):
    """Response containing scenario proposals for a target."""

    proposal_id: str
    target_type: str
    target_summary: dict = {}
    risk_assessment: list[str] = []
    proposals: list[ScenarioProposalInfo] = []
    recommended_profile: str = "standard"
    coverage_estimate: str = ""


class ProposalUpdateRequest(BaseModel):
    """Update approved/rejected proposals."""

    approved_ids: list[str] = Field(..., description="IDs of proposals to approve")


class ProposalExecuteResponse(BaseModel):
    """Response from executing approved proposals."""

    proposal_id: str
    approved_count: int = 0
    scenarios_generated: int = 0
    job_ids: list[str] = []
