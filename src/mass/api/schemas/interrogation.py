"""Interrogation schemas."""

from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class ModelConfig(BaseModel):
    """Model configuration for attacker or target."""

    model_config = ConfigDict(extra="forbid")

    provider: str = Field(..., description="Provider: ollama, openai, anthropic, bedrock, gemini, grok")
    model: str = Field(..., description="Model identifier (e.g., llama3.1:8b, gpt-4o)")
    endpoint: str | None = Field(default=None, description="Custom API endpoint URL")
    api_key: str | None = Field(default=None, description="API key (not needed for Ollama)")


class MCPServerSpec(BaseModel):
    """MCP server connection spec for tool-aware interrogation."""

    model_config = ConfigDict(extra="forbid")

    name: str = Field(..., description="Server name")
    transport: str = Field(default="stdio", description="Transport: stdio, http, sse")
    command: str | None = Field(default=None, description="Command for stdio transport")
    args: list[str] | None = Field(default=None, description="Command arguments")
    url: str | None = Field(default=None, description="URL for http/sse transport")


class InterrogationRequest(BaseModel):
    """Request to start an interrogation job."""

    model_config = ConfigDict(extra="forbid")

    name: str = Field(default="Interrogation", description="Job name")

    target: ModelConfig = Field(..., description="Target model to interrogate")
    attacker: ModelConfig = Field(..., description="Attacker model that drives the conversation")

    target_system_prompt: str | None = Field(
        default=None,
        description="System prompt configured on the target (for testing extraction)",
    )
    categories: list[str] | None = Field(
        default=None,
        description=(
            "Attack categories to test: system_prompt_leakage, jailbreak, "
            "prompt_injection, sensitive_info, excessive_agency. "
            "Null = all categories."
        ),
    )
    agent_names: list[str] | None = Field(
        default=None,
        description="Specific agent names (overrides categories)",
    )
    max_turns: int = Field(
        default=8, ge=2, le=20,
        description="Maximum conversation turns per strategy",
    )
    max_strategies_per_agent: int = Field(
        default=0, ge=0,
        description="Max strategies per agent (0 = all)",
    )
    mcp_servers: list[MCPServerSpec] | None = Field(
        default=None,
        description="MCP servers to connect during interrogation for tool-aware testing",
    )

    # Optional: link to a scan
    scan_id: str | None = Field(default=None, description="Link findings to this scan")
    deployment_id: str | None = Field(default=None, description="Link findings to this deployment")
    target_id: str | None = Field(default=None, description="Link findings to this target/project")


class ConversationTurnResponse(BaseModel):
    """A single turn in the conversation."""

    model_config = ConfigDict(extra="forbid")

    turn_number: int
    role: str = Field(description="attacker, target, system, or evaluator")
    content: str
    latency_ms: float = 0.0
    model: str = ""
    timestamp: datetime | None = None


class ConversationResponse(BaseModel):
    """A conversation between attacker and target."""

    model_config = ConfigDict(extra="forbid")

    conversation_id: str
    category: str
    strategy: str
    success: bool
    confidence: float
    analysis: str
    total_turns: int
    duration_seconds: float
    attacker_model: str
    target_model: str
    turns: list[ConversationTurnResponse]
    success_indicators: list[str] = Field(default_factory=list)
    strategy_description: str = ""


class InterrogationFinding(BaseModel):
    """Finding from interrogation."""

    model_config = ConfigDict(extra="forbid")

    title: str
    description: str
    severity: str
    category: str
    confidence: float
    agent_name: str
    strategy_name: str
    total_turns: int


class InterrogationResponse(BaseModel):
    """Response from an interrogation job."""

    model_config = ConfigDict(extra="ignore")

    job_id: str
    status: str = Field(description="pending, running, completed, failed")
    attacker_model: str
    target_model: str
    agents_run: int = 0
    strategies_run: int = 0
    successful_attacks: int = 0
    failed_attacks: int = 0
    duration_seconds: float = 0.0
    findings: list[InterrogationFinding] = Field(default_factory=list)
    conversations: list[ConversationResponse] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)
    message: str = ""
    deployment_id: str | None = Field(default=None, description="Linked deployment")
    target_id: str | None = Field(default=None, description="Linked target/project")
    scan_id: str | None = Field(default=None, description="Linked scan")


class InterrogationStatusResponse(BaseModel):
    """Brief status of an interrogation job."""

    model_config = ConfigDict(extra="forbid")

    job_id: str
    status: str
    attacker_model: str
    target_model: str
    strategies_run: int = 0
    successful_attacks: int = 0
    duration_seconds: float = 0.0
    message: str = ""


class AvailableAgent(BaseModel):
    """Available red team agent."""

    model_config = ConfigDict(extra="forbid")

    name: str
    category: str
    description: str
    strategies: list[str]
    tags: list[str]


class OllamaModel(BaseModel):
    """An Ollama model available locally."""

    model_config = ConfigDict(extra="forbid")

    name: str
    size: str = ""
    modified: str = ""
    instance: str = Field(
        default="destination",
        description="Which Ollama instance: 'destination' (victim) or 'source' (interrogator)",
    )


# ---- Custom Strategy Schemas ----


class CustomStrategyFile(BaseModel):
    """Metadata for a custom strategy YAML file."""

    model_config = ConfigDict(extra="forbid")

    filename: str
    name: str
    category: str
    description: str
    severity: str
    strategy_count: int
    tags: list[str] = Field(default_factory=list)


class CustomStrategyContent(BaseModel):
    """Raw YAML content of a custom strategy file."""

    model_config = ConfigDict(extra="forbid")

    filename: str
    content: str = Field(description="Raw YAML text")


class CustomStrategyCreate(BaseModel):
    """Request to create or update a custom strategy file."""

    model_config = ConfigDict(extra="forbid")

    filename: str = Field(description="Filename ending in .yaml or .yml")
    content: str = Field(description="Raw YAML text")
