"""Browser agent testing schemas.

Request and response models for testing AI agents embedded in browser
windows via Playwright automation.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field


# ---------------------------------------------------------------------------
# Request schemas
# ---------------------------------------------------------------------------


class PageSetupStepSchema(BaseModel):
    """A browser automation step to run before testing."""

    model_config = ConfigDict(extra="forbid")

    action: str = Field(
        ...,
        description="Action: click | type | wait | navigate | select",
    )
    selector: str | None = Field(default=None, description="CSS selector")
    value: str | None = Field(default=None, description="Value to type or URL")
    wait_ms: int = Field(default=0, description="Wait after action (ms)")


class BrowserAgentConfigSchema(BaseModel):
    """Configuration for a browser-embedded chat agent."""

    model_config = ConfigDict(extra="forbid")

    url: str = Field(..., description="Page URL containing the chat widget")
    input_selector: str = Field(..., description="CSS selector for chat input")
    output_selector: str = Field(
        ..., description="CSS selector for response container"
    )
    send_selector: str = Field(..., description="CSS selector for send button")
    wait_selector: str | None = Field(
        default=None,
        description="CSS selector for loading indicator",
    )
    response_stabilize_ms: int = Field(
        default=1500, description="Wait for streaming to finish (ms)"
    )
    headless: bool = Field(default=True, description="Run headless")
    timeout_ms: int = Field(
        default=30000, description="Max wait for response (ms)"
    )
    page_setup_steps: list[PageSetupStepSchema] = Field(
        default_factory=list,
        description="Pre-test steps (login, cookie consent, etc.)",
    )


class BrowserTestConnectionRequest(BaseModel):
    """Request to test that browser selectors work."""

    model_config = ConfigDict(extra="forbid")

    config: BrowserAgentConfigSchema


class BrowserDiscoverRequest(BaseModel):
    """Request to probe a browser agent and discover its capabilities."""

    model_config = ConfigDict(extra="forbid")

    config: BrowserAgentConfigSchema


class BrowserSandboxRequest(BaseModel):
    """Request to run sandbox scenarios against a browser agent."""

    model_config = ConfigDict(extra="forbid")

    config: BrowserAgentConfigSchema
    scenarios: list[str] = Field(
        default_factory=list,
        description="Scenario names to run (empty = all browser-tagged)",
    )
    model_provider: str = Field(
        default="ollama",
        description="Model provider for scenario execution",
    )
    model_name: str = Field(
        default="",
        description="Model name for scenario execution",
    )


class BrowserInterrogationRequest(BaseModel):
    """Request to run adversarial interrogation against a browser agent."""

    model_config = ConfigDict(extra="forbid")

    config: BrowserAgentConfigSchema
    attacker_provider: str = Field(
        default="ollama",
        description="Provider for the attacker model",
    )
    attacker_model: str = Field(
        default="",
        description="Model for the attacker",
    )
    max_turns: int = Field(
        default=10,
        description="Maximum conversation turns",
    )
    category: str = Field(
        default="guardrail",
        description="Attack category to test",
    )
    strategy: str = Field(
        default="",
        description="Specific attack strategy (empty = auto-select)",
    )


# ---------------------------------------------------------------------------
# Response schemas
# ---------------------------------------------------------------------------


class SelectorStatus(BaseModel):
    """Whether a CSS selector was found on the page."""

    input: bool = False
    output: bool = False
    send: bool = False
    wait: bool | None = None


class BrowserTestConnectionResponse(BaseModel):
    """Result of testing browser connection and selectors."""

    status: str = Field(..., description="ok | selectors_missing | error")
    url: str
    selectors_found: SelectorStatus
    error: str | None = None
    screenshot_base64: str | None = Field(
        default=None, description="Base64-encoded screenshot"
    )


class DiscoveredCapability(BaseModel):
    """A capability discovered from probing the browser agent."""

    name: str
    description: str
    source: str = "browser_agent_probe"


class DiscoveredGuardrail(BaseModel):
    """A guardrail rule discovered from probing the browser agent."""

    rule: str
    source: str = "browser_agent_guardrails"


class BrowserDiscoverResponse(BaseModel):
    """Result of probing a browser agent for capabilities and guardrails."""

    status: str
    capabilities: list[DiscoveredCapability] = Field(default_factory=list)
    guardrails: list[DiscoveredGuardrail] = Field(default_factory=list)
    raw_capabilities_response: str = ""
    raw_guardrails_response: str = ""
    error: str | None = None


class BrowserSandboxResponse(BaseModel):
    """Result of running sandbox scenarios against a browser agent."""

    status: str
    job_id: str | None = None
    scenarios_queued: int = 0
    error: str | None = None


class BrowserInterrogationResponse(BaseModel):
    """Result of running adversarial interrogation against a browser agent."""

    status: str
    job_id: str | None = None
    error: str | None = None
