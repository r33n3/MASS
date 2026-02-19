"""Configuration models for browser-based agent testing.

Defines the Pydantic schemas for configuring Playwright-driven
interaction with browser-embedded chat widgets.
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field


class PageSetupStep(BaseModel):
    """A single browser automation step to execute before testing."""

    model_config = ConfigDict(extra="forbid")

    action: str = Field(
        ...,
        description="Action to perform: click | type | wait | navigate | select",
    )
    selector: str | None = Field(
        default=None,
        description="CSS selector for the target element",
    )
    value: str | None = Field(
        default=None,
        description="Value to type or URL to navigate to",
    )
    wait_ms: int = Field(
        default=0,
        description="Milliseconds to wait after the action",
    )


class BrowserAuth(BaseModel):
    """Authentication configuration for browser sessions."""

    model_config = ConfigDict(extra="forbid")

    type: str = Field(
        ...,
        description="Auth type: cookie | basic | form",
    )
    credentials: dict = Field(
        default_factory=dict,
        description="Type-specific credentials (e.g. username, password, cookie values)",
    )


class BrowserAgentConfig(BaseModel):
    """Full configuration for interacting with a browser-embedded chat agent."""

    model_config = ConfigDict(extra="forbid")

    url: str = Field(..., description="Page URL containing the chat widget")
    input_selector: str = Field(..., description="CSS selector for the chat input field")
    output_selector: str = Field(
        ...,
        description="CSS selector for the response container (last assistant message)",
    )
    send_selector: str = Field(..., description="CSS selector for the send/submit button")
    wait_selector: str | None = Field(
        default=None,
        description="CSS selector for a loading indicator (hidden when response is ready)",
    )
    response_stabilize_ms: int = Field(
        default=1500,
        description="Milliseconds to wait for streaming responses to finish",
    )
    headless: bool = Field(default=True, description="Run browser in headless mode")
    viewport_width: int = Field(default=1280, description="Browser viewport width")
    viewport_height: int = Field(default=720, description="Browser viewport height")
    page_setup_steps: list[PageSetupStep] = Field(
        default_factory=list,
        description="Steps to execute before testing (login, cookie consent, etc.)",
    )
    auth: BrowserAuth | None = Field(
        default=None,
        description="Optional authentication configuration",
    )
    timeout_ms: int = Field(
        default=30000,
        description="Maximum time to wait for a response (milliseconds)",
    )
