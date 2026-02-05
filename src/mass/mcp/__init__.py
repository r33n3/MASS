"""MCP (Model Context Protocol) interrogation module.

Provides dynamic security testing of remote MCP servers by:
- Connecting via stdio, SSE, or HTTP transports
- Enumerating available tools
- Generating adversarial test cases
- Using LLMs to craft realistic attack prompts
- Analyzing responses for security anomalies
"""

from mass.mcp.client import (
    MCPClient,
    MCPTransport,
    MCPTool,
    ToolParameter,
    ToolCallResult,
)
from mass.mcp.tool_tester import (
    MCPToolTester,
    TestCase,
    TestResult,
    AttackCategory,
)
from mass.mcp.response_analyzer import (
    ResponseAnalyzer,
    Anomaly,
    AnomalyType,
)
from mass.mcp.prompt_crafter import (
    OllamaPromptCrafter,
    CraftedPrompt,
    PromptCrafterFactory,
)
from mass.mcp.interrogator import (
    MCPInterrogator,
    InterrogationConfig,
    InterrogationResult,
    InterrogationFinding,
    InterrogationStatus,
    interrogate_mcp_server,
)

__all__ = [
    # Client
    "MCPClient",
    "MCPTransport",
    "MCPTool",
    "ToolParameter",
    "ToolCallResult",
    # Testing
    "MCPToolTester",
    "TestCase",
    "TestResult",
    "AttackCategory",
    # Analysis
    "ResponseAnalyzer",
    "Anomaly",
    "AnomalyType",
    # Prompt crafting
    "OllamaPromptCrafter",
    "CraftedPrompt",
    "PromptCrafterFactory",
    # Interrogation
    "MCPInterrogator",
    "InterrogationConfig",
    "InterrogationResult",
    "InterrogationFinding",
    "InterrogationStatus",
    "interrogate_mcp_server",
]
