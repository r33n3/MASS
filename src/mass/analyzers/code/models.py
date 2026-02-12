"""Data structures for AI architecture mapping.

Captures the architecture of an AI deployment: how user input reaches
models, what tools are available, where system prompts come from, and
what safety measures exist.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class EntryPoint:
    """User-facing interface where input enters the system."""

    type: str  # api_endpoint, cli_command, web_form, websocket
    location: str  # file_path:line_number
    accepts: str = ""  # description of accepted input
    flows_to: list[str] = field(default_factory=list)
    authentication: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "type": self.type,
            "location": self.location,
            "accepts": self.accepts,
            "flows_to": self.flows_to,
            "authentication": self.authentication,
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> EntryPoint:
        return cls(
            type=d.get("type", "unknown"),
            location=d.get("location", ""),
            accepts=d.get("accepts", ""),
            flows_to=d.get("flows_to") or [],
            authentication=d.get("authentication"),
        )


@dataclass
class ModelConnection:
    """Connection to an LLM or AI model."""

    provider: str  # openai, anthropic, ollama, langchain, etc.
    model_name: str | None = None
    call_location: str = ""  # file_path:line_number
    system_prompt_source: str | None = None  # file path or "inline"
    has_tools: bool = False
    has_streaming: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "provider": self.provider,
            "model_name": self.model_name,
            "call_location": self.call_location,
            "system_prompt_source": self.system_prompt_source,
            "has_tools": self.has_tools,
            "has_streaming": self.has_streaming,
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> ModelConnection:
        return cls(
            provider=d.get("provider", "unknown"),
            model_name=d.get("model_name"),
            call_location=d.get("call_location", ""),
            system_prompt_source=d.get("system_prompt_source"),
            has_tools=d.get("has_tools", False),
            has_streaming=d.get("has_streaming", False),
        )


@dataclass
class ToolDefinition:
    """Tool/function exposed to an AI agent."""

    name: str
    purpose: str = ""
    capabilities: list[str] = field(default_factory=list)  # file_system, network, command_execution, database
    location: str = ""  # file_path:line_number
    validation: str | None = None  # description of input validation, or None

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "purpose": self.purpose,
            "capabilities": self.capabilities,
            "location": self.location,
            "validation": self.validation,
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> ToolDefinition:
        return cls(
            name=d.get("name", "unknown"),
            purpose=d.get("purpose", ""),
            capabilities=d.get("capabilities") or [],
            location=d.get("location", ""),
            validation=d.get("validation"),
        )


@dataclass
class DataFlow:
    """Flow of data through the system."""

    source: str
    target: str
    flow_type: str = ""  # user_input, model_query, tool_call, tool_response
    data_type: str = ""  # text, json, file, etc.
    sensitive: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "source": self.source,
            "target": self.target,
            "flow_type": self.flow_type,
            "data_type": self.data_type,
            "sensitive": self.sensitive,
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> DataFlow:
        return cls(
            source=d.get("source", ""),
            target=d.get("target", ""),
            flow_type=d.get("flow_type", ""),
            data_type=d.get("data_type", ""),
            sensitive=d.get("sensitive", False),
        )


@dataclass
class SafetyMeasure:
    """A safety or guardrail mechanism detected in the code."""

    type: str  # input_validation, output_filtering, rate_limiting, content_moderation
    location: str = ""
    description: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "type": self.type,
            "location": self.location,
            "description": self.description,
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> SafetyMeasure:
        return cls(
            type=d.get("type", "unknown"),
            location=d.get("location", ""),
            description=d.get("description", ""),
        )


@dataclass
class ArchitectureMap:
    """Complete AI architecture understanding of a deployment."""

    entry_points: list[EntryPoint] = field(default_factory=list)
    model_connections: list[ModelConnection] = field(default_factory=list)
    tool_definitions: list[ToolDefinition] = field(default_factory=list)
    data_flows: list[DataFlow] = field(default_factory=list)
    safety_measures: list[SafetyMeasure] = field(default_factory=list)

    # High-level classification
    pattern: str = "unknown"  # chatbot, agent, rag_pipeline, workflow, mcp_server, unknown
    summary: str = ""  # one-paragraph description

    # Analysis metadata
    analyzed_files: int = 0
    total_files: int = 0
    confidence: float = 0.0  # 0.0-1.0
    model_used: str = ""
    provider_used: str = ""
    duration_seconds: float = 0.0
    errors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "entry_points": [ep.to_dict() for ep in self.entry_points],
            "model_connections": [mc.to_dict() for mc in self.model_connections],
            "tool_definitions": [td.to_dict() for td in self.tool_definitions],
            "data_flows": [df.to_dict() for df in self.data_flows],
            "safety_measures": [sm.to_dict() for sm in self.safety_measures],
            "pattern": self.pattern,
            "summary": self.summary,
            "analyzed_files": self.analyzed_files,
            "total_files": self.total_files,
            "confidence": self.confidence,
            "model_used": self.model_used,
            "provider_used": self.provider_used,
            "duration_seconds": self.duration_seconds,
            "errors": self.errors,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ArchitectureMap:
        return cls(
            entry_points=[EntryPoint.from_dict(d) for d in data.get("entry_points") or []],
            model_connections=[ModelConnection.from_dict(d) for d in data.get("model_connections") or []],
            tool_definitions=[ToolDefinition.from_dict(d) for d in data.get("tool_definitions") or []],
            data_flows=[DataFlow.from_dict(d) for d in data.get("data_flows") or []],
            safety_measures=[SafetyMeasure.from_dict(d) for d in data.get("safety_measures") or []],
            pattern=data.get("pattern", "unknown"),
            summary=data.get("summary", ""),
            analyzed_files=data.get("analyzed_files", 0),
            total_files=data.get("total_files", 0),
            confidence=data.get("confidence", 0.0),
            model_used=data.get("model_used", ""),
            provider_used=data.get("provider_used", ""),
            duration_seconds=data.get("duration_seconds", 0.0),
            errors=data.get("errors") or [],
        )

    def build_topology(self) -> dict[str, Any]:
        """Generate a topology graph (nodes + edges) for the threat model builder."""
        nodes: list[dict[str, Any]] = []
        edges: list[dict[str, Any]] = []
        node_ids: set[str] = set()

        def _add_node(nid: str, name: str, ntype: str, **meta: Any) -> None:
            if nid not in node_ids:
                node_ids.add(nid)
                nodes.append({"id": nid, "name": name, "type": ntype, "metadata": meta})

        # Entry points → external zone
        for i, ep in enumerate(self.entry_points):
            nid = f"entry_{i}"
            _add_node(nid, ep.location or f"entry_{ep.type}", "api_endpoint",
                       accepts=ep.accepts, auth=ep.authentication)

        # Model connections → model zone
        for i, mc in enumerate(self.model_connections):
            nid = f"model_{i}"
            label = mc.model_name or mc.provider
            _add_node(nid, label, "model_provider",
                       provider=mc.provider, has_tools=mc.has_tools)

        # Tools → tool zone
        for i, td in enumerate(self.tool_definitions):
            nid = f"tool_{i}"
            _add_node(nid, td.name, "tool",
                       capabilities=td.capabilities, validation=td.validation)

        # Data flow edges
        for i, df in enumerate(self.data_flows):
            edges.append({
                "id": f"flow_{i}",
                "source": df.source,
                "target": df.target,
                "edge_type": df.flow_type,
                "metadata": {"data_type": df.data_type, "sensitive": df.sensitive},
            })

        return {"nodes": nodes, "edges": edges}
