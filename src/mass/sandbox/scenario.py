"""Scenario definition and YAML parser for sandbox testing.

A scenario defines a sequence of turns to execute against a simulated
AI application runtime. Each turn includes user input, optional tool
mocks, memory operations, and post-turn assertions.
"""

from __future__ import annotations

import importlib.resources
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml


@dataclass
class ToolMock:
    """Scripted response for a tool call."""

    tool_name: str
    response: dict[str, Any] = field(default_factory=dict)
    mode: str = "normal"  # normal | error | timeout | malformed | adversarial
    delay_ms: int = 0
    error_message: str | None = None

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ToolMock:
        return cls(
            tool_name=data["tool_name"],
            response=data.get("response", {}),
            mode=data.get("mode", "normal"),
            delay_ms=data.get("delay_ms", 0),
            error_message=data.get("error_message"),
        )


@dataclass
class MemoryOp:
    """A memory operation to inject or assert."""

    action: str  # set | delete | assert_contains | assert_missing
    key: str
    value: Any = None

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> MemoryOp:
        return cls(
            action=data["action"],
            key=data["key"],
            value=data.get("value"),
        )


@dataclass
class Assertion:
    """Post-turn assertion."""

    type: str  # contains | not_contains | tool_called | tool_not_called
    # | memory_has | memory_missing | detector | regex | response_length
    target: str
    value: str | None = None

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Assertion:
        return cls(
            type=data["type"],
            target=data["target"],
            value=data.get("value"),
        )


@dataclass
class ScenarioTurn:
    """Single turn in a scenario."""

    user_input: str
    tool_mocks: list[ToolMock] = field(default_factory=list)
    memory_ops: list[MemoryOp] = field(default_factory=list)
    assertions: list[Assertion] = field(default_factory=list)
    expect_tools: list[str] | None = None
    max_response_ms: int | None = None

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ScenarioTurn:
        return cls(
            user_input=data["user_input"],
            tool_mocks=[ToolMock.from_dict(t) for t in data.get("tool_mocks", [])],
            memory_ops=[MemoryOp.from_dict(m) for m in data.get("memory_ops", [])],
            assertions=[Assertion.from_dict(a) for a in data.get("assertions", [])],
            expect_tools=data.get("expect_tools"),
            max_response_ms=data.get("max_response_ms"),
        )


@dataclass
class Scenario:
    """Complete test scenario definition."""

    name: str
    description: str = ""
    category: str = "general"  # boundary | tool | routing | memory | load
    tags: list[str] = field(default_factory=list)

    # Target app config
    system_prompt: str = ""
    tools: list[dict[str, Any]] = field(default_factory=list)  # OpenAI-format tool defs
    skills: list[str] = field(default_factory=list)
    initial_memory: dict[str, Any] = field(default_factory=dict)

    # Model config
    model_provider: str = "ollama"
    model_name: str = ""
    model_endpoint: str | None = None
    model_api_key: str | None = None
    temperature: float = 0.0
    seed: int | None = None

    # Turns
    turns: list[ScenarioTurn] = field(default_factory=list)

    # Scoring
    detectors: list[str] = field(default_factory=list)
    severity_if_fail: str = "medium"

    # Finding validation — IDs of scan findings this scenario validates
    validates_findings: list[str] = field(default_factory=list)

    # Tool execution mode
    tool_mode: str = "mock"  # mock | live | hybrid
    mcp_transport: str | None = None  # stdio | http | sse
    mcp_command: str | None = None
    mcp_args: list[str] = field(default_factory=list)
    mcp_url: str | None = None
    mcp_headers: dict[str, str] = field(default_factory=dict)
    mcp_env: dict[str, str] = field(default_factory=dict)
    live_tools: list[str] = field(default_factory=list)  # Tool names for hybrid mode

    # Source info
    source_file: str | None = None
    deployment_id: str | None = None

    @classmethod
    def from_yaml(cls, path: str | Path) -> Scenario:
        """Load scenario from a YAML file."""
        path = Path(path)
        with open(path, encoding="utf-8") as f:
            data = yaml.safe_load(f)
        scenario = cls.from_dict(data)
        scenario.source_file = str(path)
        return scenario

    @classmethod
    def from_yaml_string(cls, content: str) -> Scenario:
        """Parse scenario from a YAML string."""
        data = yaml.safe_load(content)
        return cls.from_dict(data)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Scenario:
        """Construct scenario from a dictionary."""
        turns_data = data.get("turns", [])
        turns = [ScenarioTurn.from_dict(t) for t in turns_data]

        return cls(
            name=data.get("name", "Unnamed Scenario"),
            description=data.get("description", ""),
            category=data.get("category", "general"),
            tags=data.get("tags", []),
            system_prompt=data.get("system_prompt", ""),
            tools=data.get("tools", []),
            skills=data.get("skills", []),
            initial_memory=data.get("initial_memory", {}),
            model_provider=data.get("model_provider", "ollama"),
            model_name=data.get("model_name", ""),
            model_endpoint=data.get("model_endpoint"),
            model_api_key=data.get("model_api_key"),
            temperature=data.get("temperature", 0.0),
            seed=data.get("seed"),
            turns=turns,
            detectors=data.get("detectors", []),
            severity_if_fail=data.get("severity_if_fail", "medium"),
            validates_findings=data.get("validates_findings", []),
            tool_mode=data.get("tool_mode", "mock"),
            mcp_transport=data.get("mcp_transport"),
            mcp_command=data.get("mcp_command"),
            mcp_args=data.get("mcp_args", []),
            mcp_url=data.get("mcp_url"),
            mcp_headers=data.get("mcp_headers", {}),
            mcp_env=data.get("mcp_env", {}),
            live_tools=data.get("live_tools", []),
            deployment_id=data.get("deployment_id"),
        )

    def to_dict(self) -> dict[str, Any]:
        """Serialize to dictionary."""
        return {
            "name": self.name,
            "description": self.description,
            "category": self.category,
            "tags": self.tags,
            "system_prompt": self.system_prompt,
            "tools": self.tools,
            "skills": self.skills,
            "initial_memory": self.initial_memory,
            "model_provider": self.model_provider,
            "model_name": self.model_name,
            "model_endpoint": self.model_endpoint,
            "model_api_key": self.model_api_key,
            "temperature": self.temperature,
            "seed": self.seed,
            "turns": [
                {
                    "user_input": t.user_input,
                    "tool_mocks": [
                        {
                            "tool_name": tm.tool_name,
                            "response": tm.response,
                            "mode": tm.mode,
                            "delay_ms": tm.delay_ms,
                            "error_message": tm.error_message,
                        }
                        for tm in t.tool_mocks
                    ],
                    "memory_ops": [
                        {"action": m.action, "key": m.key, "value": m.value}
                        for m in t.memory_ops
                    ],
                    "assertions": [
                        {"type": a.type, "target": a.target, "value": a.value}
                        for a in t.assertions
                    ],
                    "expect_tools": t.expect_tools,
                    "max_response_ms": t.max_response_ms,
                }
                for t in self.turns
            ],
            "detectors": self.detectors,
            "severity_if_fail": self.severity_if_fail,
            "validates_findings": self.validates_findings,
            "tool_mode": self.tool_mode,
            "mcp_transport": self.mcp_transport,
            "mcp_command": self.mcp_command,
            "mcp_args": self.mcp_args,
            "mcp_url": self.mcp_url,
            "mcp_headers": self.mcp_headers,
            "mcp_env": self.mcp_env,
            "live_tools": self.live_tools,
        }

    def to_yaml(self) -> str:
        """Serialize to YAML string."""
        return yaml.dump(self.to_dict(), default_flow_style=False, sort_keys=False)


def list_builtin_scenarios() -> list[dict[str, str]]:
    """List built-in scenario files shipped with MASS.

    Returns list of dicts with name, category, description, and path.
    """
    scenarios_dir = Path(__file__).parent / "scenarios"
    results = []
    if not scenarios_dir.exists():
        return results

    for yaml_file in sorted(scenarios_dir.glob("*.yaml")):
        try:
            with open(yaml_file, encoding="utf-8") as f:
                data = yaml.safe_load(f)
            results.append({
                "name": data.get("name", yaml_file.stem),
                "category": data.get("category", "general"),
                "description": data.get("description", ""),
                "tags": data.get("tags", []),
                "turns_count": len(data.get("turns", [])),
                "file": str(yaml_file),
            })
        except Exception:
            continue
    return results


def load_builtin_scenario(name: str) -> Scenario | None:
    """Load a built-in scenario by name.

    Searches the scenarios/ directory for a matching YAML file.
    """
    scenarios_dir = Path(__file__).parent / "scenarios"
    if not scenarios_dir.exists():
        return None

    for yaml_file in scenarios_dir.glob("*.yaml"):
        try:
            with open(yaml_file, encoding="utf-8") as f:
                data = yaml.safe_load(f)
            if data.get("name") == name:
                scenario = Scenario.from_dict(data)
                scenario.source_file = str(yaml_file)
                return scenario
        except Exception:
            continue

    # Try by filename stem
    candidate = scenarios_dir / f"{name}.yaml"
    if candidate.exists():
        return Scenario.from_yaml(candidate)
    return None
