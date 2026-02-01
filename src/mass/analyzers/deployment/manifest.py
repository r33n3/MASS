"""Deployment manifest models.

Represents discovered deployment components and extracted instructions.
"""

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from mass.core.types import ComponentType


@dataclass
class Component:
    """A discovered deployment component.

    Represents an individual piece of an AI deployment such as
    a model, prompt, tool, or configuration.
    """

    id: str
    type: ComponentType
    name: str
    path: Path
    content: str | None = None
    content_hash: str | None = None
    line_start: int | None = None
    line_end: int | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        """Compute content hash if content is provided."""
        if self.content and not self.content_hash:
            import hashlib
            self.content_hash = hashlib.sha256(self.content.encode()).hexdigest()


@dataclass
class ExtractedInstruction:
    """An instruction extracted from a component.

    Represents system prompts, personas, skills, or other
    instructional content discovered during scanning.
    """

    content: str
    source_file: Path
    source_line: int
    extraction_method: str  # ast, regex, yaml_key, json_key, markdown
    context_type: str  # system_prompt, persona, skill, tool_description
    is_template: bool = False
    template_vars: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def has_variables(self) -> bool:
        """Check if this instruction contains template variables."""
        return self.is_template and len(self.template_vars) > 0


@dataclass
class DependencyInfo:
    """Information about a project dependency."""

    name: str
    version: str | None = None
    source: str = "pip"  # pip, npm, cargo, etc.
    is_dev: bool = False
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class ModelConfig:
    """Configuration for a model component."""

    provider: str  # openai, anthropic, local, etc.
    model_name: str
    endpoint: str | None = None
    api_key_env: str | None = None  # Environment variable name
    temperature: float | None = None
    max_tokens: int | None = None
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class MCPServerConfig:
    """Configuration for an MCP server component."""

    server_url: str
    transport: str = "sse"  # sse, stdio, http
    tools: list[str] = field(default_factory=list)
    auth_method: str | None = None  # token, basic, none
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class DeploymentManifest:
    """Complete manifest of a scanned deployment.

    Contains all discovered components, instructions,
    and metadata about the deployment.
    """

    name: str
    path: Path
    components: list[Component] = field(default_factory=list)
    instructions: list[ExtractedInstruction] = field(default_factory=list)
    dependencies: dict[str, DependencyInfo] = field(default_factory=dict)
    model_configs: list[ModelConfig] = field(default_factory=list)
    mcp_servers: list[MCPServerConfig] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def component_count(self) -> int:
        """Get total number of components."""
        return len(self.components)

    @property
    def instruction_count(self) -> int:
        """Get total number of extracted instructions."""
        return len(self.instructions)

    def components_by_type(self, component_type: ComponentType) -> list[Component]:
        """Get components filtered by type."""
        return [c for c in self.components if c.type == component_type]

    def has_component_type(self, component_type: ComponentType) -> bool:
        """Check if manifest contains a specific component type."""
        return any(c.type == component_type for c in self.components)

    def add_component(self, component: Component) -> None:
        """Add a component to the manifest."""
        self.components.append(component)

    def add_instruction(self, instruction: ExtractedInstruction) -> None:
        """Add an extracted instruction to the manifest."""
        self.instructions.append(instruction)

    def add_dependency(self, dep: DependencyInfo) -> None:
        """Add a dependency to the manifest."""
        self.dependencies[dep.name] = dep

    def to_dict(self) -> dict[str, Any]:
        """Convert manifest to dictionary for serialization."""
        return {
            "name": self.name,
            "path": str(self.path),
            "component_count": self.component_count,
            "instruction_count": self.instruction_count,
            "components": [
                {
                    "id": c.id,
                    "type": c.type.value,
                    "name": c.name,
                    "path": str(c.path),
                    "content_hash": c.content_hash,
                    "metadata": c.metadata,
                }
                for c in self.components
            ],
            "instructions": [
                {
                    "content": i.content[:200] + "..." if len(i.content) > 200 else i.content,
                    "source_file": str(i.source_file),
                    "source_line": i.source_line,
                    "context_type": i.context_type,
                    "is_template": i.is_template,
                    "template_vars": i.template_vars,
                }
                for i in self.instructions
            ],
            "dependencies": {
                name: {"version": d.version, "source": d.source}
                for name, d in self.dependencies.items()
            },
            "metadata": self.metadata,
        }
