"""Base extractor interface.

Defines the protocol for content extractors.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol, runtime_checkable

from mass.analyzers.deployment.manifest import (
    Component,
    ExtractedInstruction,
    ModelConfig,
    MCPServerConfig,
)


@dataclass
class ExtractionContext:
    """Context for extraction operations.

    Provides information about the file being processed
    and configuration for the extraction.
    """

    file_path: Path
    content: str
    encoding: str = "utf-8"
    base_path: Path | None = None
    options: dict[str, Any] = field(default_factory=dict)

    @property
    def relative_path(self) -> Path:
        """Get path relative to base path."""
        if self.base_path:
            try:
                return self.file_path.relative_to(self.base_path)
            except ValueError:
                return self.file_path
        return self.file_path

    @property
    def file_name(self) -> str:
        """Get the file name."""
        return self.file_path.name

    @property
    def extension(self) -> str:
        """Get the file extension (lowercase, without dot)."""
        return self.file_path.suffix.lower().lstrip(".")


@dataclass
class ExtractionResult:
    """Result of an extraction operation.

    Contains all extracted artifacts from a single file.
    """

    components: list[Component] = field(default_factory=list)
    instructions: list[ExtractedInstruction] = field(default_factory=list)
    model_configs: list[ModelConfig] = field(default_factory=list)
    mcp_servers: list[MCPServerConfig] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def has_results(self) -> bool:
        """Check if extraction found any results."""
        return bool(
            self.components
            or self.instructions
            or self.model_configs
            or self.mcp_servers
        )

    @property
    def has_errors(self) -> bool:
        """Check if extraction encountered errors."""
        return bool(self.errors)

    def merge(self, other: "ExtractionResult") -> None:
        """Merge another extraction result into this one."""
        self.components.extend(other.components)
        self.instructions.extend(other.instructions)
        self.model_configs.extend(other.model_configs)
        self.mcp_servers.extend(other.mcp_servers)
        self.errors.extend(other.errors)
        self.metadata.update(other.metadata)


@runtime_checkable
class Extractor(Protocol):
    """Protocol for content extractors."""

    name: str
    supported_extensions: list[str]

    def can_handle(self, context: ExtractionContext) -> bool:
        """Check if this extractor can handle the given context."""
        ...

    def extract(self, context: ExtractionContext) -> ExtractionResult:
        """Extract content from the given context."""
        ...


class BaseExtractor(ABC):
    """Base class for content extractors.

    Provides common functionality for extracting instructions
    and configurations from various file types.
    """

    name: str = "base"
    supported_extensions: list[str] = []

    def can_handle(self, context: ExtractionContext) -> bool:
        """Check if this extractor can handle the given file.

        Override for custom matching logic.
        """
        return context.extension in self.supported_extensions

    @abstractmethod
    def extract(self, context: ExtractionContext) -> ExtractionResult:
        """Extract content from the given context.

        Args:
            context: The extraction context.

        Returns:
            Extraction result with discovered components and instructions.
        """
        ...

    def _create_instruction(
        self,
        content: str,
        context: ExtractionContext,
        line_number: int,
        context_type: str = "system_prompt",
        extraction_method: str | None = None,
        is_template: bool = False,
        template_vars: list[str] | None = None,
    ) -> ExtractedInstruction:
        """Create an extracted instruction.

        Helper method for subclasses.
        """
        return ExtractedInstruction(
            content=content,
            source_file=context.file_path,
            source_line=line_number,
            extraction_method=extraction_method or self.name,
            context_type=context_type,
            is_template=is_template,
            template_vars=template_vars or [],
        )

    def _detect_template_vars(self, content: str) -> tuple[bool, list[str]]:
        """Detect template variables in content.

        Supports:
        - Python f-string style: {variable}
        - Jinja2 style: {{ variable }}
        - Handlebars style: {{ variable }}
        """
        import re

        vars_found = []

        # Python f-string / simple braces
        simple_pattern = r"\{([a-zA-Z_][a-zA-Z0-9_]*)\}"
        vars_found.extend(re.findall(simple_pattern, content))

        # Jinja2/Handlebars double braces
        double_pattern = r"\{\{\s*([a-zA-Z_][a-zA-Z0-9_.]*)\s*\}\}"
        vars_found.extend(re.findall(double_pattern, content))

        # Remove duplicates while preserving order
        seen = set()
        unique_vars = []
        for var in vars_found:
            if var not in seen:
                seen.add(var)
                unique_vars.append(var)

        return bool(unique_vars), unique_vars
