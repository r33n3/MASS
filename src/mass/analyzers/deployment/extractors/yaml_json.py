"""YAML and JSON configuration extractor.

Extracts instructions and configurations from YAML/JSON files.
"""

import json
import re
import uuid
from typing import Any

from mass.core.types import ComponentType
from mass.analyzers.deployment.manifest import (
    Component,
    ExtractedInstruction,
    ModelConfig,
    MCPServerConfig,
)
from mass.analyzers.deployment.extractors.base import (
    BaseExtractor,
    ExtractionContext,
    ExtractionResult,
)


class YamlJsonExtractor(BaseExtractor):
    """Extracts content from YAML and JSON configuration files.

    Looks for:
    - System prompts and instructions
    - Model configurations
    - MCP server definitions
    - Tool/skill definitions
    """

    name = "yaml_json"
    supported_extensions = ["yaml", "yml", "json"]

    # Keys that typically contain prompts
    PROMPT_KEYS = [
        "system_prompt",
        "system_message",
        "system",
        "prompt",
        "instructions",
        "instruction",
        "persona",
        "role_content",
        "template",
        "prefix",
        "suffix",
    ]

    # Keys that indicate model configuration
    MODEL_CONFIG_KEYS = ["model", "llm", "chat_model", "language_model"]

    # Keys that indicate MCP servers
    MCP_KEYS = ["mcp", "mcp_servers", "mcpServers", "servers"]

    def can_handle(self, context: ExtractionContext) -> bool:
        """Check if this is a YAML or JSON file."""
        if context.extension in self.supported_extensions:
            return True

        # Also handle .mcp.json files
        if context.file_name.endswith(".mcp.json"):
            return True

        return False

    def extract(self, context: ExtractionContext) -> ExtractionResult:
        """Extract content from YAML/JSON file."""
        result = ExtractionResult()

        try:
            data = self._parse_content(context)
        except Exception as e:
            result.errors.append(f"Parse error: {e}")
            return result

        if data is None:
            return result

        # Extract prompts
        self._extract_prompts(data, context, result, path=[])

        # Extract model configs
        self._extract_model_configs(data, result)

        # Extract MCP servers
        self._extract_mcp_servers(data, context, result)

        # Extract tool/skill definitions
        self._extract_tools(data, context, result)

        return result

    def _parse_content(self, context: ExtractionContext) -> Any:
        """Parse YAML or JSON content."""
        if context.extension == "json" or context.file_name.endswith(".json"):
            return json.loads(context.content)
        else:
            # Try to import yaml
            try:
                import yaml
                return yaml.safe_load(context.content)
            except ImportError:
                # Fallback: try to parse as JSON in case it's valid
                try:
                    return json.loads(context.content)
                except json.JSONDecodeError:
                    raise ValueError("YAML parsing requires pyyaml package")

    def _extract_prompts(
        self,
        data: Any,
        context: ExtractionContext,
        result: ExtractionResult,
        path: list[str],
    ) -> None:
        """Recursively extract prompts from data structure."""
        if isinstance(data, dict):
            for key, value in data.items():
                current_path = path + [key]

                # Check if this key contains a prompt
                if not isinstance(key, str):
                    continue
                key_lower = key.lower().replace("-", "_").replace(" ", "_")
                if key_lower in self.PROMPT_KEYS:
                    if isinstance(value, str) and len(value) > 20:
                        is_template, vars_found = self._detect_template_vars(value)
                        result.instructions.append(
                            ExtractedInstruction(
                                content=value,
                                source_file=context.file_path,
                                source_line=1,  # YAML/JSON doesn't give us line numbers easily
                                extraction_method="yaml_key",
                                context_type=self._infer_context_type(key_lower),
                                is_template=is_template,
                                template_vars=vars_found,
                                metadata={"path": ".".join(current_path)},
                            )
                        )

                # Recurse into nested structures
                self._extract_prompts(value, context, result, current_path)

        elif isinstance(data, list):
            for i, item in enumerate(data):
                self._extract_prompts(item, context, result, path + [f"[{i}]"])

    def _extract_model_configs(self, data: Any, result: ExtractionResult) -> None:
        """Extract model configurations."""
        if not isinstance(data, dict):
            return

        for key in self.MODEL_CONFIG_KEYS:
            if key in data:
                config_data = data[key]
                if isinstance(config_data, dict):
                    config = self._parse_model_config(config_data)
                    if config:
                        result.model_configs.append(config)
                elif isinstance(config_data, str):
                    # Just a model name
                    result.model_configs.append(
                        ModelConfig(
                            provider="unknown",
                            model_name=config_data,
                        )
                    )

        # Recurse into nested dictionaries
        for value in data.values():
            if isinstance(value, dict):
                self._extract_model_configs(value, result)

    def _parse_model_config(self, data: dict) -> ModelConfig | None:
        """Parse a model configuration dictionary."""
        model_name = data.get("model") or data.get("model_name") or data.get("name")
        if not model_name:
            return None

        provider = data.get("provider", "unknown")
        if "gpt" in str(model_name).lower():
            provider = "openai"
        elif "claude" in str(model_name).lower():
            provider = "anthropic"
        elif "gemini" in str(model_name).lower():
            provider = "google"

        return ModelConfig(
            provider=provider,
            model_name=str(model_name),
            endpoint=data.get("endpoint") or data.get("api_base"),
            temperature=data.get("temperature"),
            max_tokens=data.get("max_tokens"),
        )

    def _extract_mcp_servers(
        self,
        data: Any,
        context: ExtractionContext,
        result: ExtractionResult,
    ) -> None:
        """Extract MCP server configurations."""
        if not isinstance(data, dict):
            return

        # Check for MCP configuration
        for key in self.MCP_KEYS:
            if key in data:
                mcp_data = data[key]
                if isinstance(mcp_data, dict):
                    for server_name, server_config in mcp_data.items():
                        if isinstance(server_config, dict):
                            server = self._parse_mcp_server(
                                server_name, server_config
                            )
                            if server:
                                result.mcp_servers.append(server)

                                # Also add as component
                                result.components.append(
                                    Component(
                                        id=str(uuid.uuid4()),
                                        type=ComponentType.MCP_SERVER,
                                        name=server_name,
                                        path=context.file_path,
                                        metadata={"url": server.server_url},
                                    )
                                )

    def _parse_mcp_server(
        self, name: str, data: dict
    ) -> MCPServerConfig | None:
        """Parse an MCP server configuration."""
        # Handle different config formats
        server_url = (
            data.get("url")
            or data.get("server_url")
            or data.get("command")  # For stdio transport
        )

        if not server_url:
            return None

        return MCPServerConfig(
            server_url=str(server_url),
            transport=data.get("transport", "sse"),
            tools=data.get("tools", []),
            auth_method=data.get("auth") or data.get("auth_method"),
        )

    def _extract_tools(
        self,
        data: Any,
        context: ExtractionContext,
        result: ExtractionResult,
    ) -> None:
        """Extract tool/skill definitions."""
        if not isinstance(data, dict):
            return

        # Look for tools/skills arrays
        for key in ["tools", "skills", "functions", "actions"]:
            if key in data:
                tools_data = data[key]
                if isinstance(tools_data, list):
                    for tool in tools_data:
                        if isinstance(tool, dict):
                            name = tool.get("name") or tool.get("function_name")
                            description = tool.get("description")

                            if name:
                                result.components.append(
                                    Component(
                                        id=str(uuid.uuid4()),
                                        type=ComponentType.SKILL,
                                        name=str(name),
                                        path=context.file_path,
                                        content=description,
                                    )
                                )

                            if description and len(description) > 20:
                                result.instructions.append(
                                    ExtractedInstruction(
                                        content=description,
                                        source_file=context.file_path,
                                        source_line=1,
                                        extraction_method="yaml_key",
                                        context_type="tool_description",
                                    )
                                )

    def _infer_context_type(self, key: str) -> str:
        """Infer context type from key name."""
        if "persona" in key:
            return "persona"
        if "skill" in key:
            return "skill"
        if "tool" in key:
            return "tool_description"
        if "template" in key:
            return "template"
        return "system_prompt"
