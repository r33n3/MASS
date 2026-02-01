"""JavaScript/TypeScript code extractor.

Extracts instructions and configurations from JS/TS files.
"""

import re
import uuid
from typing import Any

from mass.core.types import ComponentType
from mass.analyzers.deployment.manifest import (
    Component,
    ExtractedInstruction,
    ModelConfig,
)
from mass.analyzers.deployment.extractors.base import (
    BaseExtractor,
    ExtractionContext,
    ExtractionResult,
)


class JavaScriptExtractor(BaseExtractor):
    """Extracts content from JavaScript/TypeScript files.

    Uses regex-based extraction since we don't want to add
    a full JS parser dependency.
    """

    name = "javascript"
    supported_extensions = ["js", "jsx", "ts", "tsx", "mjs", "cjs"]

    # Patterns for system prompts
    PROMPT_PATTERNS = [
        # Variable assignments
        r'(?:const|let|var)\s+(\w*(?:system|prompt|instruction|persona)\w*)\s*=\s*[`"\']([^`"\']+)[`"\']',
        # Object properties
        r'(?:system|prompt|instructions?|persona|role)\s*:\s*[`"\']([^`"\']+)[`"\']',
        # Function parameters (OpenAI style)
        r'(?:system|content)\s*:\s*[`"\']([^`"\']+)[`"\']',
    ]

    # LLM client patterns
    LLM_PATTERNS = {
        "openai": [
            r'new\s+OpenAI\s*\(',
            r'OpenAI\.(?:Chat|Completion)',
            r'createChatCompletion',
        ],
        "anthropic": [
            r'new\s+Anthropic\s*\(',
            r'Anthropic\.messages',
        ],
        "langchain": [
            r'new\s+ChatOpenAI\s*\(',
            r'new\s+ChatAnthropic\s*\(',
            r'LLMChain',
        ],
    }

    # Template literal patterns
    TEMPLATE_LITERAL_PATTERN = r'`([^`]+)`'

    def extract(self, context: ExtractionContext) -> ExtractionResult:
        """Extract content from JavaScript/TypeScript file."""
        result = ExtractionResult()

        # Extract prompts
        self._extract_prompts(context, result)

        # Extract model configurations
        self._extract_model_configs(context, result)

        # Extract components (agents, chains, etc.)
        self._extract_components(context, result)

        return result

    def _extract_prompts(
        self, context: ExtractionContext, result: ExtractionResult
    ) -> None:
        """Extract prompt content from file."""
        lines = context.content.split("\n")

        # Find multi-line template literals
        self._extract_template_literals(context, result)

        # Find single-line prompts
        for i, line in enumerate(lines, start=1):
            for pattern in self.PROMPT_PATTERNS:
                match = re.search(pattern, line, re.IGNORECASE)
                if match:
                    # Get the captured content (last group)
                    content = match.group(match.lastindex) if match.lastindex else None
                    if content and len(content) > 20:
                        is_template, vars_found = self._detect_template_vars(content)
                        result.instructions.append(
                            ExtractedInstruction(
                                content=content,
                                source_file=context.file_path,
                                source_line=i,
                                extraction_method="regex",
                                context_type=self._infer_context_type(line),
                                is_template=is_template,
                                template_vars=vars_found,
                            )
                        )
                    break

    def _extract_template_literals(
        self, context: ExtractionContext, result: ExtractionResult
    ) -> None:
        """Extract multi-line template literals that might contain prompts."""
        # Find template literals with prompt-like content
        pattern = r'(?:system|prompt|instruction|persona)\w*\s*[=:]\s*`([^`]+)`'

        for match in re.finditer(pattern, context.content, re.IGNORECASE | re.DOTALL):
            content = match.group(1).strip()
            if len(content) > 20:
                # Calculate line number
                line_num = context.content[:match.start()].count("\n") + 1
                is_template, vars_found = self._detect_js_template_vars(content)

                result.instructions.append(
                    ExtractedInstruction(
                        content=content,
                        source_file=context.file_path,
                        source_line=line_num,
                        extraction_method="template_literal",
                        context_type="system_prompt",
                        is_template=is_template,
                        template_vars=vars_found,
                    )
                )

    def _extract_model_configs(
        self, context: ExtractionContext, result: ExtractionResult
    ) -> None:
        """Extract model configurations."""
        for provider, patterns in self.LLM_PATTERNS.items():
            for pattern in patterns:
                for match in re.finditer(pattern, context.content):
                    # Try to find associated config
                    config = self._find_model_config(
                        context.content, match.start(), provider
                    )
                    if config:
                        result.model_configs.append(config)

    def _find_model_config(
        self, content: str, start_pos: int, provider: str
    ) -> ModelConfig | None:
        """Find model configuration near a match."""
        # Look for config in the next 500 characters
        search_area = content[start_pos:start_pos + 500]

        model_name = None
        temperature = None

        # Find model name
        model_match = re.search(r'model\s*:\s*["\']([^"\']+)["\']', search_area)
        if model_match:
            model_name = model_match.group(1)

        # Find temperature
        temp_match = re.search(r'temperature\s*:\s*([\d.]+)', search_area)
        if temp_match:
            temperature = float(temp_match.group(1))

        if model_name:
            return ModelConfig(
                provider=provider,
                model_name=model_name,
                temperature=temperature,
            )

        return None

    def _extract_components(
        self, context: ExtractionContext, result: ExtractionResult
    ) -> None:
        """Extract component definitions."""
        # Look for class definitions that might be agents/chains
        class_pattern = r'class\s+(\w+(?:Agent|Chain|Tool|Skill))\s*(?:extends|{)'

        for match in re.finditer(class_pattern, context.content):
            name = match.group(1)
            line_num = context.content[:match.start()].count("\n") + 1

            component_type = ComponentType.WORKFLOW
            if "Tool" in name:
                component_type = ComponentType.MCP_SERVER
            elif "Skill" in name:
                component_type = ComponentType.SKILL

            result.components.append(
                Component(
                    id=str(uuid.uuid4()),
                    type=component_type,
                    name=name,
                    path=context.file_path,
                    line_start=line_num,
                )
            )

    def _detect_js_template_vars(self, content: str) -> tuple[bool, list[str]]:
        """Detect JavaScript template literal variables."""
        # ${variable} pattern
        pattern = r'\$\{([a-zA-Z_][a-zA-Z0-9_.]*)\}'
        vars_found = re.findall(pattern, content)

        # Remove duplicates while preserving order
        seen = set()
        unique_vars = []
        for var in vars_found:
            if var not in seen:
                seen.add(var)
                unique_vars.append(var)

        return bool(unique_vars), unique_vars

    def _infer_context_type(self, line: str) -> str:
        """Infer context type from the line content."""
        line_lower = line.lower()
        if "persona" in line_lower:
            return "persona"
        if "skill" in line_lower:
            return "skill"
        if "tool" in line_lower:
            return "tool_description"
        return "system_prompt"
