"""Python code extractor.

Extracts instructions and configurations from Python files using AST analysis.
"""

import ast
import re
import uuid
from pathlib import Path
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


class PythonExtractor(BaseExtractor):
    """Extracts content from Python files.

    Analyzes Python AST to find:
    - System prompts and instructions
    - Model configurations
    - API key references
    - LangChain/LlamaIndex usage
    """

    name = "python"
    supported_extensions = ["py"]

    # Patterns for detecting prompts in string literals
    PROMPT_PATTERNS = [
        r"system[_\s]*prompt",
        r"system[_\s]*message",
        r"instructions?",
        r"persona",
        r"role[_\s]*content",
        r"assistant[_\s]*role",
    ]

    # Known LLM client patterns
    LLM_PATTERNS = {
        "openai": r"(?:OpenAI|ChatOpenAI|AzureOpenAI)",
        "anthropic": r"(?:Anthropic|Claude|ChatAnthropic)",
        "google": r"(?:GenerativeModel|ChatGoogleGenerative|Gemini)",
        "ollama": r"(?:Ollama|ChatOllama)",
    }

    def extract(self, context: ExtractionContext) -> ExtractionResult:
        """Extract content from Python file."""
        result = ExtractionResult()

        try:
            tree = ast.parse(context.content)
        except SyntaxError as e:
            result.errors.append(f"Python syntax error: {e}")
            return result

        # Visit AST nodes
        visitor = PythonASTVisitor(context, result, self)
        visitor.visit(tree)

        # Also do regex-based extraction for missed patterns
        self._extract_with_regex(context, result)

        return result

    def _extract_with_regex(
        self, context: ExtractionContext, result: ExtractionResult
    ) -> None:
        """Extract patterns that might be missed by AST analysis."""
        lines = context.content.split("\n")

        for i, line in enumerate(lines, start=1):
            # Look for system prompt assignments
            for pattern in self.PROMPT_PATTERNS:
                if re.search(pattern, line, re.IGNORECASE):
                    # Try to extract the value
                    match = re.search(r'["\']([^"\']{20,})["\']', line)
                    if match:
                        content = match.group(1)
                        is_template, vars_found = self._detect_template_vars(content)
                        result.instructions.append(
                            ExtractedInstruction(
                                content=content,
                                source_file=context.file_path,
                                source_line=i,
                                extraction_method="regex",
                                context_type="system_prompt",
                                is_template=is_template,
                                template_vars=vars_found,
                            )
                        )
                    break


class PythonASTVisitor(ast.NodeVisitor):
    """AST visitor for extracting content from Python code."""

    def __init__(
        self,
        context: ExtractionContext,
        result: ExtractionResult,
        extractor: PythonExtractor,
    ):
        self.context = context
        self.result = result
        self.extractor = extractor
        self.current_class: str | None = None
        self.current_function: str | None = None

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        """Visit class definition."""
        old_class = self.current_class
        self.current_class = node.name

        # Check if this is a LangChain/LlamaIndex agent or chain
        base_names = [self._get_name(base) for base in node.bases]
        if any("Agent" in name or "Chain" in name for name in base_names if name):
            self._add_component(
                ComponentType.WORKFLOW,
                node.name,
                node.lineno,
                node.end_lineno,
            )

        self.generic_visit(node)
        self.current_class = old_class

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        """Visit function definition."""
        old_function = self.current_function
        self.current_function = node.name

        self.generic_visit(node)
        self.current_function = old_function

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        """Visit async function definition."""
        old_function = self.current_function
        self.current_function = node.name

        self.generic_visit(node)
        self.current_function = old_function

    def visit_Assign(self, node: ast.Assign) -> None:
        """Visit assignment."""
        for target in node.targets:
            target_name = self._get_name(target)
            if target_name:
                self._check_assignment(target_name, node.value, node.lineno)

        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        """Visit function call."""
        func_name = self._get_full_name(node.func)
        if func_name:
            self._check_llm_call(func_name, node)

        self.generic_visit(node)

    def _get_name(self, node: ast.AST) -> str | None:
        """Get simple name from AST node."""
        if isinstance(node, ast.Name):
            return node.id
        if isinstance(node, ast.Attribute):
            return node.attr
        return None

    def _get_full_name(self, node: ast.AST) -> str | None:
        """Get full dotted name from AST node."""
        if isinstance(node, ast.Name):
            return node.id
        if isinstance(node, ast.Attribute):
            value_name = self._get_full_name(node.value)
            if value_name:
                return f"{value_name}.{node.attr}"
            return node.attr
        return None

    def _check_assignment(
        self, name: str, value: ast.AST, lineno: int
    ) -> None:
        """Check if assignment contains relevant content."""
        name_lower = name.lower()

        # Check for prompt-like variable names
        prompt_keywords = ["prompt", "system", "instruction", "persona", "template"]
        if any(kw in name_lower for kw in prompt_keywords):
            content = self._extract_string_value(value)
            if content and len(content) > 20:
                is_template, vars_found = self.extractor._detect_template_vars(content)
                self.result.instructions.append(
                    ExtractedInstruction(
                        content=content,
                        source_file=self.context.file_path,
                        source_line=lineno,
                        extraction_method="ast_assignment",
                        context_type=self._infer_context_type(name_lower),
                        is_template=is_template,
                        template_vars=vars_found,
                    )
                )

    def _check_llm_call(self, func_name: str, node: ast.Call) -> None:
        """Check if this is an LLM client initialization."""
        for provider, pattern in self.extractor.LLM_PATTERNS.items():
            if re.search(pattern, func_name):
                config = self._extract_model_config(node, provider)
                if config:
                    self.result.model_configs.append(config)
                break

    def _extract_model_config(
        self, node: ast.Call, provider: str
    ) -> ModelConfig | None:
        """Extract model configuration from a call node."""
        model_name = None
        api_key_env = None
        temperature = None
        max_tokens = None

        for keyword in node.keywords:
            if keyword.arg == "model" or keyword.arg == "model_name":
                model_name = self._extract_string_value(keyword.value)
            elif keyword.arg == "api_key":
                # Check if it's an env var reference
                if isinstance(keyword.value, ast.Call):
                    call_name = self._get_full_name(keyword.value.func)
                    if call_name and "getenv" in call_name:
                        if keyword.value.args:
                            api_key_env = self._extract_string_value(
                                keyword.value.args[0]
                            )
            elif keyword.arg == "temperature":
                if isinstance(keyword.value, ast.Constant):
                    temperature = float(keyword.value.value)
            elif keyword.arg == "max_tokens":
                if isinstance(keyword.value, ast.Constant):
                    max_tokens = int(keyword.value.value)

        if model_name or provider:
            return ModelConfig(
                provider=provider,
                model_name=model_name or "unknown",
                api_key_env=api_key_env,
                temperature=temperature,
                max_tokens=max_tokens,
            )

        return None

    def _extract_string_value(self, node: ast.AST) -> str | None:
        """Extract string value from AST node."""
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            return node.value
        if isinstance(node, ast.JoinedStr):
            # f-string - extract parts
            parts = []
            for value in node.values:
                if isinstance(value, ast.Constant):
                    parts.append(str(value.value))
                elif isinstance(value, ast.FormattedValue):
                    parts.append("{...}")
            return "".join(parts)
        return None

    def _infer_context_type(self, name: str) -> str:
        """Infer context type from variable name."""
        if "persona" in name:
            return "persona"
        if "skill" in name:
            return "skill"
        if "tool" in name:
            return "tool_description"
        return "system_prompt"

    def _add_component(
        self,
        component_type: ComponentType,
        name: str,
        line_start: int,
        line_end: int | None,
    ) -> None:
        """Add a component to the result."""
        self.result.components.append(
            Component(
                id=str(uuid.uuid4()),
                type=component_type,
                name=name,
                path=self.context.file_path,
                line_start=line_start,
                line_end=line_end,
            )
        )
