"""Markdown extractor.

Extracts prompts and skills from markdown files.
"""

import re
import uuid
from typing import Any

from mass.core.types import ComponentType
from mass.analyzers.deployment.manifest import Component, ExtractedInstruction
from mass.analyzers.deployment.extractors.base import (
    BaseExtractor,
    ExtractionContext,
    ExtractionResult,
)


class MarkdownExtractor(BaseExtractor):
    """Extracts content from Markdown files.

    Identifies:
    - System prompts in code blocks
    - Skill definitions (Claude CLAUDE.md style)
    - Persona definitions
    - README instructions
    """

    name = "markdown"
    supported_extensions = ["md", "markdown"]

    # File patterns that likely contain prompts
    PROMPT_FILE_PATTERNS = [
        r"claude",
        r"system[_-]?prompt",
        r"prompt[s]?",
        r"instruction[s]?",
        r"persona",
        r"skill[s]?",
        r"agent",
    ]

    # Section headers that indicate prompt content
    PROMPT_SECTION_PATTERNS = [
        r"^#+\s*(?:system\s+)?prompt",
        r"^#+\s*instructions?",
        r"^#+\s*persona",
        r"^#+\s*context",
        r"^#+\s*(?:assistant|agent)\s+(?:behavior|personality)",
        r"^#+\s*skills?",
        r"^#+\s*tools?",
    ]

    def can_handle(self, context: ExtractionContext) -> bool:
        """Check if this markdown file should be analyzed."""
        if context.extension not in self.supported_extensions:
            return False

        # Always handle files with prompt-like names
        name_lower = context.file_name.lower()
        if any(
            re.search(pattern, name_lower)
            for pattern in self.PROMPT_FILE_PATTERNS
        ):
            return True

        # Handle common AI project files
        if name_lower in ["claude.md", "system.md", "prompt.md", "skills.md"]:
            return True

        # Check content for prompt sections
        for pattern in self.PROMPT_SECTION_PATTERNS:
            if re.search(pattern, context.content, re.IGNORECASE | re.MULTILINE):
                return True

        return True  # Analyze all markdown files

    def extract(self, context: ExtractionContext) -> ExtractionResult:
        """Extract content from Markdown file."""
        result = ExtractionResult()

        # Determine file type
        is_skill_file = "skill" in context.file_name.lower()
        is_claude_file = "claude" in context.file_name.lower()
        is_prompt_file = any(
            p in context.file_name.lower()
            for p in ["prompt", "system", "persona"]
        )

        # Extract code blocks
        self._extract_code_blocks(context, result)

        # Extract sections
        self._extract_sections(context, result, is_skill_file or is_claude_file)

        # If this is a prompt file, treat entire content as potential prompt
        if is_prompt_file and not result.instructions:
            self._extract_full_content(context, result)

        # Add as component if significant content found
        if result.instructions:
            component_type = ComponentType.CONTEXT
            if is_skill_file:
                component_type = ComponentType.SKILL

            result.components.append(
                Component(
                    id=str(uuid.uuid4()),
                    type=component_type,
                    name=context.file_name,
                    path=context.file_path,
                    content=context.content[:1000],  # First 1000 chars
                )
            )

        return result

    def _extract_code_blocks(
        self, context: ExtractionContext, result: ExtractionResult
    ) -> None:
        """Extract prompt content from code blocks."""
        # Find fenced code blocks
        pattern = r'```(?:\w+)?\n(.*?)```'

        for match in re.finditer(pattern, context.content, re.DOTALL):
            content = match.group(1).strip()

            # Skip short blocks or obvious code
            if len(content) < 50:
                continue

            # Check if this looks like a prompt (has natural language)
            if not self._looks_like_prompt(content):
                continue

            line_num = context.content[:match.start()].count("\n") + 1
            is_template, vars_found = self._detect_template_vars(content)

            result.instructions.append(
                ExtractedInstruction(
                    content=content,
                    source_file=context.file_path,
                    source_line=line_num,
                    extraction_method="code_block",
                    context_type="system_prompt",
                    is_template=is_template,
                    template_vars=vars_found,
                )
            )

    def _extract_sections(
        self,
        context: ExtractionContext,
        result: ExtractionResult,
        is_skill_file: bool,
    ) -> None:
        """Extract content from markdown sections."""
        lines = context.content.split("\n")
        current_section: str | None = None
        section_content: list[str] = []
        section_start: int = 0

        for i, line in enumerate(lines, start=1):
            # Check if this is a header
            header_match = re.match(r'^(#+)\s+(.+)$', line)

            if header_match:
                # Save previous section if it was a prompt section
                if current_section and section_content:
                    self._save_section_if_relevant(
                        current_section,
                        "\n".join(section_content),
                        section_start,
                        context,
                        result,
                        is_skill_file,
                    )

                # Start new section
                current_section = header_match.group(2).strip()
                section_content = []
                section_start = i
            else:
                section_content.append(line)

        # Don't forget the last section
        if current_section and section_content:
            self._save_section_if_relevant(
                current_section,
                "\n".join(section_content),
                section_start,
                context,
                result,
                is_skill_file,
            )

    def _save_section_if_relevant(
        self,
        section_name: str,
        content: str,
        line_num: int,
        context: ExtractionContext,
        result: ExtractionResult,
        is_skill_file: bool,
    ) -> None:
        """Save section content if it appears to be a prompt or skill."""
        content = content.strip()
        if len(content) < 20:
            return

        section_lower = section_name.lower()

        # Determine if this section is relevant
        is_relevant = any(
            keyword in section_lower
            for keyword in [
                "prompt", "instruction", "persona", "context",
                "behavior", "skill", "tool", "system", "overview",
            ]
        )

        if not is_relevant and not is_skill_file:
            return

        is_template, vars_found = self._detect_template_vars(content)

        context_type = "system_prompt"
        if "skill" in section_lower:
            context_type = "skill"
        elif "persona" in section_lower:
            context_type = "persona"
        elif "tool" in section_lower:
            context_type = "tool_description"

        result.instructions.append(
            ExtractedInstruction(
                content=content,
                source_file=context.file_path,
                source_line=line_num,
                extraction_method="markdown_section",
                context_type=context_type,
                is_template=is_template,
                template_vars=vars_found,
                metadata={"section": section_name},
            )
        )

    def _extract_full_content(
        self, context: ExtractionContext, result: ExtractionResult
    ) -> None:
        """Extract full file content as a prompt."""
        content = context.content.strip()

        # Remove YAML frontmatter if present
        if content.startswith("---"):
            end_marker = content.find("---", 3)
            if end_marker > 0:
                content = content[end_marker + 3:].strip()

        if len(content) < 20:
            return

        is_template, vars_found = self._detect_template_vars(content)

        result.instructions.append(
            ExtractedInstruction(
                content=content,
                source_file=context.file_path,
                source_line=1,
                extraction_method="full_file",
                context_type="system_prompt",
                is_template=is_template,
                template_vars=vars_found,
            )
        )

    def _looks_like_prompt(self, content: str) -> bool:
        """Check if content looks like a prompt rather than code."""
        # Count characteristics of natural language vs code
        lines = content.split("\n")

        # Check for code indicators
        code_indicators = sum(
            1 for line in lines
            if re.match(r'^\s*(?:def |class |import |from |if |for |while |return )', line)
        )

        # Check for natural language indicators
        nl_indicators = sum(
            1 for line in lines
            if len(line) > 50 and " " in line and not line.strip().startswith(("#", "//", "/*"))
        )

        # More natural language than code
        return nl_indicators > code_indicators
