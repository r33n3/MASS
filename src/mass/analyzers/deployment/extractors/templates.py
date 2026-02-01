"""Template file extractor.

Extracts prompts from Jinja2 and Handlebars template files.
"""

import re
import uuid

from mass.core.types import ComponentType
from mass.analyzers.deployment.manifest import Component, ExtractedInstruction
from mass.analyzers.deployment.extractors.base import (
    BaseExtractor,
    ExtractionContext,
    ExtractionResult,
)


class TemplateExtractor(BaseExtractor):
    """Extracts content from template files.

    Supports:
    - Jinja2 templates (.j2, .jinja, .jinja2)
    - Handlebars templates (.hbs, .handlebars)
    - Mustache templates (.mustache)
    """

    name = "template"
    supported_extensions = [
        "j2", "jinja", "jinja2",
        "hbs", "handlebars",
        "mustache",
    ]

    # Jinja2 variable pattern
    JINJA_VAR_PATTERN = r'\{\{\s*([a-zA-Z_][a-zA-Z0-9_.]*)\s*\}\}'
    JINJA_BLOCK_PATTERN = r'\{%\s*(\w+).*?%\}'

    # Handlebars/Mustache pattern
    HBS_VAR_PATTERN = r'\{\{\s*([#/]?)([a-zA-Z_][a-zA-Z0-9_.]*)\s*\}\}'

    def can_handle(self, context: ExtractionContext) -> bool:
        """Check if this is a template file."""
        if context.extension in self.supported_extensions:
            return True

        # Also check for prompt template files
        name_lower = context.file_name.lower()
        if "prompt" in name_lower and "template" in name_lower:
            return True

        return False

    def extract(self, context: ExtractionContext) -> ExtractionResult:
        """Extract content from template file."""
        result = ExtractionResult()

        # Determine template type
        is_jinja = context.extension in ["j2", "jinja", "jinja2"]
        is_handlebars = context.extension in ["hbs", "handlebars", "mustache"]

        # Extract variables
        if is_jinja:
            vars_found = self._extract_jinja_vars(context.content)
        else:
            vars_found = self._extract_handlebars_vars(context.content)

        # Get the template content (removing template syntax for analysis)
        clean_content = self._clean_template(context.content, is_jinja)

        # Only process if there's substantial content
        if len(clean_content.strip()) > 20:
            result.instructions.append(
                ExtractedInstruction(
                    content=context.content,  # Keep original with template syntax
                    source_file=context.file_path,
                    source_line=1,
                    extraction_method="template",
                    context_type=self._infer_context_type(context),
                    is_template=True,
                    template_vars=list(vars_found),
                    metadata={
                        "template_type": "jinja2" if is_jinja else "handlebars",
                    },
                )
            )

            # Add as component
            result.components.append(
                Component(
                    id=str(uuid.uuid4()),
                    type=ComponentType.CONTEXT,
                    name=context.file_name,
                    path=context.file_path,
                    content=context.content,
                    metadata={
                        "is_template": True,
                        "template_type": "jinja2" if is_jinja else "handlebars",
                        "variables": list(vars_found),
                    },
                )
            )

        return result

    def _extract_jinja_vars(self, content: str) -> set[str]:
        """Extract variable names from Jinja2 template."""
        vars_found = set()

        # Simple variable references
        for match in re.finditer(self.JINJA_VAR_PATTERN, content):
            var_name = match.group(1)
            # Handle dot notation (e.g., user.name -> user)
            base_var = var_name.split(".")[0]
            vars_found.add(base_var)

        # Variables in blocks
        # {# set var = ... #}
        set_pattern = r'\{%\s*set\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*='
        for match in re.finditer(set_pattern, content):
            vars_found.add(match.group(1))

        # Variables in for loops
        # {% for item in items %}
        for_pattern = r'\{%\s*for\s+([a-zA-Z_][a-zA-Z0-9_]*)\s+in\s+([a-zA-Z_][a-zA-Z0-9_.]*)'
        for match in re.finditer(for_pattern, content):
            vars_found.add(match.group(2).split(".")[0])

        return vars_found

    def _extract_handlebars_vars(self, content: str) -> set[str]:
        """Extract variable names from Handlebars template."""
        vars_found = set()

        for match in re.finditer(self.HBS_VAR_PATTERN, content):
            prefix = match.group(1)
            var_name = match.group(2)

            # Skip closing tags and special helpers
            if prefix == "/" or var_name in ["if", "unless", "each", "with", "else"]:
                continue

            # Handle dot notation
            base_var = var_name.split(".")[0]
            vars_found.add(base_var)

        return vars_found

    def _clean_template(self, content: str, is_jinja: bool) -> str:
        """Remove template syntax to get clean content."""
        if is_jinja:
            # Remove Jinja blocks
            content = re.sub(r'\{%.*?%\}', '', content, flags=re.DOTALL)
            # Remove Jinja comments
            content = re.sub(r'\{#.*?#\}', '', content, flags=re.DOTALL)
            # Replace variables with placeholder
            content = re.sub(r'\{\{.*?\}\}', '[VAR]', content)
        else:
            # Remove Handlebars blocks
            content = re.sub(r'\{\{[#/].*?\}\}', '', content)
            # Replace variables with placeholder
            content = re.sub(r'\{\{.*?\}\}', '[VAR]', content)

        return content

    def _infer_context_type(self, context: ExtractionContext) -> str:
        """Infer context type from file name."""
        name_lower = context.file_name.lower()

        if "system" in name_lower:
            return "system_prompt"
        if "persona" in name_lower:
            return "persona"
        if "skill" in name_lower:
            return "skill"
        if "tool" in name_lower:
            return "tool_description"

        return "template"
