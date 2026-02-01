"""Tests for content extractors."""

from pathlib import Path

import pytest

from mass.analyzers.deployment.extractors.base import (
    BaseExtractor,
    ExtractionContext,
    ExtractionResult,
)
from mass.analyzers.deployment.extractors.python import PythonExtractor
from mass.analyzers.deployment.extractors.javascript import JavaScriptExtractor
from mass.analyzers.deployment.extractors.yaml_json import YamlJsonExtractor
from mass.analyzers.deployment.extractors.env import EnvExtractor
from mass.analyzers.deployment.extractors.markdown import MarkdownExtractor
from mass.analyzers.deployment.extractors.templates import TemplateExtractor


class TestExtractionContext:
    """Tests for ExtractionContext."""

    def test_context_creation(self) -> None:
        """Test context creation."""
        context = ExtractionContext(
            file_path=Path("/project/src/main.py"),
            content="print('hello')",
            base_path=Path("/project"),
        )
        assert context.extension == "py"
        assert context.file_name == "main.py"

    def test_relative_path(self) -> None:
        """Test relative path calculation."""
        context = ExtractionContext(
            file_path=Path("/project/src/main.py"),
            content="",
            base_path=Path("/project"),
        )
        assert context.relative_path == Path("src/main.py")


class TestExtractionResult:
    """Tests for ExtractionResult."""

    def test_empty_result(self) -> None:
        """Test empty result properties."""
        result = ExtractionResult()
        assert not result.has_results
        assert not result.has_errors

    def test_result_with_content(self) -> None:
        """Test result with content."""
        from mass.analyzers.deployment.manifest import ExtractedInstruction

        result = ExtractionResult()
        result.instructions.append(
            ExtractedInstruction(
                content="test",
                source_file=Path("/test"),
                source_line=1,
                extraction_method="test",
                context_type="test",
            )
        )
        assert result.has_results

    def test_result_merge(self) -> None:
        """Test merging results."""
        from mass.analyzers.deployment.manifest import ExtractedInstruction

        result1 = ExtractionResult()
        result1.instructions.append(
            ExtractedInstruction(
                content="test1",
                source_file=Path("/test"),
                source_line=1,
                extraction_method="test",
                context_type="test",
            )
        )

        result2 = ExtractionResult()
        result2.instructions.append(
            ExtractedInstruction(
                content="test2",
                source_file=Path("/test"),
                source_line=2,
                extraction_method="test",
                context_type="test",
            )
        )

        result1.merge(result2)
        assert len(result1.instructions) == 2


class TestPythonExtractor:
    """Tests for PythonExtractor."""

    def test_can_handle(self) -> None:
        """Test file type detection."""
        extractor = PythonExtractor()
        context = ExtractionContext(
            file_path=Path("/test/main.py"),
            content="",
        )
        assert extractor.can_handle(context)

        context = ExtractionContext(
            file_path=Path("/test/main.js"),
            content="",
        )
        assert not extractor.can_handle(context)

    def test_extract_system_prompt_variable(self) -> None:
        """Test extracting system prompt from variable."""
        extractor = PythonExtractor()
        code = '''
SYSTEM_PROMPT = """You are a helpful AI assistant that helps users with coding tasks."""

def main():
    pass
'''
        context = ExtractionContext(
            file_path=Path("/test/main.py"),
            content=code,
        )
        result = extractor.extract(context)

        assert result.has_results
        assert any(
            "helpful AI assistant" in i.content
            for i in result.instructions
        )

    def test_extract_openai_client(self) -> None:
        """Test extracting OpenAI client configuration."""
        extractor = PythonExtractor()
        code = '''
from openai import OpenAI

client = OpenAI(model="gpt-4-turbo", temperature=0.7)
'''
        context = ExtractionContext(
            file_path=Path("/test/main.py"),
            content=code,
        )
        result = extractor.extract(context)

        assert len(result.model_configs) > 0


class TestJavaScriptExtractor:
    """Tests for JavaScriptExtractor."""

    def test_can_handle(self) -> None:
        """Test file type detection."""
        extractor = JavaScriptExtractor()

        for ext in ["js", "jsx", "ts", "tsx", "mjs"]:
            context = ExtractionContext(
                file_path=Path(f"/test/main.{ext}"),
                content="",
            )
            assert extractor.can_handle(context)

    def test_extract_template_literal(self) -> None:
        """Test extracting from template literals."""
        extractor = JavaScriptExtractor()
        code = '''
const systemPrompt = `You are a helpful assistant that writes code.
You should always explain your reasoning.`;

export { systemPrompt };
'''
        context = ExtractionContext(
            file_path=Path("/test/main.js"),
            content=code,
        )
        result = extractor.extract(context)

        assert result.has_results
        assert any(
            "helpful assistant" in i.content
            for i in result.instructions
        )


class TestYamlJsonExtractor:
    """Tests for YamlJsonExtractor."""

    def test_can_handle_yaml(self) -> None:
        """Test YAML file detection."""
        extractor = YamlJsonExtractor()
        context = ExtractionContext(
            file_path=Path("/test/config.yaml"),
            content="",
        )
        assert extractor.can_handle(context)

    def test_can_handle_json(self) -> None:
        """Test JSON file detection."""
        extractor = YamlJsonExtractor()
        context = ExtractionContext(
            file_path=Path("/test/config.json"),
            content="",
        )
        assert extractor.can_handle(context)

    def test_extract_system_prompt(self) -> None:
        """Test extracting system prompt from JSON."""
        extractor = YamlJsonExtractor()
        content = '''
{
    "system_prompt": "You are a helpful coding assistant.",
    "model": "gpt-4",
    "temperature": 0.7
}
'''
        context = ExtractionContext(
            file_path=Path("/test/config.json"),
            content=content,
        )
        result = extractor.extract(context)

        assert result.has_results
        assert any(
            "coding assistant" in i.content
            for i in result.instructions
        )

    def test_extract_model_config(self) -> None:
        """Test extracting model configuration."""
        extractor = YamlJsonExtractor()
        content = '''
{
    "model": {
        "name": "gpt-4-turbo",
        "provider": "openai"
    }
}
'''
        context = ExtractionContext(
            file_path=Path("/test/config.json"),
            content=content,
        )
        result = extractor.extract(context)

        assert len(result.model_configs) > 0


class TestEnvExtractor:
    """Tests for EnvExtractor."""

    def test_can_handle(self) -> None:
        """Test env file detection."""
        extractor = EnvExtractor()

        for name in [".env", ".env.local", ".env.production"]:
            context = ExtractionContext(
                file_path=Path(f"/test/{name}"),
                content="",
            )
            assert extractor.can_handle(context)

    def test_extract_api_keys(self) -> None:
        """Test extracting API key references."""
        extractor = EnvExtractor()
        content = '''
OPENAI_API_KEY=sk-test123
ANTHROPIC_API_KEY=sk-ant-test123
DATABASE_URL=postgres://localhost/db
'''
        context = ExtractionContext(
            file_path=Path("/test/.env"),
            content=content,
        )
        result = extractor.extract(context)

        assert len(result.components) >= 2
        api_key_names = [c.name for c in result.components]
        assert any("OPENAI" in name for name in api_key_names)


class TestMarkdownExtractor:
    """Tests for MarkdownExtractor."""

    def test_can_handle(self) -> None:
        """Test markdown file detection."""
        extractor = MarkdownExtractor()
        context = ExtractionContext(
            file_path=Path("/test/README.md"),
            content="",
        )
        assert extractor.can_handle(context)

    def test_extract_from_prompt_file(self) -> None:
        """Test extracting from a prompt markdown file."""
        extractor = MarkdownExtractor()
        content = '''# System Prompt

You are a helpful AI assistant that specializes in Python programming.

## Instructions

1. Always explain your code
2. Use type hints
3. Follow PEP 8
'''
        context = ExtractionContext(
            file_path=Path("/test/system_prompt.md"),
            content=content,
        )
        result = extractor.extract(context)

        assert result.has_results


class TestTemplateExtractor:
    """Tests for TemplateExtractor."""

    def test_can_handle_jinja(self) -> None:
        """Test Jinja template detection."""
        extractor = TemplateExtractor()
        context = ExtractionContext(
            file_path=Path("/test/prompt.j2"),
            content="",
        )
        assert extractor.can_handle(context)

    def test_extract_jinja_template(self) -> None:
        """Test extracting Jinja template."""
        extractor = TemplateExtractor()
        content = '''You are a {{ role }} assistant.
{% if expertise %}
You specialize in {{ expertise }}.
{% endif %}

Please help the user with their question: {{ question }}
'''
        context = ExtractionContext(
            file_path=Path("/test/prompt.j2"),
            content=content,
        )
        result = extractor.extract(context)

        assert result.has_results
        assert result.instructions[0].is_template
        assert "role" in result.instructions[0].template_vars
