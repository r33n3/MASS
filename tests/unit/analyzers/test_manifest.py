"""Tests for deployment manifest models."""

from pathlib import Path

import pytest

from mass.core.types import ComponentType
from mass.analyzers.deployment.manifest import (
    Component,
    ExtractedInstruction,
    DeploymentManifest,
    DependencyInfo,
    ModelConfig,
    MCPServerConfig,
)


class TestComponent:
    """Tests for Component dataclass."""

    def test_component_creation(self) -> None:
        """Test basic component creation."""
        component = Component(
            id="comp-123",
            type=ComponentType.CODE,
            name="main.py",
            path=Path("/project/main.py"),
        )
        assert component.id == "comp-123"
        assert component.type == ComponentType.CODE
        assert component.name == "main.py"

    def test_component_with_content(self) -> None:
        """Test component with content generates hash."""
        component = Component(
            id="comp-123",
            type=ComponentType.CONTEXT,
            name="prompt.md",
            path=Path("/project/prompt.md"),
            content="You are a helpful assistant.",
        )
        assert component.content_hash is not None
        assert len(component.content_hash) == 64  # SHA-256

    def test_component_hash_consistency(self) -> None:
        """Test same content produces same hash."""
        content = "Test content"
        comp1 = Component(
            id="1",
            type=ComponentType.CODE,
            name="test",
            path=Path("/test"),
            content=content,
        )
        comp2 = Component(
            id="2",
            type=ComponentType.CODE,
            name="test2",
            path=Path("/test2"),
            content=content,
        )
        assert comp1.content_hash == comp2.content_hash


class TestExtractedInstruction:
    """Tests for ExtractedInstruction dataclass."""

    def test_instruction_creation(self) -> None:
        """Test basic instruction creation."""
        instruction = ExtractedInstruction(
            content="You are a helpful assistant.",
            source_file=Path("/project/prompt.py"),
            source_line=10,
            extraction_method="ast",
            context_type="system_prompt",
        )
        assert instruction.content == "You are a helpful assistant."
        assert instruction.source_line == 10
        assert not instruction.is_template

    def test_instruction_with_template_vars(self) -> None:
        """Test instruction with template variables."""
        instruction = ExtractedInstruction(
            content="Hello {name}, you are {role}.",
            source_file=Path("/project/prompt.py"),
            source_line=1,
            extraction_method="regex",
            context_type="template",
            is_template=True,
            template_vars=["name", "role"],
        )
        assert instruction.is_template
        assert instruction.has_variables
        assert "name" in instruction.template_vars


class TestDeploymentManifest:
    """Tests for DeploymentManifest dataclass."""

    def test_manifest_creation(self) -> None:
        """Test basic manifest creation."""
        manifest = DeploymentManifest(
            name="my-agent",
            path=Path("/project"),
        )
        assert manifest.name == "my-agent"
        assert manifest.component_count == 0
        assert manifest.instruction_count == 0

    def test_add_component(self) -> None:
        """Test adding components."""
        manifest = DeploymentManifest(name="test", path=Path("/test"))
        component = Component(
            id="1",
            type=ComponentType.CODE,
            name="main.py",
            path=Path("/test/main.py"),
        )
        manifest.add_component(component)
        assert manifest.component_count == 1

    def test_add_instruction(self) -> None:
        """Test adding instructions."""
        manifest = DeploymentManifest(name="test", path=Path("/test"))
        instruction = ExtractedInstruction(
            content="Test prompt",
            source_file=Path("/test/prompt.py"),
            source_line=1,
            extraction_method="test",
            context_type="system_prompt",
        )
        manifest.add_instruction(instruction)
        assert manifest.instruction_count == 1

    def test_components_by_type(self) -> None:
        """Test filtering components by type."""
        manifest = DeploymentManifest(name="test", path=Path("/test"))

        for i, comp_type in enumerate([
            ComponentType.CODE,
            ComponentType.CODE,
            ComponentType.CONFIG,
            ComponentType.CONTEXT,
        ]):
            manifest.add_component(Component(
                id=str(i),
                type=comp_type,
                name=f"file{i}",
                path=Path(f"/test/file{i}"),
            ))

        code_components = manifest.components_by_type(ComponentType.CODE)
        assert len(code_components) == 2

        config_components = manifest.components_by_type(ComponentType.CONFIG)
        assert len(config_components) == 1

    def test_has_component_type(self) -> None:
        """Test checking for component type."""
        manifest = DeploymentManifest(name="test", path=Path("/test"))
        manifest.add_component(Component(
            id="1",
            type=ComponentType.MCP_SERVER,
            name="server",
            path=Path("/test/server"),
        ))

        assert manifest.has_component_type(ComponentType.MCP_SERVER)
        assert not manifest.has_component_type(ComponentType.MODEL)

    def test_to_dict(self) -> None:
        """Test manifest serialization."""
        manifest = DeploymentManifest(name="test", path=Path("/test"))
        manifest.add_component(Component(
            id="1",
            type=ComponentType.CODE,
            name="main.py",
            path=Path("/test/main.py"),
        ))

        result = manifest.to_dict()
        assert result["name"] == "test"
        assert result["component_count"] == 1
        assert len(result["components"]) == 1


class TestDependencyInfo:
    """Tests for DependencyInfo dataclass."""

    def test_dependency_creation(self) -> None:
        """Test dependency creation."""
        dep = DependencyInfo(
            name="langchain",
            version="0.1.0",
            source="pip",
        )
        assert dep.name == "langchain"
        assert dep.version == "0.1.0"
        assert not dep.is_dev


class TestModelConfig:
    """Tests for ModelConfig dataclass."""

    def test_model_config_creation(self) -> None:
        """Test model config creation."""
        config = ModelConfig(
            provider="openai",
            model_name="gpt-4",
            temperature=0.7,
        )
        assert config.provider == "openai"
        assert config.model_name == "gpt-4"
        assert config.temperature == 0.7


class TestMCPServerConfig:
    """Tests for MCPServerConfig dataclass."""

    def test_mcp_server_creation(self) -> None:
        """Test MCP server config creation."""
        server = MCPServerConfig(
            server_url="http://localhost:3000",
            transport="sse",
            tools=["read_file", "write_file"],
        )
        assert server.server_url == "http://localhost:3000"
        assert len(server.tools) == 2
