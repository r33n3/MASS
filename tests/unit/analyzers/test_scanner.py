"""Tests for deployment scanner."""

import tempfile
from pathlib import Path

import pytest

from mass.core.types import ComponentType
from mass.analyzers.deployment.scanner import DeploymentScanner
from mass.analyzers.deployment.discovery import ComponentDiscovery


class TestComponentDiscovery:
    """Tests for ComponentDiscovery."""

    def test_ignore_patterns(self) -> None:
        """Test that ignore patterns work."""
        discovery = ComponentDiscovery()

        with tempfile.TemporaryDirectory() as tmpdir:
            base = Path(tmpdir)

            # Create some files
            (base / "main.py").write_text("print('hello')")
            (base / "__pycache__").mkdir()
            (base / "__pycache__" / "main.cpython-312.pyc").write_bytes(b"")

            components, _ = discovery.discover(base)

            # Should find main.py but not pycache
            names = [c.name for c in components]
            assert "main.py" in names
            assert "main.cpython-312.pyc" not in names

    def test_discover_components(self) -> None:
        """Test component discovery."""
        discovery = ComponentDiscovery()

        with tempfile.TemporaryDirectory() as tmpdir:
            base = Path(tmpdir)

            # Create various file types
            (base / "main.py").write_text("print('hello')")
            (base / "config.yaml").write_text("key: value")
            (base / "README.md").write_text("# Project")

            components, _ = discovery.discover(base)

            assert len(components) == 3

            types = {c.type for c in components}
            assert ComponentType.CODE in types
            assert ComponentType.CONFIG in types
            assert ComponentType.CONTEXT in types

    def test_discover_dependencies(self) -> None:
        """Test dependency discovery."""
        discovery = ComponentDiscovery()

        with tempfile.TemporaryDirectory() as tmpdir:
            base = Path(tmpdir)

            # Create requirements.txt
            (base / "requirements.txt").write_text(
                "langchain==0.1.0\nopenai>=1.0.0\n"
            )

            _, dependencies = discovery.discover(base)

            assert "langchain" in dependencies
            assert dependencies["langchain"].version == "0.1.0"

    def test_discover_npm_dependencies(self) -> None:
        """Test npm dependency discovery."""
        discovery = ComponentDiscovery()

        with tempfile.TemporaryDirectory() as tmpdir:
            base = Path(tmpdir)

            # Create package.json
            (base / "package.json").write_text('''
{
    "dependencies": {
        "openai": "^4.0.0"
    },
    "devDependencies": {
        "typescript": "^5.0.0"
    }
}
''')

            _, dependencies = discovery.discover(base)

            assert "openai" in dependencies
            assert "typescript" in dependencies
            assert dependencies["typescript"].is_dev


class TestDeploymentScanner:
    """Tests for DeploymentScanner."""

    def test_scan_empty_directory(self) -> None:
        """Test scanning an empty directory."""
        scanner = DeploymentScanner()

        with tempfile.TemporaryDirectory() as tmpdir:
            manifest = scanner.scan(tmpdir)

            assert manifest.name == Path(tmpdir).name
            assert manifest.component_count == 0

    def test_scan_python_project(self) -> None:
        """Test scanning a Python project."""
        scanner = DeploymentScanner()

        with tempfile.TemporaryDirectory() as tmpdir:
            base = Path(tmpdir)

            # Create a simple Python project
            (base / "main.py").write_text('''
SYSTEM_PROMPT = """You are a helpful assistant."""

def run():
    from openai import OpenAI
    client = OpenAI(model="gpt-4")
    return client.chat.completions.create(
        messages=[{"role": "system", "content": SYSTEM_PROMPT}]
    )
''')
            (base / "config.yaml").write_text('''
model:
  name: gpt-4
  temperature: 0.7
''')

            manifest = scanner.scan(base)

            assert manifest.component_count >= 2
            assert manifest.instruction_count >= 1

    def test_scan_with_mcp_config(self) -> None:
        """Test scanning with MCP configuration."""
        scanner = DeploymentScanner()

        with tempfile.TemporaryDirectory() as tmpdir:
            base = Path(tmpdir)

            # Create MCP config
            (base / ".mcp.json").write_text('''
{
    "mcpServers": {
        "filesystem": {
            "url": "http://localhost:3000",
            "tools": ["read_file", "write_file"]
        }
    }
}
''')

            manifest = scanner.scan(base)

            assert len(manifest.mcp_servers) >= 1

    def test_scan_file(self) -> None:
        """Test scanning a single file."""
        scanner = DeploymentScanner()

        with tempfile.TemporaryDirectory() as tmpdir:
            file_path = Path(tmpdir) / "prompt.py"
            file_path.write_text('''
PROMPT = """You are a code review assistant.
Focus on:
1. Code quality
2. Best practices
3. Security issues
"""
''')

            result = scanner.scan_file(file_path)

            assert result.has_results
            assert any(
                "code review" in i.content.lower()
                for i in result.instructions
            )

    def test_scan_nonexistent_path(self) -> None:
        """Test error handling for nonexistent path."""
        scanner = DeploymentScanner()

        with pytest.raises(ValueError, match="does not exist"):
            scanner.scan("/nonexistent/path")

    def test_get_summary(self) -> None:
        """Test getting scan summary."""
        scanner = DeploymentScanner()

        with tempfile.TemporaryDirectory() as tmpdir:
            base = Path(tmpdir)

            (base / "main.py").write_text("x = 1")
            (base / "config.yaml").write_text("key: value")

            manifest = scanner.scan(base)
            summary = scanner.get_summary(manifest)

            assert "deployment_name" in summary
            assert "total_components" in summary
            assert "components_by_type" in summary
            assert summary["total_components"] == 2
