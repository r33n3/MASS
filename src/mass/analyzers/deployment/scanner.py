"""Deployment scanner.

Scans AI deployments to build a comprehensive manifest.
"""

import logging
from pathlib import Path
from typing import Any

from mass.analyzers.deployment.manifest import (
    Component,
    DeploymentManifest,
    ExtractedInstruction,
)
from mass.analyzers.deployment.discovery import ComponentDiscovery
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

logger = logging.getLogger(__name__)


class DeploymentScanner:
    """Scans AI deployments to discover components and extract instructions.

    The scanner performs:
    1. Component discovery - finds all relevant files
    2. Content extraction - extracts prompts, configs, etc.
    3. Dependency analysis - identifies project dependencies
    4. Manifest generation - produces structured output
    """

    # Default extractors in priority order
    DEFAULT_EXTRACTORS: list[type[BaseExtractor]] = [
        PythonExtractor,
        JavaScriptExtractor,
        YamlJsonExtractor,
        EnvExtractor,
        MarkdownExtractor,
        TemplateExtractor,
    ]

    def __init__(
        self,
        extractors: list[BaseExtractor] | None = None,
        ignore_patterns: list[str] | None = None,
        max_file_size: int = 10 * 1024 * 1024,
    ):
        """Initialize the deployment scanner.

        Args:
            extractors: Custom extractors to use. If None, uses defaults.
            ignore_patterns: Additional file patterns to ignore.
            max_file_size: Maximum file size to process in bytes.
        """
        if extractors is None:
            self.extractors = [cls() for cls in self.DEFAULT_EXTRACTORS]
        else:
            self.extractors = extractors

        self.discovery = ComponentDiscovery(
            ignore_patterns=ignore_patterns,
            max_file_size=max_file_size,
        )

        self.max_file_size = max_file_size

    def scan(self, path: str | Path) -> DeploymentManifest:
        """Scan a deployment directory.

        Args:
            path: Path to the deployment directory.

        Returns:
            DeploymentManifest containing all discovered components.
        """
        path = Path(path)

        if not path.exists():
            raise ValueError(f"Path does not exist: {path}")

        if not path.is_dir():
            raise ValueError(f"Path is not a directory: {path}")

        logger.info(f"Scanning deployment at: {path}")

        # Create manifest
        manifest = DeploymentManifest(
            name=path.name,
            path=path,
        )

        # Discover components and dependencies
        components, dependencies = self.discovery.discover(path)

        for dep in dependencies.values():
            manifest.add_dependency(dep)

        # Process each discovered component
        for component in components:
            manifest.add_component(component)

            # Extract content from the component
            self._extract_component(component, path, manifest)

        logger.info(
            f"Scan complete: {manifest.component_count} components, "
            f"{manifest.instruction_count} instructions"
        )

        return manifest

    def scan_file(self, file_path: str | Path) -> ExtractionResult:
        """Scan a single file.

        Args:
            file_path: Path to the file.

        Returns:
            ExtractionResult with discovered content.
        """
        file_path = Path(file_path)

        if not file_path.exists():
            raise ValueError(f"File does not exist: {file_path}")

        if not file_path.is_file():
            raise ValueError(f"Path is not a file: {file_path}")

        try:
            content = file_path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            # Try with latin-1 as fallback
            try:
                content = file_path.read_text(encoding="latin-1")
            except Exception:
                return ExtractionResult(
                    errors=[f"Could not read file: {file_path}"]
                )

        context = ExtractionContext(
            file_path=file_path,
            content=content,
            base_path=file_path.parent,
        )

        # Find appropriate extractor
        for extractor in self.extractors:
            if extractor.can_handle(context):
                return extractor.extract(context)

        return ExtractionResult()

    def _extract_component(
        self,
        component: Component,
        base_path: Path,
        manifest: DeploymentManifest,
    ) -> None:
        """Extract content from a component file."""
        file_path = component.path

        if not file_path.is_file():
            return

        # Check file size
        try:
            if file_path.stat().st_size > self.max_file_size:
                logger.debug(f"Skipping large file: {file_path}")
                return
        except OSError:
            return

        # Read file content
        try:
            content = file_path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            try:
                content = file_path.read_text(encoding="latin-1")
            except Exception as e:
                logger.debug(f"Could not read {file_path}: {e}")
                return

        context = ExtractionContext(
            file_path=file_path,
            content=content,
            base_path=base_path,
        )

        # Update component content
        component.content = content

        # Find and run appropriate extractor
        for extractor in self.extractors:
            if extractor.can_handle(context):
                result = extractor.extract(context)

                # Add extracted instructions to manifest
                for instruction in result.instructions:
                    manifest.add_instruction(instruction)

                # Add model configs
                manifest.model_configs.extend(result.model_configs)

                # Add MCP servers
                manifest.mcp_servers.extend(result.mcp_servers)

                # Update component metadata with extraction results
                if result.has_results:
                    component.metadata["extracted"] = True
                    component.metadata["instruction_count"] = len(result.instructions)

                if result.has_errors:
                    component.metadata["extraction_errors"] = result.errors

                break

    def get_summary(self, manifest: DeploymentManifest) -> dict[str, Any]:
        """Get a summary of the scan results.

        Args:
            manifest: The deployment manifest.

        Returns:
            Dictionary with summary statistics.
        """
        from collections import Counter

        component_types = Counter(c.type.value for c in manifest.components)
        context_types = Counter(i.context_type for i in manifest.instructions)

        template_count = sum(
            1 for i in manifest.instructions if i.is_template
        )

        return {
            "deployment_name": manifest.name,
            "deployment_path": str(manifest.path),
            "total_components": manifest.component_count,
            "total_instructions": manifest.instruction_count,
            "components_by_type": dict(component_types),
            "instructions_by_context": dict(context_types),
            "template_count": template_count,
            "model_configs": len(manifest.model_configs),
            "mcp_servers": len(manifest.mcp_servers),
            "dependencies": len(manifest.dependencies),
            "providers": list(set(m.provider for m in manifest.model_configs)),
        }
