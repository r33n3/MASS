"""Component discovery logic.

Discovers components within a deployment by analyzing file structure
and content.
"""

import fnmatch
import logging
import uuid
from pathlib import Path
from typing import Any

from mass.core.filesystem import EXCLUDED_DIRS as _SHARED_EXCLUDED_DIRS
from mass.core.types import ComponentType
from mass.analyzers.deployment.manifest import Component, DependencyInfo

logger = logging.getLogger(__name__)


class ComponentDiscovery:
    """Discovers components in a deployment directory.

    Analyzes project structure to identify:
    - Source code files
    - Configuration files
    - Model definitions
    - Infrastructure files
    """

    # Default patterns to ignore (file name patterns)
    IGNORE_PATTERNS = [
        "*.pyc",
        ".env.local",
        "*.egg-info",
        "*.log",
        "*.tmp",
        ".DS_Store",
        "Thumbs.db",
    ]

    # Shared exclusion list — single source of truth in mass.core.filesystem
    IGNORE_DIRS = _SHARED_EXCLUDED_DIRS

    # File patterns for different component types
    COMPONENT_PATTERNS = {
        ComponentType.CODE: [
            "*.py",
            "*.js",
            "*.ts",
            "*.jsx",
            "*.tsx",
            "*.mjs",
            "*.cjs",
        ],
        ComponentType.CONFIG: [
            "*.yaml",
            "*.yml",
            "*.json",
            "*.toml",
            "*.ini",
            "*.cfg",
            ".env*",
            "*.mcp.json",
        ],
        ComponentType.CONTEXT: [
            "*.md",
            "*.txt",
            "CLAUDE.md",
            "system_prompt*",
            "prompt*",
            "instruction*",
        ],
        ComponentType.INFRASTRUCTURE: [
            "Dockerfile*",
            "docker-compose*.yml",
            "docker-compose*.yaml",
            "*.dockerfile",
            "*.k8s.yaml",
            "*.k8s.yml",
            "helm/**/*.yaml",
            "terraform/*.tf",
            "*.tf",
        ],
        ComponentType.KNOWLEDGE: [
            "*.csv",
            "*.parquet",
            "*.jsonl",
            "data/**/*",
            "knowledge/**/*",
        ],
    }

    # Dependency file patterns
    DEPENDENCY_PATTERNS = {
        "pip": ["requirements*.txt", "pyproject.toml", "setup.py", "Pipfile"],
        "npm": ["package.json", "package-lock.json", "yarn.lock", "pnpm-lock.yaml"],
        "cargo": ["Cargo.toml", "Cargo.lock"],
        "go": ["go.mod", "go.sum"],
    }

    def __init__(
        self,
        ignore_patterns: list[str] | None = None,
        max_file_size: int = 10 * 1024 * 1024,  # 10MB
    ):
        """Initialize component discovery.

        Args:
            ignore_patterns: Additional patterns to ignore.
            max_file_size: Maximum file size to process in bytes.
        """
        self.ignore_patterns = self.IGNORE_PATTERNS + (ignore_patterns or [])
        self.max_file_size = max_file_size

    def discover(self, path: Path) -> tuple[list[Component], dict[str, DependencyInfo]]:
        """Discover all components in a directory.

        Args:
            path: Path to the deployment directory.

        Returns:
            Tuple of (components, dependencies).
        """
        components: list[Component] = []
        dependencies: dict[str, DependencyInfo] = {}

        if not path.exists():
            logger.warning(f"Path does not exist: {path}")
            return components, dependencies

        # Walk the directory tree
        for file_path in self._walk_directory(path):
            # Check for dependency files
            self._check_dependency_file(file_path, dependencies)

            # Determine component type
            component_type = self._determine_component_type(file_path)

            if component_type:
                components.append(
                    Component(
                        id=str(uuid.uuid4()),
                        type=component_type,
                        name=file_path.name,
                        path=file_path,
                        metadata={
                            "size": file_path.stat().st_size,
                            "relative_path": str(file_path.relative_to(path)),
                        },
                    )
                )

        return components, dependencies

    def _walk_directory(self, path: Path):
        """Walk directory yielding files that should be processed.

        Uses os.walk with topdown=True to prune excluded directories
        in-place, avoiding traversal of large subtrees like llama.cpp,
        node_modules, etc.
        """
        import os

        for dirpath, dirnames, filenames in os.walk(str(path), topdown=True):
            # Prune excluded directories IN PLACE so os.walk skips them
            dirnames[:] = [
                d for d in dirnames
                if d not in self.IGNORE_DIRS and not d.endswith(".egg-info")
            ]

            for filename in filenames:
                file_path = Path(dirpath) / filename

                # Check filename ignore patterns
                if self._should_ignore_file(filename):
                    continue

                # Check file size
                try:
                    if file_path.stat().st_size > self.max_file_size:
                        continue
                except OSError:
                    continue

                yield file_path

    def _should_ignore_file(self, filename: str) -> bool:
        """Check if a file should be ignored based on its name.

        Directory-level exclusion is handled by _walk_directory via
        IGNORE_DIRS pruning.  This method only checks filename patterns.
        """
        for pattern in self.ignore_patterns:
            if fnmatch.fnmatch(filename, pattern):
                return True
        return False

    def _determine_component_type(self, file_path: Path) -> ComponentType | None:
        """Determine the component type of a file."""
        name = file_path.name.lower()
        suffix = file_path.suffix.lower()

        # Check each component type
        for component_type, patterns in self.COMPONENT_PATTERNS.items():
            for pattern in patterns:
                if fnmatch.fnmatch(name, pattern.lower()):
                    return component_type
                if pattern.startswith("*") and fnmatch.fnmatch(name, pattern.lower()):
                    return component_type

        # Fallback based on extension
        code_extensions = {".py", ".js", ".ts", ".jsx", ".tsx", ".mjs", ".cjs"}
        config_extensions = {".yaml", ".yml", ".json", ".toml", ".ini"}
        doc_extensions = {".md", ".txt", ".rst"}

        if suffix in code_extensions:
            return ComponentType.CODE
        if suffix in config_extensions:
            return ComponentType.CONFIG
        if suffix in doc_extensions:
            return ComponentType.CONTEXT

        return None

    def _check_dependency_file(
        self, file_path: Path, dependencies: dict[str, DependencyInfo]
    ) -> None:
        """Check if file is a dependency file and parse it."""
        name = file_path.name.lower()

        for source, patterns in self.DEPENDENCY_PATTERNS.items():
            for pattern in patterns:
                if fnmatch.fnmatch(name, pattern.lower()):
                    try:
                        deps = self._parse_dependency_file(file_path, source)
                        dependencies.update(deps)
                    except Exception as e:
                        logger.debug(f"Error parsing {file_path}: {e}")
                    return

    def _parse_dependency_file(
        self, file_path: Path, source: str
    ) -> dict[str, DependencyInfo]:
        """Parse a dependency file."""
        dependencies: dict[str, DependencyInfo] = {}

        try:
            content = file_path.read_text(encoding="utf-8")
        except Exception:
            return dependencies

        if source == "pip":
            dependencies.update(self._parse_pip_dependencies(content, file_path))
        elif source == "npm":
            dependencies.update(self._parse_npm_dependencies(content))

        return dependencies

    def _parse_pip_dependencies(
        self, content: str, file_path: Path
    ) -> dict[str, DependencyInfo]:
        """Parse pip dependency files."""
        import re
        dependencies: dict[str, DependencyInfo] = {}

        if file_path.name.endswith(".txt"):
            # requirements.txt format
            for line in content.split("\n"):
                line = line.strip()
                if not line or line.startswith("#") or line.startswith("-"):
                    continue

                # Parse package==version or package>=version
                match = re.match(r'^([a-zA-Z0-9_-]+)([<>=!~]+.*)?$', line)
                if match:
                    name = match.group(1)
                    version = match.group(2).lstrip("=<>!~") if match.group(2) else None
                    dependencies[name] = DependencyInfo(
                        name=name,
                        version=version,
                        source="pip",
                        is_dev="dev" in file_path.name.lower(),
                    )

        elif file_path.name == "pyproject.toml":
            # Parse pyproject.toml
            try:
                import tomllib
                data = tomllib.loads(content)

                # project.dependencies
                for dep in data.get("project", {}).get("dependencies", []):
                    match = re.match(r'^([a-zA-Z0-9_-]+)', dep)
                    if match:
                        dependencies[match.group(1)] = DependencyInfo(
                            name=match.group(1),
                            source="pip",
                        )

                # optional-dependencies (dev dependencies)
                for group, deps in data.get("project", {}).get("optional-dependencies", {}).items():
                    for dep in deps:
                        match = re.match(r'^([a-zA-Z0-9_-]+)', dep)
                        if match:
                            dependencies[match.group(1)] = DependencyInfo(
                                name=match.group(1),
                                source="pip",
                                is_dev=True,
                            )

            except Exception:
                pass

        return dependencies

    def _parse_npm_dependencies(self, content: str) -> dict[str, DependencyInfo]:
        """Parse npm package.json."""
        import json
        dependencies: dict[str, DependencyInfo] = {}

        try:
            data = json.loads(content)

            for name, version in data.get("dependencies", {}).items():
                dependencies[name] = DependencyInfo(
                    name=name,
                    version=version.lstrip("^~"),
                    source="npm",
                )

            for name, version in data.get("devDependencies", {}).items():
                dependencies[name] = DependencyInfo(
                    name=name,
                    version=version.lstrip("^~"),
                    source="npm",
                    is_dev=True,
                )

        except json.JSONDecodeError:
            pass

        return dependencies
