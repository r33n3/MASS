"""Static analysis for MCP server code.

Performs AST-based static analysis on MCP server implementations.
"""

import ast
import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterator

from mass.core.types import Severity
from mass.analyzers.mcp.analyzer import MCPFinding, MCPRiskCategory

logger = logging.getLogger(__name__)


@dataclass
class CodeLocation:
    """Location in source code."""
    file_path: Path
    line_number: int
    column: int = 0
    end_line: int | None = None

    def __str__(self) -> str:
        return f"{self.file_path}:{self.line_number}"


@dataclass
class StaticFinding:
    """Finding from static analysis."""
    category: MCPRiskCategory
    severity: Severity
    title: str
    description: str
    location: CodeLocation
    code_snippet: str | None = None
    evidence: dict[str, Any] = field(default_factory=dict)
    remediation: str | None = None


class MCPStaticAnalyzer:
    """Static analyzer for MCP server code.

    Performs AST analysis on Python MCP server implementations
    to detect security issues.
    """

    def __init__(self):
        """Initialize static analyzer."""
        # Dangerous function calls
        # NOTE: open() excluded — it's a Python builtin used in virtually
        # every file and generates excessive false positives.
        self._dangerous_calls = {
            "eval": (Severity.CRITICAL, "Code execution via eval"),
            "exec": (Severity.CRITICAL, "Code execution via exec"),
            "compile": (Severity.HIGH, "Dynamic code compilation"),
            "os.system": (Severity.CRITICAL, "Shell command execution"),
            "os.popen": (Severity.CRITICAL, "Shell command execution"),
            "subprocess.call": (Severity.HIGH, "Subprocess execution"),
            "subprocess.run": (Severity.HIGH, "Subprocess execution"),
            "subprocess.Popen": (Severity.HIGH, "Subprocess execution"),
            "__import__": (Severity.LOW, "Dynamic import"),
            "pickle.loads": (Severity.HIGH, "Unsafe deserialization"),
            "yaml.load": (Severity.MEDIUM, "Potentially unsafe YAML loading"),
            "marshal.loads": (Severity.HIGH, "Unsafe deserialization"),
        }

        # Dangerous module imports
        # NOTE: ctypes and socket excluded — they are standard library modules
        # used legitimately in most applications.  More specific checks
        # (exfiltration patterns, subprocess calls) catch actual misuse.
        self._dangerous_imports = {
            "cffi": (Severity.MEDIUM, "Native code access via CFFI"),
            "pickle": (Severity.MEDIUM, "Serialization (deserialization attacks)"),
            "marshal": (Severity.MEDIUM, "Serialization (deserialization attacks)"),
        }

    def analyze_file(self, file_path: Path | str) -> list[StaticFinding]:
        """Analyze a Python file.

        Args:
            file_path: Path to Python file.

        Returns:
            List of findings.
        """
        file_path = Path(file_path)

        if not file_path.exists():
            return []

        try:
            content = file_path.read_text(encoding="utf-8")
        except Exception as e:
            logger.error(f"Error reading {file_path}: {e}")
            return []

        return self.analyze_code(content, file_path)

    def analyze_code(
        self,
        code: str,
        file_path: Path | None = None,
    ) -> list[StaticFinding]:
        """Analyze Python code.

        Args:
            code: Python source code.
            file_path: Optional file path for context.

        Returns:
            List of findings.
        """
        file_path = file_path or Path("<string>")
        findings = []

        try:
            tree = ast.parse(code)
        except SyntaxError as e:
            logger.debug(f"Syntax error in {file_path}: {e}")
            return []

        # Analyze AST
        findings.extend(self._analyze_imports(tree, file_path, code))
        findings.extend(self._analyze_calls(tree, file_path, code))
        findings.extend(self._analyze_strings(tree, file_path, code))
        findings.extend(self._analyze_tool_handlers(tree, file_path, code))

        return findings

    def _analyze_imports(
        self,
        tree: ast.AST,
        file_path: Path,
        code: str,
    ) -> Iterator[StaticFinding]:
        """Analyze import statements.

        Args:
            tree: AST tree.
            file_path: File path.
            code: Source code.

        Yields:
            Findings for dangerous imports.
        """
        lines = code.splitlines()

        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name in self._dangerous_imports:
                        severity, desc = self._dangerous_imports[alias.name]
                        yield StaticFinding(
                            category=MCPRiskCategory.UNSAFE_EXECUTION,
                            severity=severity,
                            title=f"Dangerous import: {alias.name}",
                            description=desc,
                            location=CodeLocation(
                                file_path=file_path,
                                line_number=node.lineno,
                            ),
                            code_snippet=lines[node.lineno - 1] if node.lineno <= len(lines) else None,
                            remediation="Review necessity of this import",
                        )

            elif isinstance(node, ast.ImportFrom):
                module = node.module or ""
                if module in self._dangerous_imports:
                    severity, desc = self._dangerous_imports[module]
                    yield StaticFinding(
                        category=MCPRiskCategory.UNSAFE_EXECUTION,
                        severity=severity,
                        title=f"Dangerous import: {module}",
                        description=desc,
                        location=CodeLocation(
                            file_path=file_path,
                            line_number=node.lineno,
                        ),
                        code_snippet=lines[node.lineno - 1] if node.lineno <= len(lines) else None,
                        remediation="Review necessity of this import",
                    )

    def _analyze_calls(
        self,
        tree: ast.AST,
        file_path: Path,
        code: str,
    ) -> Iterator[StaticFinding]:
        """Analyze function calls.

        Args:
            tree: AST tree.
            file_path: File path.
            code: Source code.

        Yields:
            Findings for dangerous calls.
        """
        lines = code.splitlines()

        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                func_name = self._get_call_name(node)

                if func_name in self._dangerous_calls:
                    severity, desc = self._dangerous_calls[func_name]
                    yield StaticFinding(
                        category=MCPRiskCategory.UNSAFE_EXECUTION,
                        severity=severity,
                        title=f"Dangerous call: {func_name}",
                        description=desc,
                        location=CodeLocation(
                            file_path=file_path,
                            line_number=node.lineno,
                        ),
                        code_snippet=lines[node.lineno - 1] if node.lineno <= len(lines) else None,
                        remediation="Review and validate inputs to this call",
                    )

    def _get_call_name(self, node: ast.Call) -> str:
        """Get the name of a function call.

        Args:
            node: Call AST node.

        Returns:
            Function name string.
        """
        if isinstance(node.func, ast.Name):
            return node.func.id
        elif isinstance(node.func, ast.Attribute):
            parts = []
            current = node.func
            while isinstance(current, ast.Attribute):
                parts.append(current.attr)
                current = current.value
            if isinstance(current, ast.Name):
                parts.append(current.id)
            return ".".join(reversed(parts))
        return ""

    def _analyze_strings(
        self,
        tree: ast.AST,
        file_path: Path,
        code: str,
    ) -> Iterator[StaticFinding]:
        """Analyze string literals for secrets.

        Args:
            tree: AST tree.
            file_path: File path.
            code: Source code.

        Yields:
            Findings for exposed secrets.
        """
        lines = code.splitlines()

        # Patterns for secrets in strings
        secret_patterns = [
            (r"^(sk|pk|api|key|token|secret|password|auth)[-_]?[a-zA-Z0-9]{20,}$", "Potential API key"),
            (r"^ghp_[a-zA-Z0-9]{36}$", "GitHub personal access token"),
            (r"^sk-[a-zA-Z0-9]{48}$", "OpenAI API key"),
            (r"^sk-ant-api[a-zA-Z0-9\-]{40,}$", "Anthropic API key"),
        ]

        for node in ast.walk(tree):
            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                value = node.value
                for pattern, desc in secret_patterns:
                    if re.match(pattern, value, re.IGNORECASE):
                        yield StaticFinding(
                            category=MCPRiskCategory.AUTHENTICATION,
                            severity=Severity.CRITICAL,
                            title=f"Hardcoded secret: {desc}",
                            description="Hardcoded credential found in source",
                            location=CodeLocation(
                                file_path=file_path,
                                line_number=node.lineno,
                            ),
                            code_snippet=lines[node.lineno - 1] if node.lineno <= len(lines) else None,
                            evidence={"pattern": desc},
                            remediation="Use environment variables for secrets",
                        )
                        break

    def _analyze_tool_handlers(
        self,
        tree: ast.AST,
        file_path: Path,
        code: str,
    ) -> Iterator[StaticFinding]:
        """Analyze MCP tool handler implementations.

        Args:
            tree: AST tree.
            file_path: File path.
            code: Source code.

        Yields:
            Findings for unsafe tool handlers.
        """
        lines = code.splitlines()

        for node in ast.walk(tree):
            # Look for functions that might be tool handlers
            if isinstance(node, ast.FunctionDef):
                # Check if it looks like a tool handler
                if self._is_tool_handler(node):
                    # Check for input validation
                    has_validation = self._has_input_validation(node)
                    if not has_validation:
                        yield StaticFinding(
                            category=MCPRiskCategory.UNSAFE_EXECUTION,
                            severity=Severity.MEDIUM,
                            title=f"Tool handler without input validation: {node.name}",
                            description="Tool handler may not validate inputs properly",
                            location=CodeLocation(
                                file_path=file_path,
                                line_number=node.lineno,
                            ),
                            code_snippet=lines[node.lineno - 1] if node.lineno <= len(lines) else None,
                            remediation="Add input validation to tool handler",
                        )

    # Function name patterns that indicate actual MCP/LLM tool handlers.
    # Uses regex with word boundaries to avoid matching "callback",
    # "toolbar", "install", "recall", etc.
    _TOOL_HANDLER_NAME_RE = re.compile(
        r"(?:^|_)(?:tool|handle_tool|call_tool|execute_tool|run_tool|"
        r"tool_handler|tool_executor)(?:$|_)",
        re.IGNORECASE,
    )

    def _is_tool_handler(self, node: ast.FunctionDef) -> bool:
        """Check if function is a tool handler.

        Args:
            node: Function definition node.

        Returns:
            True if function appears to be a tool handler.
        """
        # Check decorators (high confidence — these are explicit markers)
        for decorator in node.decorator_list:
            if isinstance(decorator, ast.Name):
                if decorator.id in ("tool", "server_tool", "handle_tool"):
                    return True
            elif isinstance(decorator, ast.Call):
                if isinstance(decorator.func, ast.Attribute):
                    if decorator.func.attr in ("tool", "list_tools", "call_tool"):
                        return True

        # Check function name with word-boundary-aware patterns
        if self._TOOL_HANDLER_NAME_RE.search(node.name):
            return True

        return False

    def _has_input_validation(self, node: ast.FunctionDef) -> bool:
        """Check if function has input validation.

        Args:
            node: Function definition node.

        Returns:
            True if function appears to validate inputs.
        """
        # Look for validation patterns
        validation_patterns = [
            "validate",
            "check",
            "assert",
            "raise",
            "isinstance",
            "try",
        ]

        for child in ast.walk(node):
            if isinstance(child, ast.Name):
                if any(p in child.id.lower() for p in validation_patterns):
                    return True
            elif isinstance(child, ast.Call):
                name = self._get_call_name(child)
                if any(p in name.lower() for p in validation_patterns):
                    return True
            elif isinstance(child, ast.Assert):
                return True
            elif isinstance(child, ast.Raise):
                return True
            elif isinstance(child, ast.Try):
                return True

        return False

    def analyze_directory(
        self,
        directory: Path | str,
        recursive: bool = True,
    ) -> list[StaticFinding]:
        """Analyze all Python files in a directory.

        Args:
            directory: Directory to scan.
            recursive: Scan subdirectories.

        Returns:
            List of all findings.
        """
        directory = Path(directory)
        findings = []

        pattern = "**/*.py" if recursive else "*.py"
        for file_path in directory.glob(pattern):
            file_findings = self.analyze_file(file_path)
            findings.extend(file_findings)

        return findings
