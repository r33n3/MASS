"""Pickle deserialization attack detection.

Detects malicious pickle payloads that could execute arbitrary code
when deserialized. Based on techniques from fickling and modelscan.
"""

import io
import logging
import pickle
import pickletools
import struct
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterator

from mass.core.types import Severity
from mass.analyzers.model_file.scanner import (
    ModelFileFinding,
    FindingCategory,
)

logger = logging.getLogger(__name__)


# Dangerous modules and functions that indicate code execution
DANGEROUS_IMPORTS: dict[str, dict[str, str]] = {
    # OS command execution
    "os": {
        "system": "Executes shell commands",
        "popen": "Opens a pipe to a shell command",
        "spawn": "Spawns a new process",
        "exec": "Executes a program",
        "fork": "Creates a child process",
    },
    "subprocess": {
        "call": "Executes a command",
        "run": "Executes a command",
        "Popen": "Opens a process",
        "check_output": "Executes and returns output",
        "check_call": "Executes a command",
    },
    "commands": {
        "getoutput": "Executes shell command",
        "getstatusoutput": "Executes shell command",
    },
    # Code execution
    "builtins": {
        "exec": "Executes Python code",
        "eval": "Evaluates Python expression",
        "compile": "Compiles code",
        "__import__": "Dynamic import",
    },
    "__builtin__": {
        "exec": "Executes Python code",
        "eval": "Evaluates Python expression",
    },
    # Network operations
    "socket": {
        "socket": "Creates network socket",
        "create_connection": "Opens network connection",
    },
    "urllib": {
        "urlopen": "Opens URL connection",
        "urlretrieve": "Downloads file from URL",
    },
    "urllib.request": {
        "urlopen": "Opens URL connection",
        "urlretrieve": "Downloads file from URL",
    },
    "requests": {
        "get": "HTTP GET request",
        "post": "HTTP POST request",
        "request": "HTTP request",
    },
    # File operations
    "io": {
        "open": "Opens files",
        "FileIO": "File I/O operations",
    },
    "shutil": {
        "rmtree": "Deletes directory tree",
        "copy": "Copies files",
        "move": "Moves files",
    },
    # Code/module manipulation
    "importlib": {
        "import_module": "Dynamic module import",
    },
    "ctypes": {
        "CDLL": "Loads shared library",
        "cdll": "C library loader",
    },
    # Pickle-specific exploits
    "pickle": {
        "loads": "Nested pickle deserialization",
    },
    "_pickle": {
        "loads": "Nested pickle deserialization",
    },
    # Common exploit patterns
    "nt": {
        "system": "Windows command execution",
    },
    "posix": {
        "system": "POSIX command execution",
    },
}

# Suspicious but not necessarily malicious
SUSPICIOUS_IMPORTS: dict[str, dict[str, str]] = {
    "marshal": {
        "loads": "Binary Python object loading",
    },
    "code": {
        "CodeType": "Code object creation",
    },
    "types": {
        "FunctionType": "Function object creation",
        "CodeType": "Code object creation",
    },
}


@dataclass
class PickleFinding:
    """Finding from pickle analysis."""
    opcode: str
    module: str
    name: str
    position: int
    is_dangerous: bool
    description: str


@dataclass
class PickleAnalysisResult:
    """Result of pickle file analysis."""
    is_valid_pickle: bool
    protocol_version: int | None = None
    findings: list[PickleFinding] = field(default_factory=list)
    imports: list[tuple[str, str]] = field(default_factory=list)
    reduce_calls: list[dict[str, Any]] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


class PickleAnalyzer:
    """Analyzes pickle files for malicious content.

    Uses static analysis to detect dangerous operations without
    actually deserializing the pickle payload.
    """

    def __init__(
        self,
        check_dangerous: bool = True,
        check_suspicious: bool = True,
        max_file_size: int = 500 * 1024 * 1024,  # 500MB
    ):
        """Initialize pickle analyzer.

        Args:
            check_dangerous: Flag known dangerous imports.
            check_suspicious: Flag suspicious imports.
            max_file_size: Maximum file size to analyze.
        """
        self.check_dangerous = check_dangerous
        self.check_suspicious = check_suspicious
        self.max_file_size = max_file_size

    def analyze(self, file_path: Path) -> Iterator[ModelFileFinding]:
        """Analyze a pickle file for security issues.

        Args:
            file_path: Path to the pickle file.

        Yields:
            Security findings.
        """
        # Check file size
        file_size = file_path.stat().st_size
        if file_size > self.max_file_size:
            yield ModelFileFinding(
                category=FindingCategory.SUSPICIOUS_CONTENT,
                severity=Severity.LOW,
                title="Large pickle file",
                description=f"File size ({file_size} bytes) exceeds analysis limit",
                file_path=file_path,
            )
            return

        try:
            with open(file_path, "rb") as f:
                data = f.read()
        except Exception as e:
            logger.error(f"Failed to read {file_path}: {e}")
            return

        # Analyze pickle content
        result = self.analyze_bytes(data)

        if not result.is_valid_pickle:
            for error in result.errors:
                yield ModelFileFinding(
                    category=FindingCategory.FORMAT_VIOLATION,
                    severity=Severity.LOW,
                    title="Invalid pickle format",
                    description=error,
                    file_path=file_path,
                )
            return

        # Convert findings to ModelFileFindings
        for finding in result.findings:
            if finding.is_dangerous:
                yield ModelFileFinding(
                    category=FindingCategory.CODE_EXECUTION,
                    severity=Severity.CRITICAL,
                    title=f"Dangerous import: {finding.module}.{finding.name}",
                    description=finding.description,
                    file_path=file_path,
                    location=f"offset {finding.position}",
                    evidence={
                        "opcode": finding.opcode,
                        "module": finding.module,
                        "name": finding.name,
                    },
                    remediation="Do not load this model file. It contains code that could execute malicious operations.",
                )
            else:
                yield ModelFileFinding(
                    category=FindingCategory.SUSPICIOUS_CONTENT,
                    severity=Severity.MEDIUM,
                    title=f"Suspicious import: {finding.module}.{finding.name}",
                    description=finding.description,
                    file_path=file_path,
                    location=f"offset {finding.position}",
                    evidence={
                        "opcode": finding.opcode,
                        "module": finding.module,
                        "name": finding.name,
                    },
                    remediation="Review this model file carefully before loading.",
                )

        # Check for REDUCE operations (function calls)
        for reduce_call in result.reduce_calls:
            if reduce_call.get("suspicious"):
                yield ModelFileFinding(
                    category=FindingCategory.SUSPICIOUS_CONTENT,
                    severity=Severity.MEDIUM,
                    title="Pickle REDUCE operation detected",
                    description="Pickle contains function call that may execute code on deserialization",
                    file_path=file_path,
                    location=f"offset {reduce_call.get('position', 'unknown')}",
                    evidence=reduce_call,
                    remediation="Verify the source and integrity of this model file.",
                )

    def analyze_bytes(self, data: bytes) -> PickleAnalysisResult:
        """Analyze pickle bytes without deserializing.

        Args:
            data: Raw pickle bytes.

        Returns:
            Analysis result with findings.
        """
        result = PickleAnalysisResult(is_valid_pickle=False)

        # Try to get protocol version
        try:
            if data[0:2] == b"\x80\x05":
                result.protocol_version = 5
            elif data[0:2] == b"\x80\x04":
                result.protocol_version = 4
            elif data[0:2] == b"\x80\x03":
                result.protocol_version = 3
            elif data[0:2] == b"\x80\x02":
                result.protocol_version = 2
            else:
                result.protocol_version = 0
        except IndexError:
            result.errors.append("File too small to be a valid pickle")
            return result

        # Use pickletools to disassemble
        try:
            ops = list(pickletools.genops(io.BytesIO(data)))
            result.is_valid_pickle = True
        except Exception as e:
            result.errors.append(f"Failed to parse pickle: {e}")
            return result

        # Analyze opcodes
        for op, arg, pos in ops:
            opname = op.name

            # Check for GLOBAL/STACK_GLOBAL (imports)
            if opname in ("GLOBAL", "STACK_GLOBAL"):
                if isinstance(arg, tuple) and len(arg) == 2:
                    module, name = arg
                elif isinstance(arg, str) and " " in arg:
                    module, name = arg.split(" ", 1)
                else:
                    continue

                result.imports.append((module, name))

                # Check if dangerous
                if self.check_dangerous and module in DANGEROUS_IMPORTS:
                    if name in DANGEROUS_IMPORTS[module]:
                        result.findings.append(PickleFinding(
                            opcode=opname,
                            module=module,
                            name=name,
                            position=pos,
                            is_dangerous=True,
                            description=DANGEROUS_IMPORTS[module][name],
                        ))
                        continue

                # Check if suspicious
                if self.check_suspicious and module in SUSPICIOUS_IMPORTS:
                    if name in SUSPICIOUS_IMPORTS[module]:
                        result.findings.append(PickleFinding(
                            opcode=opname,
                            module=module,
                            name=name,
                            position=pos,
                            is_dangerous=False,
                            description=SUSPICIOUS_IMPORTS[module][name],
                        ))

            # Check for REDUCE (function calls)
            elif opname == "REDUCE":
                result.reduce_calls.append({
                    "position": pos,
                    "suspicious": True,
                })

            # Check for BUILD (object reconstruction)
            elif opname == "BUILD":
                # BUILD can invoke __setstate__ which might be dangerous
                pass

        return result

    def scan_for_exploits(self, data: bytes) -> list[dict[str, Any]]:
        """Scan for known pickle exploit patterns.

        Args:
            data: Raw pickle bytes.

        Returns:
            List of detected exploit patterns.
        """
        exploits = []

        # Common exploit signatures
        patterns = [
            (b"cos\nsystem", "os.system command execution"),
            (b"csubprocess\n", "subprocess module usage"),
            (b"cbuiltins\nexec", "builtins.exec code execution"),
            (b"cbuiltins\neval", "builtins.eval code execution"),
            (b"c__builtin__\nexec", "__builtin__.exec code execution"),
            (b"c__builtin__\neval", "__builtin__.eval code execution"),
            (b"cposix\nsystem", "posix.system command execution"),
            (b"cnt\nsystem", "nt.system command execution"),
            (b"cio\nopen", "io.open file access"),
            (b"csocket\nsocket", "socket network access"),
            (b"curllib", "urllib network access"),
            (b"crequests", "requests network access"),
            (b"cctypes", "ctypes native code loading"),
        ]

        for pattern, description in patterns:
            if pattern in data:
                pos = data.find(pattern)
                exploits.append({
                    "pattern": pattern.decode("latin-1"),
                    "description": description,
                    "position": pos,
                })

        return exploits
