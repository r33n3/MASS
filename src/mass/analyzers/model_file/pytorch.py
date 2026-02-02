"""PyTorch model file security analysis.

Detects malicious content in PyTorch model files (.pt, .pth, .bin).
PyTorch uses pickle for serialization, so this builds on pickle analysis.
"""

import io
import logging
import struct
import zipfile
from pathlib import Path
from typing import Any, Iterator

from mass.core.types import Severity
from mass.analyzers.model_file.scanner import (
    ModelFileFinding,
    FindingCategory,
)

logger = logging.getLogger(__name__)


# PyTorch-specific dangerous patterns
PYTORCH_DANGEROUS_MODULES = {
    "torch.utils.data": {
        "DataLoader": "May execute custom collate functions",
    },
    "torch.jit": {
        "load": "JIT model loading can execute code",
        "script": "JIT scripting can embed code",
    },
    "torch.cuda": {
        "memory": "CUDA memory operations",
    },
}

# Files that shouldn't be in model archives
SUSPICIOUS_ARCHIVE_FILES = [
    ".py",
    ".pyc",
    ".pyo",
    ".sh",
    ".bash",
    ".bat",
    ".cmd",
    ".exe",
    ".dll",
    ".so",
]


class PyTorchAnalyzer:
    """Analyzes PyTorch model files for security issues.

    PyTorch models are typically zip archives containing:
    - data.pkl: Pickled tensor metadata
    - data/: Directory with tensor data
    - code/: Optional TorchScript code
    """

    def __init__(
        self,
        check_archive: bool = True,
        check_torchscript: bool = True,
        max_file_size: int = 10 * 1024 * 1024 * 1024,  # 10GB
    ):
        """Initialize PyTorch analyzer.

        Args:
            check_archive: Check archive structure for suspicious files.
            check_torchscript: Check TorchScript code if present.
            max_file_size: Maximum file size to analyze.
        """
        self.check_archive = check_archive
        self.check_torchscript = check_torchscript
        self.max_file_size = max_file_size

    def analyze(self, file_path: Path) -> Iterator[ModelFileFinding]:
        """Analyze a PyTorch model file for security issues.

        Args:
            file_path: Path to the PyTorch model file.

        Yields:
            Security findings.
        """
        file_size = file_path.stat().st_size

        if file_size > self.max_file_size:
            yield ModelFileFinding(
                category=FindingCategory.SUSPICIOUS_CONTENT,
                severity=Severity.LOW,
                title="Large model file",
                description=f"File size ({file_size} bytes) exceeds analysis limit",
                file_path=file_path,
            )
            return

        # Check if it's a zip archive (PyTorch format)
        if self._is_pytorch_zip(file_path):
            yield from self._analyze_pytorch_zip(file_path)
        else:
            # Might be raw pickle
            yield from self._analyze_raw_pytorch(file_path)

    def _is_pytorch_zip(self, file_path: Path) -> bool:
        """Check if file is a PyTorch zip archive."""
        try:
            with open(file_path, "rb") as f:
                magic = f.read(4)
            return magic == b"PK\x03\x04"  # ZIP magic number
        except Exception:
            return False

    def _analyze_pytorch_zip(self, file_path: Path) -> Iterator[ModelFileFinding]:
        """Analyze PyTorch zip archive format.

        Args:
            file_path: Path to the PyTorch model file.

        Yields:
            Security findings.
        """
        try:
            with zipfile.ZipFile(file_path, "r") as zf:
                file_list = zf.namelist()

                # Check for suspicious files in archive
                if self.check_archive:
                    for name in file_list:
                        for ext in SUSPICIOUS_ARCHIVE_FILES:
                            if name.lower().endswith(ext):
                                yield ModelFileFinding(
                                    category=FindingCategory.SUSPICIOUS_CONTENT,
                                    severity=Severity.HIGH,
                                    title=f"Suspicious file in model archive: {name}",
                                    description=f"Model archive contains a {ext} file which may indicate embedded code",
                                    file_path=file_path,
                                    location=name,
                                    evidence={"archive_file": name},
                                    remediation="Inspect the archive contents before loading",
                                )

                # Analyze pickle files in archive
                for name in file_list:
                    if name.endswith(".pkl") or name == "data.pkl":
                        yield from self._analyze_archive_pickle(zf, name, file_path)

                # Check for TorchScript code
                if self.check_torchscript:
                    code_files = [n for n in file_list if n.startswith("code/")]
                    if code_files:
                        yield from self._analyze_torchscript(zf, code_files, file_path)

        except zipfile.BadZipFile:
            yield ModelFileFinding(
                category=FindingCategory.FORMAT_VIOLATION,
                severity=Severity.LOW,
                title="Invalid ZIP format",
                description="File appears to be ZIP but is malformed",
                file_path=file_path,
            )
        except Exception as e:
            logger.error(f"Error analyzing PyTorch zip {file_path}: {e}")

    def _analyze_archive_pickle(
        self,
        zf: zipfile.ZipFile,
        name: str,
        file_path: Path,
    ) -> Iterator[ModelFileFinding]:
        """Analyze pickle file within archive.

        Args:
            zf: Open zip file.
            name: Name of pickle file in archive.
            file_path: Path to the model file.

        Yields:
            Security findings.
        """
        try:
            data = zf.read(name)

            # Use pickle analyzer
            from mass.analyzers.model_file.pickle import PickleAnalyzer
            analyzer = PickleAnalyzer()
            result = analyzer.analyze_bytes(data)

            for finding in result.findings:
                severity = Severity.CRITICAL if finding.is_dangerous else Severity.MEDIUM
                yield ModelFileFinding(
                    category=FindingCategory.CODE_EXECUTION if finding.is_dangerous else FindingCategory.SUSPICIOUS_CONTENT,
                    severity=severity,
                    title=f"{'Dangerous' if finding.is_dangerous else 'Suspicious'} import in {name}: {finding.module}.{finding.name}",
                    description=finding.description,
                    file_path=file_path,
                    location=f"{name}:offset {finding.position}",
                    evidence={
                        "archive_file": name,
                        "opcode": finding.opcode,
                        "module": finding.module,
                        "name": finding.name,
                    },
                    remediation="Do not load this model without verifying its source and integrity",
                )

        except Exception as e:
            logger.debug(f"Error analyzing pickle {name} in {file_path}: {e}")

    def _analyze_torchscript(
        self,
        zf: zipfile.ZipFile,
        code_files: list[str],
        file_path: Path,
    ) -> Iterator[ModelFileFinding]:
        """Analyze TorchScript code files.

        Args:
            zf: Open zip file.
            code_files: List of code file names.
            file_path: Path to the model file.

        Yields:
            Security findings.
        """
        # TorchScript presence is notable
        yield ModelFileFinding(
            category=FindingCategory.SUSPICIOUS_CONTENT,
            severity=Severity.LOW,
            title="TorchScript code detected",
            description=f"Model contains {len(code_files)} TorchScript code file(s)",
            file_path=file_path,
            evidence={"code_files": code_files},
            remediation="TorchScript code may contain custom logic - review before loading",
        )

        # Check code files for suspicious patterns
        dangerous_patterns = [
            (b"os.system", "System command execution"),
            (b"subprocess", "Subprocess execution"),
            (b"exec(", "Dynamic code execution"),
            (b"eval(", "Dynamic code evaluation"),
            (b"__import__", "Dynamic import"),
            (b"open(", "File operations"),
            (b"socket", "Network operations"),
        ]

        for name in code_files:
            try:
                content = zf.read(name)
                for pattern, desc in dangerous_patterns:
                    if pattern in content:
                        yield ModelFileFinding(
                            category=FindingCategory.CODE_EXECUTION,
                            severity=Severity.HIGH,
                            title=f"Suspicious pattern in TorchScript: {desc}",
                            description=f"TorchScript file {name} contains {pattern.decode()}",
                            file_path=file_path,
                            location=name,
                            evidence={
                                "pattern": pattern.decode(),
                                "file": name,
                            },
                            remediation="Review TorchScript code before loading this model",
                        )
            except Exception as e:
                logger.debug(f"Error reading TorchScript {name}: {e}")

    def _analyze_raw_pytorch(self, file_path: Path) -> Iterator[ModelFileFinding]:
        """Analyze raw (non-zip) PyTorch file.

        Args:
            file_path: Path to the model file.

        Yields:
            Security findings.
        """
        # Check if it's a pickle file
        try:
            with open(file_path, "rb") as f:
                header = f.read(2)

            if header in (b"\x80\x02", b"\x80\x03", b"\x80\x04", b"\x80\x05"):
                # It's a pickle, delegate to pickle analyzer
                from mass.analyzers.model_file.pickle import PickleAnalyzer
                analyzer = PickleAnalyzer()
                yield from analyzer.analyze(file_path)
        except Exception as e:
            logger.debug(f"Error analyzing raw PyTorch file {file_path}: {e}")

    def check_model_integrity(
        self,
        file_path: Path,
        expected_keys: list[str] | None = None,
    ) -> Iterator[ModelFileFinding]:
        """Check model structure integrity.

        Args:
            file_path: Path to the model file.
            expected_keys: Optional list of expected state dict keys.

        Yields:
            Integrity findings.
        """
        if not self._is_pytorch_zip(file_path):
            return

        try:
            with zipfile.ZipFile(file_path, "r") as zf:
                file_list = zf.namelist()

                # Check for expected structure
                has_data_pkl = "data.pkl" in file_list or any(
                    n.endswith("/data.pkl") for n in file_list
                )
                has_data_dir = any(n.startswith("data/") for n in file_list)

                if not has_data_pkl:
                    yield ModelFileFinding(
                        category=FindingCategory.FORMAT_VIOLATION,
                        severity=Severity.MEDIUM,
                        title="Missing data.pkl",
                        description="PyTorch archive missing expected data.pkl file",
                        file_path=file_path,
                    )

        except Exception as e:
            logger.debug(f"Error checking integrity of {file_path}: {e}")
