"""Model file security scanner.

Main scanner that orchestrates analysis of model files for security issues.
"""

import hashlib
import logging
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Iterator

from mass.core.types import Severity

logger = logging.getLogger(__name__)


class ModelFormat(str, Enum):
    """Supported model file formats."""
    PICKLE = "pickle"
    PYTORCH = "pytorch"
    SAFETENSORS = "safetensors"
    GGUF = "gguf"
    ONNX = "onnx"
    TENSORFLOW = "tensorflow"
    KERAS = "keras"
    UNKNOWN = "unknown"


class FindingCategory(str, Enum):
    """Categories of model file security findings."""
    CODE_EXECUTION = "code_execution"
    MALICIOUS_PAYLOAD = "malicious_payload"
    UNSAFE_DESERIALIZATION = "unsafe_deserialization"
    SUPPLY_CHAIN = "supply_chain"
    FORMAT_VIOLATION = "format_violation"
    SUSPICIOUS_CONTENT = "suspicious_content"


@dataclass
class ModelFileFinding:
    """A security finding in a model file."""
    category: FindingCategory
    severity: Severity
    title: str
    description: str
    file_path: Path
    location: str | None = None
    evidence: dict[str, Any] = field(default_factory=dict)
    remediation: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "category": self.category.value,
            "severity": self.severity.value,
            "title": self.title,
            "description": self.description,
            "file_path": str(self.file_path),
            "location": self.location,
            "evidence": self.evidence,
            "remediation": self.remediation,
        }


@dataclass
class ModelFileResult:
    """Result of scanning a model file."""
    file_path: Path
    file_size: int
    file_hash: str
    format: ModelFormat
    findings: list[ModelFileFinding] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)

    @property
    def is_safe(self) -> bool:
        """Check if no security issues were found."""
        return len(self.findings) == 0

    @property
    def critical_count(self) -> int:
        """Count of critical findings."""
        return sum(1 for f in self.findings if f.severity == Severity.CRITICAL)

    @property
    def high_count(self) -> int:
        """Count of high severity findings."""
        return sum(1 for f in self.findings if f.severity == Severity.HIGH)

    def findings_by_severity(self, severity: Severity) -> list[ModelFileFinding]:
        """Get findings filtered by severity."""
        return [f for f in self.findings if f.severity == severity]


# File extension to format mapping
FORMAT_EXTENSIONS: dict[str, ModelFormat] = {
    ".pkl": ModelFormat.PICKLE,
    ".pickle": ModelFormat.PICKLE,
    ".pt": ModelFormat.PYTORCH,
    ".pth": ModelFormat.PYTORCH,
    ".bin": ModelFormat.PYTORCH,  # Can also be safetensors
    ".safetensors": ModelFormat.SAFETENSORS,
    ".gguf": ModelFormat.GGUF,
    ".onnx": ModelFormat.ONNX,
    ".pb": ModelFormat.TENSORFLOW,
    ".h5": ModelFormat.KERAS,
    ".keras": ModelFormat.KERAS,
}


class ModelFileScanner:
    """Scanner for detecting security issues in model files.

    Analyzes model files for:
    - Pickle deserialization attacks
    - Malicious code embedded in PyTorch models
    - Format-specific vulnerabilities
    - Supply chain issues (hash verification, provenance)
    """

    def __init__(
        self,
        check_pickle: bool = True,
        check_pytorch: bool = True,
        check_safetensors: bool = True,
        check_gguf: bool = True,
        check_supply_chain: bool = True,
        trusted_sources: list[str] | None = None,
    ):
        """Initialize model file scanner.

        Args:
            check_pickle: Enable pickle exploit detection.
            check_pytorch: Enable PyTorch malware detection.
            check_safetensors: Enable safetensors validation.
            check_gguf: Enable GGUF validation.
            check_supply_chain: Enable supply chain verification.
            trusted_sources: List of trusted model sources/hubs.
        """
        self.check_pickle = check_pickle
        self.check_pytorch = check_pytorch
        self.check_safetensors = check_safetensors
        self.check_gguf = check_gguf
        self.check_supply_chain = check_supply_chain
        self.trusted_sources = trusted_sources or [
            "huggingface.co",
            "pytorch.org",
            "tensorflow.org",
        ]

        # Lazy-load analyzers
        self._pickle_analyzer = None
        self._pytorch_analyzer = None
        self._safetensors_analyzer = None
        self._gguf_analyzer = None
        self._supply_chain_analyzer = None

    @property
    def pickle_analyzer(self):
        """Get pickle analyzer (lazy load)."""
        if self._pickle_analyzer is None:
            from mass.analyzers.model_file.pickle import PickleAnalyzer
            self._pickle_analyzer = PickleAnalyzer()
        return self._pickle_analyzer

    @property
    def pytorch_analyzer(self):
        """Get PyTorch analyzer (lazy load)."""
        if self._pytorch_analyzer is None:
            from mass.analyzers.model_file.pytorch import PyTorchAnalyzer
            self._pytorch_analyzer = PyTorchAnalyzer()
        return self._pytorch_analyzer

    @property
    def safetensors_analyzer(self):
        """Get safetensors analyzer (lazy load)."""
        if self._safetensors_analyzer is None:
            from mass.analyzers.model_file.safetensors import SafetensorsAnalyzer
            self._safetensors_analyzer = SafetensorsAnalyzer()
        return self._safetensors_analyzer

    @property
    def gguf_analyzer(self):
        """Get GGUF analyzer (lazy load)."""
        if self._gguf_analyzer is None:
            from mass.analyzers.model_file.gguf import GGUFAnalyzer
            self._gguf_analyzer = GGUFAnalyzer()
        return self._gguf_analyzer

    @property
    def supply_chain_analyzer(self):
        """Get supply chain analyzer (lazy load)."""
        if self._supply_chain_analyzer is None:
            from mass.analyzers.model_file.supply_chain import SupplyChainAnalyzer
            self._supply_chain_analyzer = SupplyChainAnalyzer(
                trusted_sources=self.trusted_sources
            )
        return self._supply_chain_analyzer

    def detect_format(self, file_path: Path) -> ModelFormat:
        """Detect model file format.

        Args:
            file_path: Path to the model file.

        Returns:
            Detected model format.
        """
        suffix = file_path.suffix.lower()

        # Check extension first
        if suffix in FORMAT_EXTENSIONS:
            # Special case: .bin could be PyTorch or safetensors
            if suffix == ".bin":
                return self._detect_bin_format(file_path)
            return FORMAT_EXTENSIONS[suffix]

        # Try to detect from content
        return self._detect_from_content(file_path)

    def _detect_bin_format(self, file_path: Path) -> ModelFormat:
        """Detect format of .bin files."""
        try:
            with open(file_path, "rb") as f:
                header = f.read(8)

            # Safetensors starts with JSON header size
            if len(header) >= 8:
                # Check if it looks like safetensors (little-endian u64 header size)
                header_size = int.from_bytes(header[:8], "little")
                if 0 < header_size < 100_000_000:  # Reasonable header size
                    return ModelFormat.SAFETENSORS

            return ModelFormat.PYTORCH
        except Exception:
            return ModelFormat.UNKNOWN

    def _detect_from_content(self, file_path: Path) -> ModelFormat:
        """Detect format from file content."""
        try:
            with open(file_path, "rb") as f:
                header = f.read(16)

            # Check magic bytes
            if header.startswith(b"GGUF"):
                return ModelFormat.GGUF
            if header.startswith(b"\x80\x04\x95"):  # Pickle protocol 4
                return ModelFormat.PICKLE
            if header.startswith(b"\x80\x05\x95"):  # Pickle protocol 5
                return ModelFormat.PICKLE

            return ModelFormat.UNKNOWN
        except Exception:
            return ModelFormat.UNKNOWN

    def compute_hash(self, file_path: Path, algorithm: str = "sha256") -> str:
        """Compute file hash.

        Args:
            file_path: Path to the file.
            algorithm: Hash algorithm (sha256, sha1, md5).

        Returns:
            Hex digest of the hash.
        """
        hasher = hashlib.new(algorithm)
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                hasher.update(chunk)
        return hasher.hexdigest()

    def scan_file(self, file_path: Path | str) -> ModelFileResult:
        """Scan a single model file for security issues.

        Args:
            file_path: Path to the model file.

        Returns:
            ModelFileResult with findings.
        """
        file_path = Path(file_path)

        if not file_path.exists():
            return ModelFileResult(
                file_path=file_path,
                file_size=0,
                file_hash="",
                format=ModelFormat.UNKNOWN,
                errors=[f"File not found: {file_path}"],
            )

        # Get file info
        file_size = file_path.stat().st_size
        file_hash = self.compute_hash(file_path)
        model_format = self.detect_format(file_path)

        result = ModelFileResult(
            file_path=file_path,
            file_size=file_size,
            file_hash=file_hash,
            format=model_format,
            metadata={
                "extension": file_path.suffix,
                "name": file_path.name,
            },
        )

        # Run format-specific analyzers
        try:
            findings = list(self._analyze_file(file_path, model_format))
            result.findings.extend(findings)
        except Exception as e:
            result.errors.append(f"Analysis error: {e}")
            logger.exception(f"Error analyzing {file_path}")

        # Run supply chain checks
        if self.check_supply_chain:
            try:
                supply_findings = self.supply_chain_analyzer.analyze(
                    file_path, file_hash
                )
                result.findings.extend(supply_findings)
            except Exception as e:
                result.errors.append(f"Supply chain check error: {e}")

        return result

    def _analyze_file(
        self,
        file_path: Path,
        model_format: ModelFormat,
    ) -> Iterator[ModelFileFinding]:
        """Analyze file based on format.

        Args:
            file_path: Path to the model file.
            model_format: Detected model format.

        Yields:
            Security findings.
        """
        # Pickle analysis (applies to pickle and pytorch)
        if self.check_pickle and model_format in (
            ModelFormat.PICKLE,
            ModelFormat.PYTORCH,
        ):
            yield from self.pickle_analyzer.analyze(file_path)

        # Format-specific analysis
        if self.check_pytorch and model_format == ModelFormat.PYTORCH:
            yield from self.pytorch_analyzer.analyze(file_path)

        if self.check_safetensors and model_format == ModelFormat.SAFETENSORS:
            yield from self.safetensors_analyzer.analyze(file_path)

        if self.check_gguf and model_format == ModelFormat.GGUF:
            yield from self.gguf_analyzer.analyze(file_path)

    def scan_directory(
        self,
        directory: Path | str,
        recursive: bool = True,
    ) -> list[ModelFileResult]:
        """Scan a directory for model files.

        Args:
            directory: Directory to scan.
            recursive: Scan subdirectories.

        Returns:
            List of results for each model file found.
        """
        directory = Path(directory)
        results = []

        # Find model files
        pattern = "**/*" if recursive else "*"
        for file_path in directory.glob(pattern):
            if file_path.is_file() and self._is_model_file(file_path):
                result = self.scan_file(file_path)
                results.append(result)

        return results

    def _is_model_file(self, file_path: Path) -> bool:
        """Check if file is a model file.

        Args:
            file_path: Path to check.

        Returns:
            True if file appears to be a model file.
        """
        suffix = file_path.suffix.lower()
        return suffix in FORMAT_EXTENSIONS or self.detect_format(file_path) != ModelFormat.UNKNOWN
