"""GGUF format validation.

GGUF (GPT-Generated Unified Format) is used by llama.cpp for model storage.
This analyzer validates the format and checks for anomalies.
"""

import logging
import struct
from dataclasses import dataclass
from enum import IntEnum
from pathlib import Path
from typing import Any, Iterator

from mass.core.types import Severity
from mass.analyzers.model_file.scanner import (
    ModelFileFinding,
    FindingCategory,
)

logger = logging.getLogger(__name__)


# GGUF magic number
GGUF_MAGIC = b"GGUF"

# Supported GGUF versions
SUPPORTED_VERSIONS = {2, 3}


class GGUFValueType(IntEnum):
    """GGUF metadata value types."""
    UINT8 = 0
    INT8 = 1
    UINT16 = 2
    INT16 = 3
    UINT32 = 4
    INT32 = 5
    FLOAT32 = 6
    BOOL = 7
    STRING = 8
    ARRAY = 9
    UINT64 = 10
    INT64 = 11
    FLOAT64 = 12


class GGMLType(IntEnum):
    """GGML tensor quantization types."""
    F32 = 0
    F16 = 1
    Q4_0 = 2
    Q4_1 = 3
    Q5_0 = 6
    Q5_1 = 7
    Q8_0 = 8
    Q8_1 = 9
    Q2_K = 10
    Q3_K = 11
    Q4_K = 12
    Q5_K = 13
    Q6_K = 14
    Q8_K = 15
    IQ2_XXS = 16
    IQ2_XS = 17
    IQ3_XXS = 18
    IQ1_S = 19
    IQ4_NL = 20
    IQ3_S = 21
    IQ2_S = 22
    IQ4_XS = 23
    I8 = 24
    I16 = 25
    I32 = 26
    I64 = 27
    F64 = 28
    BF16 = 29


@dataclass
class GGUFHeader:
    """GGUF file header information."""
    magic: bytes
    version: int
    tensor_count: int
    metadata_kv_count: int


class GGUFAnalyzer:
    """Analyzes GGUF files for format compliance.

    GGUF is designed to be safe - no code execution possible.
    We validate the format to detect corruption or tampering.
    """

    def __init__(
        self,
        validate_header: bool = True,
        validate_metadata: bool = True,
        validate_tensors: bool = True,
        check_alignment: bool = True,
    ):
        """Initialize GGUF analyzer.

        Args:
            validate_header: Validate GGUF header.
            validate_metadata: Validate metadata key-value pairs.
            validate_tensors: Validate tensor information.
            check_alignment: Check data alignment.
        """
        self.validate_header = validate_header
        self.validate_metadata = validate_metadata
        self.validate_tensors = validate_tensors
        self.check_alignment = check_alignment

    def analyze(self, file_path: Path) -> Iterator[ModelFileFinding]:
        """Analyze a GGUF file.

        Args:
            file_path: Path to the GGUF file.

        Yields:
            Security findings (format violations, anomalies).
        """
        file_size = file_path.stat().st_size

        if file_size < 24:  # Minimum header size
            yield ModelFileFinding(
                category=FindingCategory.FORMAT_VIOLATION,
                severity=Severity.HIGH,
                title="Invalid GGUF file",
                description="File too small to be a valid GGUF file",
                file_path=file_path,
            )
            return

        try:
            with open(file_path, "rb") as f:
                # Read and validate header
                header = self._read_header(f)

                if self.validate_header:
                    yield from self._validate_header(file_path, header)
                    if header is None:
                        return

                # Read metadata
                if self.validate_metadata and header:
                    yield from self._validate_metadata(f, file_path, header)

                # Validate tensor info
                if self.validate_tensors and header:
                    yield from self._validate_tensors(f, file_path, header, file_size)

        except Exception as e:
            yield ModelFileFinding(
                category=FindingCategory.FORMAT_VIOLATION,
                severity=Severity.MEDIUM,
                title="Error reading GGUF file",
                description=str(e),
                file_path=file_path,
            )

    def _read_header(self, f) -> GGUFHeader | None:
        """Read GGUF header.

        Args:
            f: Open file object.

        Returns:
            GGUFHeader or None if invalid.
        """
        try:
            magic = f.read(4)
            version = struct.unpack("<I", f.read(4))[0]
            tensor_count = struct.unpack("<Q", f.read(8))[0]
            metadata_kv_count = struct.unpack("<Q", f.read(8))[0]

            return GGUFHeader(
                magic=magic,
                version=version,
                tensor_count=tensor_count,
                metadata_kv_count=metadata_kv_count,
            )
        except Exception:
            return None

    def _validate_header(
        self,
        file_path: Path,
        header: GGUFHeader | None,
    ) -> Iterator[ModelFileFinding]:
        """Validate GGUF header.

        Args:
            file_path: Path to the file.
            header: Parsed header.

        Yields:
            Validation findings.
        """
        if header is None:
            yield ModelFileFinding(
                category=FindingCategory.FORMAT_VIOLATION,
                severity=Severity.HIGH,
                title="Failed to read GGUF header",
                description="Could not parse GGUF header",
                file_path=file_path,
            )
            return

        # Check magic
        if header.magic != GGUF_MAGIC:
            yield ModelFileFinding(
                category=FindingCategory.FORMAT_VIOLATION,
                severity=Severity.HIGH,
                title="Invalid GGUF magic number",
                description=f"Expected {GGUF_MAGIC!r}, got {header.magic!r}",
                file_path=file_path,
                evidence={"expected": GGUF_MAGIC.hex(), "actual": header.magic.hex()},
            )

        # Check version
        if header.version not in SUPPORTED_VERSIONS:
            yield ModelFileFinding(
                category=FindingCategory.FORMAT_VIOLATION,
                severity=Severity.MEDIUM,
                title="Unsupported GGUF version",
                description=f"Version {header.version} not in supported versions {SUPPORTED_VERSIONS}",
                file_path=file_path,
                evidence={"version": header.version},
            )

        # Sanity check counts
        if header.tensor_count > 100000:
            yield ModelFileFinding(
                category=FindingCategory.SUSPICIOUS_CONTENT,
                severity=Severity.MEDIUM,
                title="Excessive tensor count",
                description=f"File claims {header.tensor_count} tensors",
                file_path=file_path,
                evidence={"tensor_count": header.tensor_count},
            )

        if header.metadata_kv_count > 10000:
            yield ModelFileFinding(
                category=FindingCategory.SUSPICIOUS_CONTENT,
                severity=Severity.MEDIUM,
                title="Excessive metadata count",
                description=f"File claims {header.metadata_kv_count} metadata entries",
                file_path=file_path,
                evidence={"metadata_count": header.metadata_kv_count},
            )

    def _validate_metadata(
        self,
        f,
        file_path: Path,
        header: GGUFHeader,
    ) -> Iterator[ModelFileFinding]:
        """Validate metadata key-value pairs.

        Args:
            f: Open file object.
            file_path: Path to the file.
            header: Parsed header.

        Yields:
            Validation findings.
        """
        try:
            for i in range(min(header.metadata_kv_count, 1000)):  # Limit iterations
                # Read key
                key_length = struct.unpack("<Q", f.read(8))[0]
                if key_length > 1024:  # Sanity check
                    yield ModelFileFinding(
                        category=FindingCategory.FORMAT_VIOLATION,
                        severity=Severity.MEDIUM,
                        title="Excessive metadata key length",
                        description=f"Metadata key {i} has length {key_length}",
                        file_path=file_path,
                    )
                    return

                key = f.read(key_length).decode("utf-8", errors="replace")

                # Read value type
                value_type = struct.unpack("<I", f.read(4))[0]

                # Skip value based on type
                self._skip_value(f, value_type)

                # Check for suspicious keys
                if self._is_suspicious_key(key):
                    yield ModelFileFinding(
                        category=FindingCategory.SUSPICIOUS_CONTENT,
                        severity=Severity.LOW,
                        title="Suspicious metadata key",
                        description=f"Metadata contains suspicious key: {key}",
                        file_path=file_path,
                        evidence={"key": key},
                    )

        except Exception as e:
            yield ModelFileFinding(
                category=FindingCategory.FORMAT_VIOLATION,
                severity=Severity.MEDIUM,
                title="Error reading metadata",
                description=str(e),
                file_path=file_path,
            )

    def _skip_value(self, f, value_type: int) -> None:
        """Skip a metadata value based on its type.

        Args:
            f: Open file object.
            value_type: GGUF value type.
        """
        if value_type == GGUFValueType.UINT8:
            f.read(1)
        elif value_type == GGUFValueType.INT8:
            f.read(1)
        elif value_type == GGUFValueType.UINT16:
            f.read(2)
        elif value_type == GGUFValueType.INT16:
            f.read(2)
        elif value_type == GGUFValueType.UINT32:
            f.read(4)
        elif value_type == GGUFValueType.INT32:
            f.read(4)
        elif value_type == GGUFValueType.FLOAT32:
            f.read(4)
        elif value_type == GGUFValueType.BOOL:
            f.read(1)
        elif value_type == GGUFValueType.STRING:
            length = struct.unpack("<Q", f.read(8))[0]
            f.read(min(length, 10 * 1024 * 1024))  # Cap at 10MB
        elif value_type == GGUFValueType.ARRAY:
            array_type = struct.unpack("<I", f.read(4))[0]
            array_len = struct.unpack("<Q", f.read(8))[0]
            for _ in range(min(array_len, 100000)):
                self._skip_value(f, array_type)
        elif value_type == GGUFValueType.UINT64:
            f.read(8)
        elif value_type == GGUFValueType.INT64:
            f.read(8)
        elif value_type == GGUFValueType.FLOAT64:
            f.read(8)

    def _validate_tensors(
        self,
        f,
        file_path: Path,
        header: GGUFHeader,
        file_size: int,
    ) -> Iterator[ModelFileFinding]:
        """Validate tensor information.

        Args:
            f: Open file object.
            file_path: Path to the file.
            header: Parsed header.
            file_size: Total file size.

        Yields:
            Validation findings.
        """
        try:
            for i in range(min(header.tensor_count, 10000)):  # Limit iterations
                # Read tensor name
                name_length = struct.unpack("<Q", f.read(8))[0]
                if name_length > 1024:
                    yield ModelFileFinding(
                        category=FindingCategory.FORMAT_VIOLATION,
                        severity=Severity.MEDIUM,
                        title="Excessive tensor name length",
                        description=f"Tensor {i} has name length {name_length}",
                        file_path=file_path,
                    )
                    return

                name = f.read(name_length).decode("utf-8", errors="replace")

                # Read dimensions
                n_dims = struct.unpack("<I", f.read(4))[0]
                if n_dims > 8:
                    yield ModelFileFinding(
                        category=FindingCategory.FORMAT_VIOLATION,
                        severity=Severity.MEDIUM,
                        title="Excessive tensor dimensions",
                        description=f"Tensor '{name}' has {n_dims} dimensions",
                        file_path=file_path,
                        evidence={"tensor": name, "dimensions": n_dims},
                    )

                # Read dimension sizes
                dims = []
                for _ in range(n_dims):
                    dim = struct.unpack("<Q", f.read(8))[0]
                    dims.append(dim)

                # Read type
                tensor_type = struct.unpack("<I", f.read(4))[0]

                # Read offset
                offset = struct.unpack("<Q", f.read(8))[0]

                # Validate offset
                if offset > file_size:
                    yield ModelFileFinding(
                        category=FindingCategory.FORMAT_VIOLATION,
                        severity=Severity.HIGH,
                        title="Invalid tensor offset",
                        description=f"Tensor '{name}' offset ({offset}) exceeds file size ({file_size})",
                        file_path=file_path,
                        evidence={"tensor": name, "offset": offset, "file_size": file_size},
                    )

        except Exception as e:
            yield ModelFileFinding(
                category=FindingCategory.FORMAT_VIOLATION,
                severity=Severity.MEDIUM,
                title="Error reading tensor info",
                description=str(e),
                file_path=file_path,
            )

    def _is_suspicious_key(self, key: str) -> bool:
        """Check if metadata key is suspicious.

        Args:
            key: Metadata key.

        Returns:
            True if suspicious.
        """
        suspicious_patterns = [
            "exec",
            "eval",
            "system",
            "subprocess",
            "__import__",
            "os.",
            "cmd",
            "shell",
        ]
        key_lower = key.lower()
        return any(p in key_lower for p in suspicious_patterns)

    def get_model_info(self, file_path: Path) -> dict[str, Any]:
        """Get model information from GGUF file.

        Args:
            file_path: Path to the GGUF file.

        Returns:
            Dictionary with model information.
        """
        result = {
            "version": None,
            "tensor_count": 0,
            "metadata_count": 0,
            "file_size": file_path.stat().st_size,
        }

        try:
            with open(file_path, "rb") as f:
                header = self._read_header(f)
                if header:
                    result["version"] = header.version
                    result["tensor_count"] = header.tensor_count
                    result["metadata_count"] = header.metadata_kv_count
        except Exception as e:
            logger.error(f"Error reading GGUF info: {e}")

        return result
