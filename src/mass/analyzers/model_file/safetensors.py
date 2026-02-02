"""Safetensors format validation.

Safetensors is a safe serialization format that prevents code execution.
This analyzer validates the format and checks for anomalies.
"""

import json
import logging
import struct
from pathlib import Path
from typing import Any, Iterator

from mass.core.types import Severity
from mass.analyzers.model_file.scanner import (
    ModelFileFinding,
    FindingCategory,
)

logger = logging.getLogger(__name__)


# Maximum reasonable header size (100MB should be more than enough)
MAX_HEADER_SIZE = 100 * 1024 * 1024

# Supported tensor dtypes
VALID_DTYPES = {
    "F64", "F32", "F16", "BF16",
    "I64", "I32", "I16", "I8",
    "U8", "BOOL",
}


class SafetensorsAnalyzer:
    """Analyzes safetensors files for format compliance.

    Safetensors is designed to be safe - no code execution possible.
    However, we validate the format to detect corruption or tampering.
    """

    def __init__(
        self,
        validate_header: bool = True,
        validate_offsets: bool = True,
        check_metadata: bool = True,
    ):
        """Initialize safetensors analyzer.

        Args:
            validate_header: Validate JSON header structure.
            validate_offsets: Validate tensor offsets and sizes.
            check_metadata: Check metadata for suspicious content.
        """
        self.validate_header = validate_header
        self.validate_offsets = validate_offsets
        self.check_metadata = check_metadata

    def analyze(self, file_path: Path) -> Iterator[ModelFileFinding]:
        """Analyze a safetensors file.

        Args:
            file_path: Path to the safetensors file.

        Yields:
            Security findings (format violations, anomalies).
        """
        file_size = file_path.stat().st_size

        if file_size < 8:
            yield ModelFileFinding(
                category=FindingCategory.FORMAT_VIOLATION,
                severity=Severity.HIGH,
                title="Invalid safetensors file",
                description="File too small to be a valid safetensors file",
                file_path=file_path,
            )
            return

        try:
            with open(file_path, "rb") as f:
                # Read header size (8 bytes, little-endian u64)
                header_size_bytes = f.read(8)
                header_size = struct.unpack("<Q", header_size_bytes)[0]

                # Validate header size
                if header_size > MAX_HEADER_SIZE:
                    yield ModelFileFinding(
                        category=FindingCategory.FORMAT_VIOLATION,
                        severity=Severity.HIGH,
                        title="Excessive header size",
                        description=f"Header size ({header_size}) exceeds maximum ({MAX_HEADER_SIZE})",
                        file_path=file_path,
                        evidence={"header_size": header_size},
                    )
                    return

                if header_size > file_size - 8:
                    yield ModelFileFinding(
                        category=FindingCategory.FORMAT_VIOLATION,
                        severity=Severity.HIGH,
                        title="Invalid header size",
                        description="Header size exceeds file size",
                        file_path=file_path,
                        evidence={
                            "header_size": header_size,
                            "file_size": file_size,
                        },
                    )
                    return

                # Read and parse header
                header_bytes = f.read(header_size)

                try:
                    header = json.loads(header_bytes.decode("utf-8"))
                except json.JSONDecodeError as e:
                    yield ModelFileFinding(
                        category=FindingCategory.FORMAT_VIOLATION,
                        severity=Severity.HIGH,
                        title="Invalid JSON header",
                        description=f"Failed to parse header: {e}",
                        file_path=file_path,
                    )
                    return
                except UnicodeDecodeError as e:
                    yield ModelFileFinding(
                        category=FindingCategory.FORMAT_VIOLATION,
                        severity=Severity.HIGH,
                        title="Invalid header encoding",
                        description=f"Header is not valid UTF-8: {e}",
                        file_path=file_path,
                    )
                    return

                # Validate header structure
                if self.validate_header:
                    yield from self._validate_header(file_path, header, file_size, header_size)

                # Validate tensor offsets
                if self.validate_offsets:
                    yield from self._validate_offsets(file_path, header, file_size, header_size)

                # Check metadata
                if self.check_metadata and "__metadata__" in header:
                    yield from self._check_metadata(file_path, header["__metadata__"])

        except Exception as e:
            yield ModelFileFinding(
                category=FindingCategory.FORMAT_VIOLATION,
                severity=Severity.MEDIUM,
                title="Error reading safetensors file",
                description=str(e),
                file_path=file_path,
            )

    def _validate_header(
        self,
        file_path: Path,
        header: dict[str, Any],
        file_size: int,
        header_size: int,
    ) -> Iterator[ModelFileFinding]:
        """Validate header structure.

        Args:
            file_path: Path to the file.
            header: Parsed JSON header.
            file_size: Total file size.
            header_size: Header size in bytes.

        Yields:
            Validation findings.
        """
        if not isinstance(header, dict):
            yield ModelFileFinding(
                category=FindingCategory.FORMAT_VIOLATION,
                severity=Severity.HIGH,
                title="Invalid header type",
                description="Header must be a JSON object",
                file_path=file_path,
            )
            return

        # Check each tensor entry
        for key, value in header.items():
            if key == "__metadata__":
                continue

            if not isinstance(value, dict):
                yield ModelFileFinding(
                    category=FindingCategory.FORMAT_VIOLATION,
                    severity=Severity.MEDIUM,
                    title=f"Invalid tensor entry: {key}",
                    description="Tensor entry must be an object",
                    file_path=file_path,
                    location=key,
                )
                continue

            # Check required fields
            if "dtype" not in value:
                yield ModelFileFinding(
                    category=FindingCategory.FORMAT_VIOLATION,
                    severity=Severity.MEDIUM,
                    title=f"Missing dtype for tensor: {key}",
                    description="Tensor entry missing required 'dtype' field",
                    file_path=file_path,
                    location=key,
                )

            if "shape" not in value:
                yield ModelFileFinding(
                    category=FindingCategory.FORMAT_VIOLATION,
                    severity=Severity.MEDIUM,
                    title=f"Missing shape for tensor: {key}",
                    description="Tensor entry missing required 'shape' field",
                    file_path=file_path,
                    location=key,
                )

            if "data_offsets" not in value:
                yield ModelFileFinding(
                    category=FindingCategory.FORMAT_VIOLATION,
                    severity=Severity.MEDIUM,
                    title=f"Missing data_offsets for tensor: {key}",
                    description="Tensor entry missing required 'data_offsets' field",
                    file_path=file_path,
                    location=key,
                )

            # Validate dtype
            dtype = value.get("dtype")
            if dtype and dtype not in VALID_DTYPES:
                yield ModelFileFinding(
                    category=FindingCategory.FORMAT_VIOLATION,
                    severity=Severity.MEDIUM,
                    title=f"Unknown dtype for tensor: {key}",
                    description=f"Tensor has unknown dtype: {dtype}",
                    file_path=file_path,
                    location=key,
                    evidence={"dtype": dtype, "valid_dtypes": list(VALID_DTYPES)},
                )

            # Validate shape
            shape = value.get("shape")
            if shape and not isinstance(shape, list):
                yield ModelFileFinding(
                    category=FindingCategory.FORMAT_VIOLATION,
                    severity=Severity.MEDIUM,
                    title=f"Invalid shape for tensor: {key}",
                    description="Shape must be a list",
                    file_path=file_path,
                    location=key,
                )
            elif shape:
                for i, dim in enumerate(shape):
                    if not isinstance(dim, int) or dim < 0:
                        yield ModelFileFinding(
                            category=FindingCategory.FORMAT_VIOLATION,
                            severity=Severity.MEDIUM,
                            title=f"Invalid shape dimension for tensor: {key}",
                            description=f"Shape dimension {i} is invalid: {dim}",
                            file_path=file_path,
                            location=key,
                        )

    def _validate_offsets(
        self,
        file_path: Path,
        header: dict[str, Any],
        file_size: int,
        header_size: int,
    ) -> Iterator[ModelFileFinding]:
        """Validate tensor data offsets.

        Args:
            file_path: Path to the file.
            header: Parsed JSON header.
            file_size: Total file size.
            header_size: Header size in bytes.

        Yields:
            Validation findings.
        """
        data_start = 8 + header_size
        data_size = file_size - data_start

        for key, value in header.items():
            if key == "__metadata__" or not isinstance(value, dict):
                continue

            offsets = value.get("data_offsets")
            if not offsets or not isinstance(offsets, list) or len(offsets) != 2:
                continue

            start, end = offsets

            # Check offset validity
            if not isinstance(start, int) or not isinstance(end, int):
                yield ModelFileFinding(
                    category=FindingCategory.FORMAT_VIOLATION,
                    severity=Severity.MEDIUM,
                    title=f"Invalid offsets for tensor: {key}",
                    description="Offsets must be integers",
                    file_path=file_path,
                    location=key,
                )
                continue

            if start < 0 or end < 0:
                yield ModelFileFinding(
                    category=FindingCategory.FORMAT_VIOLATION,
                    severity=Severity.HIGH,
                    title=f"Negative offset for tensor: {key}",
                    description=f"Tensor has negative offset: [{start}, {end}]",
                    file_path=file_path,
                    location=key,
                )
                continue

            if start > end:
                yield ModelFileFinding(
                    category=FindingCategory.FORMAT_VIOLATION,
                    severity=Severity.HIGH,
                    title=f"Invalid offset range for tensor: {key}",
                    description=f"Start offset ({start}) > end offset ({end})",
                    file_path=file_path,
                    location=key,
                )
                continue

            if end > data_size:
                yield ModelFileFinding(
                    category=FindingCategory.FORMAT_VIOLATION,
                    severity=Severity.HIGH,
                    title=f"Offset out of bounds for tensor: {key}",
                    description=f"End offset ({end}) exceeds data size ({data_size})",
                    file_path=file_path,
                    location=key,
                    evidence={
                        "end_offset": end,
                        "data_size": data_size,
                    },
                )

    def _check_metadata(
        self,
        file_path: Path,
        metadata: Any,
    ) -> Iterator[ModelFileFinding]:
        """Check metadata for suspicious content.

        Args:
            file_path: Path to the file.
            metadata: Metadata from header.

        Yields:
            Metadata findings.
        """
        if not isinstance(metadata, dict):
            yield ModelFileFinding(
                category=FindingCategory.FORMAT_VIOLATION,
                severity=Severity.LOW,
                title="Invalid metadata type",
                description="Metadata must be an object",
                file_path=file_path,
            )
            return

        # Check for suspicious metadata keys/values
        suspicious_patterns = [
            "exec",
            "eval",
            "system",
            "subprocess",
            "os.",
            "__import__",
            "open(",
            "file(",
        ]

        for key, value in metadata.items():
            str_value = str(value).lower()
            for pattern in suspicious_patterns:
                if pattern in str_value:
                    yield ModelFileFinding(
                        category=FindingCategory.SUSPICIOUS_CONTENT,
                        severity=Severity.LOW,
                        title="Suspicious metadata content",
                        description=f"Metadata key '{key}' contains suspicious pattern: {pattern}",
                        file_path=file_path,
                        evidence={
                            "key": key,
                            "pattern": pattern,
                        },
                        remediation="Review metadata content - may be benign but warrants inspection",
                    )

    def get_tensor_info(self, file_path: Path) -> dict[str, Any]:
        """Get tensor information from safetensors file.

        Args:
            file_path: Path to the safetensors file.

        Returns:
            Dictionary with tensor information.
        """
        result = {
            "tensors": {},
            "metadata": {},
            "total_size": 0,
            "header_size": 0,
        }

        try:
            with open(file_path, "rb") as f:
                header_size_bytes = f.read(8)
                header_size = struct.unpack("<Q", header_size_bytes)[0]
                result["header_size"] = header_size

                header_bytes = f.read(header_size)
                header = json.loads(header_bytes.decode("utf-8"))

                if "__metadata__" in header:
                    result["metadata"] = header.pop("__metadata__")

                for name, info in header.items():
                    result["tensors"][name] = {
                        "dtype": info.get("dtype"),
                        "shape": info.get("shape"),
                        "size": info.get("data_offsets", [0, 0])[1] - info.get("data_offsets", [0, 0])[0],
                    }

                result["total_size"] = file_path.stat().st_size

        except Exception as e:
            logger.error(f"Error reading safetensors info: {e}")

        return result
