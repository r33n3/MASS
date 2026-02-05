"""Model file magic number registry.

Maps binary file signatures (magic numbers) to model format metadata.
Used for reliable format detection independent of file extensions.

Reference:
    GGUF: https://github.com/ggerganov/ggml/blob/master/docs/gguf.md
    Safetensors: https://huggingface.co/docs/safetensors
    ONNX/Protobuf: https://onnx.ai/
    Pickle: https://docs.python.org/3/library/pickle.html
    PyTorch (ZIP): https://pytorch.org/docs/stable/notes/serialization.html
"""

from dataclasses import dataclass


@dataclass(frozen=True)
class MagicSignature:
    """A binary file signature with format metadata."""

    magic: bytes
    offset: int
    format_name: str
    description: str
    is_model: bool = True
    risk_level: str = "low"


# Ordered list of magic signatures, checked sequentially.
# More specific signatures should come before generic ones.
MODEL_SIGNATURES: list[MagicSignature] = [
    # --- ML Model Formats ---
    MagicSignature(
        magic=b"GGUF",
        offset=0,
        format_name="gguf",
        description="GGML Universal Format (quantized LLM)",
        risk_level="low",
    ),
    MagicSignature(
        magic=b"\x93NUMPY",
        offset=0,
        format_name="numpy",
        description="NumPy array file (.npy)",
        risk_level="low",
    ),
    # Safetensors: little-endian u64 header_size followed by JSON '{'.
    # We match the opening '{' at byte 8 which follows the length.
    MagicSignature(
        magic=b"{",
        offset=8,
        format_name="safetensors",
        description="Hugging Face Safetensors (safe tensor storage)",
        risk_level="low",
    ),
    # Pickle protocol 4/5 (used by PyTorch .bin, .pt, .pkl)
    MagicSignature(
        magic=b"\x80\x04\x95",
        offset=0,
        format_name="pickle_v4",
        description="Python Pickle protocol 4",
        risk_level="critical",
    ),
    MagicSignature(
        magic=b"\x80\x05\x95",
        offset=0,
        format_name="pickle_v5",
        description="Python Pickle protocol 5",
        risk_level="critical",
    ),
    MagicSignature(
        magic=b"\x80\x02",
        offset=0,
        format_name="pickle_v2",
        description="Python Pickle protocol 2",
        risk_level="critical",
    ),
    # ZIP-based formats: PyTorch .pt, ONNX .onnx (sometimes)
    MagicSignature(
        magic=b"PK\x03\x04",
        offset=0,
        format_name="zip_archive",
        description="ZIP archive (PyTorch checkpoint, ONNX, or JAR)",
        risk_level="medium",
    ),
    # ONNX / Protobuf: no fixed magic, but TensorFlow SavedModel
    # uses protobuf with field tag 0x0a as first byte.
    MagicSignature(
        magic=b"\x08",
        offset=0,
        format_name="protobuf",
        description="Protocol Buffers (TensorFlow/ONNX)",
        is_model=True,
        risk_level="low",
    ),
    # HDF5 (Keras .h5 files)
    MagicSignature(
        magic=b"\x89HDF\r\n\x1a\n",
        offset=0,
        format_name="hdf5",
        description="HDF5 (Keras/TensorFlow model)",
        risk_level="low",
    ),
    # TensorFlow Lite
    MagicSignature(
        magic=b"TFL3",
        offset=4,
        format_name="tflite",
        description="TensorFlow Lite FlatBuffer",
        risk_level="low",
    ),

    # --- Common Binary (Non-Model) Formats ---
    MagicSignature(
        magic=b"\x89PNG\r\n\x1a\n",
        offset=0,
        format_name="png",
        description="PNG image",
        is_model=False,
        risk_level="none",
    ),
    MagicSignature(
        magic=b"\xff\xd8\xff",
        offset=0,
        format_name="jpeg",
        description="JPEG image",
        is_model=False,
        risk_level="none",
    ),
    MagicSignature(
        magic=b"GIF8",
        offset=0,
        format_name="gif",
        description="GIF image",
        is_model=False,
        risk_level="none",
    ),
    MagicSignature(
        magic=b"\x1f\x8b",
        offset=0,
        format_name="gzip",
        description="Gzip compressed data",
        is_model=False,
        risk_level="none",
    ),
    MagicSignature(
        magic=b"BZh",
        offset=0,
        format_name="bzip2",
        description="Bzip2 compressed data",
        is_model=False,
        risk_level="none",
    ),
    MagicSignature(
        magic=b"\xfd7zXZ\x00",
        offset=0,
        format_name="xz",
        description="XZ compressed data",
        is_model=False,
        risk_level="none",
    ),
    MagicSignature(
        magic=b"\x7fELF",
        offset=0,
        format_name="elf",
        description="ELF executable (Linux)",
        is_model=False,
        risk_level="none",
    ),
    MagicSignature(
        magic=b"MZ",
        offset=0,
        format_name="pe",
        description="PE executable (Windows)",
        is_model=False,
        risk_level="none",
    ),
    MagicSignature(
        magic=b"%PDF",
        offset=0,
        format_name="pdf",
        description="PDF document",
        is_model=False,
        risk_level="none",
    ),
    MagicSignature(
        magic=b"SQLite format 3",
        offset=0,
        format_name="sqlite",
        description="SQLite database",
        is_model=False,
        risk_level="none",
    ),
]


def identify_file(file_path: str, read_size: int = 64) -> MagicSignature | None:
    """Identify a file by reading its magic bytes.

    Args:
        file_path: Path to the file to check.
        read_size: Number of bytes to read from the start of the file.

    Returns:
        Matching MagicSignature, or None if no known signature matched.
    """
    try:
        with open(file_path, "rb") as f:
            header = f.read(read_size)
    except OSError:
        return None

    if not header:
        return None

    for sig in MODEL_SIGNATURES:
        end = sig.offset + len(sig.magic)
        if end <= len(header) and header[sig.offset:end] == sig.magic:
            return sig

    return None


def is_model_file(file_path: str) -> bool:
    """Check if a file is a recognized model format.

    Args:
        file_path: Path to the file.

    Returns:
        True if the file matches a known model file signature.
    """
    sig = identify_file(file_path)
    return sig is not None and sig.is_model


def is_binary_file(file_path: str, read_size: int = 8192) -> bool:
    """Check if a file is binary (not text).

    Uses magic number signatures first, then falls back to
    null-byte heuristic on the first ``read_size`` bytes.

    Args:
        file_path: Path to the file.
        read_size: Number of bytes to sample for null-byte check.

    Returns:
        True if the file appears to be binary.
    """
    # Quick check via magic signatures
    sig = identify_file(file_path)
    if sig is not None:
        return True

    # Null-byte heuristic for unrecognised formats
    try:
        with open(file_path, "rb") as f:
            chunk = f.read(read_size)
    except OSError:
        return True

    return b"\x00" in chunk
