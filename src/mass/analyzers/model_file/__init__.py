"""Model file security scanner.

Detects malicious model files including pickle attacks, supply chain issues,
and format-specific vulnerabilities.
"""

from mass.analyzers.model_file.scanner import (
    ModelFileScanner,
    ModelFileFinding,
    ModelFileResult,
    ModelFormat,
)
from mass.analyzers.model_file.pickle import PickleAnalyzer, PickleFinding
from mass.analyzers.model_file.pytorch import PyTorchAnalyzer
from mass.analyzers.model_file.safetensors import SafetensorsAnalyzer
from mass.analyzers.model_file.gguf import GGUFAnalyzer
from mass.analyzers.model_file.supply_chain import SupplyChainAnalyzer, ProvenanceInfo

__all__ = [
    "ModelFileScanner",
    "ModelFileFinding",
    "ModelFileResult",
    "ModelFormat",
    "PickleAnalyzer",
    "PickleFinding",
    "PyTorchAnalyzer",
    "SafetensorsAnalyzer",
    "GGUFAnalyzer",
    "SupplyChainAnalyzer",
    "ProvenanceInfo",
]
