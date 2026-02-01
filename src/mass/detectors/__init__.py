"""Detector module for response analysis.

Detectors analyze model responses to determine if vulnerabilities were triggered.
Inspired by NVIDIA garak's detector architecture.
"""

from mass.detectors.base import (
    BaseDetector,
    DetectionResult,
    detector_registry,
    register_detector,
    get_detector,
    list_detectors,
)

__all__ = [
    "BaseDetector",
    "DetectionResult",
    "detector_registry",
    "register_detector",
    "get_detector",
    "list_detectors",
]
