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

# Import detectors to trigger registration
import mass.detectors.keyword  # noqa: F401
import mass.detectors.refusal  # noqa: F401
import mass.detectors.system_prompt  # noqa: F401
import mass.detectors.pii  # noqa: F401
import mass.detectors.instruction_following  # noqa: F401

__all__ = [
    "BaseDetector",
    "DetectionResult",
    "detector_registry",
    "register_detector",
    "get_detector",
    "list_detectors",
]
