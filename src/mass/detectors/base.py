"""Base detector protocol and registry.

Defines the interface for detectors and provides registration/discovery.
"""

import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

logger = logging.getLogger(__name__)


class DetectionStatus(str, Enum):
    """Status of detection."""
    VULNERABLE = "vulnerable"
    SAFE = "safe"
    UNCERTAIN = "uncertain"
    ERROR = "error"


@dataclass
class DetectionResult:
    """Result of a detection analysis."""
    status: DetectionStatus
    confidence: float
    detector_name: str
    details: dict[str, Any] = field(default_factory=dict)
    evidence: list[str] = field(default_factory=list)
    error: str | None = None

    @property
    def is_vulnerable(self) -> bool:
        """Check if detection indicates vulnerability."""
        return self.status == DetectionStatus.VULNERABLE

    @property
    def is_safe(self) -> bool:
        """Check if detection indicates safety."""
        return self.status == DetectionStatus.SAFE


class BaseDetector(ABC):
    """Base class for all detectors.

    Detectors analyze model responses to determine if a vulnerability
    was successfully triggered by a probe.
    """

    # Class attributes - must be defined by subclasses
    name: str = ""
    description: str = ""
    tags: list[str] = []

    # Detection thresholds
    threshold: float = 0.5

    def __init__(self, **kwargs: Any):
        """Initialize detector with optional configuration."""
        self.config = kwargs
        if "threshold" in kwargs:
            self.threshold = kwargs["threshold"]

    @abstractmethod
    def detect(self, prompt: str, response: str) -> DetectionResult:
        """Detect if response indicates vulnerability.

        Args:
            prompt: The prompt that was sent.
            response: The model's response.

        Returns:
            DetectionResult with analysis.
        """
        ...

    async def detect_async(self, prompt: str, response: str) -> DetectionResult:
        """Detect asynchronously.

        Default implementation wraps synchronous detect.
        Override for true async detection (e.g., LLM-based).

        Args:
            prompt: The prompt that was sent.
            response: The model's response.

        Returns:
            DetectionResult with analysis.
        """
        return self.detect(prompt, response)

    def _create_result(
        self,
        status: DetectionStatus,
        confidence: float,
        details: dict[str, Any] | None = None,
        evidence: list[str] | None = None,
        error: str | None = None,
    ) -> DetectionResult:
        """Helper to create a DetectionResult.

        Args:
            status: Detection status.
            confidence: Confidence score (0-1).
            details: Additional details.
            evidence: Evidence strings.
            error: Error message if any.

        Returns:
            DetectionResult instance.
        """
        return DetectionResult(
            status=status,
            confidence=confidence,
            detector_name=self.name,
            details=details or {},
            evidence=evidence or [],
            error=error,
        )


class DetectorRegistry:
    """Registry for detector discovery and management."""

    def __init__(self):
        """Initialize detector registry."""
        self._detectors: dict[str, type[BaseDetector]] = {}
        self._instances: dict[str, BaseDetector] = {}

    def register(self, detector_class: type[BaseDetector]) -> type[BaseDetector]:
        """Register a detector class.

        Args:
            detector_class: Detector class to register.

        Returns:
            The registered class (for use as decorator).
        """
        name = detector_class.name or detector_class.__name__
        self._detectors[name] = detector_class
        logger.debug(f"Registered detector: {name}")
        return detector_class

    def get(self, name: str, **kwargs: Any) -> BaseDetector | None:
        """Get a detector instance by name.

        Args:
            name: Detector name.
            **kwargs: Detector configuration.

        Returns:
            Detector instance or None if not found.
        """
        if name in self._instances and not kwargs:
            return self._instances[name]

        detector_class = self._detectors.get(name)
        if detector_class:
            instance = detector_class(**kwargs)
            if not kwargs:
                self._instances[name] = instance
            return instance

        return None

    def get_class(self, name: str) -> type[BaseDetector] | None:
        """Get a detector class by name.

        Args:
            name: Detector name.

        Returns:
            Detector class or None if not found.
        """
        return self._detectors.get(name)

    def list_detectors(self) -> list[str]:
        """List all registered detector names.

        Returns:
            List of detector names.
        """
        return list(self._detectors.keys())

    def list_by_tag(self, tag: str) -> list[str]:
        """List detectors by tag.

        Args:
            tag: Tag to filter by.

        Returns:
            List of detector names with that tag.
        """
        return [
            name for name, cls in self._detectors.items()
            if tag in cls.tags
        ]

    def get_all(self, **kwargs: Any) -> list[BaseDetector]:
        """Get instances of all registered detectors.

        Args:
            **kwargs: Detector configuration.

        Returns:
            List of detector instances.
        """
        detectors = []
        for name in self._detectors:
            detector = self.get(name, **kwargs)
            if detector:
                detectors.append(detector)
        return detectors

    @property
    def count(self) -> int:
        """Get number of registered detectors."""
        return len(self._detectors)


# Global detector registry
detector_registry = DetectorRegistry()


def register_detector(cls: type[BaseDetector]) -> type[BaseDetector]:
    """Decorator to register a detector class.

    Usage:
        @register_detector
        class MyDetector(BaseDetector):
            name = "my_detector"
            ...
    """
    return detector_registry.register(cls)


def get_detector(name: str, **kwargs: Any) -> BaseDetector | None:
    """Get a detector instance by name from the global registry."""
    return detector_registry.get(name, **kwargs)


def list_detectors() -> list[str]:
    """List all registered detectors from the global registry."""
    return detector_registry.list_detectors()
