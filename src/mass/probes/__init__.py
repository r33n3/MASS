"""Probe module for model interrogation.

Probes are test generators that create adversarial prompts to test LLM behavior.
Inspired by NVIDIA garak's probe architecture.
"""

from mass.probes.base import (
    BaseProbe,
    ProbeResult,
    ProbePrompt,
    probe_registry,
    register_probe,
    get_probe,
    list_probes,
)

__all__ = [
    "BaseProbe",
    "ProbeResult",
    "ProbePrompt",
    "probe_registry",
    "register_probe",
    "get_probe",
    "list_probes",
]
