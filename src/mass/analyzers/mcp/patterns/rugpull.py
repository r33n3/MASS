"""Rug pull / delayed activation patterns.

Patterns for detecting malicious tools that activate after trust is established.
"""

from dataclasses import dataclass
from mass.core.types import Severity


@dataclass
class RugpullPattern:
    """Pattern for detecting rug pull / delayed activation."""
    name: str
    pattern: str
    severity: Severity
    description: str
    attack_phase: str  # setup, trigger, execution


# Rug pull / delayed activation patterns
RUGPULL_PATTERNS = [
    # Setup phase indicators
    RugpullPattern(
        name="usage_counter",
        pattern=r"(count|track|monitor)\s*(usage|calls?|invocations?)",
        severity=Severity.MEDIUM,
        description="Tool tracks usage count (potential trigger)",
        attack_phase="setup",
    ),
    RugpullPattern(
        name="time_based_check",
        pattern=r"(after|when|once)\s*(time|date|days?|hours?)",
        severity=Severity.MEDIUM,
        description="Time-based conditional behavior",
        attack_phase="setup",
    ),
    RugpullPattern(
        name="version_check",
        pattern=r"(version|update)\s*(check|available|new)",
        severity=Severity.LOW,
        description="Version checking (potential update hijack)",
        attack_phase="setup",
    ),

    # Trigger indicators
    RugpullPattern(
        name="conditional_behavior",
        pattern=r"(if|when|after)\s*(trusted|verified|established|confirmed)",
        severity=Severity.HIGH,
        description="Behavior changes after trust is established",
        attack_phase="trigger",
    ),
    RugpullPattern(
        name="usage_threshold",
        pattern=r"(after|once)\s*\d+\s*(uses?|calls?|times?)",
        severity=Severity.MEDIUM,
        description="Behavior changes after usage threshold",
        attack_phase="trigger",
    ),
    RugpullPattern(
        name="feature_unlock",
        pattern=r"(unlock|enable|activate)\s*(hidden|premium|advanced|special)\s*(features?|mode)",
        severity=Severity.MEDIUM,
        description="Hidden features that unlock later",
        attack_phase="trigger",
    ),

    # Execution indicators
    RugpullPattern(
        name="silent_update",
        pattern=r"(silent|automatic|background)\s*(update|upgrade|change)",
        severity=Severity.HIGH,
        description="Silent updates that could change behavior",
        attack_phase="execution",
    ),
    RugpullPattern(
        name="remote_config",
        pattern=r"(remote|server|cloud)\s*(config|configuration|settings)",
        severity=Severity.MEDIUM,
        description="Remote configuration that could change behavior",
        attack_phase="execution",
    ),
    RugpullPattern(
        name="dynamic_behavior",
        pattern=r"(dynamic|adaptive|evolving)\s*(behavior|functionality|features?)",
        severity=Severity.MEDIUM,
        description="Behavior that can change dynamically",
        attack_phase="execution",
    ),

    # Deception indicators
    RugpullPattern(
        name="different_production",
        pattern=r"(production|live|real)\s*(mode|environment)\s*(different|behave)",
        severity=Severity.HIGH,
        description="Different behavior in production vs development",
        attack_phase="execution",
    ),
    RugpullPattern(
        name="test_detection",
        pattern=r"(detect|check)\s*(test|sandbox|simulation)",
        severity=Severity.HIGH,
        description="Detects testing/sandbox environment",
        attack_phase="execution",
    ),
    RugpullPattern(
        name="hidden_payload",
        pattern=r"(hidden|encrypted|obfuscated)\s*(payload|code|functionality)",
        severity=Severity.CRITICAL,
        description="Hidden or encrypted malicious payload",
        attack_phase="execution",
    ),
]
