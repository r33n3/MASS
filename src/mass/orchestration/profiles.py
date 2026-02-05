"""Scan profiles defining which analyzers to run.

Profiles configure the scope and depth of security scans,
from quick assessments to comprehensive deep dives.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class ProfileType(str, Enum):
    """Available scan profile types."""

    QUICK = "quick"
    STANDARD = "standard"
    COMPREHENSIVE = "comprehensive"
    CUSTOM = "custom"


@dataclass
class AnalyzerConfig:
    """Configuration for a single analyzer."""

    enabled: bool = True
    priority: int = 50  # Lower = higher priority
    timeout_seconds: int = 300
    options: dict[str, Any] = field(default_factory=dict)


@dataclass
class ScanProfile:
    """Scan profile defining analyzers and configuration.

    Profiles determine which analyzers run, their priority,
    and specific configuration options.
    """

    name: str
    description: str
    profile_type: ProfileType

    # Analyzer configurations
    deployment_scanner: AnalyzerConfig = field(default_factory=AnalyzerConfig)
    secret_detector: AnalyzerConfig = field(default_factory=AnalyzerConfig)
    infrastructure_scanner: AnalyzerConfig = field(default_factory=AnalyzerConfig)
    model_file_scanner: AnalyzerConfig = field(default_factory=AnalyzerConfig)
    context_analyzer: AnalyzerConfig = field(default_factory=AnalyzerConfig)
    mcp_analyzer: AnalyzerConfig = field(default_factory=AnalyzerConfig)
    attack_surface_analyzer: AnalyzerConfig = field(default_factory=AnalyzerConfig)
    workflow_analyzer: AnalyzerConfig = field(default_factory=AnalyzerConfig)
    model_interrogator: AnalyzerConfig = field(default_factory=AnalyzerConfig)

    # Global settings
    max_concurrent_jobs: int = 4
    total_timeout_seconds: int = 1800
    fail_fast: bool = False
    include_info_findings: bool = True

    def get_enabled_analyzers(self) -> list[str]:
        """Get list of enabled analyzer names ordered by priority."""
        analyzers = [
            ("deployment_scanner", self.deployment_scanner),
            ("secret_detector", self.secret_detector),
            ("infrastructure_scanner", self.infrastructure_scanner),
            ("model_file_scanner", self.model_file_scanner),
            ("context_analyzer", self.context_analyzer),
            ("mcp_analyzer", self.mcp_analyzer),
            ("attack_surface_analyzer", self.attack_surface_analyzer),
            ("workflow_analyzer", self.workflow_analyzer),
            ("model_interrogator", self.model_interrogator),
        ]
        enabled = [(name, cfg) for name, cfg in analyzers if cfg.enabled]
        enabled.sort(key=lambda x: x[1].priority)
        return [name for name, _ in enabled]

    def to_dict(self) -> dict[str, Any]:
        """Convert profile to dictionary."""
        return {
            "name": self.name,
            "description": self.description,
            "profile_type": self.profile_type.value,
            "max_concurrent_jobs": self.max_concurrent_jobs,
            "total_timeout_seconds": self.total_timeout_seconds,
            "fail_fast": self.fail_fast,
            "include_info_findings": self.include_info_findings,
            "enabled_analyzers": self.get_enabled_analyzers(),
        }


# Predefined profiles
QUICK_PROFILE = ScanProfile(
    name="quick",
    description="Fast assessment focusing on high-risk issues",
    profile_type=ProfileType.QUICK,
    deployment_scanner=AnalyzerConfig(enabled=True, priority=10),
    secret_detector=AnalyzerConfig(enabled=True, priority=20),
    infrastructure_scanner=AnalyzerConfig(enabled=False),
    model_file_scanner=AnalyzerConfig(enabled=True, priority=30),
    context_analyzer=AnalyzerConfig(enabled=True, priority=40),
    mcp_analyzer=AnalyzerConfig(enabled=False),
    attack_surface_analyzer=AnalyzerConfig(enabled=False),
    workflow_analyzer=AnalyzerConfig(enabled=False),
    model_interrogator=AnalyzerConfig(
        enabled=True,
        priority=50,
        timeout_seconds=300,
        options={"probe_categories": ["prompt_injection", "jailbreak"], "max_probes": 5, "max_prompts_per_probe": 2, "max_concurrent_probes": 2, "max_concurrent_prompts": 1},
    ),
    max_concurrent_jobs=2,
    total_timeout_seconds=600,
    fail_fast=False,
    include_info_findings=False,
)

STANDARD_PROFILE = ScanProfile(
    name="standard",
    description="Balanced assessment with all static analyzers",
    profile_type=ProfileType.STANDARD,
    deployment_scanner=AnalyzerConfig(enabled=True, priority=10),
    secret_detector=AnalyzerConfig(enabled=True, priority=20),
    infrastructure_scanner=AnalyzerConfig(enabled=True, priority=30),
    model_file_scanner=AnalyzerConfig(enabled=True, priority=40),
    context_analyzer=AnalyzerConfig(enabled=True, priority=50),
    mcp_analyzer=AnalyzerConfig(enabled=True, priority=60),
    attack_surface_analyzer=AnalyzerConfig(enabled=True, priority=70),
    workflow_analyzer=AnalyzerConfig(enabled=True, priority=80),
    model_interrogator=AnalyzerConfig(enabled=False),
    max_concurrent_jobs=4,
    total_timeout_seconds=900,
    fail_fast=False,
    include_info_findings=True,
)

COMPREHENSIVE_PROFILE = ScanProfile(
    name="comprehensive",
    description="Full assessment including model interrogation",
    profile_type=ProfileType.COMPREHENSIVE,
    deployment_scanner=AnalyzerConfig(enabled=True, priority=10),
    secret_detector=AnalyzerConfig(enabled=True, priority=20),
    infrastructure_scanner=AnalyzerConfig(enabled=True, priority=30),
    model_file_scanner=AnalyzerConfig(enabled=True, priority=40),
    context_analyzer=AnalyzerConfig(enabled=True, priority=50),
    mcp_analyzer=AnalyzerConfig(enabled=True, priority=60),
    attack_surface_analyzer=AnalyzerConfig(enabled=True, priority=70),
    workflow_analyzer=AnalyzerConfig(enabled=True, priority=80),
    model_interrogator=AnalyzerConfig(
        enabled=True,
        priority=90,
        timeout_seconds=600,
        options={"probe_categories": ["jailbreak", "prompt_injection", "sensitive_info"], "max_concurrent_probes": 4, "max_concurrent_prompts": 3},
    ),
    max_concurrent_jobs=4,
    total_timeout_seconds=1800,
    fail_fast=False,
    include_info_findings=True,
)

PROFILES: dict[str, ScanProfile] = {
    "quick": QUICK_PROFILE,
    "standard": STANDARD_PROFILE,
    "comprehensive": COMPREHENSIVE_PROFILE,
}


def get_profile(name: str) -> ScanProfile:
    """Get a scan profile by name.

    Args:
        name: Profile name (quick, standard, comprehensive).

    Returns:
        ScanProfile instance.

    Raises:
        ValueError: If profile name is not recognized.
    """
    if name not in PROFILES:
        raise ValueError(
            f"Unknown profile '{name}'. Available: {list(PROFILES.keys())}"
        )
    return PROFILES[name]


def create_custom_profile(
    base: str = "standard",
    enabled_analyzers: list[str] | None = None,
    disabled_analyzers: list[str] | None = None,
    **kwargs: Any,
) -> ScanProfile:
    """Create a custom profile based on an existing one.

    Args:
        base: Base profile name to customize.
        enabled_analyzers: Analyzers to enable.
        disabled_analyzers: Analyzers to disable.
        **kwargs: Additional profile settings to override.

    Returns:
        Customized ScanProfile instance.
    """
    from dataclasses import replace

    profile = get_profile(base)
    profile = replace(profile, name="custom", profile_type=ProfileType.CUSTOM)

    # Apply enabled/disabled changes
    analyzer_attrs = [
        "deployment_scanner",
        "secret_detector",
        "infrastructure_scanner",
        "model_file_scanner",
        "context_analyzer",
        "mcp_analyzer",
        "attack_surface_analyzer",
        "workflow_analyzer",
        "model_interrogator",
    ]

    for attr in analyzer_attrs:
        config = getattr(profile, attr)
        if enabled_analyzers and attr in enabled_analyzers:
            config = replace(config, enabled=True)
        if disabled_analyzers and attr in disabled_analyzers:
            config = replace(config, enabled=False)
        profile = replace(profile, **{attr: config})

    # Apply additional kwargs
    for key, value in kwargs.items():
        if hasattr(profile, key):
            profile = replace(profile, **{key: value})

    return profile
