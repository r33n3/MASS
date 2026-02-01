"""Protocol definitions for MASS plugin architecture.

Defines the interfaces (protocols) that probes, detectors, runners,
and analyzers must implement for the plugin system.
"""

from typing import Any, AsyncIterator, Protocol, runtime_checkable

from mass.core.findings import Finding
from mass.core.types import AttackCategory, Severity


class DetectionResult:
    """Result of a detection check.

    Attributes:
        detected: Whether the vulnerability was detected.
        confidence: Confidence level of the detection (0-1).
        evidence: List of evidence strings supporting the detection.
        metadata: Additional detection metadata.
    """

    def __init__(
        self,
        detected: bool,
        confidence: float = 1.0,
        evidence: list[str] | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> None:
        """Initialize DetectionResult.

        Args:
            detected: Whether the vulnerability was detected.
            confidence: Confidence level (0-1).
            evidence: Supporting evidence strings.
            metadata: Additional metadata.
        """
        self.detected = detected
        self.confidence = min(max(confidence, 0.0), 1.0)  # Clamp to [0, 1]
        self.evidence = evidence or []
        self.metadata = metadata or {}


@runtime_checkable
class Probe(Protocol):
    """Protocol for attack probe plugins.

    Probes generate test prompts designed to elicit vulnerable
    behavior from AI models. Inspired by NVIDIA garak.

    Attributes:
        name: Unique probe identifier.
        description: Human-readable description.
        category: Attack category this probe tests.
        tags: Tags for filtering and organization.
    """

    name: str
    description: str
    category: AttackCategory
    tags: list[str]

    async def generate_prompts(self) -> AsyncIterator[str]:
        """Generate test prompts.

        Yields:
            Test prompts to send to the model.
        """
        ...

    def get_detectors(self) -> list[str]:
        """Get compatible detector names.

        Returns:
            List of detector names that can evaluate responses
            from this probe.
        """
        ...


@runtime_checkable
class Detector(Protocol):
    """Protocol for vulnerability detector plugins.

    Detectors analyze model responses to determine if they
    indicate a successful attack or vulnerability.

    Attributes:
        name: Unique detector identifier.
        description: Human-readable description.
    """

    name: str
    description: str

    async def detect(self, prompt: str, response: str) -> DetectionResult:
        """Detect vulnerability in response.

        Args:
            prompt: The prompt that was sent.
            response: The model's response.

        Returns:
            DetectionResult indicating if vulnerability was found.
        """
        ...


@runtime_checkable
class Runner(Protocol):
    """Protocol for model execution runners.

    Runners handle communication with AI models, whether
    local or API-based.

    Attributes:
        name: Runner identifier.
        provider: Model provider type.
    """

    name: str
    provider: str

    async def run(self, prompt: str, **kwargs: Any) -> str:
        """Send prompt to model and get response.

        Args:
            prompt: The prompt to send.
            **kwargs: Additional model parameters.

        Returns:
            The model's response text.
        """
        ...

    async def run_batch(self, prompts: list[str], **kwargs: Any) -> list[str]:
        """Send multiple prompts and get responses.

        Args:
            prompts: List of prompts to send.
            **kwargs: Additional model parameters.

        Returns:
            List of response texts.
        """
        ...

    async def health_check(self) -> bool:
        """Check if the runner is operational.

        Returns:
            True if runner can communicate with model.
        """
        ...


@runtime_checkable
class Analyzer(Protocol):
    """Protocol for component analyzers.

    Analyzers examine deployment components for security issues.

    Attributes:
        name: Analyzer identifier.
        component_types: Component types this analyzer handles.
    """

    name: str
    component_types: list[str]

    async def analyze(self, component: Any) -> list[Finding]:
        """Analyze a component for security issues.

        Args:
            component: The component to analyze.

        Returns:
            List of findings discovered.
        """
        ...


@runtime_checkable
class Extractor(Protocol):
    """Protocol for instruction extractors.

    Extractors identify and extract embedded instructions
    from various file types.

    Attributes:
        name: Extractor identifier.
        file_patterns: Glob patterns for files this extractor handles.
    """

    name: str
    file_patterns: list[str]

    async def extract(self, file_path: str, content: str) -> list[dict[str, Any]]:
        """Extract instructions from file content.

        Args:
            file_path: Path to the file.
            content: File content.

        Returns:
            List of extracted instruction dictionaries.
        """
        ...


@runtime_checkable
class ReportFormatter(Protocol):
    """Protocol for report format handlers.

    Report formatters convert findings to specific output formats.

    Attributes:
        name: Formatter identifier.
        format: Output format (html, pdf, sarif, json, etc.).
        extension: File extension for output.
    """

    name: str
    format: str
    extension: str

    async def format(
        self, findings: list[Finding], metadata: dict[str, Any]
    ) -> bytes:
        """Format findings into report.

        Args:
            findings: List of findings to include.
            metadata: Report metadata (title, scan info, etc.).

        Returns:
            Formatted report as bytes.
        """
        ...


class ScanProfile:
    """Configuration profile for security scans.

    Defines which probes, detectors, and analyzers to use
    for a particular scan.

    Attributes:
        name: Profile name.
        description: Profile description.
        probes: List of probe names to use.
        detectors: List of detector names to use.
        analyzers: List of analyzer names to use.
        settings: Additional profile settings.
    """

    def __init__(
        self,
        name: str,
        description: str = "",
        probes: list[str] | None = None,
        detectors: list[str] | None = None,
        analyzers: list[str] | None = None,
        settings: dict[str, Any] | None = None,
    ) -> None:
        """Initialize ScanProfile.

        Args:
            name: Profile name.
            description: Profile description.
            probes: Probe names to use.
            detectors: Detector names to use.
            analyzers: Analyzer names to use.
            settings: Additional settings.
        """
        self.name = name
        self.description = description
        self.probes = probes or []
        self.detectors = detectors or []
        self.analyzers = analyzers or []
        self.settings = settings or {}


# Predefined scan profiles
PROFILES = {
    "quick": ScanProfile(
        name="quick",
        description="Fast scan with essential probes",
        probes=["direct_injection", "system_prompt_leak"],
        detectors=["keyword", "refusal"],
        settings={"max_prompts_per_probe": 10},
    ),
    "standard": ScanProfile(
        name="standard",
        description="Balanced scan with common vulnerability checks",
        probes=[
            "direct_injection",
            "indirect_injection",
            "system_prompt_leak",
            "jailbreak_dan",
            "jailbreak_roleplay",
        ],
        detectors=["keyword", "refusal", "toxicity", "llm_judge"],
        settings={"max_prompts_per_probe": 50},
    ),
    "comprehensive": ScanProfile(
        name="comprehensive",
        description="Thorough scan with all available probes",
        probes=["*"],  # All probes
        detectors=["*"],  # All detectors
        analyzers=["*"],  # All analyzers
        settings={"max_prompts_per_probe": 100},
    ),
    "adversarial": ScanProfile(
        name="adversarial",
        description="Aggressive testing with advanced attack techniques",
        probes=[
            "direct_injection",
            "indirect_injection",
            "jailbreak_dan",
            "jailbreak_roleplay",
            "jailbreak_encoding",
            "jailbreak_multilingual",
            "system_prompt_leak",
            "training_data_extraction",
        ],
        detectors=["keyword", "refusal", "llm_judge", "classifier"],
        settings={
            "max_prompts_per_probe": 200,
            "use_mutations": True,
            "use_rl_attacks": True,
        },
    ),
    "compliance": ScanProfile(
        name="compliance",
        description="Compliance-focused scan for regulatory requirements",
        probes=[
            "pii_leakage",
            "sensitive_info",
            "bias_demographic",
            "toxicity",
            "hallucination_factual",
        ],
        detectors=["pii_detector", "toxicity", "bias_classifier", "llm_judge"],
        analyzers=["compliance_assessor"],
        settings={"frameworks": ["owasp_llm", "nist_ai_rmf", "eu_ai_act"]},
    ),
}
