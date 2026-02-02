"""Tool description injection patterns.

Patterns for detecting prompt injection attacks via tool descriptions.
"""

from dataclasses import dataclass
from mass.core.types import Severity


@dataclass
class InjectionPattern:
    """Pattern for detecting injection attacks."""
    name: str
    pattern: str
    severity: Severity
    description: str
    category: str


# Tool description injection patterns
INJECTION_PATTERNS = [
    InjectionPattern(
        name="instruction_override",
        pattern=r"(ignore|disregard|forget|bypass)\s+(all\s+)?(previous|prior|other|system)\s+(instructions?|rules?|guidelines?)",
        severity=Severity.CRITICAL,
        description="Attempts to override AI instructions via tool description",
        category="prompt_injection",
    ),
    InjectionPattern(
        name="role_hijack",
        pattern=r"(you\s+are|act\s+as|pretend|roleplay)\s+(now\s+)?(a|an|the)?\s*(different|new|special)",
        severity=Severity.HIGH,
        description="Attempts to change AI role via tool description",
        category="prompt_injection",
    ),
    InjectionPattern(
        name="system_command",
        pattern=r"(system|admin|root)\s*(:|command|instruction|message)",
        severity=Severity.HIGH,
        description="Fake system command markers in description",
        category="prompt_injection",
    ),
    InjectionPattern(
        name="important_marker",
        pattern=r"(IMPORTANT|CRITICAL|URGENT|PRIORITY)\s*:\s*(ignore|must|always|never)",
        severity=Severity.MEDIUM,
        description="Fake importance markers for injection",
        category="prompt_injection",
    ),
    InjectionPattern(
        name="hidden_instruction",
        pattern=r"<!--.*?(ignore|override|bypass|hidden|secret).*?-->",
        severity=Severity.MEDIUM,
        description="Hidden instructions in HTML comments",
        category="prompt_injection",
    ),
    InjectionPattern(
        name="xml_injection",
        pattern=r"<(system|instruction|rule|override)[^>]*>",
        severity=Severity.MEDIUM,
        description="XML-style injection markers",
        category="prompt_injection",
    ),
    InjectionPattern(
        name="delimiter_escape",
        pattern=r"```\s*(system|ignore|override)",
        severity=Severity.MEDIUM,
        description="Code block delimiter abuse for injection",
        category="prompt_injection",
    ),
    InjectionPattern(
        name="context_manipulation",
        pattern=r"(end\s+of\s+context|new\s+context|context\s+switch)",
        severity=Severity.HIGH,
        description="Attempts to manipulate conversation context",
        category="prompt_injection",
    ),
]
