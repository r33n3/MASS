"""Data exfiltration patterns.

Patterns for detecting data exfiltration attempts via MCP tools.
"""

from dataclasses import dataclass
from mass.core.types import Severity


@dataclass
class ExfiltrationPattern:
    """Pattern for detecting exfiltration attempts."""
    name: str
    pattern: str
    severity: Severity
    description: str
    indicator_type: str  # behavior, network, data


# Data exfiltration patterns
EXFILTRATION_PATTERNS = [
    # Network-based exfiltration
    ExfiltrationPattern(
        name="external_url_send",
        pattern=r"(send|post|upload|transmit)\s+(to|via)\s+(external|remote|http|https)",
        severity=Severity.HIGH,
        description="Tool sends data to external URLs",
        indicator_type="network",
    ),
    ExfiltrationPattern(
        name="webhook_callback",
        pattern=r"(webhook|callback|notify)\s*(url|endpoint)",
        severity=Severity.MEDIUM,
        description="Tool uses webhook callbacks",
        indicator_type="network",
    ),
    ExfiltrationPattern(
        name="dns_exfil",
        pattern=r"(dns|subdomain)\s*(lookup|query|exfil)",
        severity=Severity.HIGH,
        description="Potential DNS-based exfiltration",
        indicator_type="network",
    ),

    # Data collection
    ExfiltrationPattern(
        name="collect_all",
        pattern=r"(collect|gather|harvest)\s+(all|every|entire)",
        severity=Severity.MEDIUM,
        description="Tool collects large amounts of data",
        indicator_type="data",
    ),
    ExfiltrationPattern(
        name="sensitive_access",
        pattern=r"(access|read|get)\s+(credentials?|secrets?|passwords?|tokens?|keys?)",
        severity=Severity.HIGH,
        description="Tool accesses sensitive data",
        indicator_type="data",
    ),
    ExfiltrationPattern(
        name="env_access",
        pattern=r"(environment|env)\s*(variables?|vars?)",
        severity=Severity.MEDIUM,
        description="Tool accesses environment variables",
        indicator_type="data",
    ),

    # Behavioral indicators
    ExfiltrationPattern(
        name="hidden_send",
        pattern=r"(silently|quietly|secretly|hidden)\s*(send|transmit|upload)",
        severity=Severity.CRITICAL,
        description="Tool sends data covertly",
        indicator_type="behavior",
    ),
    ExfiltrationPattern(
        name="background_sync",
        pattern=r"(background|async|periodic)\s*(sync|upload|send)",
        severity=Severity.MEDIUM,
        description="Tool performs background data operations",
        indicator_type="behavior",
    ),
    ExfiltrationPattern(
        name="telemetry_collection",
        pattern=r"(telemetry|analytics|tracking|metrics)\s*(collect|send|upload)",
        severity=Severity.LOW,
        description="Tool collects telemetry data",
        indicator_type="behavior",
    ),

    # File-based exfiltration
    ExfiltrationPattern(
        name="file_upload",
        pattern=r"(upload|send|transfer)\s+(files?|documents?)",
        severity=Severity.MEDIUM,
        description="Tool uploads files",
        indicator_type="data",
    ),
    ExfiltrationPattern(
        name="archive_create",
        pattern=r"(create|make|generate)\s+(archive|zip|tar)",
        severity=Severity.LOW,
        description="Tool creates archives (potential for exfil)",
        indicator_type="data",
    ),
]
