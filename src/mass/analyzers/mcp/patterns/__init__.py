"""MCP security patterns.

Patterns for detecting various MCP security risks.
"""

from mass.analyzers.mcp.patterns.injection import INJECTION_PATTERNS
from mass.analyzers.mcp.patterns.exfiltration import EXFILTRATION_PATTERNS
from mass.analyzers.mcp.patterns.rugpull import RUGPULL_PATTERNS
from mass.analyzers.mcp.patterns.privilege import PRIVILEGE_PATTERNS

__all__ = [
    "INJECTION_PATTERNS",
    "EXFILTRATION_PATTERNS",
    "RUGPULL_PATTERNS",
    "PRIVILEGE_PATTERNS",
]
