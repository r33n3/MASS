"""Context file analyzer.

Analyzes AI context files (CLAUDE.md, .cursorrules, system prompts)
for security risks and policy violations.
"""

from mass.analyzers.context.analyzer import (
    ContextAnalyzer,
    ContextFinding,
    ContextAnalysisResult,
    ContextFileType,
)
from mass.analyzers.context.patterns import (
    RiskPattern,
    RiskCategory,
    RISK_PATTERNS,
)
from mass.analyzers.context.instruction import InstructionAnalyzer

__all__ = [
    "ContextAnalyzer",
    "ContextFinding",
    "ContextAnalysisResult",
    "ContextFileType",
    "RiskPattern",
    "RiskCategory",
    "RISK_PATTERNS",
    "InstructionAnalyzer",
]
