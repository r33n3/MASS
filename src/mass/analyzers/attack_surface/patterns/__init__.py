"""Attack surface patterns.

Patterns for detecting specific attack vectors in AI deployments.
"""

from mass.analyzers.attack_surface.patterns.rag_poisoning import (
    RAGPoisoningPattern,
    RAGPoisoningDetector,
)
from mass.analyzers.attack_surface.patterns.tool_chaining import (
    ToolChainingPattern,
    ToolChainingDetector,
)
from mass.analyzers.attack_surface.patterns.prompt_leak import (
    PromptLeakPattern,
    PromptLeakDetector,
)
from mass.analyzers.attack_surface.patterns.privilege_escalation import (
    PrivilegeEscalationPattern,
    PrivilegeEscalationDetector,
)

__all__ = [
    # RAG Poisoning
    "RAGPoisoningPattern",
    "RAGPoisoningDetector",
    # Tool Chaining
    "ToolChainingPattern",
    "ToolChainingDetector",
    # Prompt Leak
    "PromptLeakPattern",
    "PromptLeakDetector",
    # Privilege Escalation
    "PrivilegeEscalationPattern",
    "PrivilegeEscalationDetector",
]
