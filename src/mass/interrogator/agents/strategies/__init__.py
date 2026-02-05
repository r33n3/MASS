"""Red team agent strategy definitions.

Import all strategy modules to register them with the agent registry.
"""

from mass.interrogator.agents.strategies import (
    prompt_extraction,
    jailbreak,
    data_exfil,
    tool_abuse,
    injection,
    censorship,
)

__all__ = [
    "prompt_extraction",
    "jailbreak",
    "data_exfil",
    "tool_abuse",
    "injection",
    "censorship",
]
