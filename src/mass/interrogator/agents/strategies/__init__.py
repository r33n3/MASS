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
    hallucination,
    output_injection,
    reasoning_exploit,
    encoding_bypass,
    rag_poisoning,
    model_extraction,
)

__all__ = [
    "prompt_extraction",
    "jailbreak",
    "data_exfil",
    "tool_abuse",
    "injection",
    "censorship",
    "hallucination",
    "output_injection",
    "reasoning_exploit",
    "encoding_bypass",
    "rag_poisoning",
    "model_extraction",
]

# Load user-defined custom strategies from YAML files
from mass.interrogator.agents.custom_loader import load_custom_strategies  # noqa: E402
load_custom_strategies()
