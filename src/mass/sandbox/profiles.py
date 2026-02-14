"""Test profiles for corpus-based sandbox testing.

Profiles control how many payloads are selected per category, which
detectors run, and whether the LLM judge is invoked.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class TestProfile:
    """Configuration for a sandbox test run."""

    name: str
    max_payloads_per_category: int
    categories: list[str] | None  # None = all categories
    detectors: list[str] = field(default_factory=list)
    use_judge: bool = False
    description: str = ""


PROFILES: dict[str, TestProfile] = {
    "quick": TestProfile(
        name="quick",
        max_payloads_per_category=1,
        categories=[
            "command_injection",
            "prompt_injection",
            "boundary",
            "exfiltration",
        ],
        detectors=["keyword"],
        use_judge=False,
        description="Fast smoke test — 1 payload per top-4 categories",
    ),
    "standard": TestProfile(
        name="standard",
        max_payloads_per_category=3,
        categories=None,
        detectors=["keyword", "instruction_following"],
        use_judge=False,
        description="Balanced test — 3 payloads per category, key detectors",
    ),
    "comprehensive": TestProfile(
        name="comprehensive",
        max_payloads_per_category=5,
        categories=None,
        detectors=[
            "keyword",
            "instruction_following",
            "system_prompt_leak",
            "pii",
            "refusal",
            "harm",
        ],
        use_judge=True,
        description="Full test — all payloads, all detectors, LLM judge",
    ),
}
