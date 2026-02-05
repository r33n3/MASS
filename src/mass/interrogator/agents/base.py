"""Base red team agent definition.

A RedTeamAgent encapsulates the attacker's identity: its system prompt,
category of attack, supported strategies, and evaluation criteria.
The ConversationManager does the actual conversation loop;
the agent just provides the instructions.
"""

from dataclasses import dataclass, field
from typing import Any

from mass.core.types import AttackCategory, Severity


@dataclass
class AttackStrategy:
    """A specific strategy within an agent's playbook."""
    name: str
    description: str
    system_prompt: str
    opening_prompt: str | None = None
    max_turns: int = 8
    success_indicators: list[str] = field(default_factory=list)


@dataclass
class RedTeamAgent:
    """Definition of a red team agent for a specific attack category."""
    name: str
    category: AttackCategory
    description: str
    base_severity: Severity
    strategies: list[AttackStrategy] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)
    cwe_ids: list[str] = field(default_factory=list)
    owasp_ids: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)


class AgentRegistry:
    """Registry for red team agent definitions."""

    def __init__(self) -> None:
        self._agents: dict[str, RedTeamAgent] = {}

    def register(self, agent: RedTeamAgent) -> None:
        self._agents[agent.name] = agent

    def get(self, name: str) -> RedTeamAgent | None:
        return self._agents.get(name)

    def list_all(self) -> list[RedTeamAgent]:
        return list(self._agents.values())

    def list_by_category(self, category: AttackCategory) -> list[RedTeamAgent]:
        return [a for a in self._agents.values() if a.category == category]

    def list_names(self) -> list[str]:
        return list(self._agents.keys())


agent_registry = AgentRegistry()
