"""Red team agent definitions.

Each agent specializes in a category of adversarial testing and carries
a system prompt that instructs the attacker model how to probe the target.
"""

from mass.interrogator.agents.base import RedTeamAgent, AgentRegistry, agent_registry

__all__ = ["RedTeamAgent", "AgentRegistry", "agent_registry"]
