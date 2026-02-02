"""Framework-specific workflow parsers.

Specialized parsers for different agentic workflow frameworks:
- LangChain / LangGraph
- CrewAI
- AutoGen
- OpenAI Agents SDK
"""

from mass.analyzers.workflow.frameworks.langchain import LangChainParser
from mass.analyzers.workflow.frameworks.langgraph import LangGraphParser
from mass.analyzers.workflow.frameworks.crewai import CrewAIParser
from mass.analyzers.workflow.frameworks.autogen import AutoGenParser
from mass.analyzers.workflow.frameworks.openai_agents import OpenAIAgentsParser

__all__ = [
    "LangChainParser",
    "LangGraphParser",
    "CrewAIParser",
    "AutoGenParser",
    "OpenAIAgentsParser",
]
