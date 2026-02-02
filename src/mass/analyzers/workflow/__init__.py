"""Workflow analysis for agentic AI systems.

Analyzes agentic workflows for security vulnerabilities across frameworks:
- LangChain
- LangGraph
- CrewAI
- AutoGen
- OpenAI Agents SDK
"""

from mass.analyzers.workflow.analyzer import (
    WorkflowAnalyzer,
    WorkflowFinding,
    WorkflowAnalysisResult,
    WorkflowNode,
    WorkflowEdge,
    WorkflowGraph,
    AgentRole,
    WorkflowRiskCategory,
)
from mass.analyzers.workflow.graph import GraphBuilder, GraphAnalyzer
from mass.analyzers.workflow.visualization import (
    WorkflowVisualizer,
    VisualizationFormat,
)

__all__ = [
    # Core analyzer
    "WorkflowAnalyzer",
    "WorkflowFinding",
    "WorkflowAnalysisResult",
    # Graph types
    "WorkflowNode",
    "WorkflowEdge",
    "WorkflowGraph",
    "AgentRole",
    "WorkflowRiskCategory",
    # Graph utilities
    "GraphBuilder",
    "GraphAnalyzer",
    # Visualization
    "WorkflowVisualizer",
    "VisualizationFormat",
]
