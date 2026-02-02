"""Tests for workflow analyzer module."""

import tempfile
from pathlib import Path

import pytest

from mass.core.types import Severity
from mass.analyzers.workflow.analyzer import (
    WorkflowAnalyzer,
    WorkflowFinding,
    WorkflowAnalysisResult,
    WorkflowNode,
    WorkflowEdge,
    WorkflowGraph,
    WorkflowFramework,
    WorkflowRiskCategory,
    AgentRole,
)
from mass.analyzers.workflow.graph import GraphBuilder, GraphAnalyzer, GraphMetrics
from mass.analyzers.workflow.visualization import (
    WorkflowVisualizer,
    VisualizationFormat,
)


class TestWorkflowNode:
    """Tests for WorkflowNode."""

    def test_node_creation(self):
        """Test creating a node."""
        node = WorkflowNode(
            id="agent1",
            name="Research Agent",
            node_type="agent",
            role=AgentRole.RESEARCHER,
            tools=["search", "read_file"],
        )
        assert node.id == "agent1"
        assert node.role == AgentRole.RESEARCHER
        assert len(node.tools) == 2

    def test_node_to_dict(self):
        """Test converting to dict."""
        node = WorkflowNode(
            id="agent1",
            name="Agent",
            node_type="agent",
            role=AgentRole.EXECUTOR,
        )
        d = node.to_dict()
        assert d["id"] == "agent1"
        assert d["role"] == "executor"


class TestWorkflowEdge:
    """Tests for WorkflowEdge."""

    def test_edge_creation(self):
        """Test creating an edge."""
        edge = WorkflowEdge(
            source="agent1",
            target="agent2",
            edge_type="flow",
            condition="success",
        )
        assert edge.source == "agent1"
        assert edge.target == "agent2"
        assert edge.condition == "success"

    def test_edge_to_dict(self):
        """Test converting to dict."""
        edge = WorkflowEdge(
            source="a",
            target="b",
            edge_type="conditional",
        )
        d = edge.to_dict()
        assert d["source"] == "a"
        assert d["edge_type"] == "conditional"


class TestWorkflowGraph:
    """Tests for WorkflowGraph."""

    def test_graph_creation(self):
        """Test creating a graph."""
        graph = WorkflowGraph(
            name="test_workflow",
            framework=WorkflowFramework.CREWAI,
        )
        assert graph.name == "test_workflow"
        assert graph.framework == WorkflowFramework.CREWAI

    def test_get_node(self):
        """Test getting a node by ID."""
        graph = WorkflowGraph(name="test", framework=WorkflowFramework.CUSTOM)
        node = WorkflowNode(id="n1", name="Node 1", node_type="agent")
        graph.nodes.append(node)

        assert graph.get_node("n1") == node
        assert graph.get_node("nonexistent") is None

    def test_get_outgoing_edges(self):
        """Test getting outgoing edges."""
        graph = WorkflowGraph(name="test", framework=WorkflowFramework.CUSTOM)
        graph.edges.append(WorkflowEdge(source="a", target="b"))
        graph.edges.append(WorkflowEdge(source="a", target="c"))
        graph.edges.append(WorkflowEdge(source="b", target="c"))

        outgoing = graph.get_outgoing_edges("a")
        assert len(outgoing) == 2

    def test_to_dict(self):
        """Test converting to dict."""
        graph = WorkflowGraph(
            name="test",
            framework=WorkflowFramework.LANGGRAPH,
            entry_points=["start"],
        )
        d = graph.to_dict()
        assert d["name"] == "test"
        assert d["framework"] == "langgraph"


class TestWorkflowFinding:
    """Tests for WorkflowFinding."""

    def test_finding_creation(self):
        """Test creating a finding."""
        finding = WorkflowFinding(
            category=WorkflowRiskCategory.EXCESSIVE_PERMISSIONS,
            severity=Severity.HIGH,
            title="Test Finding",
            description="Description",
            node_id="agent1",
        )
        assert finding.category == WorkflowRiskCategory.EXCESSIVE_PERMISSIONS
        assert finding.node_id == "agent1"

    def test_finding_to_dict(self):
        """Test converting to dict."""
        finding = WorkflowFinding(
            category=WorkflowRiskCategory.RECURSIVE_LOOP,
            severity=Severity.MEDIUM,
            title="Loop",
            description="Desc",
            attack_path=["a", "b", "a"],
        )
        d = finding.to_dict()
        assert d["category"] == "recursive_loop"
        assert d["attack_path"] == ["a", "b", "a"]


class TestWorkflowAnalysisResult:
    """Tests for WorkflowAnalysisResult."""

    def test_is_safe(self):
        """Test is_safe property."""
        graph = WorkflowGraph(name="test", framework=WorkflowFramework.CUSTOM)
        result = WorkflowAnalysisResult(graph=graph)
        assert result.is_safe is True

        result.findings.append(WorkflowFinding(
            category=WorkflowRiskCategory.EXCESSIVE_PERMISSIONS,
            severity=Severity.HIGH,
            title="Test",
            description="Desc",
        ))
        assert result.is_safe is False

    def test_severity_counts(self):
        """Test severity counting."""
        graph = WorkflowGraph(name="test", framework=WorkflowFramework.CUSTOM)
        result = WorkflowAnalysisResult(
            graph=graph,
            findings=[
                WorkflowFinding(
                    category=WorkflowRiskCategory.EXCESSIVE_PERMISSIONS,
                    severity=Severity.CRITICAL,
                    title="Critical",
                    description="Desc",
                ),
                WorkflowFinding(
                    category=WorkflowRiskCategory.RECURSIVE_LOOP,
                    severity=Severity.HIGH,
                    title="High",
                    description="Desc",
                ),
            ],
        )
        assert result.critical_count == 1
        assert result.high_count == 1


class TestWorkflowAnalyzer:
    """Tests for WorkflowAnalyzer."""

    def test_initialization(self):
        """Test analyzer initialization."""
        analyzer = WorkflowAnalyzer()
        assert analyzer is not None

    def test_detect_framework_langgraph(self):
        """Test detecting LangGraph framework."""
        analyzer = WorkflowAnalyzer()
        content = """
from langgraph.graph import StateGraph

graph = StateGraph(State)
graph.add_node("agent", agent_node)
"""
        assert analyzer.detect_framework(content) == WorkflowFramework.LANGGRAPH

    def test_detect_framework_crewai(self):
        """Test detecting CrewAI framework."""
        analyzer = WorkflowAnalyzer()
        content = """
from crewai import Agent, Crew, Task

agent = Agent(role="Researcher")
crew = Crew(agents=[agent])
"""
        assert analyzer.detect_framework(content) == WorkflowFramework.CREWAI

    def test_detect_framework_autogen(self):
        """Test detecting AutoGen framework."""
        analyzer = WorkflowAnalyzer()
        content = """
from autogen import AssistantAgent, UserProxyAgent

assistant = AssistantAgent(name="assistant")
user_proxy = UserProxyAgent(name="user")
"""
        assert analyzer.detect_framework(content) == WorkflowFramework.AUTOGEN

    def test_analyze_graph_safe(self):
        """Test analyzing a safe graph."""
        analyzer = WorkflowAnalyzer()
        graph = WorkflowGraph(
            name="safe_workflow",
            framework=WorkflowFramework.CUSTOM,
            nodes=[
                WorkflowNode(id="agent1", name="Safe Agent", node_type="agent"),
            ],
            entry_points=["agent1"],
        )
        result = analyzer.analyze_graph(graph)
        # Should have minimal findings
        assert result.critical_count == 0

    def test_analyze_graph_with_loop(self):
        """Test detecting cycles in graph."""
        analyzer = WorkflowAnalyzer()
        graph = WorkflowGraph(
            name="loop_workflow",
            framework=WorkflowFramework.CUSTOM,
            nodes=[
                WorkflowNode(id="a", name="A", node_type="agent"),
                WorkflowNode(id="b", name="B", node_type="agent"),
            ],
            edges=[
                WorkflowEdge(source="a", target="b"),
                WorkflowEdge(source="b", target="a"),
            ],
            entry_points=["a"],
        )
        result = analyzer.analyze_graph(graph)
        cycle_findings = [
            f for f in result.findings
            if f.category == WorkflowRiskCategory.RECURSIVE_LOOP
        ]
        assert len(cycle_findings) > 0

    def test_analyze_graph_dangerous_tools(self):
        """Test detecting dangerous tool names."""
        analyzer = WorkflowAnalyzer()
        graph = WorkflowGraph(
            name="dangerous_workflow",
            framework=WorkflowFramework.CUSTOM,
            nodes=[
                WorkflowNode(
                    id="agent1",
                    name="Executor",
                    node_type="agent",
                    tools=["shell_exec", "file_delete", "sql_query"],
                ),
            ],
            entry_points=["agent1"],
        )
        result = analyzer.analyze_graph(graph)
        tool_findings = [
            f for f in result.findings
            if f.category == WorkflowRiskCategory.UNVALIDATED_TOOL_USE
        ]
        assert len(tool_findings) > 0

    def test_analyze_file_nonexistent(self):
        """Test analyzing non-existent file."""
        analyzer = WorkflowAnalyzer()
        result = analyzer.analyze_file(Path("/nonexistent/file.py"))
        assert len(result.errors) > 0


class TestGraphBuilder:
    """Tests for GraphBuilder."""

    def test_build_simple_graph(self):
        """Test building a simple graph."""
        builder = GraphBuilder("test_graph")
        graph = (
            builder
            .add_node("agent1", "Agent 1", "agent", AgentRole.EXECUTOR)
            .add_node("agent2", "Agent 2", "agent", AgentRole.REVIEWER)
            .add_edge("agent1", "agent2")
            .set_entry_point("agent1")
            .build()
        )

        assert len(graph.nodes) == 2
        assert len(graph.edges) == 1
        assert "agent1" in graph.entry_points

    def test_builder_with_tools(self):
        """Test building nodes with tools."""
        builder = GraphBuilder("tool_graph")
        graph = (
            builder
            .add_node(
                "agent",
                "Tool Agent",
                "agent",
                tools=["search", "read", "write"],
            )
            .build()
        )

        agent = graph.get_node("agent")
        assert len(agent.tools) == 3


class TestGraphAnalyzer:
    """Tests for GraphAnalyzer."""

    def test_compute_metrics(self):
        """Test computing graph metrics."""
        graph = WorkflowGraph(
            name="test",
            framework=WorkflowFramework.CUSTOM,
            nodes=[
                WorkflowNode(id="a", name="A", node_type="agent"),
                WorkflowNode(id="b", name="B", node_type="agent"),
                WorkflowNode(id="c", name="C", node_type="agent"),
            ],
            edges=[
                WorkflowEdge(source="a", target="b"),
                WorkflowEdge(source="b", target="c"),
            ],
            entry_points=["a"],
        )

        analyzer = GraphAnalyzer(graph)
        metrics = analyzer.compute_metrics()

        assert metrics.node_count == 3
        assert metrics.edge_count == 2
        assert metrics.entry_points == 1

    def test_get_reachable_from(self):
        """Test getting reachable nodes."""
        graph = WorkflowGraph(
            name="test",
            framework=WorkflowFramework.CUSTOM,
            nodes=[
                WorkflowNode(id="a", name="A", node_type="agent"),
                WorkflowNode(id="b", name="B", node_type="agent"),
                WorkflowNode(id="c", name="C", node_type="agent"),
            ],
            edges=[
                WorkflowEdge(source="a", target="b"),
                WorkflowEdge(source="b", target="c"),
            ],
        )

        analyzer = GraphAnalyzer(graph)
        reachable = analyzer.get_reachable_from("a")

        assert "a" in reachable
        assert "b" in reachable
        assert "c" in reachable

    def test_find_paths(self):
        """Test finding paths between nodes."""
        graph = WorkflowGraph(
            name="test",
            framework=WorkflowFramework.CUSTOM,
            nodes=[
                WorkflowNode(id="a", name="A", node_type="agent"),
                WorkflowNode(id="b", name="B", node_type="agent"),
                WorkflowNode(id="c", name="C", node_type="agent"),
            ],
            edges=[
                WorkflowEdge(source="a", target="b"),
                WorkflowEdge(source="a", target="c"),
                WorkflowEdge(source="b", target="c"),
            ],
        )

        analyzer = GraphAnalyzer(graph)
        paths = analyzer.find_paths("a", "c")

        assert len(paths) >= 2  # At least direct and via b


class TestWorkflowVisualizer:
    """Tests for WorkflowVisualizer."""

    def test_render_mermaid(self):
        """Test rendering Mermaid diagram."""
        graph = WorkflowGraph(
            name="test",
            framework=WorkflowFramework.CREWAI,
            nodes=[
                WorkflowNode(id="agent1", name="Researcher", node_type="agent"),
                WorkflowNode(id="agent2", name="Writer", node_type="agent"),
            ],
            edges=[
                WorkflowEdge(source="agent1", target="agent2"),
            ],
            entry_points=["agent1"],
        )

        visualizer = WorkflowVisualizer(graph)
        mermaid = visualizer.render(VisualizationFormat.MERMAID)

        assert "graph TD" in mermaid
        assert "agent1" in mermaid
        assert "agent2" in mermaid

    def test_render_graphviz(self):
        """Test rendering GraphViz DOT."""
        graph = WorkflowGraph(
            name="test",
            framework=WorkflowFramework.CUSTOM,
            nodes=[
                WorkflowNode(id="a", name="A", node_type="agent"),
            ],
        )

        visualizer = WorkflowVisualizer(graph)
        dot = visualizer.render(VisualizationFormat.GRAPHVIZ_DOT)

        assert "digraph" in dot
        assert '"a"' in dot

    def test_render_ascii(self):
        """Test rendering ASCII representation."""
        graph = WorkflowGraph(
            name="test_workflow",
            framework=WorkflowFramework.LANGGRAPH,
            nodes=[
                WorkflowNode(id="node1", name="Node 1", node_type="agent"),
            ],
        )

        visualizer = WorkflowVisualizer(graph)
        ascii_output = visualizer.render(VisualizationFormat.ASCII)

        assert "test_workflow" in ascii_output
        assert "langgraph" in ascii_output

    def test_render_json(self):
        """Test rendering JSON."""
        graph = WorkflowGraph(
            name="test",
            framework=WorkflowFramework.CUSTOM,
        )

        visualizer = WorkflowVisualizer(graph)
        json_output = visualizer.render(VisualizationFormat.JSON)

        assert '"name": "test"' in json_output

    def test_to_html(self):
        """Test generating HTML page."""
        graph = WorkflowGraph(
            name="test",
            framework=WorkflowFramework.CREWAI,
        )

        visualizer = WorkflowVisualizer(graph)
        html = visualizer.to_html()

        assert "<html>" in html
        assert "mermaid" in html


class TestIntegration:
    """Integration tests for workflow analysis."""

    def test_full_analysis_workflow(self):
        """Test full analysis workflow."""
        # Build a workflow
        builder = GraphBuilder("research_crew", WorkflowFramework.CREWAI)
        graph = (
            builder
            .add_node("researcher", "Research Agent", "agent", AgentRole.RESEARCHER,
                     tools=["search", "read_url"])
            .add_node("writer", "Writer Agent", "agent", AgentRole.WRITER,
                     tools=["write_file"])
            .add_edge("researcher", "writer", data_flow=["research_results"])
            .set_entry_point("researcher")
            .build()
        )

        # Analyze
        analyzer = WorkflowAnalyzer()
        result = analyzer.analyze_graph(graph)

        # Visualize
        visualizer = WorkflowVisualizer(graph)
        mermaid = visualizer.render(VisualizationFormat.MERMAID)

        # Verify
        assert len(graph.nodes) == 2
        assert len(graph.edges) == 1
        assert "graph TD" in mermaid

    def test_analyze_crewai_file(self):
        """Test analyzing a CrewAI file."""
        content = '''
from crewai import Agent, Crew, Task

researcher = Agent(
    role="Research Analyst",
    goal="Find information",
    tools=[search_tool],
)

writer = Agent(
    role="Content Writer",
    goal="Write content",
)

research_task = Task(
    description="Research the topic",
    agent=researcher,
)

crew = Crew(
    agents=[researcher, writer],
    tasks=[research_task],
)
'''
        analyzer = WorkflowAnalyzer()

        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write(content)
            f.flush()
            path = Path(f.name)

        try:
            result = analyzer.analyze_file(path)
            assert result.graph.framework == WorkflowFramework.CREWAI
            assert len(result.graph.nodes) >= 2
        finally:
            path.unlink()
