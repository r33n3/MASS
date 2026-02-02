"""Workflow graph building and analysis utilities.

Graph construction and analysis for workflow security assessment.
"""

from dataclasses import dataclass, field
from typing import Any

from mass.analyzers.workflow.analyzer import (
    WorkflowGraph,
    WorkflowNode,
    WorkflowEdge,
    WorkflowFramework,
    AgentRole,
)


@dataclass
class GraphMetrics:
    """Metrics about a workflow graph."""
    node_count: int
    edge_count: int
    entry_points: int
    max_depth: int
    max_fan_out: int
    cycle_count: int
    isolated_nodes: int
    density: float  # edges / (nodes * (nodes - 1))

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "node_count": self.node_count,
            "edge_count": self.edge_count,
            "entry_points": self.entry_points,
            "max_depth": self.max_depth,
            "max_fan_out": self.max_fan_out,
            "cycle_count": self.cycle_count,
            "isolated_nodes": self.isolated_nodes,
            "density": self.density,
        }


class GraphBuilder:
    """Builder for constructing workflow graphs.

    Provides fluent interface for building graphs programmatically.
    """

    def __init__(self, name: str, framework: WorkflowFramework = WorkflowFramework.CUSTOM):
        """Initialize graph builder.

        Args:
            name: Graph name.
            framework: Workflow framework.
        """
        self._graph = WorkflowGraph(name=name, framework=framework)

    def add_node(
        self,
        node_id: str,
        name: str | None = None,
        node_type: str = "agent",
        role: AgentRole = AgentRole.CUSTOM,
        description: str = "",
        tools: list[str] | None = None,
        **kwargs: Any,
    ) -> "GraphBuilder":
        """Add a node to the graph.

        Args:
            node_id: Unique node identifier.
            name: Display name (defaults to node_id).
            node_type: Type of node (agent, tool, router, etc.).
            role: Agent role.
            description: Node description.
            tools: List of tools available to the node.
            **kwargs: Additional metadata.

        Returns:
            Self for chaining.
        """
        node = WorkflowNode(
            id=node_id,
            name=name or node_id,
            node_type=node_type,
            role=role,
            description=description,
            tools=tools or [],
            metadata=kwargs,
        )
        self._graph.nodes.append(node)
        return self

    def add_edge(
        self,
        source: str,
        target: str,
        edge_type: str = "flow",
        condition: str | None = None,
        data_flow: list[str] | None = None,
        **kwargs: Any,
    ) -> "GraphBuilder":
        """Add an edge to the graph.

        Args:
            source: Source node ID.
            target: Target node ID.
            edge_type: Type of edge.
            condition: Condition for conditional edges.
            data_flow: Data types that flow through this edge.
            **kwargs: Additional metadata.

        Returns:
            Self for chaining.
        """
        edge = WorkflowEdge(
            source=source,
            target=target,
            edge_type=edge_type,
            condition=condition,
            data_flow=data_flow or [],
            metadata=kwargs,
        )
        self._graph.edges.append(edge)
        return self

    def set_entry_point(self, node_id: str) -> "GraphBuilder":
        """Set an entry point for the graph.

        Args:
            node_id: Node ID to mark as entry point.

        Returns:
            Self for chaining.
        """
        if node_id not in self._graph.entry_points:
            self._graph.entry_points.append(node_id)
        return self

    def add_metadata(self, **kwargs: Any) -> "GraphBuilder":
        """Add metadata to the graph.

        Args:
            **kwargs: Metadata key-value pairs.

        Returns:
            Self for chaining.
        """
        self._graph.metadata.update(kwargs)
        return self

    def build(self) -> WorkflowGraph:
        """Build and return the graph.

        Returns:
            Constructed WorkflowGraph.
        """
        return self._graph


class GraphAnalyzer:
    """Analyzes workflow graph structure.

    Provides metrics and structural analysis of graphs.
    """

    def __init__(self, graph: WorkflowGraph):
        """Initialize graph analyzer.

        Args:
            graph: Graph to analyze.
        """
        self.graph = graph

    def compute_metrics(self) -> GraphMetrics:
        """Compute metrics about the graph.

        Returns:
            GraphMetrics with computed values.
        """
        node_count = len(self.graph.nodes)
        edge_count = len(self.graph.edges)

        # Calculate max depth from entry points
        max_depth = 0
        for entry in self.graph.entry_points:
            depth = self._max_depth_from(entry)
            max_depth = max(max_depth, depth)

        # Calculate max fan-out
        max_fan_out = 0
        for node in self.graph.nodes:
            fan_out = len(self.graph.get_outgoing_edges(node.id))
            max_fan_out = max(max_fan_out, fan_out)

        # Count isolated nodes
        connected = set()
        for edge in self.graph.edges:
            connected.add(edge.source)
            connected.add(edge.target)
        isolated_nodes = sum(
            1 for n in self.graph.nodes
            if n.id not in connected
        )

        # Count cycles
        cycle_count = len(self._find_all_cycles())

        # Calculate density
        if node_count > 1:
            max_edges = node_count * (node_count - 1)
            density = edge_count / max_edges
        else:
            density = 0.0

        return GraphMetrics(
            node_count=node_count,
            edge_count=edge_count,
            entry_points=len(self.graph.entry_points),
            max_depth=max_depth,
            max_fan_out=max_fan_out,
            cycle_count=cycle_count,
            isolated_nodes=isolated_nodes,
            density=density,
        )

    def _max_depth_from(self, start: str, visited: set | None = None) -> int:
        """Calculate maximum depth from a starting node.

        Args:
            start: Starting node ID.
            visited: Set of visited nodes (for cycle prevention).

        Returns:
            Maximum depth.
        """
        if visited is None:
            visited = set()

        if start in visited:
            return 0

        visited.add(start)

        outgoing = self.graph.get_outgoing_edges(start)
        if not outgoing:
            return 1

        max_child_depth = 0
        for edge in outgoing:
            child_depth = self._max_depth_from(edge.target, visited.copy())
            max_child_depth = max(max_child_depth, child_depth)

        return 1 + max_child_depth

    def _find_all_cycles(self) -> list[list[str]]:
        """Find all cycles in the graph.

        Returns:
            List of cycles (each cycle is a list of node IDs).
        """
        cycles: list[list[str]] = []
        visited: set[str] = set()
        rec_stack: set[str] = set()

        def dfs(node_id: str, path: list[str]) -> None:
            visited.add(node_id)
            rec_stack.add(node_id)
            path.append(node_id)

            for edge in self.graph.get_outgoing_edges(node_id):
                if edge.target not in visited:
                    dfs(edge.target, path.copy())
                elif edge.target in rec_stack:
                    cycle_start = path.index(edge.target)
                    cycle = path[cycle_start:] + [edge.target]
                    cycles.append(cycle)

            rec_stack.remove(node_id)

        for node in self.graph.nodes:
            if node.id not in visited:
                dfs(node.id, [])

        return cycles

    def get_reachable_from(self, start: str) -> set[str]:
        """Get all nodes reachable from a starting node.

        Args:
            start: Starting node ID.

        Returns:
            Set of reachable node IDs.
        """
        reachable = set()
        queue = [start]

        while queue:
            current = queue.pop(0)
            if current in reachable:
                continue

            reachable.add(current)

            for edge in self.graph.get_outgoing_edges(current):
                if edge.target not in reachable:
                    queue.append(edge.target)

        return reachable

    def get_nodes_by_type(self, node_type: str) -> list[WorkflowNode]:
        """Get nodes of a specific type.

        Args:
            node_type: Node type to filter by.

        Returns:
            List of matching nodes.
        """
        return [n for n in self.graph.nodes if n.node_type == node_type]

    def get_nodes_by_role(self, role: AgentRole) -> list[WorkflowNode]:
        """Get nodes of a specific role.

        Args:
            role: Agent role to filter by.

        Returns:
            List of matching nodes.
        """
        return [n for n in self.graph.nodes if n.role == role]

    def find_paths(
        self,
        start: str,
        end: str,
        max_paths: int = 10,
    ) -> list[list[str]]:
        """Find all paths between two nodes.

        Args:
            start: Start node ID.
            end: End node ID.
            max_paths: Maximum number of paths to return.

        Returns:
            List of paths (each path is a list of node IDs).
        """
        paths: list[list[str]] = []

        def dfs(current: str, path: list[str], visited: set[str]) -> None:
            if len(paths) >= max_paths:
                return

            if current == end:
                paths.append(path.copy())
                return

            for edge in self.graph.get_outgoing_edges(current):
                if edge.target not in visited:
                    visited.add(edge.target)
                    path.append(edge.target)
                    dfs(edge.target, path, visited)
                    path.pop()
                    visited.remove(edge.target)

        dfs(start, [start], {start})
        return paths

    def get_critical_paths(self) -> list[list[str]]:
        """Find critical paths (longest paths from entry to exit).

        Returns:
            List of critical paths.
        """
        # Find terminal nodes (no outgoing edges)
        terminal_nodes = [
            n.id for n in self.graph.nodes
            if not self.graph.get_outgoing_edges(n.id)
        ]

        critical_paths: list[list[str]] = []
        max_length = 0

        for entry in self.graph.entry_points:
            for terminal in terminal_nodes:
                paths = self.find_paths(entry, terminal, max_paths=5)
                for path in paths:
                    if len(path) > max_length:
                        max_length = len(path)
                        critical_paths = [path]
                    elif len(path) == max_length:
                        critical_paths.append(path)

        return critical_paths

    def get_subgraph(self, node_ids: set[str]) -> WorkflowGraph:
        """Extract a subgraph containing specified nodes.

        Args:
            node_ids: Set of node IDs to include.

        Returns:
            New WorkflowGraph containing only specified nodes.
        """
        subgraph = WorkflowGraph(
            name=f"{self.graph.name}_subgraph",
            framework=self.graph.framework,
        )

        # Add matching nodes
        for node in self.graph.nodes:
            if node.id in node_ids:
                subgraph.nodes.append(node)

        # Add edges between matching nodes
        for edge in self.graph.edges:
            if edge.source in node_ids and edge.target in node_ids:
                subgraph.edges.append(edge)

        # Update entry points
        for entry in self.graph.entry_points:
            if entry in node_ids:
                subgraph.entry_points.append(entry)

        return subgraph
