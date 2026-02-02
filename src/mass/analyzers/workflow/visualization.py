"""Workflow visualization utilities.

Generates visual representations of workflow graphs.
"""

from enum import Enum
from typing import Any

from mass.analyzers.workflow.analyzer import (
    WorkflowGraph,
    WorkflowNode,
    WorkflowEdge,
    AgentRole,
    WorkflowRiskCategory,
    WorkflowFinding,
)


class VisualizationFormat(str, Enum):
    """Supported visualization formats."""
    MERMAID = "mermaid"
    GRAPHVIZ_DOT = "graphviz_dot"
    PLANTUML = "plantuml"
    ASCII = "ascii"
    JSON = "json"


class WorkflowVisualizer:
    """Visualizes workflow graphs.

    Generates representations in various formats:
    - Mermaid (for GitHub/GitLab/Notion)
    - GraphViz DOT (for rendering with dot)
    - PlantUML
    - ASCII art
    """

    def __init__(self, graph: WorkflowGraph):
        """Initialize visualizer.

        Args:
            graph: Workflow graph to visualize.
        """
        self.graph = graph

    def render(
        self,
        format: VisualizationFormat = VisualizationFormat.MERMAID,
        highlight_findings: list[WorkflowFinding] | None = None,
        include_legend: bool = True,
    ) -> str:
        """Render graph in specified format.

        Args:
            format: Output format.
            highlight_findings: Findings to highlight in the visualization.
            include_legend: Include legend in output.

        Returns:
            Rendered visualization as string.
        """
        if format == VisualizationFormat.MERMAID:
            return self._render_mermaid(highlight_findings, include_legend)
        elif format == VisualizationFormat.GRAPHVIZ_DOT:
            return self._render_graphviz(highlight_findings)
        elif format == VisualizationFormat.PLANTUML:
            return self._render_plantuml(highlight_findings)
        elif format == VisualizationFormat.ASCII:
            return self._render_ascii()
        elif format == VisualizationFormat.JSON:
            return self._render_json()
        else:
            raise ValueError(f"Unsupported format: {format}")

    def _render_mermaid(
        self,
        findings: list[WorkflowFinding] | None = None,
        include_legend: bool = True,
    ) -> str:
        """Render as Mermaid diagram.

        Args:
            findings: Findings to highlight.
            include_legend: Include legend.

        Returns:
            Mermaid diagram source.
        """
        lines = ["graph TD"]

        # Track nodes with findings for highlighting
        finding_nodes = set()
        if findings:
            for f in findings:
                if f.node_id:
                    finding_nodes.add(f.node_id)

        # Add nodes with styling
        for node in self.graph.nodes:
            shape = self._get_mermaid_shape(node)
            style = self._get_mermaid_style(node, node.id in finding_nodes)

            # Create node with label
            label = self._escape_mermaid(node.name)
            if node.tools:
                label += f"\\n({len(node.tools)} tools)"

            lines.append(f"    {node.id}{shape[0]}{label}{shape[1]}")

            if style:
                lines.append(f"    style {node.id} {style}")

        # Add edges
        for edge in self.graph.edges:
            arrow = self._get_mermaid_arrow(edge)
            label = ""
            if edge.condition:
                label = f"|{self._escape_mermaid(edge.condition)}|"

            lines.append(f"    {edge.source} {arrow}{label} {edge.target}")

        # Mark entry points
        if self.graph.entry_points and include_legend:
            lines.append("")
            lines.append("    %% Entry points marked with double circle")
            for entry in self.graph.entry_points:
                lines.append(f"    {entry}:::entrypoint")

        # Add legend
        if include_legend:
            lines.extend([
                "",
                "    classDef entrypoint stroke:#0f0,stroke-width:3px",
                "    classDef danger fill:#f66,stroke:#f00,stroke-width:2px",
                "    classDef warning fill:#ff9,stroke:#f90,stroke-width:2px",
            ])

            # Mark nodes with findings
            if finding_nodes:
                lines.append(f"    class {','.join(finding_nodes)} danger")

        return "\n".join(lines)

    def _get_mermaid_shape(self, node: WorkflowNode) -> tuple[str, str]:
        """Get Mermaid shape delimiters for node type.

        Args:
            node: Node to get shape for.

        Returns:
            Tuple of (opening, closing) delimiters.
        """
        node_type = node.node_type.lower()

        if "agent" in node_type:
            return ("[", "]")  # Rectangle
        elif "tool" in node_type:
            return ("[[", "]]")  # Subroutine
        elif "router" in node_type or "condition" in node_type:
            return ("{", "}")  # Diamond
        elif "memory" in node_type or "state" in node_type:
            return ("[(", ")]")  # Cylinder
        elif "input" in node_type or "output" in node_type:
            return ("[/", "/]")  # Parallelogram
        else:
            return ("(", ")")  # Rounded

    def _get_mermaid_style(self, node: WorkflowNode, is_danger: bool = False) -> str:
        """Get Mermaid style string for node.

        Args:
            node: Node to style.
            is_danger: Whether node has findings.

        Returns:
            Style string.
        """
        if is_danger:
            return "fill:#f66,stroke:#f00,stroke-width:2px"

        role_colors = {
            AgentRole.ORCHESTRATOR: "fill:#9cf,stroke:#36c",
            AgentRole.PLANNER: "fill:#c9f,stroke:#63c",
            AgentRole.EXECUTOR: "fill:#fc9,stroke:#c63",
            AgentRole.REVIEWER: "fill:#9fc,stroke:#3c6",
            AgentRole.TOOL_USER: "fill:#ff9,stroke:#cc3",
        }

        return role_colors.get(node.role, "")

    def _get_mermaid_arrow(self, edge: WorkflowEdge) -> str:
        """Get Mermaid arrow for edge type.

        Args:
            edge: Edge to get arrow for.

        Returns:
            Arrow string.
        """
        if edge.edge_type == "conditional":
            return "-.->|"
        elif edge.edge_type == "bidirectional":
            return "<-->"
        elif edge.edge_type == "tool_call":
            return "==>|"
        else:
            return "-->"

    def _escape_mermaid(self, text: str) -> str:
        """Escape text for Mermaid.

        Args:
            text: Text to escape.

        Returns:
            Escaped text.
        """
        # Replace quotes and special chars
        text = text.replace('"', "'")
        text = text.replace("<", "&lt;")
        text = text.replace(">", "&gt;")
        return text

    def _render_graphviz(
        self,
        findings: list[WorkflowFinding] | None = None,
    ) -> str:
        """Render as GraphViz DOT.

        Args:
            findings: Findings to highlight.

        Returns:
            DOT source.
        """
        lines = [
            f'digraph "{self.graph.name}" {{',
            "    rankdir=TB;",
            '    node [fontname="Arial"];',
            '    edge [fontname="Arial"];',
            "",
        ]

        # Track nodes with findings
        finding_nodes = set()
        if findings:
            for f in findings:
                if f.node_id:
                    finding_nodes.add(f.node_id)

        # Add nodes
        for node in self.graph.nodes:
            attrs = self._get_graphviz_attrs(node, node.id in finding_nodes)
            attrs_str = ", ".join(f'{k}="{v}"' for k, v in attrs.items())
            lines.append(f'    "{node.id}" [{attrs_str}];')

        lines.append("")

        # Add edges
        for edge in self.graph.edges:
            attrs = {}
            if edge.condition:
                attrs["label"] = edge.condition
            if edge.edge_type == "conditional":
                attrs["style"] = "dashed"
            elif edge.edge_type == "bidirectional":
                attrs["dir"] = "both"

            attrs_str = ""
            if attrs:
                attrs_str = " [" + ", ".join(f'{k}="{v}"' for k, v in attrs.items()) + "]"

            lines.append(f'    "{edge.source}" -> "{edge.target}"{attrs_str};')

        lines.append("}")
        return "\n".join(lines)

    def _get_graphviz_attrs(
        self,
        node: WorkflowNode,
        is_danger: bool = False,
    ) -> dict[str, str]:
        """Get GraphViz attributes for node.

        Args:
            node: Node to get attributes for.
            is_danger: Whether node has findings.

        Returns:
            Attribute dictionary.
        """
        attrs: dict[str, str] = {
            "label": node.name,
        }

        # Shape based on type
        node_type = node.node_type.lower()
        if "agent" in node_type:
            attrs["shape"] = "box"
        elif "tool" in node_type:
            attrs["shape"] = "component"
        elif "router" in node_type or "condition" in node_type:
            attrs["shape"] = "diamond"
        elif "memory" in node_type or "state" in node_type:
            attrs["shape"] = "cylinder"
        else:
            attrs["shape"] = "ellipse"

        # Color based on findings or role
        if is_danger:
            attrs["fillcolor"] = "#ff6666"
            attrs["style"] = "filled"
        elif node.role == AgentRole.ORCHESTRATOR:
            attrs["fillcolor"] = "#99ccff"
            attrs["style"] = "filled"
        elif node.role == AgentRole.EXECUTOR:
            attrs["fillcolor"] = "#ffcc99"
            attrs["style"] = "filled"

        return attrs

    def _render_plantuml(
        self,
        findings: list[WorkflowFinding] | None = None,
    ) -> str:
        """Render as PlantUML activity diagram.

        Args:
            findings: Findings to highlight.

        Returns:
            PlantUML source.
        """
        lines = [
            "@startuml",
            f"title {self.graph.name}",
            "",
        ]

        # Track nodes with findings
        finding_nodes = set()
        if findings:
            for f in findings:
                if f.node_id:
                    finding_nodes.add(f.node_id)

        # Define colors
        lines.append("skinparam activity {")
        lines.append("    BackgroundColor #E0E0E0")
        lines.append("    BorderColor #404040")
        lines.append("}")
        lines.append("")

        # Add start
        if self.graph.entry_points:
            lines.append("(*) --> " + self.graph.entry_points[0])
            lines.append("")

        # Add edges with styling
        for edge in self.graph.edges:
            source_style = "#FF6666" if edge.source in finding_nodes else ""
            target_style = "#FF6666" if edge.target in finding_nodes else ""

            if source_style:
                lines.append(f"{edge.source} {source_style}")
            if target_style:
                lines.append(f"{edge.target} {target_style}")

            if edge.condition:
                lines.append(f'if "{edge.condition}" then')
                lines.append(f"    --> {edge.target}")
                lines.append("endif")
            else:
                lines.append(f"{edge.source} --> {edge.target}")

        lines.append("")
        lines.append("@enduml")
        return "\n".join(lines)

    def _render_ascii(self) -> str:
        """Render as ASCII art.

        Returns:
            ASCII representation.
        """
        lines = [
            f"Workflow: {self.graph.name}",
            f"Framework: {self.graph.framework.value}",
            "=" * 50,
            "",
        ]

        # List nodes
        lines.append("Nodes:")
        for node in self.graph.nodes:
            role_str = f" ({node.role.value})" if node.role != AgentRole.CUSTOM else ""
            tools_str = f" [{len(node.tools)} tools]" if node.tools else ""
            lines.append(f"  [{node.node_type}] {node.name}{role_str}{tools_str}")

        lines.append("")

        # List connections
        lines.append("Connections:")
        for edge in self.graph.edges:
            condition_str = f" when '{edge.condition}'" if edge.condition else ""
            arrow = "<=>" if edge.edge_type == "bidirectional" else "-->"
            lines.append(f"  {edge.source} {arrow} {edge.target}{condition_str}")

        lines.append("")

        # Entry points
        if self.graph.entry_points:
            lines.append(f"Entry points: {', '.join(self.graph.entry_points)}")

        return "\n".join(lines)

    def _render_json(self) -> str:
        """Render as JSON.

        Returns:
            JSON representation.
        """
        import json
        return json.dumps(self.graph.to_dict(), indent=2)

    def to_html(
        self,
        format: VisualizationFormat = VisualizationFormat.MERMAID,
        findings: list[WorkflowFinding] | None = None,
    ) -> str:
        """Generate HTML page with embedded visualization.

        Args:
            format: Visualization format.
            findings: Findings to highlight.

        Returns:
            Complete HTML page.
        """
        if format == VisualizationFormat.MERMAID:
            diagram = self._render_mermaid(findings)
            return f"""<!DOCTYPE html>
<html>
<head>
    <title>{self.graph.name} - Workflow</title>
    <script src="https://cdn.jsdelivr.net/npm/mermaid/dist/mermaid.min.js"></script>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; }}
        h1 {{ color: #333; }}
        .mermaid {{ background: #f9f9f9; padding: 20px; border-radius: 8px; }}
    </style>
</head>
<body>
    <h1>{self.graph.name}</h1>
    <p>Framework: {self.graph.framework.value}</p>
    <div class="mermaid">
{diagram}
    </div>
    <script>mermaid.initialize({{startOnLoad:true}});</script>
</body>
</html>"""

        else:
            # For other formats, show code block
            content = self.render(format, findings)
            return f"""<!DOCTYPE html>
<html>
<head>
    <title>{self.graph.name} - Workflow</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; }}
        pre {{ background: #f0f0f0; padding: 20px; border-radius: 8px; overflow: auto; }}
    </style>
</head>
<body>
    <h1>{self.graph.name}</h1>
    <p>Framework: {self.graph.framework.value}</p>
    <pre>{content}</pre>
</body>
</html>"""
