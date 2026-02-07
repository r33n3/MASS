"""Main CLI entry point for MASS.

Usage:
    mass scan ./my-deployment --profile comprehensive
    mass analyze model ./model.gguf
    mass compliance assess --framework owasp_llm --scan scan_123
    mass report export scan_123 --format sarif -o findings.sarif
"""

from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.panel import Panel

app = typer.Typer(
    name="mass",
    help="MASS - Model & Application Security Suite",
    no_args_is_help=True,
)

console = Console()

# Sub-apps
scan_app = typer.Typer(help="Scan deployments for vulnerabilities")
analyze_app = typer.Typer(help="Analyze specific components")
compliance_app = typer.Typer(help="Compliance assessment and reporting")
report_app = typer.Typer(help="Generate and export reports")

app.add_typer(scan_app, name="scan")
app.add_typer(analyze_app, name="analyze")
app.add_typer(compliance_app, name="compliance")
app.add_typer(report_app, name="report")


@app.callback()
def callback() -> None:
    """MASS - Model & Application Security Suite.

    Comprehensive AI deployment security platform.
    """
    pass


@app.command()
def version() -> None:
    """Show MASS version."""
    from mass.version import __version__
    console.print(f"MASS version {__version__}")


@app.command()
def info() -> None:
    """Show MASS system information."""
    from mass.version import __version__

    info_table = Table(title="MASS System Information")
    info_table.add_column("Property", style="cyan")
    info_table.add_column("Value", style="green")

    info_table.add_row("Version", __version__)
    info_table.add_row("Python", "3.10+")
    info_table.add_row("Analyzers", "8 (deployment, secrets, infra, model_file, context, mcp, attack_surface, workflow)")
    info_table.add_row("Frameworks", "OWASP LLM, MITRE ATLAS, NIST AI RMF, EU AI Act")
    info_table.add_row("Output Formats", "SARIF, HTML, JSON, PDF")

    console.print(info_table)


# ============== SCAN COMMANDS ==============

@scan_app.command("run")
def scan_run(
    path: Path = typer.Argument(..., help="Path to deployment directory"),
    profile: str = typer.Option("standard", "--profile", "-p", help="Scan profile: quick, standard, comprehensive"),
    output: Optional[Path] = typer.Option(None, "--output", "-o", help="Output directory for reports"),
    format: str = typer.Option("json", "--format", "-f", help="Output format: json, sarif, html"),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Verbose output"),
) -> None:
    """Run a security scan on a deployment.

    Example:
        mass scan run ./my-agent --profile comprehensive -o reports/
    """
    if not path.exists():
        console.print(f"[red]Error: Path not found: {path}[/red]")
        raise typer.Exit(1)

    console.print(Panel(f"[bold]MASS Security Scan[/bold]\nTarget: {path}\nProfile: {profile}"))

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        task = progress.add_task("Initializing scan...", total=None)

        try:
            from mass.orchestration.service import ScanService
            from mass.orchestration.profiles import get_profile
            from mass.reporting.generator import ReportGenerator, ReportFormat

            # Create and run scan
            service = ScanService()
            progress.update(task, description="Running security analysis...")

            result = service.scan_deployment(
                deployment_path=str(path),
                profile_name=profile,
                deployment_name=path.name,
            )

            progress.update(task, description="Generating report...")

            # Generate report
            generator = ReportGenerator()
            fmt = ReportFormat(format.lower())
            report = generator.generate(
                format=fmt,
                findings=result.findings,
                scan_id=result.scan_id,
                scan_result=result,
            )

            # Save report
            if output:
                output.mkdir(parents=True, exist_ok=True)
                report_path = report.save(output)
                console.print(f"[green]Report saved to: {report_path}[/green]")
            else:
                # Print summary to console
                console.print(report.content)

        except Exception as e:
            console.print(f"[red]Error: {e}[/red]")
            if verbose:
                console.print_exception()
            raise typer.Exit(1)

    # Print summary
    _print_scan_summary(result)


@scan_app.command("list-profiles")
def scan_list_profiles() -> None:
    """List available scan profiles."""
    from mass.orchestration.profiles import PROFILES

    table = Table(title="Available Scan Profiles")
    table.add_column("Profile", style="cyan")
    table.add_column("Description", style="white")
    table.add_column("Analyzers", style="green")

    for name, profile in PROFILES.items():
        enabled = profile.get_enabled_analyzers()
        table.add_row(
            name,
            profile.description,
            str(len(enabled)),
        )

    console.print(table)


# ============== ANALYZE COMMANDS ==============

@analyze_app.command("model")
def analyze_model(
    path: Path = typer.Argument(..., help="Path to model file"),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Verbose output"),
) -> None:
    """Analyze a model file for security issues.

    Example:
        mass analyze model ./model.pt
    """
    if not path.exists():
        console.print(f"[red]Error: Model file not found: {path}[/red]")
        raise typer.Exit(1)

    console.print(f"[bold]Analyzing model:[/bold] {path}")

    try:
        from mass.analyzers.model_file.scanner import ModelFileScanner

        scanner = ModelFileScanner()
        result = scanner.scan_path(str(path))

        if result.findings:
            _print_findings_table(result.findings)
        else:
            console.print("[green]No security issues found.[/green]")

    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        if verbose:
            console.print_exception()
        raise typer.Exit(1)


@analyze_app.command("context")
def analyze_context(
    path: Path = typer.Argument(..., help="Path to context/prompt file"),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Verbose output"),
) -> None:
    """Analyze system prompts and context for security issues.

    Example:
        mass analyze context ./prompts/system.txt
    """
    if not path.exists():
        console.print(f"[red]Error: File not found: {path}[/red]")
        raise typer.Exit(1)

    console.print(f"[bold]Analyzing context:[/bold] {path}")

    try:
        from mass.analyzers.context.analyzer import ContextAnalyzer

        content = path.read_text()
        analyzer = ContextAnalyzer()
        result = analyzer.analyze(content)

        if result.findings:
            _print_findings_table(result.findings)
        else:
            console.print("[green]No security issues found.[/green]")

    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        if verbose:
            console.print_exception()
        raise typer.Exit(1)


@analyze_app.command("mcp")
def analyze_mcp(
    config: Path = typer.Argument(..., help="Path to MCP configuration file"),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Verbose output"),
) -> None:
    """Analyze MCP server configuration for security issues.

    Example:
        mass analyze mcp ./.mcp.json
    """
    if not config.exists():
        console.print(f"[red]Error: Config file not found: {config}[/red]")
        raise typer.Exit(1)

    console.print(f"[bold]Analyzing MCP config:[/bold] {config}")

    try:
        import json
        from mass.analyzers.mcp.analyzer import MCPAnalyzer

        config_data = json.loads(config.read_text())
        analyzer = MCPAnalyzer()
        result = analyzer.analyze(config_data)

        if result.findings:
            _print_findings_table(result.findings)
        else:
            console.print("[green]No security issues found.[/green]")

    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        if verbose:
            console.print_exception()
        raise typer.Exit(1)


@analyze_app.command("workflow")
def analyze_workflow(
    path: Path = typer.Argument(..., help="Path to workflow file"),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Verbose output"),
) -> None:
    """Analyze agentic workflow for security issues.

    Example:
        mass analyze workflow ./agents/workflow.py
    """
    if not path.exists():
        console.print(f"[red]Error: File not found: {path}[/red]")
        raise typer.Exit(1)

    console.print(f"[bold]Analyzing workflow:[/bold] {path}")

    try:
        from mass.analyzers.workflow.analyzer import WorkflowAnalyzer

        analyzer = WorkflowAnalyzer()
        result = analyzer.analyze_file(str(path))

        if result.findings:
            _print_findings_table(result.findings)
        else:
            console.print("[green]No security issues found.[/green]")

    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        if verbose:
            console.print_exception()
        raise typer.Exit(1)


# ============== COMPLIANCE COMMANDS ==============

@compliance_app.command("assess")
def compliance_assess(
    findings_file: Path = typer.Argument(..., help="Path to findings JSON file"),
    framework: str = typer.Option("owasp_llm", "--framework", "-f", help="Framework: owasp_llm, mitre_atlas, nist_ai_rmf, eu_ai_act"),
    output: Optional[Path] = typer.Option(None, "--output", "-o", help="Output file"),
) -> None:
    """Assess findings against compliance framework.

    Example:
        mass compliance assess findings.json --framework owasp_llm
    """
    if not findings_file.exists():
        console.print(f"[red]Error: Findings file not found: {findings_file}[/red]")
        raise typer.Exit(1)

    try:
        import json
        from mass.core.findings import Finding
        from mass.core.types import FrameworkType
        from mass.compliance.assessor import ComplianceAssessor

        # Load findings
        data = json.loads(findings_file.read_text())
        findings_data = data.get("findings", data) if isinstance(data, dict) else data

        # Convert to Finding objects (simplified)
        findings = []
        for f in findings_data:
            from mass.core.types import Severity, AttackCategory, ComponentType
            finding = Finding(
                id=f.get("id", ""),
                title=f.get("title", ""),
                description=f.get("description", ""),
                severity=Severity(f.get("severity", "info")),
                category=AttackCategory(f.get("category", "prompt_injection")),
                component_type=ComponentType(f.get("component_type", "model")),
                component_name=f.get("component_name", "unknown"),
            )
            findings.append(finding)

        # Assess
        fw_type = FrameworkType(framework)
        assessor = ComplianceAssessor(frameworks=[fw_type])
        result = assessor.assess(findings)

        # Output
        summary = assessor.generate_compliance_summary(result)
        if output:
            output.write_text(json.dumps(result.to_dict(), indent=2))
            console.print(f"[green]Assessment saved to: {output}[/green]")

        # Print summary
        _print_compliance_summary(summary)

    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        raise typer.Exit(1)


@compliance_app.command("frameworks")
def compliance_frameworks() -> None:
    """List supported compliance frameworks."""
    from mass.core.types import FrameworkType

    table = Table(title="Supported Compliance Frameworks")
    table.add_column("Framework", style="cyan")
    table.add_column("Name", style="white")

    for fw in FrameworkType:
        table.add_row(fw.value, fw.name.replace("_", " "))

    console.print(table)


# ============== REPORT COMMANDS ==============

@report_app.command("export")
def report_export(
    findings_file: Path = typer.Argument(..., help="Path to findings JSON file"),
    format: str = typer.Option("sarif", "--format", "-f", help="Format: sarif, html, json"),
    output: Path = typer.Option(Path("report"), "--output", "-o", help="Output file path"),
) -> None:
    """Export findings to report format.

    Example:
        mass report export findings.json --format sarif -o report.sarif
    """
    if not findings_file.exists():
        console.print(f"[red]Error: Findings file not found: {findings_file}[/red]")
        raise typer.Exit(1)

    try:
        import json
        from mass.core.findings import Finding
        from mass.core.types import Severity, AttackCategory, ComponentType
        from mass.reporting.generator import ReportGenerator, ReportFormat

        # Load findings
        data = json.loads(findings_file.read_text())
        findings_data = data.get("findings", data) if isinstance(data, dict) else data

        # Convert to Finding objects
        findings = []
        for f in findings_data:
            finding = Finding(
                id=f.get("id", ""),
                title=f.get("title", ""),
                description=f.get("description", ""),
                severity=Severity(f.get("severity", "info")),
                category=AttackCategory(f.get("category", "prompt_injection")),
                component_type=ComponentType(f.get("component_type", "model")),
                component_name=f.get("component_name", "unknown"),
            )
            findings.append(finding)

        # Generate report
        generator = ReportGenerator()
        fmt = ReportFormat(format.lower())
        report = generator.generate(format=fmt, findings=findings)

        # Save
        report.save(output)
        console.print(f"[green]Report saved to: {output}[/green]")

    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        raise typer.Exit(1)


@report_app.command("formats")
def report_formats() -> None:
    """List supported report formats."""
    from mass.reporting.generator import ReportFormat

    table = Table(title="Supported Report Formats")
    table.add_column("Format", style="cyan")
    table.add_column("Description", style="white")
    table.add_column("File Extension", style="green")

    formats_info = {
        ReportFormat.SARIF: ("SARIF 2.1.0 - GitHub/VS Code compatible", ".sarif"),
        ReportFormat.HTML: ("Interactive HTML report", ".html"),
        ReportFormat.JSON: ("Structured JSON report", ".json"),
        ReportFormat.PDF: ("PDF report (coming soon)", ".pdf"),
    }

    for fmt, (desc, ext) in formats_info.items():
        table.add_row(fmt.value, desc, ext)

    console.print(table)


# ============== HELPER FUNCTIONS ==============

def _print_scan_summary(result) -> None:
    """Print scan result summary."""
    from mass.core.types import ScanStatus

    console.print()

    status_color = "green" if result.status == ScanStatus.COMPLETED else "red"
    console.print(f"[bold]Scan Status:[/bold] [{status_color}]{result.status.value}[/{status_color}]")

    if result.summary:
        table = Table(title="Findings Summary")
        table.add_column("Severity", style="cyan")
        table.add_column("Count", style="white", justify="right")

        table.add_row("Critical", str(result.summary.critical_count), style="red")
        table.add_row("High", str(result.summary.high_count), style="bright_red")
        table.add_row("Medium", str(result.summary.medium_count), style="yellow")
        table.add_row("Low", str(result.summary.low_count), style="blue")
        table.add_row("Info", str(result.summary.info_count), style="dim")
        table.add_row("Total", str(result.summary.total), style="bold")

        console.print(table)


def _print_findings_table(findings) -> None:
    """Print findings as table."""
    table = Table(title=f"Security Findings ({len(findings)} found)")
    table.add_column("Severity", style="cyan")
    table.add_column("Title", style="white")
    table.add_column("Category", style="yellow")
    table.add_column("Component", style="green")

    severity_styles = {
        "critical": "red",
        "high": "bright_red",
        "medium": "yellow",
        "low": "blue",
        "info": "dim",
    }

    for finding in findings:
        style = severity_styles.get(finding.severity.value, "white")
        table.add_row(
            finding.severity.value.upper(),
            finding.title[:50] + "..." if len(finding.title) > 50 else finding.title,
            finding.category.value,
            finding.component_name,
            style=style,
        )

    console.print(table)


def _print_compliance_summary(summary: dict) -> None:
    """Print compliance assessment summary."""
    console.print()
    console.print(Panel(
        f"[bold]Compliance Score:[/bold] {summary['overall']['compliance_score']}\n"
        f"[bold]Risk Level:[/bold] {summary['overall']['risk_level']}\n"
        f"[bold]Total Findings:[/bold] {summary['overall']['total_findings']}",
        title="Compliance Assessment",
    ))

    if summary.get("top_issues"):
        table = Table(title="Top Issues")
        table.add_column("Requirement", style="cyan")
        table.add_column("Framework", style="white")
        table.add_column("Status", style="red")
        table.add_column("Findings", style="yellow", justify="right")

        for issue in summary["top_issues"]:
            table.add_row(
                issue["requirement"],
                issue["framework"],
                issue["status"],
                str(issue["findings_count"]),
            )

        console.print(table)


def main() -> None:
    """Main entry point."""
    app()


if __name__ == "__main__":
    main()
