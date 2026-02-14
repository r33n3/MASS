"""Report generation and export for sandbox results.

Extends the existing report system to support sandbox-specific output
formats and maps sandbox results into compliance frameworks and
guardrail recommendations.
"""

from __future__ import annotations

import csv
import io
import json
import logging
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any

from mass.sandbox.logger import SandboxTelemetry
from mass.sandbox.scorer import ScenarioScore

logger = logging.getLogger("mass.sandbox.reporter")


class SandboxReportFormat(str, Enum):
    JSON = "json"
    SARIF = "sarif"
    HTML = "html"
    JSONL = "jsonl"
    CSV = "csv"
    JUNIT = "junit"


@dataclass
class SandboxReport:
    """Generated sandbox report."""

    format: SandboxReportFormat
    content: str | bytes
    filename: str
    generated_at: datetime = field(default_factory=datetime.utcnow)
    metadata: dict[str, Any] = field(default_factory=dict)

    def save(self, path: str) -> str:
        from pathlib import Path

        p = Path(path)
        if p.is_dir():
            p = p / self.filename
        if isinstance(self.content, bytes):
            p.write_bytes(self.content)
        else:
            p.write_text(self.content, encoding="utf-8")
        return str(p)


class SandboxReporter:
    """Generates reports from sandbox results + telemetry."""

    def __init__(self) -> None:
        pass

    def generate(
        self,
        result: Any,  # SandboxResult
        telemetry: SandboxTelemetry | None = None,
        score: ScenarioScore | None = None,
        fmt: SandboxReportFormat = SandboxReportFormat.JSON,
    ) -> SandboxReport:
        """Generate a report in the specified format."""
        timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")

        if fmt == SandboxReportFormat.JSON:
            content = self.to_json(result, telemetry, score)
            filename = f"sandbox_report_{timestamp}.json"
        elif fmt == SandboxReportFormat.SARIF:
            content = self.to_sarif(result)
            filename = f"sandbox_report_{timestamp}.sarif"
        elif fmt == SandboxReportFormat.HTML:
            content = self.to_html(result, telemetry, score)
            filename = f"sandbox_report_{timestamp}.html"
        elif fmt == SandboxReportFormat.JSONL:
            content = self.to_jsonl(telemetry)
            filename = f"sandbox_telemetry_{timestamp}.jsonl"
        elif fmt == SandboxReportFormat.CSV:
            content = self.to_csv(result, score)
            filename = f"sandbox_report_{timestamp}.csv"
        elif fmt == SandboxReportFormat.JUNIT:
            content = self.to_junit(result, score)
            filename = f"sandbox_report_{timestamp}.xml"
        else:
            raise ValueError(f"Unsupported format: {fmt}")

        return SandboxReport(
            format=fmt,
            content=content,
            filename=filename,
            metadata={
                "scenario_name": result.scenario_name,
                "job_id": result.job_id,
            },
        )

    def to_json(
        self,
        result: Any,
        telemetry: SandboxTelemetry | None = None,
        score: ScenarioScore | None = None,
    ) -> str:
        """Full structured JSON report."""
        report_data: dict[str, Any] = {
            "report_type": "sandbox",
            "version": "1.0",
            "generated_at": datetime.utcnow().isoformat(),
            "scenario": {
                "name": result.scenario_name,
                "job_id": result.job_id,
                "seed": result.seed,
            },
            "execution": {
                "status": result.status,
                "model": result.model_used,
                "provider": result.provider_used,
                "duration_seconds": result.duration_seconds,
                "total_turns": result.total_turns,
            },
        }

        if score:
            report_data["score"] = score.to_dict()

        report_data["steps"] = [s.to_dict() for s in result.steps]

        if telemetry:
            report_data["telemetry"] = telemetry.to_dict()

        report_data["findings"] = [
            f.model_dump(mode="json") if hasattr(f, "model_dump") else f
            for f in result.findings
        ]

        # Compliance mapping
        try:
            report_data["compliance"] = self.map_to_compliance(result)
        except Exception:
            report_data["compliance"] = {}

        # Guardrail recommendations
        try:
            report_data["guardrail_recommendations"] = self.generate_guardrail_recommendations(result)
        except Exception:
            report_data["guardrail_recommendations"] = []

        return json.dumps(report_data, indent=2, default=str)

    def to_jsonl(self, telemetry: SandboxTelemetry | None = None) -> str:
        """One telemetry event per line."""
        if not telemetry:
            return ""
        return telemetry.to_jsonl()

    def to_sarif(self, result: Any) -> str:
        """SARIF 2.1.0 output from sandbox findings."""
        try:
            from mass.reporting.formats.sarif import SarifFormatter

            formatter = SarifFormatter(
                tool_name="MASS Sandbox",
                tool_version="0.1.0",
            )
            return formatter.format_to_string(result.findings, result.job_id)
        except Exception as e:
            logger.warning("SARIF generation failed, using fallback: %s", e)
            # Fallback SARIF
            sarif = {
                "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
                "version": "2.1.0",
                "runs": [{
                    "tool": {
                        "driver": {
                            "name": "MASS Sandbox",
                            "version": "0.1.0",
                        },
                    },
                    "results": [
                        {
                            "ruleId": f.metadata.get("assertion", "sandbox-check"),
                            "level": "error" if f.severity.value in ("critical", "high") else "warning",
                            "message": {"text": f.description},
                        }
                        for f in result.findings
                    ],
                }],
            }
            return json.dumps(sarif, indent=2)

    def to_html(
        self,
        result: Any,
        telemetry: SandboxTelemetry | None = None,
        score: ScenarioScore | None = None,
    ) -> str:
        """Standalone HTML report."""
        steps_html = ""
        for step in result.steps:
            status_class = "pass" if not step.assertions_failed else "fail"
            tools_str = ", ".join(tc.name for tc in step.tool_calls_made) or "none"
            passed_str = ", ".join(step.assertions_passed) or "none"
            failed_str = ", ".join(step.assertions_failed) or "none"

            steps_html += f"""
            <div class="step {status_class}">
                <div class="step-header">
                    <span class="turn-num">Turn {step.turn_number}</span>
                    <span class="badge {'badge-pass' if not step.assertions_failed else 'badge-fail'}">
                        {'PASS' if not step.assertions_failed else 'FAIL'}
                    </span>
                    <span class="latency">{step.latency_ms:.0f}ms</span>
                </div>
                <div class="step-body">
                    <div class="field"><label>User Input:</label><pre>{_html_escape(step.user_input)}</pre></div>
                    <div class="field"><label>Response:</label><pre>{_html_escape(step.model_response[:500])}</pre></div>
                    <div class="field"><label>Tools Called:</label><span>{tools_str}</span></div>
                    <div class="field"><label>Passed:</label><span class="text-pass">{passed_str}</span></div>
                    <div class="field"><label>Failed:</label><span class="text-fail">{failed_str}</span></div>
                </div>
            </div>
            """

        findings_html = ""
        for f in result.findings:
            sev = f.severity.value if hasattr(f.severity, "value") else str(f.severity)
            findings_html += f"""
            <div class="finding sev-{sev}">
                <span class="sev-badge">{sev.upper()}</span>
                <strong>{_html_escape(f.title)}</strong>
                <p>{_html_escape(f.description)}</p>
            </div>
            """

        score_html = ""
        if score:
            score_html = f"""
            <div class="score-summary">
                <div class="score-item">
                    <span class="score-label">Score</span>
                    <span class="score-value {'score-pass' if score.overall_pass else 'score-fail'}">{score.combined_score:.0f}/100</span>
                </div>
                <div class="score-item">
                    <span class="score-label">Pass Rate</span>
                    <span class="score-value">{score.assertion_pass_rate:.0%}</span>
                </div>
                <div class="score-item">
                    <span class="score-label">Findings</span>
                    <span class="score-value">{score.detector_findings}</span>
                </div>
                <div class="score-item">
                    <span class="score-label">Overall</span>
                    <span class="score-value {'score-pass' if score.overall_pass else 'score-fail'}">{'PASS' if score.overall_pass else 'FAIL'}</span>
                </div>
            </div>
            """

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>MASS Sandbox Report — {_html_escape(result.scenario_name)}</title>
<style>
body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; background: #0d1117; color: #c9d1d9; margin: 0; padding: 2rem; }}
h1 {{ color: #58a6ff; border-bottom: 1px solid #30363d; padding-bottom: 0.5rem; }}
h2 {{ color: #8b949e; margin-top: 2rem; }}
.meta {{ color: #8b949e; margin-bottom: 2rem; }}
.score-summary {{ display: flex; gap: 2rem; margin: 1.5rem 0; padding: 1rem; background: #161b22; border-radius: 8px; border: 1px solid #30363d; }}
.score-item {{ text-align: center; }}
.score-label {{ display: block; font-size: 0.8rem; color: #8b949e; }}
.score-value {{ display: block; font-size: 1.8rem; font-weight: bold; }}
.score-pass {{ color: #3fb950; }}
.score-fail {{ color: #f85149; }}
.step {{ margin: 1rem 0; padding: 1rem; background: #161b22; border-radius: 8px; border-left: 4px solid #30363d; }}
.step.pass {{ border-left-color: #3fb950; }}
.step.fail {{ border-left-color: #f85149; }}
.step-header {{ display: flex; align-items: center; gap: 1rem; margin-bottom: 0.5rem; }}
.turn-num {{ font-weight: bold; color: #58a6ff; }}
.badge {{ padding: 2px 8px; border-radius: 4px; font-size: 0.75rem; font-weight: bold; }}
.badge-pass {{ background: #238636; color: #fff; }}
.badge-fail {{ background: #da3633; color: #fff; }}
.latency {{ color: #8b949e; font-size: 0.8rem; }}
.field {{ margin: 0.3rem 0; }}
.field label {{ font-weight: bold; color: #8b949e; min-width: 120px; display: inline-block; }}
.field pre {{ margin: 0.2rem 0; padding: 0.5rem; background: #0d1117; border-radius: 4px; white-space: pre-wrap; word-break: break-word; font-size: 0.85rem; }}
.text-pass {{ color: #3fb950; }}
.text-fail {{ color: #f85149; }}
.finding {{ margin: 0.5rem 0; padding: 0.8rem; background: #161b22; border-radius: 6px; border-left: 4px solid #8b949e; }}
.sev-critical {{ border-left-color: #f85149; }}
.sev-high {{ border-left-color: #db6d28; }}
.sev-medium {{ border-left-color: #d29922; }}
.sev-low {{ border-left-color: #3fb950; }}
.sev-badge {{ padding: 2px 6px; border-radius: 3px; font-size: 0.7rem; font-weight: bold; background: #30363d; margin-right: 0.5rem; }}
</style>
</head>
<body>
<h1>MASS Sandbox Report</h1>
<div class="meta">
    <strong>Scenario:</strong> {_html_escape(result.scenario_name)} |
    <strong>Model:</strong> {_html_escape(result.model_used)} ({_html_escape(result.provider_used)}) |
    <strong>Status:</strong> {result.status} |
    <strong>Duration:</strong> {result.duration_seconds:.1f}s |
    <strong>Generated:</strong> {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}
</div>

{score_html}

<h2>Execution Timeline ({result.total_turns} turns)</h2>
{steps_html}

<h2>Findings ({len(result.findings)})</h2>
{findings_html if findings_html else '<p style="color:#8b949e;">No findings generated.</p>'}

<hr style="border-color:#30363d; margin-top:2rem;">
<p style="color:#484f58; font-size:0.8rem;">Generated by MASS (Model-Agnostic Security Scanner) Sandbox</p>
</body>
</html>"""

    def to_csv(self, result: Any, score: ScenarioScore | None = None) -> str:
        """Tabular CSV summary."""
        output = io.StringIO()
        writer = csv.writer(output)

        writer.writerow([
            "turn", "user_input", "response_preview", "tools_called",
            "assertions_passed", "assertions_failed", "latency_ms", "tokens",
        ])

        for step in result.steps:
            writer.writerow([
                step.turn_number,
                step.user_input[:200],
                step.model_response[:200],
                "|".join(tc.name for tc in step.tool_calls_made),
                len(step.assertions_passed),
                len(step.assertions_failed),
                f"{step.latency_ms:.0f}",
                step.tokens_used,
            ])

        return output.getvalue()

    def to_junit(self, result: Any, score: ScenarioScore | None = None) -> str:
        """JUnit XML — each assertion = test case, each scenario = test suite."""
        testsuites = ET.Element("testsuites")
        testsuite = ET.SubElement(testsuites, "testsuite", {
            "name": result.scenario_name,
            "tests": str(result.passed_assertions + result.failed_assertions),
            "failures": str(result.failed_assertions),
            "time": f"{result.duration_seconds:.3f}",
        })

        for step in result.steps:
            for assertion in step.assertions_passed:
                ET.SubElement(testsuite, "testcase", {
                    "name": f"turn{step.turn_number}:{assertion}",
                    "classname": result.scenario_name,
                    "time": f"{step.latency_ms / 1000:.3f}",
                })

            for assertion in step.assertions_failed:
                tc = ET.SubElement(testsuite, "testcase", {
                    "name": f"turn{step.turn_number}:{assertion}",
                    "classname": result.scenario_name,
                    "time": f"{step.latency_ms / 1000:.3f}",
                })
                failure = ET.SubElement(tc, "failure", {
                    "message": f"Assertion failed: {assertion}",
                    "type": "AssertionFailure",
                })
                failure.text = (
                    f"User input: {step.user_input[:200]}\n"
                    f"Model response: {step.model_response[:300]}"
                )

        return ET.tostring(testsuites, encoding="unicode", xml_declaration=True)

    # ── Compliance + Guardrails Integration ──

    def map_to_compliance(self, result: Any) -> dict[str, Any]:
        """Map sandbox findings to compliance frameworks."""
        compliance: dict[str, list[dict[str, Any]]] = {
            "owasp_llm_top10": [],
            "mitre_atlas": [],
            "nist_ai_rmf": [],
        }

        for finding in result.findings:
            owasp_ids = finding.owasp_ids if hasattr(finding, "owasp_ids") else []
            mitre_ids = finding.mitre_ids if hasattr(finding, "mitre_ids") else []
            cwe_ids = finding.cwe_ids if hasattr(finding, "cwe_ids") else []
            sev = finding.severity.value if hasattr(finding.severity, "value") else str(finding.severity)

            for oid in owasp_ids:
                compliance["owasp_llm_top10"].append({
                    "id": oid,
                    "finding": finding.title,
                    "severity": sev,
                    "status": "fail",
                })

            for mid in mitre_ids:
                compliance["mitre_atlas"].append({
                    "id": mid,
                    "finding": finding.title,
                    "severity": sev,
                    "status": "fail",
                })

            # Map CWE to NIST AI RMF categories
            if cwe_ids:
                compliance["nist_ai_rmf"].append({
                    "cwe_ids": cwe_ids,
                    "finding": finding.title,
                    "severity": sev,
                    "status": "fail",
                })

        return compliance

    def generate_guardrail_recommendations(self, result: Any) -> list[dict[str, Any]]:
        """Generate guardrail recommendations from sandbox findings."""
        recommendations = []

        # Map attack categories to guardrail types
        category_to_guardrail = {
            "prompt_injection": {
                "type": "INPUT_VALIDATION",
                "recommendation": "Implement input sanitization and prompt injection detection",
            },
            "system_prompt_leakage": {
                "type": "OUTPUT_FILTERING",
                "recommendation": "Add output filters to detect and block system prompt leakage",
            },
            "excessive_agency": {
                "type": "TOOL_AUTHORIZATION",
                "recommendation": "Implement tool call authorization and argument validation",
            },
            "data_leakage": {
                "type": "DATA_LOSS_PREVENTION",
                "recommendation": "Add DLP policies to prevent sensitive data exposure",
            },
            "unbounded_consumption": {
                "type": "RATE_LIMITING",
                "recommendation": "Implement rate limiting and resource consumption caps",
            },
            "jailbreak": {
                "type": "CONTENT_FILTERING",
                "recommendation": "Deploy content safety classifiers and jailbreak detection",
            },
        }

        for finding in result.findings:
            cat = finding.category.value if hasattr(finding.category, "value") else str(finding.category)
            guardrail_info = category_to_guardrail.get(cat, {
                "type": "GENERAL_SAFETY",
                "recommendation": "Review and strengthen security controls",
            })

            turn_num = finding.metadata.get("turn_number", "unknown") if hasattr(finding, "metadata") else "unknown"

            recommendations.append({
                "guardrail_type": guardrail_info["type"],
                "triggered_by": f"{finding.title} at turn {turn_num}",
                "finding_id": finding.id if hasattr(finding, "id") else "",
                "recommendation": guardrail_info["recommendation"],
                "compliance_refs": (
                    (finding.owasp_ids if hasattr(finding, "owasp_ids") else [])
                    + (finding.cwe_ids if hasattr(finding, "cwe_ids") else [])
                ),
            })

        return recommendations


def _html_escape(text: str) -> str:
    """Basic HTML escaping."""
    return (
        text.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )
