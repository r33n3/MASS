"""HTML format report generator.

Generates interactive HTML reports styled to match the MASS dashboard
(dark grunge × enterprise fusion aesthetic).
"""

from datetime import datetime
from html import escape
from typing import Any

from mass.core.findings import Finding, FindingSummary
from mass.core.types import Severity
from mass.compliance.assessor import AssessmentResult


class HtmlFormatter:
    """Generates HTML format reports matching the MASS dashboard theme."""

    SEVERITY_COLORS: dict[Severity, str] = {
        Severity.CRITICAL: "#8b2020",
        Severity.HIGH: "#b84a3c",
        Severity.MEDIUM: "#c9943a",
        Severity.LOW: "#5d8a4a",
        Severity.INFO: "#6b6a60",
    }

    SEVERITY_TEXT: dict[Severity, str] = {
        Severity.CRITICAL: "#ff6b6b",
        Severity.HIGH: "#e07850",
        Severity.MEDIUM: "#d4a03a",
        Severity.LOW: "#7FFF00",
        Severity.INFO: "#a8a498",
    }

    def __init__(
        self,
        title: str = "MASS Security Report",
        include_charts: bool = True,
    ) -> None:
        self.title = title
        self.include_charts = include_charts

    def format(
        self,
        findings: list[Finding],
        scan_id: str = "",
        compliance_result: AssessmentResult | None = None,
        metadata: dict[str, Any] | None = None,
        verdict: dict[str, Any] | None = None,
        threat_model: dict[str, Any] | None = None,
        report_type: str = "security",
        ai_summary: str | None = None,
    ) -> str:
        """Generate HTML report from findings.

        report_type controls the layout:
          - security: full detailed report with all findings and evidence
          - compliance: full report with compliance section emphasized
          - executive: concise one-page overview (no individual finding details)
        """
        summary = FindingSummary.from_findings(findings)
        generated_at = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")

        scan_html = ""
        if scan_id:
            scan_html = f'<div class="header-meta mono">{escape(scan_id)}</div>'

        type_label = {"executive": "Executive Summary", "compliance": "Compliance Report"}.get(
            report_type, "Security Report"
        )

        # Build body sections based on report_type
        if report_type == "executive":
            body = self._build_executive_body(
                findings, summary, verdict, threat_model, compliance_result,
                ai_summary=ai_summary,
            )
        else:
            body = self._build_full_body(
                findings, summary, verdict, threat_model, compliance_result,
            )

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{escape(self.title)}</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;500;600;700&family=Instrument+Sans:wght@400;500;600;700&family=Special+Elite&display=swap" rel="stylesheet">
    <style>{self._get_styles()}</style>
</head>
<body>
    <div class="noise-overlay"></div>
    <div class="scanlines"></div>

    <div class="container">
        <header>
            <div class="header-brand">
                <div class="header-icon">M</div>
                <div>
                    <h1>{escape(self.title)}</h1>
                    <div class="header-subtitle">{escape(type_label)} &mdash; Model &amp; Application Security Suite</div>
                </div>
            </div>
            <div class="header-info">
                <div class="header-meta">Generated: {generated_at}</div>
                <div class="header-meta">{escape(type_label)}</div>
                {scan_html}
            </div>
        </header>

        {body}

        <footer>
            <div class="footer-brand">MASS</div>
            <div class="footer-text">Model &amp; Application Security Suite</div>
        </footer>
    </div>

    <script>{self._get_scripts()}</script>
</body>
</html>"""
        return html

    def _build_full_body(
        self,
        findings: list[Finding],
        summary: FindingSummary,
        verdict: dict[str, Any] | None,
        threat_model: dict[str, Any] | None,
        compliance_result: AssessmentResult | None,
    ) -> str:
        """Build the full detailed report body (security / compliance types)."""
        return (
            self._generate_stat_grid(summary)
            + (self._generate_verdict_section(verdict) if verdict else '')
            + (self._generate_threat_model_section(threat_model) if threat_model else '')
            + (self._generate_compliance_section(compliance_result) if compliance_result else '')
            + '<section class="panel"><div class="panel-header">'
            + '<span class="panel-title">Findings Overview</span></div>'
            + self._generate_findings_table(findings) + '</section>'
            + '<section class="panel"><div class="panel-header">'
            + '<span class="panel-title">Finding Details</span></div>'
            + self._generate_finding_details(findings) + '</section>'
        )

    def _build_executive_body(
        self,
        findings: list[Finding],
        summary: FindingSummary,
        verdict: dict[str, Any] | None,
        threat_model: dict[str, Any] | None,
        compliance_result: AssessmentResult | None,
        ai_summary: str | None = None,
    ) -> str:
        """Build a concise one-page executive overview."""
        parts: list[str] = []

        # 0. AI-generated project overview (if available)
        if ai_summary:
            parts.append(
                '<section class="panel"><div class="panel-header">'
                '<span class="panel-title">Project Overview</span>'
                '<span class="panel-accent">AI-generated</span></div>'
                f'<div class="exec-summary">{escape(ai_summary)}</div>'
                '</section>'
            )

        # 1. Risk posture — single panel with verdict + stats side by side
        parts.append(self._generate_exec_risk_posture(summary, verdict))

        # 2. Key findings — deduplicated by title, sorted by severity, with count
        parts.append(self._generate_exec_findings_table(findings, summary.total))

        # 3. Threat landscape — compact STRIDE summary (if available)
        if threat_model:
            parts.append(self._generate_exec_threat_summary(threat_model))

        # 4. Recommendations — from verdict
        if verdict:
            recs = verdict.get("recommendations", [])
            if recs:
                parts.append(self._generate_exec_recommendations(recs))

        # 5. Compliance snapshot (if available)
        if compliance_result:
            parts.append(self._generate_compliance_section(compliance_result))

        return ''.join(parts)

    def _generate_stat_grid(self, summary: FindingSummary) -> str:
        """Stat grid panel shared by full reports."""
        return (
            '<section class="panel"><div class="panel-header">'
            '<span class="panel-title">Executive Summary</span>'
            f'<span class="panel-accent">{summary.total} findings</span></div>'
            '<div class="stat-grid">'
            f'<div class="stat-card stat-total"><div class="stat-value">{summary.total}</div><div class="stat-label">Total</div></div>'
            f'<div class="stat-card stat-critical"><div class="stat-value">{summary.critical_count}</div><div class="stat-label">Critical</div></div>'
            f'<div class="stat-card stat-high"><div class="stat-value">{summary.high_count}</div><div class="stat-label">High</div></div>'
            f'<div class="stat-card stat-medium"><div class="stat-value">{summary.medium_count}</div><div class="stat-label">Medium</div></div>'
            f'<div class="stat-card stat-low"><div class="stat-value">{summary.low_count}</div><div class="stat-label">Low</div></div>'
            f'<div class="stat-card stat-info"><div class="stat-value">{summary.info_count}</div><div class="stat-label">Info</div></div>'
            '</div></section>'
        )

    # ── Executive-specific sections ──

    def _generate_exec_risk_posture(
        self, summary: FindingSummary, verdict: dict[str, Any] | None,
    ) -> str:
        """Compact risk posture panel for executive report."""
        # Left: severity breakdown bar, Right: verdict risk level + assessment
        total = max(summary.total, 1)
        bars = []
        for sev, count, color in [
            ("Critical", summary.critical_count, "#8b2020"),
            ("High", summary.high_count, "#c45c3a"),
            ("Medium", summary.medium_count, "#c9943a"),
            ("Low", summary.low_count, "#5d8a4a"),
            ("Info", summary.info_count, "#6b7a4f"),
        ]:
            pct = round(count / total * 100)
            if pct > 0:
                bars.append(
                    f'<div style="width:{pct}%;background:{color};height:100%;'
                    f'min-width:{max(pct, 2)}%;display:inline-block;" '
                    f'title="{sev}: {count} ({pct}%)"></div>'
                )

        bar_html = (
            '<div style="display:flex;height:24px;border-radius:4px;overflow:hidden;'
            'border:1px solid var(--border);margin-bottom:0.75rem;">'
            + ''.join(bars) + '</div>'
        )

        # Legend
        legend = (
            '<div style="display:flex;flex-wrap:wrap;gap:0.75rem;font-size:0.6875rem;'
            'font-family:var(--font-mono);color:var(--text-secondary);margin-bottom:1rem;">'
        )
        for sev, count, color in [
            ("Critical", summary.critical_count, "#ff6b6b"),
            ("High", summary.high_count, "#e07850"),
            ("Medium", summary.medium_count, "#d4a03a"),
            ("Low", summary.low_count, "#7FFF00"),
            ("Info", summary.info_count, "#a8a498"),
        ]:
            legend += (
                f'<span><span style="display:inline-block;width:8px;height:8px;'
                f'background:{color};border-radius:2px;margin-right:0.25rem;"></span>'
                f'{sev}: {count}</span>'
            )
        legend += '</div>'

        # Verdict summary (right side)
        verdict_html = ""
        if verdict:
            risk_level = verdict.get("risk_level", "unknown")
            risk_cls = self._risk_class(risk_level)
            confidence = round((verdict.get("confidence", 0)) * 100)
            assessment = verdict.get("overall_assessment", "")
            exec_summary = verdict.get("executive_summary", "")
            themes = verdict.get("key_themes", [])
            themes_html = ''.join(
                f'<span class="theme-tag">{escape(str(t))}</span>' for t in themes[:6]
            )

            verdict_html = (
                '<div style="margin-top:1rem;padding-top:1rem;border-top:1px dashed var(--border-worn);">'
                '<div style="display:flex;align-items:center;gap:0.75rem;margin-bottom:0.75rem;">'
                f'<span class="risk-badge {risk_cls}">{escape(risk_level.upper())}</span>'
                f'<span style="font-family:var(--font-mono);font-size:0.75rem;color:var(--text-muted);">'
                f'Confidence: {confidence}%</span></div>'
                f'<p style="font-size:0.875rem;color:var(--text-primary);font-weight:600;'
                f'margin-bottom:0.5rem;">{escape(assessment)}</p>'
                + (f'<div class="exec-summary" style="margin-bottom:0.75rem;">{escape(exec_summary)}</div>' if exec_summary else '')
                + (f'<div>{themes_html}</div>' if themes else '')
                + '</div>'
            )

        return (
            '<section class="panel"><div class="panel-header">'
            '<span class="panel-title">Risk Posture</span>'
            f'<span class="panel-accent">{summary.total} findings</span></div>'
            + bar_html + legend + verdict_html + '</section>'
        )

    def _generate_exec_threat_summary(self, tm: dict[str, Any]) -> str:
        """Compact threat landscape panel for executive report."""
        risk_level = tm.get("overall_risk_level", "unknown")
        risk_cls = self._risk_class(risk_level)
        total_threats = len(tm.get("threats", []))

        # Top 3 threats only
        threats = tm.get("threats", [])
        top = sorted(threats, key=lambda t: -t.get("risk_score", 0))[:3]
        threat_items = ""
        for t in top:
            sev = t.get("severity", "medium")
            sev_cls = f"sev-{sev}" if sev in ("critical", "high", "medium", "low", "info") else "sev-medium"
            threat_items += (
                f'<div style="display:flex;align-items:center;gap:0.5rem;padding:0.5rem 0;'
                f'border-bottom:1px solid var(--border);">'
                f'<span class="sev-badge {sev_cls}" style="font-size:0.625rem;flex-shrink:0;">{sev.upper()}</span>'
                f'<span style="font-size:0.8125rem;color:var(--text-primary);flex:1;">{escape(t.get("title", ""))}</span>'
                f'<span style="font-family:var(--font-mono);font-size:0.6875rem;color:var(--text-muted);">'
                f'{t.get("risk_score", 0):.2f}</span></div>'
            )

        # STRIDE counts as compact row
        stride_counts = tm.get("threat_counts_by_stride", {})
        stride_html = ""
        if stride_counts:
            tags = ''.join(
                f'<span class="theme-tag">{escape(k)}: {v}</span>'
                for k, v in sorted(stride_counts.items(), key=lambda x: -x[1])[:6]
            )
            stride_html = f'<div style="margin-top:0.75rem;">{tags}</div>'

        return (
            '<section class="panel"><div class="panel-header">'
            '<span class="panel-title">Threat Landscape</span>'
            f'<span class="panel-accent">{total_threats} threats</span></div>'
            '<div style="display:flex;align-items:center;gap:0.75rem;margin-bottom:0.75rem;">'
            f'<span class="risk-badge {risk_cls}">{escape(risk_level.upper())}</span>'
            f'<span style="font-family:var(--font-mono);font-size:0.75rem;color:var(--text-muted);">'
            f'Data: {escape(tm.get("data_classification", "internal").upper())}</span></div>'
            + threat_items + stride_html + '</section>'
        )

    def _generate_exec_recommendations(self, recs: list) -> str:
        """Compact recommendations panel for executive report."""
        items = []
        for rec in recs[:5]:
            if isinstance(rec, dict):
                title = rec.get("title", "")
                priority = str(rec.get("priority", "medium"))
                desc = rec.get("description", "")
                desc_part = f' &mdash; {escape(desc)}' if desc else ''
                items.append(
                    f'<li><strong>[{escape(priority.upper())}]</strong> '
                    f'{escape(title)}{desc_part}</li>'
                )
            else:
                items.append(f'<li>{escape(str(rec))}</li>')

        return (
            '<section class="panel"><div class="panel-header">'
            '<span class="panel-title">Recommendations</span></div>'
            f'<ul class="rec-list">{"".join(items)}</ul></section>'
        )

    def _generate_exec_findings_table(self, findings: list[Finding], total: int) -> str:
        """Deduplicated findings table for executive report.

        Groups by title, keeps highest severity per group, sorted by severity,
        shows count column. Only Severity | Title | Category | Component | Count.
        """
        if not findings:
            return (
                '<section class="panel"><div class="panel-header">'
                '<span class="panel-title">Top Findings</span>'
                f'<span class="panel-accent">0 of {total}</span></div>'
                '<p style="color:var(--text-muted);font-size:0.8125rem;padding:1rem 0;">'
                'No findings detected.</p></section>'
            )

        sev_order = {
            Severity.CRITICAL: 0, Severity.HIGH: 1, Severity.MEDIUM: 2,
            Severity.LOW: 3, Severity.INFO: 4,
        }

        # Group by title — keep highest severity, first category/component seen
        groups: dict[str, dict] = {}
        for f in findings:
            key = f.title
            if key not in groups:
                groups[key] = {
                    "severity": f.severity,
                    "title": f.title,
                    "category": f.category.value,
                    "component": f.component_name,
                    "count": 1,
                }
            else:
                groups[key]["count"] += 1
                # Promote to higher severity if this instance is worse
                if sev_order.get(f.severity, 4) < sev_order.get(groups[key]["severity"], 4):
                    groups[key]["severity"] = f.severity

        # Sort by severity (worst first), then by count (highest first)
        sorted_groups = sorted(
            groups.values(),
            key=lambda g: (sev_order.get(g["severity"], 4), -g["count"]),
        )

        # Top 15 unique findings
        top = sorted_groups[:15]

        rows = []
        for g in top:
            sev = self._sev_class(g["severity"])
            count_badge = (
                f'<span style="font-family:var(--font-mono);font-size:0.75rem;'
                f'color:var(--text-muted);">{g["count"]}</span>'
                if g["count"] == 1
                else f'<span style="font-family:var(--font-mono);font-size:0.75rem;'
                f'padding:0.125rem 0.375rem;background:var(--bg-tertiary);'
                f'border:1px solid var(--border);border-radius:3px;'
                f'color:var(--text-primary);font-weight:600;">{g["count"]}</span>'
            )
            rows.append(
                f'<tr>'
                f'<td><span class="sev-badge {sev}">{g["severity"].value.upper()}</span></td>'
                f'<td>{escape(g["title"])}</td>'
                f'<td>{escape(g["category"])}</td>'
                f'<td>{escape(g["component"])}</td>'
                f'<td style="text-align:center;">{count_badge}</td>'
                f'</tr>'
            )

        unique_count = len(sorted_groups)

        return (
            '<section class="panel"><div class="panel-header">'
            '<span class="panel-title">Top Findings</span>'
            f'<span class="panel-accent">{unique_count} unique / {total} total</span></div>'
            '<div class="table-wrap">'
            '<table><thead><tr>'
            '<th style="width:90px;">Severity</th>'
            '<th>Title</th>'
            '<th style="width:130px;">Category</th>'
            '<th style="width:110px;">Component</th>'
            '<th style="width:60px;text-align:center;">Count</th>'
            '</tr></thead><tbody>'
            + ''.join(rows)
            + '</tbody></table></div></section>'
        )

    def _get_styles(self) -> str:
        return """
        :root {
            --bg-void: #0a0b09;
            --bg-deep: #0d100d;
            --bg-primary: #141816;
            --bg-secondary: #1a1f1c;
            --bg-tertiary: #242a26;
            --bg-elevated: #1e2420;
            --text-primary: #e8e4dc;
            --text-secondary: #a8a498;
            --text-muted: #6b6a60;
            --text-aged: #d4cfc2;
            --toxic: #7FFF00;
            --toxic-mid: #9ACD32;
            --toxic-dark: #6B8E23;
            --toxic-dim: rgba(127, 255, 0, 0.15);
            --toxic-glow: rgba(127, 255, 0, 0.4);
            --rust: #c45c3a;
            --rust-bright: #e07850;
            --rust-dim: rgba(196, 92, 58, 0.15);
            --olive: #6b7a4f;
            --olive-bright: #8a9d68;
            --olive-dim: rgba(107, 122, 79, 0.15);
            --amber: #d4a03a;
            --amber-dim: rgba(212, 160, 58, 0.15);
            --success: #5d8a4a;
            --warning: #c9943a;
            --error: #b84a3c;
            --critical: #8b2020;
            --border: #3a3c38;
            --border-worn: #4a4c48;
            --border-accent: #5a5c58;
            --font-display: 'Special Elite', 'Courier New', monospace;
            --font-mono: 'IBM Plex Mono', 'Consolas', monospace;
            --font-body: 'Instrument Sans', system-ui, sans-serif;
        }

        * { margin: 0; padding: 0; box-sizing: border-box; }

        body {
            font-family: var(--font-body);
            background: var(--bg-void);
            color: var(--text-primary);
            line-height: 1.6;
            min-height: 100vh;
            background-image:
                radial-gradient(ellipse at 0% 0%, rgba(127, 255, 0, 0.04) 0%, transparent 40%),
                radial-gradient(ellipse at 100% 100%, rgba(196, 92, 58, 0.03) 0%, transparent 40%);
        }

        .noise-overlay {
            position: fixed; inset: 0; pointer-events: none; z-index: 9999; opacity: 0.03;
            background-image: url("data:image/svg+xml,%3Csvg viewBox='0 0 256 256' xmlns='http://www.w3.org/2000/svg'%3E%3Cfilter id='n'%3E%3CfeTurbulence type='fractalNoise' baseFrequency='0.9' numOctaves='4' stitchTiles='stitch'/%3E%3C/filter%3E%3Crect width='100%25' height='100%25' filter='url(%23n)'/%3E%3C/svg%3E");
        }
        .scanlines {
            position: fixed; inset: 0; pointer-events: none; z-index: 9998; opacity: 0.015;
            background: repeating-linear-gradient(0deg, transparent, transparent 2px, rgba(0,0,0,0.3) 2px, rgba(0,0,0,0.3) 4px);
        }

        .container { max-width: 1100px; margin: 0 auto; padding: 24px 20px; position: relative; z-index: 1; overflow: hidden; }

        /* ── Header ── */
        header {
            background: linear-gradient(135deg, var(--bg-secondary) 0%, var(--bg-primary) 100%);
            border: 1px solid var(--border);
            border-radius: 6px;
            padding: 2rem 2.5rem;
            margin-bottom: 1.5rem;
            position: relative;
            overflow: hidden;
            box-shadow: 0 4px 24px rgba(0,0,0,0.4), inset 0 1px 0 rgba(255,255,255,0.02);
        }
        header::before {
            content: ''; position: absolute; top: 0; left: 0; right: 0; height: 4px;
            background: linear-gradient(90deg, var(--toxic) 0%, var(--toxic-mid) 40%, var(--toxic-dark) 80%, transparent 100%);
        }
        header::after {
            content: ''; position: absolute; bottom: 0; left: 0; right: 0; height: 1px;
            background: linear-gradient(90deg, transparent, var(--border-accent), transparent);
        }
        .header-brand { display: flex; align-items: center; gap: 1rem; margin-bottom: 1rem; }
        .header-icon {
            width: 48px; height: 48px; border-radius: 6px;
            background: linear-gradient(135deg, var(--toxic-dark) 0%, var(--bg-tertiary) 100%);
            border: 2px solid var(--toxic-mid);
            display: flex; align-items: center; justify-content: center;
            font-family: var(--font-display); font-size: 1.5rem; color: var(--toxic);
            text-shadow: 0 0 12px var(--toxic-glow);
            box-shadow: 0 0 16px var(--toxic-dim);
        }
        header h1 {
            font-family: var(--font-display); font-size: 1.75rem; color: var(--toxic);
            letter-spacing: 0.04em; text-shadow: 0 0 10px var(--toxic-dim), 2px 2px 0 rgba(0,0,0,0.5);
        }
        .header-subtitle {
            font-size: 0.75rem; color: var(--text-muted); text-transform: uppercase;
            letter-spacing: 0.12em; margin-top: 0.125rem;
        }
        .header-info { display: flex; flex-wrap: wrap; gap: 1rem; }
        .header-meta {
            font-family: var(--font-mono); font-size: 0.75rem; color: var(--text-secondary);
            padding: 0.25rem 0.75rem; background: var(--bg-deep); border-radius: 3px;
            border: 1px solid var(--border);
        }
        .mono { font-family: var(--font-mono); }

        /* ── Panel (= card/section) ── */
        .panel {
            background: var(--bg-secondary);
            border: 1px solid var(--border);
            border-radius: 6px;
            padding: 1.5rem;
            margin-bottom: 1.25rem;
            position: relative;
            box-shadow: 0 4px 12px rgba(0,0,0,0.3), inset 0 1px 0 rgba(255,255,255,0.02);
            overflow: hidden;
        }
        .panel::before {
            content: ''; position: absolute; top: -1px; left: 16px; width: 40px; height: 6px;
            background: linear-gradient(180deg, var(--toxic) 0%, var(--toxic-mid) 50%, transparent 100%);
            opacity: 0.5; border-radius: 0 0 4px 4px;
        }
        .panel-header {
            display: flex; justify-content: space-between; align-items: center;
            margin-bottom: 1.25rem; padding-bottom: 0.75rem;
            border-bottom: 1px dashed var(--border-worn);
        }
        .panel-title {
            font-family: var(--font-display); font-weight: 400; font-size: 0.9375rem;
            color: var(--text-aged); text-transform: uppercase; letter-spacing: 0.08em;
        }
        .panel-accent {
            font-family: var(--font-mono); font-size: 0.75rem; color: var(--toxic-mid);
        }

        /* ── Stat Grid ── */
        .stat-grid {
            display: grid; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr)); gap: 0.75rem;
        }
        .stat-card {
            background: var(--bg-primary); border: 1px solid var(--border); border-radius: 6px;
            padding: 1rem; text-align: center; position: relative; overflow: hidden;
            transition: all 0.15s ease;
        }
        .stat-card::before {
            content: ''; position: absolute; top: 0; left: 0; right: 0; height: 3px;
            background: var(--border-accent);
        }
        .stat-card:hover { border-color: var(--border-accent); transform: translateY(-2px); }
        .stat-value {
            font-family: var(--font-mono); font-size: 2rem; font-weight: 700; line-height: 1.2;
        }
        .stat-label {
            font-size: 0.75rem; color: var(--text-muted); text-transform: uppercase;
            letter-spacing: 0.06em; margin-top: 0.25rem;
        }
        .stat-total .stat-value { color: var(--toxic); }
        .stat-total::before { background: linear-gradient(90deg, var(--toxic), var(--toxic-dark)); }
        .stat-critical .stat-value { color: #ff6b6b; }
        .stat-critical::before { background: #8b2020; }
        .stat-high .stat-value { color: var(--rust-bright); }
        .stat-high::before { background: var(--rust); }
        .stat-medium .stat-value { color: var(--amber); }
        .stat-medium::before { background: var(--warning); }
        .stat-low .stat-value { color: var(--toxic); }
        .stat-low::before { background: var(--success); }
        .stat-info .stat-value { color: var(--text-secondary); }
        .stat-info::before { background: var(--olive); }

        /* ── Table ── */
        .table-wrap { overflow-x: auto; -webkit-overflow-scrolling: touch; }
        table {
            width: 100%; border-collapse: collapse; font-size: 0.8125rem;
            table-layout: fixed;
        }
        th {
            text-align: left; padding: 0.625rem 0.75rem; font-weight: 600;
            font-family: var(--font-mono); font-size: 0.6875rem;
            color: var(--text-muted); text-transform: uppercase; letter-spacing: 0.06em;
            border-bottom: 1px solid var(--border);
            background: var(--bg-deep);
        }
        td {
            padding: 0.625rem 0.75rem; border-bottom: 1px solid var(--border);
            color: var(--text-primary);
            overflow: hidden; text-overflow: ellipsis; white-space: nowrap;
        }
        td:nth-child(2) { white-space: normal; word-break: break-word; }
        tr:hover td { background: var(--bg-tertiary); }
        tr[data-finding-id] { cursor: pointer; }

        /* ── Severity Badge ── */
        .sev-badge {
            display: inline-flex; align-items: center; gap: 0.25rem;
            padding: 0.1875rem 0.5rem; border-radius: 3px;
            font-family: var(--font-mono); font-size: 0.6875rem; font-weight: 600;
            text-transform: uppercase; letter-spacing: 0.04em;
            border: 1px solid;
        }
        .sev-critical { background: rgba(139,32,32,0.3); color: #ff6b6b; border-color: #8b2020; }
        .sev-high { background: var(--rust-dim); color: var(--rust-bright); border-color: var(--rust); }
        .sev-medium { background: var(--amber-dim); color: var(--amber); border-color: var(--warning); }
        .sev-low { background: var(--toxic-dim); color: var(--toxic); border-color: var(--toxic-mid); }
        .sev-info { background: var(--olive-dim); color: var(--olive-bright); border-color: var(--olive); }

        /* ── Finding Card ── */
        .finding-card {
            background: var(--bg-primary); border: 1px solid var(--border); border-radius: 6px;
            padding: 1.25rem; margin-bottom: 1rem; position: relative;
            transition: border-color 0.15s ease;
        }
        .finding-card:hover { border-color: var(--border-accent); }
        .finding-card-border { position: absolute; top: 0; left: 0; bottom: 0; width: 3px; border-radius: 6px 0 0 6px; }
        .finding-card h3 {
            font-family: var(--font-body); font-size: 0.9375rem; font-weight: 600;
            color: var(--text-primary); margin-bottom: 0.5rem;
            display: flex; align-items: center; gap: 0.625rem; flex-wrap: wrap;
        }
        .finding-meta {
            font-family: var(--font-mono); font-size: 0.6875rem; color: var(--text-muted);
            margin-bottom: 0.75rem; display: flex; flex-wrap: wrap; gap: 0.5rem;
        }
        .finding-meta span {
            padding: 0.125rem 0.5rem; background: var(--bg-deep); border-radius: 3px;
            border: 1px solid var(--border);
        }
        .finding-description {
            font-size: 0.8125rem; color: var(--text-secondary); line-height: 1.7;
            padding: 0.75rem; background: var(--bg-deep); border-radius: 4px;
            border: 1px solid var(--border); margin-bottom: 0.75rem;
            word-break: break-word; overflow-wrap: anywhere;
        }
        .finding-evidence { margin-top: 0.75rem; }
        .finding-evidence-title {
            font-family: var(--font-mono); font-size: 0.6875rem; color: var(--text-muted);
            text-transform: uppercase; letter-spacing: 0.06em; margin-bottom: 0.5rem;
        }
        .evidence-item {
            background: var(--bg-deep); border: 1px solid var(--border); border-left: 3px solid var(--amber);
            border-radius: 0 4px 4px 0; padding: 0.625rem 0.75rem; margin-bottom: 0.5rem;
            font-family: var(--font-mono); font-size: 0.75rem; color: var(--text-secondary);
            word-break: break-word; white-space: pre-wrap; overflow-wrap: anywhere;
            max-height: 300px; overflow-y: auto;
        }
        .evidence-item strong { color: var(--amber); }
        .finding-remediation {
            margin-top: 0.75rem; padding: 0.75rem; background: rgba(93,138,74,0.08);
            border: 1px solid rgba(93,138,74,0.2); border-radius: 4px;
        }
        .finding-remediation-title {
            font-family: var(--font-mono); font-size: 0.6875rem; color: var(--success);
            text-transform: uppercase; letter-spacing: 0.06em; margin-bottom: 0.375rem;
        }
        .finding-remediation p { font-size: 0.8125rem; color: var(--text-secondary); }

        /* ── Verdict ── */
        .risk-badge {
            display: inline-flex; padding: 0.375rem 1rem; border-radius: 4px;
            font-family: var(--font-mono); font-weight: 700; font-size: 0.875rem;
            text-transform: uppercase; letter-spacing: 0.06em; border: 1px solid;
        }
        .risk-critical { background: rgba(139,32,32,0.3); color: #ff6b6b; border-color: #8b2020; }
        .risk-high { background: var(--rust-dim); color: var(--rust-bright); border-color: var(--rust); }
        .risk-medium { background: var(--amber-dim); color: var(--amber); border-color: var(--warning); }
        .risk-low { background: var(--toxic-dim); color: var(--toxic); border-color: var(--toxic-mid); }
        .risk-safe { background: rgba(93,138,74,0.15); color: #8a9d68; border-color: #5d8a4a; }

        .theme-tag {
            display: inline-block; padding: 0.125rem 0.5rem; margin: 0.125rem;
            background: var(--bg-tertiary); border: 1px solid var(--border);
            border-radius: 3px; font-family: var(--font-mono); font-size: 0.6875rem;
            color: var(--text-secondary);
        }
        .exec-summary {
            padding: 1rem; background: var(--bg-deep); border: 1px solid var(--border);
            border-radius: 4px; color: var(--text-secondary); font-size: 0.875rem; line-height: 1.7;
            word-break: break-word; overflow-wrap: anywhere;
        }
        .chain-item {
            border-left: 3px solid var(--border-accent); padding: 0.75rem 1rem;
            margin-bottom: 0.75rem; background: var(--bg-primary); border-radius: 0 4px 4px 0;
        }
        .chain-item strong { color: var(--text-primary); }
        .chain-item ol { margin: 0.5rem 0 0 1.25rem; color: var(--text-secondary); font-size: 0.8125rem; }
        .chain-item ol li { margin-bottom: 0.25rem; }

        .rec-list { list-style: none; padding: 0; }
        .rec-list li {
            padding: 0.5rem 0.75rem; margin-bottom: 0.375rem; background: var(--bg-primary);
            border: 1px solid var(--border); border-radius: 4px;
            font-size: 0.8125rem; color: var(--text-secondary);
        }
        .rec-list li strong { color: var(--text-primary); }

        /* ── STRIDE / Threat Model ── */
        .stride-bar-bg {
            background: var(--bg-deep); border-radius: 3px; height: 14px; overflow: hidden;
        }
        .stride-bar {
            height: 100%; border-radius: 3px;
            transition: width 0.3s ease;
        }

        /* ── Compliance ── */
        .compliance-score-large {
            font-family: var(--font-mono); font-size: 3rem; font-weight: 700;
            text-align: center; margin-bottom: 0.25rem;
        }
        .compliance-score-large.good { color: var(--toxic); }
        .compliance-score-large.warn { color: var(--amber); }
        .compliance-score-large.bad { color: #ff6b6b; }

        /* ── Footer ── */
        footer {
            text-align: center; padding: 2rem 0 1rem; border-top: 1px solid var(--border);
            margin-top: 1rem;
        }
        .footer-brand {
            font-family: var(--font-display); font-size: 1.25rem; color: var(--toxic-mid);
            letter-spacing: 0.08em; text-shadow: 0 0 8px var(--toxic-dim);
        }
        .footer-text { font-size: 0.6875rem; color: var(--text-muted); margin-top: 0.25rem; letter-spacing: 0.12em; text-transform: uppercase; }

        /* ── Responsive ── */
        @media (max-width: 768px) {
            .container { padding: 12px; }
            header { padding: 1.25rem; }
            .stat-grid { grid-template-columns: repeat(3, 1fr); }
            table { font-size: 0.75rem; }
            .finding-card { padding: 1rem; }
        }

        /* ── Print ── */
        @media print {
            body { background: #fff; color: #111; }
            .noise-overlay, .scanlines { display: none; }
            .panel { background: #fff; border-color: #ddd; box-shadow: none; }
            .panel::before { display: none; }
            header { background: #f8f8f8; }
            header::before { background: #333; }
            header h1 { color: #111; text-shadow: none; }
            .header-icon { background: #eee; color: #333; border-color: #999; text-shadow: none; box-shadow: none; }
            .stat-card { background: #f8f8f8; border-color: #ddd; }
            .stat-value { color: #111 !important; }
            .finding-card { background: #fff; border-color: #ddd; }
            .finding-description, .exec-summary, .evidence-item { background: #f8f8f8; border-color: #ddd; }
            td, th { border-color: #ddd; }
            tr:hover td { background: transparent; }
            footer { border-color: #ddd; }
            .footer-brand { color: #333; text-shadow: none; }
        }
        """

    def _get_scripts(self) -> str:
        return """
        document.querySelectorAll('tr[data-finding-id]').forEach(row => {
            row.addEventListener('click', () => {
                const id = row.dataset.findingId;
                const detail = document.getElementById('detail-' + id);
                if (detail) {
                    detail.scrollIntoView({ behavior: 'smooth', block: 'center' });
                    detail.style.borderColor = 'var(--toxic-mid)';
                    setTimeout(() => { detail.style.borderColor = ''; }, 2000);
                }
            });
        });
        """

    def _sev_class(self, severity: Severity) -> str:
        return f"sev-{severity.value}"

    def _risk_class(self, level: str) -> str:
        return f"risk-{level}" if level in ("critical", "high", "medium", "low", "safe") else "risk-medium"

    def _border_color(self, severity: Severity) -> str:
        return {
            Severity.CRITICAL: "#8b2020",
            Severity.HIGH: "#c45c3a",
            Severity.MEDIUM: "#c9943a",
            Severity.LOW: "#5d8a4a",
            Severity.INFO: "#6b7a4f",
        }.get(severity, "#3a3c38")

    def _generate_findings_table(self, findings: list[Finding]) -> str:
        if not findings:
            return '<p style="color:var(--text-muted);font-size:0.8125rem;padding:1rem 0;">No findings detected.</p>'

        rows = []
        for finding in sorted(
            findings, key=lambda f: (
                0 if f.severity == Severity.CRITICAL else
                1 if f.severity == Severity.HIGH else
                2 if f.severity == Severity.MEDIUM else
                3 if f.severity == Severity.LOW else 4
            )
        ):
            sev = self._sev_class(finding.severity)
            rows.append(
                f'<tr data-finding-id="{escape(finding.id)}">'
                f'<td><span class="sev-badge {sev}">{finding.severity.value.upper()}</span></td>'
                f'<td>{escape(finding.title)}</td>'
                f'<td>{escape(finding.category.value)}</td>'
                f'<td style="font-family:var(--font-mono);font-size:0.75rem;">{escape(finding.component_name)}</td>'
                f'<td style="font-family:var(--font-mono);font-size:0.75rem;">{escape(finding.file_path or "-")}</td>'
                f'</tr>'
            )

        return (
            '<div class="table-wrap">'
            '<table><thead><tr>'
            '<th style="width:90px;">Severity</th><th>Title</th><th style="width:140px;">Category</th>'
            '<th style="width:120px;">Component</th><th style="width:160px;">Location</th>'
            '</tr></thead><tbody>'
            + ''.join(rows)
            + '</tbody></table></div>'
        )

    def _generate_finding_details(self, findings: list[Finding]) -> str:
        if not findings:
            return ""

        cards = []
        for finding in findings:
            border_color = self._border_color(finding.severity)
            sev = self._sev_class(finding.severity)

            # Evidence
            evidence_html = ""
            if finding.evidence:
                items = []
                for ev in finding.evidence[:3]:
                    content = escape(ev.content[:500])
                    if len(ev.content) > 500:
                        content += "..."
                    items.append(
                        f'<div class="evidence-item"><strong>{escape(ev.type)}:</strong> {content}</div>'
                    )
                evidence_html = (
                    '<div class="finding-evidence">'
                    '<div class="finding-evidence-title">Evidence</div>'
                    + ''.join(items)
                    + '</div>'
                )

            # Remediation
            remediation_html = ""
            if finding.remediation:
                remediation_html = (
                    '<div class="finding-remediation">'
                    '<div class="finding-remediation-title">Remediation</div>'
                    f'<p>{escape(finding.remediation.summary)}</p>'
                    '</div>'
                )

            # Meta tags
            meta_parts = [f'<span>{escape(finding.category.value)}</span>']
            meta_parts.append(f'<span>{escape(finding.component_name)}</span>')
            if finding.file_path:
                loc = escape(finding.file_path)
                if finding.line_number:
                    loc += f":{finding.line_number}"
                meta_parts.append(f'<span>{loc}</span>')

            cards.append(
                f'<div class="finding-card" id="detail-{escape(finding.id)}">'
                f'<div class="finding-card-border" style="background:{border_color};"></div>'
                f'<h3><span class="sev-badge {sev}">{finding.severity.value.upper()}</span> {escape(finding.title)}</h3>'
                f'<div class="finding-meta">{"".join(meta_parts)}</div>'
                f'<div class="finding-description">{escape(finding.description)}</div>'
                f'{evidence_html}'
                f'{remediation_html}'
                f'</div>'
            )

        return ''.join(cards)

    def _generate_verdict_section(self, verdict: dict[str, Any]) -> str:
        risk_level = verdict.get("risk_level", "unknown")
        risk_cls = self._risk_class(risk_level)
        confidence = round((verdict.get("confidence", 0)) * 100)

        themes = verdict.get("key_themes", [])
        themes_html = ''.join(
            f'<span class="theme-tag">{escape(str(t))}</span>' for t in themes
        )

        # Attack chains
        attack_chains = verdict.get("attack_chains", [])
        chains_html = ""
        if attack_chains:
            items = []
            for chain in attack_chains:
                name = chain.get("name", "Attack Chain")
                severity = chain.get("severity", "medium")
                steps = chain.get("steps", [])
                steps_html = ""
                if steps:
                    step_items = ''.join(f'<li>{escape(str(s))}</li>' for s in steps)
                    steps_html = f'<ol>{step_items}</ol>'
                sev_cls = f"sev-{severity}" if severity in ("critical", "high", "medium", "low", "info") else "sev-medium"
                border = self._border_color(
                    {"critical": Severity.CRITICAL, "high": Severity.HIGH, "medium": Severity.MEDIUM,
                     "low": Severity.LOW}.get(severity, Severity.MEDIUM)
                )
                items.append(
                    f'<div class="chain-item" style="border-left-color:{border};">'
                    f'<strong>{escape(name)}</strong> '
                    f'<span class="sev-badge {sev_cls}" style="font-size:0.625rem;">{severity.upper()}</span>'
                    f'{steps_html}</div>'
                )
            chains_html = (
                '<div style="margin-top:1.25rem;">'
                '<div class="panel-title" style="margin-bottom:0.75rem;">Attack Chains</div>'
                + ''.join(items) + '</div>'
            )

        # Recommendations
        recs = verdict.get("recommendations", [])
        recs_html = ""
        if recs:
            rec_items = []
            for rec in recs:
                if isinstance(rec, dict):
                    title = rec.get("title", "")
                    priority = str(rec.get("priority", "medium"))
                    desc = rec.get("description", "")
                    desc_part = f' &mdash; {escape(desc)}' if desc else ''
                    rec_items.append(f'<li><strong>[{escape(priority.upper())}]</strong> {escape(title)}{desc_part}</li>')
                else:
                    rec_items.append(f'<li>{escape(str(rec))}</li>')
            recs_html = (
                '<div style="margin-top:1.25rem;">'
                '<div class="panel-title" style="margin-bottom:0.75rem;">Recommendations</div>'
                f'<ul class="rec-list">{"".join(rec_items)}</ul></div>'
            )

        return (
            '<section class="panel">'
            '<div class="panel-header"><span class="panel-title">Security Verdict</span></div>'
            f'<div style="display:flex;align-items:center;gap:1rem;margin-bottom:1rem;">'
            f'<span class="risk-badge {risk_cls}">{escape(risk_level.upper())}</span>'
            f'<span style="font-family:var(--font-mono);font-size:0.75rem;color:var(--text-muted);">Confidence: {confidence}%</span>'
            f'</div>'
            f'<p style="font-size:0.9375rem;color:var(--text-primary);margin-bottom:0.75rem;font-weight:600;">'
            f'{escape(verdict.get("overall_assessment", ""))}</p>'
            f'<div class="exec-summary">{escape(verdict.get("executive_summary", ""))}</div>'
            + (f'<div style="margin-top:0.75rem;">{themes_html}</div>' if themes else '')
            + chains_html
            + recs_html
            + '</section>'
        )

    def _generate_threat_model_section(self, tm: dict[str, Any]) -> str:
        risk_level = tm.get("overall_risk_level", "unknown")
        risk_cls = self._risk_class(risk_level)
        data_class = tm.get("data_classification", "internal")

        # Severity counts
        severity_counts = tm.get("threat_counts_by_severity", {})
        sev_tags = ''.join(
            f'<span class="sev-badge sev-{sev}">{sev.upper()}: {cnt}</span> '
            for sev, cnt in severity_counts.items() if cnt > 0
        )

        # STRIDE breakdown
        stride_counts = tm.get("threat_counts_by_stride", {})
        stride_rows = ""
        if stride_counts:
            max_count = max(stride_counts.values()) if stride_counts.values() else 1
            bar_colors = {
                "critical": "#8b2020", "high": "#c45c3a", "medium": "#c9943a",
                "low": "#5d8a4a", "safe": "#6b7a4f",
            }
            bar_color = bar_colors.get(risk_level, "#6b7a4f")
            for pillar, count in sorted(stride_counts.items(), key=lambda x: -x[1]):
                bar_w = max(int((count / max_count) * 100), 5) if max_count > 0 else 5
                stride_rows += (
                    f'<tr><td style="font-weight:600;">{escape(pillar)}</td>'
                    f'<td style="font-family:var(--font-mono);text-align:center;">{count}</td>'
                    f'<td><div class="stride-bar-bg">'
                    f'<div class="stride-bar" style="width:{bar_w}%;background:{bar_color};"></div>'
                    f'</div></td></tr>'
                )

        stride_html = ""
        if stride_rows:
            stride_html = (
                '<div style="margin-top:1.25rem;">'
                '<div class="panel-title" style="margin-bottom:0.75rem;">STRIDE Breakdown</div>'
                '<table><thead><tr><th>Category</th><th style="text-align:center;">Count</th><th>Distribution</th></tr></thead>'
                f'<tbody>{stride_rows}</tbody></table></div>'
            )

        # Top threats
        threats = tm.get("threats", [])
        top_html = ""
        if threats:
            top = sorted(threats, key=lambda t: -t.get("risk_score", 0))[:5]
            t_rows = ""
            for t in top:
                sev = t.get("severity", "medium")
                sev_cls = f"sev-{sev}" if sev in ("critical", "high", "medium", "low", "info") else "sev-medium"
                t_rows += (
                    f'<tr><td><span class="sev-badge {sev_cls}" style="font-size:0.625rem;">{sev.upper()}</span></td>'
                    f'<td>{escape(t.get("title", ""))}</td>'
                    f'<td>{escape(t.get("stride_category", ""))}</td>'
                    f'<td style="font-family:var(--font-mono);">{t.get("risk_score", 0):.2f}</td></tr>'
                )
            top_html = (
                '<div style="margin-top:1.25rem;">'
                '<div class="panel-title" style="margin-bottom:0.75rem;">Top Threats</div>'
                '<table><thead><tr><th>Severity</th><th>Threat</th><th>STRIDE</th><th>Risk</th></tr></thead>'
                f'<tbody>{t_rows}</tbody></table></div>'
            )

        # Mitigations
        mitigations = tm.get("recommended_mitigations", [])
        miti_html = ""
        if mitigations:
            items = []
            for m in mitigations[:10]:
                if isinstance(m, dict):
                    desc = m.get("description", "")
                    desc_part = f' &mdash; {escape(desc)}' if desc else ''
                    items.append(f'<li><strong>{escape(m.get("title", ""))}</strong>{desc_part}</li>')
                else:
                    items.append(f'<li>{escape(str(m))}</li>')
            miti_html = (
                '<div style="margin-top:1.25rem;">'
                '<div class="panel-title" style="margin-bottom:0.75rem;">Recommended Mitigations</div>'
                f'<ul class="rec-list">{"".join(items)}</ul></div>'
            )

        total_threats = len(threats)
        phases = ", ".join(tm.get("phases_completed", []))

        return (
            '<section class="panel">'
            '<div class="panel-header"><span class="panel-title">STRIDE-AI Threat Model</span></div>'
            '<div style="display:flex;align-items:center;gap:0.75rem;flex-wrap:wrap;margin-bottom:1rem;">'
            f'<span class="risk-badge {risk_cls}">{escape(risk_level.upper())}</span>'
            f'<span class="theme-tag">Data: {escape(data_class.upper())}</span>'
            f'<span style="font-family:var(--font-mono);font-size:0.75rem;color:var(--text-muted);">{total_threats} threats identified</span>'
            '</div>'
            + (f'<p style="font-family:var(--font-mono);font-size:0.75rem;color:var(--text-muted);margin-bottom:0.75rem;">Phases: {escape(phases)}</p>' if phases else '')
            + (f'<div style="margin-bottom:0.75rem;">{sev_tags}</div>' if sev_tags else '')
            + stride_html + top_html + miti_html
            + '</section>'
        )

    def _generate_compliance_section(self, result: AssessmentResult) -> str:
        score = result.overall_compliance_score
        score_cls = "bad" if score < 50 else "warn" if score < 80 else "good"

        framework_rows = []
        for fw, assessment in result.frameworks.items():
            framework_rows.append(
                f'<tr><td style="font-weight:600;">{escape(fw.value.upper())}</td>'
                f'<td style="font-family:var(--font-mono);">{assessment.compliance_score:.1f}%</td>'
                f'<td style="font-family:var(--font-mono);text-align:center;">{assessment.compliant_count}</td>'
                f'<td style="font-family:var(--font-mono);text-align:center;">{assessment.non_compliant_count}</td>'
                f'<td style="font-family:var(--font-mono);text-align:center;">{assessment.partial_count}</td>'
                f'</tr>'
            )

        return (
            '<section class="panel">'
            '<div class="panel-header"><span class="panel-title">Compliance Assessment</span></div>'
            f'<div style="text-align:center;margin-bottom:1.5rem;">'
            f'<div class="compliance-score-large {score_cls}">{score:.1f}%</div>'
            f'<div style="font-size:0.75rem;color:var(--text-muted);text-transform:uppercase;letter-spacing:0.08em;">Overall Compliance Score</div>'
            f'</div>'
            '<table><thead><tr>'
            '<th>Framework</th><th>Score</th><th style="text-align:center;">Compliant</th>'
            '<th style="text-align:center;">Non-Compliant</th><th style="text-align:center;">Partial</th>'
            '</tr></thead><tbody>'
            + ''.join(framework_rows)
            + '</tbody></table></section>'
        )
