"""PDF format report generator.

Converts the HTML report to PDF using available PDF libraries.

Tries in order:
  1. weasyprint (best quality, requires system deps: Cairo, Pango)
  2. xhtml2pdf  (pure Python, good quality)

If neither is installed, raises ImportError with install instructions.
"""

import io
import logging
import re
from typing import Any

from mass.core.findings import Finding
from mass.compliance.assessor import AssessmentResult
from mass.reporting.formats.html import HtmlFormatter

logger = logging.getLogger(__name__)

# CSS variable definitions from the HTML template's :root block.
# xhtml2pdf does not support CSS custom properties (var()), so we
# resolve them to literal values before rendering.
_CSS_VARIABLES: dict[str, str] = {
    "--bg-void": "#0a0b09",
    "--bg-deep": "#0d100d",
    "--bg-primary": "#141816",
    "--bg-secondary": "#1a1f1c",
    "--bg-tertiary": "#242a26",
    "--bg-elevated": "#1e2420",
    "--text-primary": "#e8e4dc",
    "--text-secondary": "#a8a498",
    "--text-muted": "#6b6a60",
    "--text-aged": "#d4cfc2",
    "--toxic": "#7FFF00",
    "--toxic-mid": "#9ACD32",
    "--toxic-dark": "#6B8E23",
    "--toxic-dim": "rgba(127, 255, 0, 0.15)",
    "--toxic-glow": "rgba(127, 255, 0, 0.4)",
    "--rust": "#c45c3a",
    "--rust-bright": "#e07850",
    "--rust-dim": "rgba(196, 92, 58, 0.15)",
    "--olive": "#6b7a4f",
    "--olive-bright": "#8a9d68",
    "--olive-dim": "rgba(107, 122, 79, 0.15)",
    "--amber": "#d4a03a",
    "--amber-dim": "rgba(212, 160, 58, 0.15)",
    "--success": "#5d8a4a",
    "--warning": "#c9943a",
    "--error": "#b84a3c",
    "--critical": "#8b2020",
    "--border": "#3a3c38",
    "--border-worn": "#4a4c48",
    "--border-accent": "#5a5c58",
    "--font-display": "'Special Elite', 'Courier New', monospace",
    "--font-mono": "'IBM Plex Mono', 'Consolas', monospace",
    "--font-body": "'Instrument Sans', system-ui, sans-serif",
}

# Regex matching var(--name) with optional fallback: var(--name, fallback)
_VAR_PATTERN = re.compile(r"var\(\s*(--[\w-]+)\s*(?:,\s*([^)]+))?\s*\)")


class PdfFormatter:
    """Generates PDF reports by rendering the HTML report to PDF."""

    def __init__(
        self,
        title: str = "MASS Security Report",
        include_charts: bool = True,
    ) -> None:
        self.title = title
        self._html_formatter = HtmlFormatter(
            title=title,
            include_charts=include_charts,
        )

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
    ) -> bytes:
        """Generate PDF report from findings.

        Args:
            findings: List of security findings.
            scan_id: Scan identifier.
            compliance_result: Optional compliance assessment.
            metadata: Optional additional metadata.
            verdict: Optional verdict data.
            threat_model: Optional threat model data.
            report_type: Report type (security, compliance, executive).
            ai_summary: Optional AI-generated project overview.

        Returns:
            PDF content as bytes.
        """
        # Generate the HTML report first
        html_content = self._html_formatter.format(
            findings,
            scan_id=scan_id,
            compliance_result=compliance_result,
            metadata=metadata,
            verdict=verdict,
            threat_model=threat_model,
            report_type=report_type,
            ai_summary=ai_summary,
        )

        # Apply print-friendly CSS overrides for PDF rendering
        html_content = self._inject_pdf_styles(html_content)

        return self._render_pdf(html_content)

    @staticmethod
    def _resolve_css_variables(html: str) -> str:
        """Replace all CSS var(--name) references with literal values.

        xhtml2pdf does not support CSS custom properties, so we resolve
        them before rendering.  Performs multiple passes to handle any
        nested variable references (e.g. a variable whose value
        itself contains var()).
        """
        def _replace(m: re.Match[str]) -> str:
            name = m.group(1)
            fallback = m.group(2)
            value = _CSS_VARIABLES.get(name)
            if value is not None:
                return value
            if fallback is not None:
                return fallback.strip()
            # Unknown variable with no fallback -- return inherit
            return "inherit"

        # Multiple passes to resolve any nested references
        for _ in range(3):
            resolved = _VAR_PATTERN.sub(_replace, html)
            if resolved == html:
                break
            html = resolved

        # Strip the :root block entirely -- xhtml2pdf can't parse
        # custom property definitions (--name: value).
        html = re.sub(
            r":root\s*\{[^}]*\}",
            "/* :root variables resolved inline */",
            html,
        )

        # Simplify linear-gradient() to the first color stop (xhtml2pdf
        # doesn't support gradients).  Matches patterns like:
        #   linear-gradient(135deg, #1a1f1c 0%, #141816 100%)  →  #1a1f1c
        html = re.sub(
            r"linear-gradient\([^,]+,\s*([#\w]+(?:\([^)]*\))?)\s+\d+%[^)]*\)",
            r"\1",
            html,
        )

        return html

    def _inject_pdf_styles(self, html: str) -> str:
        """Inject PDF-specific CSS overrides and resolve CSS variables."""
        # First resolve all var() references to literal values
        html = self._resolve_css_variables(html)

        pdf_styles = """
        <style>
        /* PDF-specific overrides */
        @page {
            size: A4;
            margin: 1.5cm;
        }
        body {
            background: #ffffff !important;
            color: #111111 !important;
            font-size: 10pt;
            -webkit-print-color-adjust: exact;
            print-color-adjust: exact;
        }
        .noise-overlay, .scanlines { display: none !important; }
        .container { max-width: 100%; padding: 0; }

        /* Use dark theme for visual impact in PDF */
        .panel {
            background: #f8f9fa !important;
            border: 1px solid #dee2e6 !important;
            box-shadow: none !important;
            page-break-inside: avoid;
            margin-bottom: 12pt;
        }
        .panel::before { display: none !important; }

        header {
            background: #1a1f1c !important;
            color: #e8e4dc !important;
            page-break-after: avoid;
        }
        header h1 { color: #7FFF00 !important; }
        .header-icon {
            background: #242a26 !important;
            border-color: #7FFF00 !important;
            color: #7FFF00 !important;
        }

        .stat-card {
            background: #ffffff !important;
            border: 1px solid #dee2e6 !important;
        }

        /* Severity badge colors preserved */
        .sev-critical { background: #f8d7da !important; color: #721c24 !important; border-color: #f5c6cb !important; }
        .sev-high { background: #fce4d6 !important; color: #8b4513 !important; border-color: #f0c4a8 !important; }
        .sev-medium { background: #fff3cd !important; color: #856404 !important; border-color: #ffeeba !important; }
        .sev-low { background: #d4edda !important; color: #155724 !important; border-color: #c3e6cb !important; }
        .sev-info { background: #e2e3e5 !important; color: #383d41 !important; border-color: #d6d8db !important; }

        .risk-critical { background: #f8d7da !important; color: #721c24 !important; border-color: #f5c6cb !important; }
        .risk-high { background: #fce4d6 !important; color: #8b4513 !important; border-color: #f0c4a8 !important; }
        .risk-medium { background: #fff3cd !important; color: #856404 !important; border-color: #ffeeba !important; }
        .risk-low { background: #d4edda !important; color: #155724 !important; border-color: #c3e6cb !important; }
        .risk-safe { background: #d4edda !important; color: #155724 !important; border-color: #c3e6cb !important; }

        .finding-card {
            background: #ffffff !important;
            border: 1px solid #dee2e6 !important;
            page-break-inside: avoid;
        }
        .finding-description, .exec-summary, .evidence-item {
            background: #f8f9fa !important;
            border-color: #dee2e6 !important;
            color: #333333 !important;
        }

        table { font-size: 9pt; }
        th {
            background: #e9ecef !important;
            color: #495057 !important;
            border-color: #dee2e6 !important;
        }
        td {
            border-color: #dee2e6 !important;
            color: #212529 !important;
        }

        .panel-title { color: #333333 !important; }
        .panel-accent { color: #28a745 !important; }
        .stat-value { color: #212529 !important; }
        .stat-total .stat-value { color: #28a745 !important; }
        .stat-critical .stat-value { color: #dc3545 !important; }
        .stat-high .stat-value { color: #e07850 !important; }
        .stat-medium .stat-value { color: #ffc107 !important; }
        .stat-low .stat-value { color: #28a745 !important; }

        .theme-tag {
            background: #e9ecef !important;
            border-color: #dee2e6 !important;
            color: #495057 !important;
        }

        footer {
            border-color: #dee2e6 !important;
            page-break-before: avoid;
        }
        .footer-brand { color: #28a745 !important; }
        .footer-text { color: #6c757d !important; }

        /* Remove hover effects and interactive elements */
        tr:hover td { background: transparent !important; }
        .stat-card:hover { transform: none !important; }
        </style>
        """
        # Insert PDF styles just before </head>
        return html.replace("</head>", pdf_styles + "\n</head>")

    def _render_pdf(self, html: str) -> bytes:
        """Render HTML to PDF using the best available library."""
        # Try weasyprint first (best quality)
        try:
            return self._render_with_weasyprint(html)
        except ImportError:
            pass

        # Try xhtml2pdf (pure Python)
        try:
            return self._render_with_xhtml2pdf(html)
        except ImportError:
            pass

        raise ImportError(
            "PDF generation requires either 'weasyprint' or 'xhtml2pdf'. "
            "Install one with: pip install xhtml2pdf  (or)  pip install weasyprint"
        )

    def _render_with_weasyprint(self, html: str) -> bytes:
        """Render PDF using weasyprint."""
        import weasyprint  # type: ignore[import-untyped]

        logger.info("Rendering PDF with weasyprint")
        pdf_bytes = weasyprint.HTML(string=html).write_pdf()
        return pdf_bytes

    def _render_with_xhtml2pdf(self, html: str) -> bytes:
        """Render PDF using xhtml2pdf (pisa)."""
        from xhtml2pdf import pisa  # type: ignore[import-untyped]

        logger.info("Rendering PDF with xhtml2pdf")
        buffer = io.BytesIO()
        pisa_status = pisa.CreatePDF(html, dest=buffer)
        if pisa_status.err:
            logger.warning(
                "xhtml2pdf reported %d errors during PDF generation",
                pisa_status.err,
            )
        buffer.seek(0)
        return buffer.read()
