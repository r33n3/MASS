"""Report generation module.

Generates security reports in multiple formats including
SARIF, HTML, JSON, and PDF.
"""

from mass.reporting.generator import ReportGenerator, ReportConfig
from mass.reporting.formats.sarif import SarifFormatter
from mass.reporting.formats.html import HtmlFormatter
from mass.reporting.formats.json import JsonFormatter

__all__ = [
    "ReportGenerator",
    "ReportConfig",
    "SarifFormatter",
    "HtmlFormatter",
    "JsonFormatter",
]
