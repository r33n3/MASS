"""Deployment extractors package.

Extracts instructions and configurations from various file types.
"""

from mass.analyzers.deployment.extractors.base import (
    BaseExtractor,
    ExtractionContext,
    ExtractionResult,
)
from mass.analyzers.deployment.extractors.python import PythonExtractor
from mass.analyzers.deployment.extractors.javascript import JavaScriptExtractor
from mass.analyzers.deployment.extractors.yaml_json import YamlJsonExtractor
from mass.analyzers.deployment.extractors.env import EnvExtractor
from mass.analyzers.deployment.extractors.markdown import MarkdownExtractor
from mass.analyzers.deployment.extractors.templates import TemplateExtractor

__all__ = [
    "BaseExtractor",
    "ExtractionContext",
    "ExtractionResult",
    "PythonExtractor",
    "JavaScriptExtractor",
    "YamlJsonExtractor",
    "EnvExtractor",
    "MarkdownExtractor",
    "TemplateExtractor",
]
