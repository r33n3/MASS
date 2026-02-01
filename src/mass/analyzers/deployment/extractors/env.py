"""Environment file extractor.

Extracts API keys and configuration from .env files.
"""

import re
import uuid
from typing import Any

from mass.core.types import ComponentType
from mass.analyzers.deployment.manifest import Component
from mass.analyzers.deployment.extractors.base import (
    BaseExtractor,
    ExtractionContext,
    ExtractionResult,
)


class EnvExtractor(BaseExtractor):
    """Extracts configuration from .env files.

    Identifies:
    - API key variables (for secret detection)
    - Model configuration variables
    - Service URLs and endpoints
    """

    name = "env"
    supported_extensions = ["env"]

    # Patterns for sensitive keys
    API_KEY_PATTERNS = [
        r"api[_-]?key",
        r"secret[_-]?key",
        r"access[_-]?token",
        r"auth[_-]?token",
        r"private[_-]?key",
        r"password",
        r"credential",
    ]

    # Known LLM provider keys
    LLM_KEY_PATTERNS = {
        "openai": r"OPENAI[_-]?(?:API[_-]?)?KEY",
        "anthropic": r"ANTHROPIC[_-]?(?:API[_-]?)?KEY",
        "google": r"(?:GOOGLE|GEMINI)[_-]?(?:API[_-]?)?KEY",
        "azure": r"AZURE[_-]?(?:OPENAI[_-]?)?(?:API[_-]?)?KEY",
        "huggingface": r"(?:HF|HUGGING[_-]?FACE)[_-]?(?:API[_-]?)?(?:KEY|TOKEN)",
        "cohere": r"COHERE[_-]?(?:API[_-]?)?KEY",
        "replicate": r"REPLICATE[_-]?(?:API[_-]?)?(?:KEY|TOKEN)",
    }

    def can_handle(self, context: ExtractionContext) -> bool:
        """Check if this is an env file."""
        name = context.file_name.lower()
        return (
            name == ".env"
            or name.endswith(".env")
            or name.startswith(".env.")
            or context.extension == "env"
        )

    def extract(self, context: ExtractionContext) -> ExtractionResult:
        """Extract content from .env file."""
        result = ExtractionResult()

        lines = context.content.split("\n")

        for i, line in enumerate(lines, start=1):
            line = line.strip()

            # Skip comments and empty lines
            if not line or line.startswith("#"):
                continue

            # Parse key=value
            match = re.match(r'^([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)$', line)
            if not match:
                continue

            key = match.group(1)
            value = match.group(2).strip()

            # Remove quotes from value
            if (value.startswith('"') and value.endswith('"')) or \
               (value.startswith("'") and value.endswith("'")):
                value = value[1:-1]

            # Check if this is a sensitive key
            self._check_sensitive_key(key, value, i, context, result)

            # Check for model configuration
            self._check_model_config(key, value, i, context, result)

        return result

    def _check_sensitive_key(
        self,
        key: str,
        value: str,
        line_num: int,
        context: ExtractionContext,
        result: ExtractionResult,
    ) -> None:
        """Check if this is a sensitive API key."""
        key_lower = key.lower()

        # Check against API key patterns
        is_sensitive = any(
            re.search(pattern, key_lower)
            for pattern in self.API_KEY_PATTERNS
        )

        # Check against known LLM providers
        provider = None
        for prov, pattern in self.LLM_KEY_PATTERNS.items():
            if re.match(pattern, key, re.IGNORECASE):
                is_sensitive = True
                provider = prov
                break

        if is_sensitive:
            # Add as a component for tracking (not storing the actual value)
            metadata: dict[str, Any] = {
                "env_var": key,
                "has_value": bool(value),
                "line": line_num,
            }
            if provider:
                metadata["provider"] = provider

            result.components.append(
                Component(
                    id=str(uuid.uuid4()),
                    type=ComponentType.CONFIG,
                    name=f"ENV:{key}",
                    path=context.file_path,
                    line_start=line_num,
                    metadata=metadata,
                )
            )

    def _check_model_config(
        self,
        key: str,
        value: str,
        line_num: int,
        context: ExtractionContext,
        result: ExtractionResult,
    ) -> None:
        """Check if this is a model configuration variable."""
        key_lower = key.lower()

        # Model name variables
        if any(
            pattern in key_lower
            for pattern in ["model", "llm_model", "chat_model", "embedding_model"]
        ):
            result.metadata.setdefault("model_configs", {})[key] = value

        # API endpoints
        if any(
            pattern in key_lower
            for pattern in ["api_base", "api_url", "endpoint", "base_url"]
        ):
            result.metadata.setdefault("endpoints", {})[key] = value

        # Temperature, max tokens, etc.
        if any(
            pattern in key_lower
            for pattern in ["temperature", "max_tokens", "top_p", "frequency_penalty"]
        ):
            result.metadata.setdefault("model_params", {})[key] = value
