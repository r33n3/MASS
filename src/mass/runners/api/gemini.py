"""Google Gemini API runner.

Runner for Google's Gemini API via the google-genai SDK.
"""

import os
import time
from typing import Any

from mass.runners.base import BaseRunner, RunnerResult, RunnerStatus, register_runner


@register_runner
class GeminiRunner(BaseRunner):
    """Google Gemini API runner.

    Executes prompts against Google's Gemini models
    using the google-genai SDK.
    """

    name = "gemini"
    description = "Google Gemini API runner"
    provider = "google"
    supports_async = True

    default_model = "gemini-2.0-flash"

    # Model aliases for convenience
    MODEL_ALIASES = {
        "gemini-flash": "gemini-2.0-flash",
        "gemini-pro": "gemini-1.5-pro",
        "gemini-2-flash": "gemini-2.0-flash",
        "gemini-2-pro": "gemini-2.0-pro",
        "gemini-1.5-flash": "gemini-1.5-flash",
    }

    def __init__(
        self,
        model: str | None = None,
        api_key: str | None = None,
        temperature: float = 0.7,
        max_tokens: int = 1024,
        **kwargs: Any,
    ):
        """Initialize Gemini runner.

        Args:
            model: Model identifier or alias.
            api_key: Google AI API key (defaults to GOOGLE_API_KEY env var).
            temperature: Sampling temperature.
            max_tokens: Maximum tokens in response.
            **kwargs: Additional configuration.
        """
        resolved_model = self.MODEL_ALIASES.get(model or "", model)
        super().__init__(model=resolved_model, **kwargs)

        self.api_key = api_key or os.getenv("GOOGLE_API_KEY") or os.getenv("GEMINI_API_KEY")
        self.temperature = temperature
        self.max_tokens = max_tokens

        self._client = None

    def _get_client(self) -> Any:
        """Get or create Gemini client."""
        if self._client is None:
            try:
                from google import genai
            except ImportError:
                raise ImportError(
                    "google-genai package not installed. "
                    "Install with: pip install google-genai"
                )

            if not self.api_key:
                raise ValueError(
                    "Google API key required. Set GOOGLE_API_KEY or "
                    "GEMINI_API_KEY env var, or pass api_key parameter."
                )

            self._client = genai.Client(api_key=self.api_key)

        return self._client

    def run(
        self,
        prompt: str,
        system_prompt: str | None = None,
        **kwargs: Any,
    ) -> RunnerResult:
        """Run a prompt through Google Gemini API.

        Args:
            prompt: The user prompt to send.
            system_prompt: Optional system prompt.
            **kwargs: Additional parameters.

        Returns:
            RunnerResult with response and metadata.
        """
        start_time = time.time()

        try:
            from google.genai import types

            client = self._get_client()
            model = kwargs.get("model", self.model)

            config = types.GenerateContentConfig(
                temperature=kwargs.get("temperature", self.temperature),
                max_output_tokens=kwargs.get("max_tokens", self.max_tokens),
            )

            if system_prompt:
                config.system_instruction = system_prompt

            response = client.models.generate_content(
                model=model,
                contents=prompt,
                config=config,
            )

            latency_ms = (time.time() - start_time) * 1000

            content = response.text or ""
            tokens_used = 0
            if response.usage_metadata:
                tokens_used = (
                    (response.usage_metadata.prompt_token_count or 0)
                    + (response.usage_metadata.candidates_token_count or 0)
                )

            return self._create_result(
                response=content,
                status=RunnerStatus.SUCCESS,
                latency_ms=latency_ms,
                tokens_used=tokens_used,
                metadata={
                    "model": model,
                    "finish_reason": (
                        response.candidates[0].finish_reason
                        if response.candidates else None
                    ),
                },
            )

        except Exception as e:
            latency_ms = (time.time() - start_time) * 1000
            error_str = str(e)

            if "429" in error_str or "quota" in error_str.lower():
                status = RunnerStatus.RATE_LIMITED
            elif "timeout" in error_str.lower():
                status = RunnerStatus.TIMEOUT
            else:
                status = RunnerStatus.ERROR

            return self._create_result(
                response="",
                status=status,
                latency_ms=latency_ms,
                error=error_str,
            )

    async def run_async(
        self,
        prompt: str,
        system_prompt: str | None = None,
        **kwargs: Any,
    ) -> RunnerResult:
        """Run a prompt asynchronously through Gemini.

        Args:
            prompt: The user prompt to send.
            system_prompt: Optional system prompt.
            **kwargs: Additional parameters.

        Returns:
            RunnerResult with response and metadata.
        """
        start_time = time.time()

        try:
            from google.genai import types

            client = self._get_client()
            model = kwargs.get("model", self.model)

            config = types.GenerateContentConfig(
                temperature=kwargs.get("temperature", self.temperature),
                max_output_tokens=kwargs.get("max_tokens", self.max_tokens),
            )

            if system_prompt:
                config.system_instruction = system_prompt

            response = await client.aio.models.generate_content(
                model=model,
                contents=prompt,
                config=config,
            )

            latency_ms = (time.time() - start_time) * 1000

            content = response.text or ""
            tokens_used = 0
            if response.usage_metadata:
                tokens_used = (
                    (response.usage_metadata.prompt_token_count or 0)
                    + (response.usage_metadata.candidates_token_count or 0)
                )

            return self._create_result(
                response=content,
                status=RunnerStatus.SUCCESS,
                latency_ms=latency_ms,
                tokens_used=tokens_used,
                metadata={
                    "model": model,
                    "finish_reason": (
                        response.candidates[0].finish_reason
                        if response.candidates else None
                    ),
                },
            )

        except ImportError:
            return self.run(prompt, system_prompt, **kwargs)
        except Exception as e:
            latency_ms = (time.time() - start_time) * 1000
            return self._create_result(
                response="",
                status=RunnerStatus.ERROR,
                latency_ms=latency_ms,
                error=str(e),
            )
