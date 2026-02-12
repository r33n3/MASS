"""Ollama API runner.

Runner for local Ollama models with tool-calling support.
"""

import os
import time
from typing import Any

import httpx

from mass.runners.base import BaseRunner, RunnerResult, RunnerStatus, ToolCall, register_runner


@register_runner
class OllamaRunner(BaseRunner):
    """Ollama API runner.

    Executes prompts against a local Ollama server.
    Supports tool/function calling via Ollama's native tools parameter.
    """

    name = "ollama"
    description = "Ollama local model runner"
    provider = "ollama"
    supports_async = True

    default_model = "llama3.2"

    def __init__(
        self,
        model: str | None = None,
        base_url: str | None = None,
        temperature: float = 0.7,
        **kwargs: Any,
    ):
        """Initialize Ollama runner.

        Args:
            model: Model identifier.
            base_url: Ollama server URL (defaults to http://localhost:11434).
            temperature: Sampling temperature.
            **kwargs: Additional configuration.
        """
        super().__init__(model=model, **kwargs)

        self.base_url = (
            base_url
            or os.getenv("OLLAMA_HOST")
            or "http://localhost:11434"
        )
        self.temperature = temperature

    @staticmethod
    def _parse_tool_calls(message: dict) -> list[ToolCall]:
        """Parse tool_calls from an Ollama response message."""
        raw = message.get("tool_calls", [])
        calls = []
        for i, tc in enumerate(raw):
            fn = tc.get("function", {})
            calls.append(ToolCall(
                id=tc.get("id", f"call_{i}"),
                name=fn.get("name", ""),
                arguments=fn.get("arguments", {}),
            ))
        return calls

    def run(
        self,
        prompt: str,
        system_prompt: str | None = None,
        **kwargs: Any,
    ) -> RunnerResult:
        """Run a prompt through Ollama.

        Args:
            prompt: The user prompt to send.
            system_prompt: Optional system prompt.
            **kwargs: Additional parameters (tools, messages).

        Returns:
            RunnerResult with response and metadata.
        """
        start_time = time.time()

        try:
            url = f"{self.base_url.rstrip('/')}/api/chat"

            # Support full message history override (for tool-call loops)
            messages_override = kwargs.get("messages")
            if messages_override:
                messages = list(messages_override)
            else:
                messages = []
                if system_prompt:
                    messages.append({"role": "system", "content": system_prompt})
                if prompt:
                    messages.append({"role": "user", "content": prompt})

            payload: dict[str, Any] = {
                "model": kwargs.get("model", self.model),
                "messages": messages,
                "stream": False,
                "options": {
                    "temperature": kwargs.get("temperature", self.temperature),
                },
            }

            # Tool calling support
            tools = kwargs.get("tools")
            if tools:
                payload["tools"] = tools

            with httpx.Client(timeout=self.timeout) as client:
                response = client.post(url, json=payload)
                response.raise_for_status()
                data = response.json()

            latency_ms = (time.time() - start_time) * 1000

            message = data.get("message", {})
            content = message.get("content", "")
            tool_calls = self._parse_tool_calls(message)
            tokens_used = (
                data.get("prompt_eval_count", 0) +
                data.get("eval_count", 0)
            )

            return self._create_result(
                response=content,
                status=RunnerStatus.SUCCESS,
                latency_ms=latency_ms,
                tokens_used=tokens_used,
                metadata={
                    "model": data.get("model"),
                    "done_reason": data.get("done_reason"),
                },
                tool_calls=tool_calls,
            )

        except httpx.TimeoutException:
            latency_ms = (time.time() - start_time) * 1000
            return self._create_result(
                response="",
                status=RunnerStatus.TIMEOUT,
                latency_ms=latency_ms,
                error="Request timed out",
            )
        except httpx.ConnectError as e:
            latency_ms = (time.time() - start_time) * 1000
            return self._create_result(
                response="",
                status=RunnerStatus.ERROR,
                latency_ms=latency_ms,
                error=f"Could not connect to Ollama at {self.base_url}: {e}",
            )
        except Exception as e:
            latency_ms = (time.time() - start_time) * 1000
            return self._create_result(
                response="",
                status=RunnerStatus.ERROR,
                latency_ms=latency_ms,
                error=str(e),
            )

    async def run_async(
        self,
        prompt: str,
        system_prompt: str | None = None,
        **kwargs: Any,
    ) -> RunnerResult:
        """Run a prompt asynchronously.

        Args:
            prompt: The user prompt to send.
            system_prompt: Optional system prompt.
            **kwargs: Additional parameters (tools, messages).

        Returns:
            RunnerResult with response and metadata.
        """
        start_time = time.time()

        try:
            url = f"{self.base_url.rstrip('/')}/api/chat"

            messages_override = kwargs.get("messages")
            if messages_override:
                messages = list(messages_override)
            else:
                messages = []
                if system_prompt:
                    messages.append({"role": "system", "content": system_prompt})
                if prompt:
                    messages.append({"role": "user", "content": prompt})

            payload: dict[str, Any] = {
                "model": kwargs.get("model", self.model),
                "messages": messages,
                "stream": False,
                "options": {
                    "temperature": kwargs.get("temperature", self.temperature),
                },
            }

            tools = kwargs.get("tools")
            if tools:
                payload["tools"] = tools

            async with httpx.AsyncClient(timeout=self.timeout) as client:
                response = await client.post(url, json=payload)
                response.raise_for_status()
                data = response.json()

            latency_ms = (time.time() - start_time) * 1000

            message = data.get("message", {})
            content = message.get("content", "")
            tool_calls = self._parse_tool_calls(message)
            tokens_used = (
                data.get("prompt_eval_count", 0) +
                data.get("eval_count", 0)
            )

            return self._create_result(
                response=content,
                status=RunnerStatus.SUCCESS,
                latency_ms=latency_ms,
                tokens_used=tokens_used,
                metadata={
                    "model": data.get("model"),
                    "done_reason": data.get("done_reason"),
                },
                tool_calls=tool_calls,
            )

        except httpx.TimeoutException:
            latency_ms = (time.time() - start_time) * 1000
            return self._create_result(
                response="",
                status=RunnerStatus.TIMEOUT,
                latency_ms=latency_ms,
                error="Request timed out",
            )
        except Exception as e:
            latency_ms = (time.time() - start_time) * 1000
            return self._create_result(
                response="",
                status=RunnerStatus.ERROR,
                latency_ms=latency_ms,
                error=str(e),
            )
