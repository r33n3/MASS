"""Base runner protocol and registry.

Defines the interface for model runners and provides registration/discovery.
"""

import logging
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

logger = logging.getLogger(__name__)


class RunnerStatus(str, Enum):
    """Status of a runner execution."""
    SUCCESS = "success"
    ERROR = "error"
    TIMEOUT = "timeout"
    RATE_LIMITED = "rate_limited"


@dataclass
class ToolCall:
    """A tool/function call requested by the model."""
    id: str                           # Provider's call ID
    name: str                         # Tool/function name
    arguments: dict[str, Any]         # Parsed arguments


@dataclass
class RunnerResult:
    """Result of running a prompt through a model."""
    response: str
    status: RunnerStatus
    latency_ms: float
    model: str
    provider: str
    tokens_used: int = 0
    metadata: dict[str, Any] = field(default_factory=dict)
    error: str | None = None
    tool_calls: list[ToolCall] = field(default_factory=list)

    @property
    def is_success(self) -> bool:
        """Check if execution was successful."""
        return self.status == RunnerStatus.SUCCESS


class BaseRunner(ABC):
    """Base class for all model runners.

    Runners execute prompts against LLM providers and return responses.
    """

    # Class attributes - must be defined by subclasses
    name: str = ""
    description: str = ""
    provider: str = ""
    supports_async: bool = True

    # Default configuration
    default_model: str = ""
    timeout: float = 60.0
    max_retries: int = 3

    def __init__(
        self,
        model: str | None = None,
        timeout: float | None = None,
        max_retries: int | None = None,
        **kwargs: Any,
    ):
        """Initialize runner.

        Args:
            model: Model identifier.
            timeout: Request timeout in seconds.
            max_retries: Maximum retry attempts.
            **kwargs: Provider-specific configuration.
        """
        self.model = model or self.default_model
        self.timeout = timeout or self.timeout
        self.max_retries = max_retries or self.max_retries
        self.config = kwargs

    @abstractmethod
    def run(
        self,
        prompt: str,
        system_prompt: str | None = None,
        **kwargs: Any,
    ) -> RunnerResult:
        """Run a prompt through the model.

        Args:
            prompt: The user prompt to send.
            system_prompt: Optional system prompt.
            **kwargs: Additional parameters.

        Returns:
            RunnerResult with response and metadata.
        """
        ...

    async def run_async(
        self,
        prompt: str,
        system_prompt: str | None = None,
        **kwargs: Any,
    ) -> RunnerResult:
        """Run a prompt asynchronously.

        Default implementation wraps synchronous run.
        Override for true async execution.

        Args:
            prompt: The user prompt to send.
            system_prompt: Optional system prompt.
            **kwargs: Additional parameters.

        Returns:
            RunnerResult with response and metadata.
        """
        return self.run(prompt, system_prompt, **kwargs)

    def run_with_retry(
        self,
        prompt: str,
        system_prompt: str | None = None,
        **kwargs: Any,
    ) -> RunnerResult:
        """Run with automatic retry on failure.

        Args:
            prompt: The user prompt to send.
            system_prompt: Optional system prompt.
            **kwargs: Additional parameters.

        Returns:
            RunnerResult with response and metadata.
        """
        last_error = None

        for attempt in range(self.max_retries):
            try:
                result = self.run(prompt, system_prompt, **kwargs)
                if result.is_success:
                    return result
                last_error = result.error
            except Exception as e:
                last_error = str(e)
                logger.warning(
                    f"Runner attempt {attempt + 1}/{self.max_retries} failed: {e}"
                )

            # Exponential backoff
            if attempt < self.max_retries - 1:
                time.sleep(2 ** attempt)

        return RunnerResult(
            response="",
            status=RunnerStatus.ERROR,
            latency_ms=0,
            model=self.model,
            provider=self.provider,
            error=f"All {self.max_retries} attempts failed. Last error: {last_error}",
        )

    def _create_result(
        self,
        response: str,
        status: RunnerStatus,
        latency_ms: float,
        tokens_used: int = 0,
        metadata: dict[str, Any] | None = None,
        error: str | None = None,
        tool_calls: list[ToolCall] | None = None,
    ) -> RunnerResult:
        """Helper to create a RunnerResult.

        Args:
            response: Model response text.
            status: Execution status.
            latency_ms: Latency in milliseconds.
            tokens_used: Tokens consumed.
            metadata: Additional metadata.
            error: Error message if any.
            tool_calls: Tool/function calls from the model.

        Returns:
            RunnerResult instance.
        """
        return RunnerResult(
            response=response,
            status=status,
            latency_ms=latency_ms,
            model=self.model,
            provider=self.provider,
            tokens_used=tokens_used,
            metadata=metadata or {},
            error=error,
            tool_calls=tool_calls or [],
        )


class RunnerRegistry:
    """Registry for runner discovery and management."""

    def __init__(self):
        """Initialize runner registry."""
        self._runners: dict[str, type[BaseRunner]] = {}
        self._instances: dict[str, BaseRunner] = {}

    def register(self, runner_class: type[BaseRunner]) -> type[BaseRunner]:
        """Register a runner class.

        Args:
            runner_class: Runner class to register.

        Returns:
            The registered class (for use as decorator).
        """
        name = runner_class.name or runner_class.__name__
        self._runners[name] = runner_class
        logger.debug(f"Registered runner: {name}")
        return runner_class

    def get(self, name: str, **kwargs: Any) -> BaseRunner | None:
        """Get a runner instance by name.

        Args:
            name: Runner name.
            **kwargs: Runner configuration.

        Returns:
            Runner instance or None if not found.
        """
        cache_key = f"{name}:{hash(frozenset(kwargs.items()))}" if kwargs else name

        if cache_key in self._instances:
            return self._instances[cache_key]

        runner_class = self._runners.get(name)
        if runner_class:
            instance = runner_class(**kwargs)
            self._instances[cache_key] = instance
            return instance

        return None

    def get_class(self, name: str) -> type[BaseRunner] | None:
        """Get a runner class by name.

        Args:
            name: Runner name.

        Returns:
            Runner class or None if not found.
        """
        return self._runners.get(name)

    def list_runners(self) -> list[str]:
        """List all registered runner names.

        Returns:
            List of runner names.
        """
        return list(self._runners.keys())

    def list_by_provider(self, provider: str) -> list[str]:
        """List runners by provider.

        Args:
            provider: Provider name.

        Returns:
            List of runner names for that provider.
        """
        return [
            name for name, cls in self._runners.items()
            if cls.provider == provider
        ]

    @property
    def count(self) -> int:
        """Get number of registered runners."""
        return len(self._runners)


# Global runner registry
runner_registry = RunnerRegistry()


def register_runner(cls: type[BaseRunner]) -> type[BaseRunner]:
    """Decorator to register a runner class.

    Usage:
        @register_runner
        class MyRunner(BaseRunner):
            name = "my_runner"
            ...
    """
    return runner_registry.register(cls)


def get_runner(name: str, **kwargs: Any) -> BaseRunner | None:
    """Get a runner instance by name from the global registry."""
    return runner_registry.get(name, **kwargs)


def list_runners() -> list[str]:
    """List all registered runners from the global registry."""
    return runner_registry.list_runners()
