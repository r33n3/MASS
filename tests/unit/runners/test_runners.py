"""Tests for runner module."""

import pytest
from unittest.mock import Mock, patch, MagicMock
from mass.runners.base import (
    BaseRunner,
    RunnerResult,
    RunnerStatus,
    runner_registry,
    register_runner,
)
from mass.runners.api.openai import OpenAIRunner
from mass.runners.api.anthropic import AnthropicRunner
from mass.runners.api.ollama import OllamaRunner


class TestRunnerResult:
    """Tests for RunnerResult dataclass."""

    def test_result_creation(self):
        """Test creating a runner result."""
        result = RunnerResult(
            response="Hello!",
            status=RunnerStatus.SUCCESS,
            latency_ms=100.0,
            model="gpt-4",
            provider="openai",
            tokens_used=10,
        )
        assert result.response == "Hello!"
        assert result.model == "gpt-4"
        assert result.tokens_used == 10
        assert result.latency_ms == 100.0
        assert result.error is None
        assert result.is_success is True

    def test_result_with_error(self):
        """Test creating result with error."""
        result = RunnerResult(
            response="",
            status=RunnerStatus.ERROR,
            latency_ms=50.0,
            model="gpt-4",
            provider="openai",
            error="Connection failed",
        )
        assert result.response == ""
        assert result.error == "Connection failed"
        assert result.is_success is False

    def test_result_is_success(self):
        """Test is_success property."""
        success = RunnerResult(
            response="Hello!",
            status=RunnerStatus.SUCCESS,
            latency_ms=100.0,
            model="test",
            provider="test",
        )
        failure = RunnerResult(
            response="",
            status=RunnerStatus.ERROR,
            latency_ms=100.0,
            model="test",
            provider="test",
            error="Error",
        )

        assert success.is_success is True
        assert failure.is_success is False

    def test_result_status_types(self):
        """Test different status types."""
        assert RunnerStatus.SUCCESS == "success"
        assert RunnerStatus.ERROR == "error"
        assert RunnerStatus.TIMEOUT == "timeout"
        assert RunnerStatus.RATE_LIMITED == "rate_limited"


class TestRunnerRegistry:
    """Tests for runner registry."""

    def test_registry_has_runners(self):
        """Test that runners are registered."""
        assert runner_registry.count > 0

    def test_registry_list_runners(self):
        """Test listing registered runners."""
        runners = runner_registry.list_runners()
        assert isinstance(runners, list)
        assert "openai" in runners
        assert "anthropic" in runners
        assert "ollama" in runners

    def test_registry_get_class(self):
        """Test getting runner class by name."""
        openai_cls = runner_registry.get_class("openai")
        assert openai_cls is not None
        assert openai_cls.name == "openai"

    def test_registry_get_nonexistent(self):
        """Test getting non-existent runner."""
        result = runner_registry.get_class("nonexistent")
        assert result is None


class TestOpenAIRunner:
    """Tests for OpenAI runner."""

    def test_initialization(self):
        """Test runner initialization."""
        runner = OpenAIRunner(api_key="test-key", model="gpt-4")
        assert runner.name == "openai"
        assert runner.provider == "openai"
        assert runner.model == "gpt-4"
        assert runner.api_key == "test-key"

    def test_initialization_from_env(self):
        """Test initialization from environment."""
        with patch.dict("os.environ", {"OPENAI_API_KEY": "env-key"}):
            runner = OpenAIRunner()
            assert runner.api_key == "env-key"

    def test_default_model(self):
        """Test default model setting."""
        runner = OpenAIRunner(api_key="test-key")
        assert runner.model == "gpt-4o-mini"

    def test_run_success(self):
        """Test successful run."""
        runner = OpenAIRunner(api_key="test-key")

        # Mock the _get_client method
        mock_client = MagicMock()
        mock_response = MagicMock()
        mock_response.choices = [MagicMock(message=MagicMock(content="Hello!"), finish_reason="stop")]
        mock_response.model = "gpt-4"
        mock_response.usage = MagicMock(total_tokens=20)
        mock_client.chat.completions.create.return_value = mock_response

        with patch.object(runner, "_get_client", return_value=mock_client):
            result = runner.run("Hello")

        assert result.is_success
        assert result.response == "Hello!"
        mock_client.chat.completions.create.assert_called_once()

    def test_run_with_system_prompt(self):
        """Test run with system prompt."""
        runner = OpenAIRunner(api_key="test-key")

        mock_client = MagicMock()
        mock_response = MagicMock()
        mock_response.choices = [MagicMock(message=MagicMock(content="Response"), finish_reason="stop")]
        mock_response.model = "gpt-4"
        mock_response.usage = MagicMock(total_tokens=30)
        mock_client.chat.completions.create.return_value = mock_response

        with patch.object(runner, "_get_client", return_value=mock_client):
            result = runner.run("Hello", system_prompt="You are helpful")

        call_args = mock_client.chat.completions.create.call_args
        messages = call_args.kwargs.get("messages", [])
        assert any(m["role"] == "system" for m in messages)

    def test_run_error(self):
        """Test run with error."""
        runner = OpenAIRunner(api_key="test-key")

        mock_client = MagicMock()
        mock_client.chat.completions.create.side_effect = Exception("API Error")

        with patch.object(runner, "_get_client", return_value=mock_client):
            result = runner.run("Hello")

        assert not result.is_success
        assert "API Error" in result.error


class TestAnthropicRunner:
    """Tests for Anthropic runner."""

    def test_initialization(self):
        """Test runner initialization."""
        runner = AnthropicRunner(api_key="test-key", model="claude-3-opus-20240229")
        assert runner.name == "anthropic"
        assert runner.provider == "anthropic"
        assert runner.model == "claude-3-opus-20240229"

    def test_initialization_from_env(self):
        """Test initialization from environment."""
        with patch.dict("os.environ", {"ANTHROPIC_API_KEY": "env-key"}):
            runner = AnthropicRunner()
            assert runner.api_key == "env-key"

    def test_default_model(self):
        """Test default model setting."""
        runner = AnthropicRunner(api_key="test-key")
        assert "claude" in runner.model.lower()

    def test_run_success(self):
        """Test successful run."""
        runner = AnthropicRunner(api_key="test-key")

        mock_client = MagicMock()
        mock_response = MagicMock()
        mock_response.content = [MagicMock(text="Hello from Claude!")]
        mock_response.model = "claude-3-opus-20240229"
        mock_response.usage = MagicMock(input_tokens=10, output_tokens=15)
        mock_response.stop_reason = "end_turn"
        mock_client.messages.create.return_value = mock_response

        with patch.object(runner, "_get_client", return_value=mock_client):
            result = runner.run("Hello")

        assert result.is_success
        assert result.response == "Hello from Claude!"
        mock_client.messages.create.assert_called_once()

    def test_run_error(self):
        """Test run with error."""
        runner = AnthropicRunner(api_key="test-key")

        mock_client = MagicMock()
        mock_client.messages.create.side_effect = Exception("API Error")

        with patch.object(runner, "_get_client", return_value=mock_client):
            result = runner.run("Hello")

        assert not result.is_success
        assert "API Error" in result.error


class TestOllamaRunner:
    """Tests for Ollama runner."""

    def test_initialization(self):
        """Test runner initialization."""
        runner = OllamaRunner(model="llama2", base_url="http://localhost:11434")
        assert runner.name == "ollama"
        assert runner.provider == "ollama"
        assert runner.model == "llama2"
        assert runner.base_url == "http://localhost:11434"

    def test_default_initialization(self):
        """Test default initialization."""
        runner = OllamaRunner()
        assert runner.model == "llama3.2"
        assert runner.base_url == "http://localhost:11434"

    @patch("mass.runners.api.ollama.httpx.Client")
    def test_run_success(self, mock_client_class):
        """Test successful run."""
        mock_client = MagicMock()
        mock_client.__enter__ = MagicMock(return_value=mock_client)
        mock_client.__exit__ = MagicMock(return_value=False)

        mock_response = MagicMock()
        mock_response.json.return_value = {
            "message": {"content": "Hello from Ollama!"},
            "model": "llama3.2",
            "eval_count": 50,
        }
        mock_response.raise_for_status = MagicMock()
        mock_client.post.return_value = mock_response
        mock_client_class.return_value = mock_client

        runner = OllamaRunner()
        result = runner.run("Hello")

        assert result.is_success
        assert result.response == "Hello from Ollama!"
        mock_client.post.assert_called_once()

    @patch("mass.runners.api.ollama.httpx.Client")
    def test_run_with_system_prompt(self, mock_client_class):
        """Test run with system prompt."""
        mock_client = MagicMock()
        mock_client.__enter__ = MagicMock(return_value=mock_client)
        mock_client.__exit__ = MagicMock(return_value=False)

        mock_response = MagicMock()
        mock_response.json.return_value = {
            "message": {"content": "Response"},
            "model": "llama3.2",
        }
        mock_response.raise_for_status = MagicMock()
        mock_client.post.return_value = mock_response
        mock_client_class.return_value = mock_client

        runner = OllamaRunner()
        result = runner.run("Hello", system_prompt="You are helpful")

        call_args = mock_client.post.call_args
        json_data = call_args.kwargs.get("json", {})
        messages = json_data.get("messages", [])
        assert any(m.get("role") == "system" for m in messages)

    @patch("mass.runners.api.ollama.httpx.Client")
    def test_run_connection_error(self, mock_client_class):
        """Test run with connection error."""
        mock_client = MagicMock()
        mock_client.__enter__ = MagicMock(return_value=mock_client)
        mock_client.__exit__ = MagicMock(return_value=False)
        mock_client.post.side_effect = Exception("Connection refused")
        mock_client_class.return_value = mock_client

        runner = OllamaRunner()
        result = runner.run("Hello")

        assert not result.is_success
        assert "Connection refused" in result.error

    @patch("mass.runners.api.ollama.httpx.Client")
    def test_run_streaming_disabled(self, mock_client_class):
        """Test that streaming is disabled by default."""
        mock_client = MagicMock()
        mock_client.__enter__ = MagicMock(return_value=mock_client)
        mock_client.__exit__ = MagicMock(return_value=False)

        mock_response = MagicMock()
        mock_response.json.return_value = {
            "message": {"content": "Response"},
            "model": "llama3.2",
        }
        mock_response.raise_for_status = MagicMock()
        mock_client.post.return_value = mock_response
        mock_client_class.return_value = mock_client

        runner = OllamaRunner()
        runner.run("Hello")

        call_args = mock_client.post.call_args
        json_data = call_args.kwargs.get("json", {})
        assert json_data.get("stream") is False


class TestRunnerIntegration:
    """Integration tests for runners."""

    def test_all_runners_registered(self):
        """Test that all runners are registered."""
        expected = {"openai", "anthropic", "ollama"}
        registered = set(runner_registry.list_runners())
        assert expected.issubset(registered)

    def test_runners_have_required_attributes(self):
        """Test that runners have required attributes."""
        for name in runner_registry.list_runners():
            runner_cls = runner_registry.get_class(name)
            assert hasattr(runner_cls, "name")
            assert hasattr(runner_cls, "provider")
            assert hasattr(runner_cls, "run")
            assert hasattr(runner_cls, "run_async")

    def test_runner_result_format_consistent(self):
        """Test that all runners return consistent result format."""
        result = RunnerResult(
            response="test",
            status=RunnerStatus.SUCCESS,
            latency_ms=50.0,
            model="test-model",
            provider="test",
            tokens_used=10,
        )

        # Check all expected fields exist
        assert hasattr(result, "response")
        assert hasattr(result, "status")
        assert hasattr(result, "model")
        assert hasattr(result, "provider")
        assert hasattr(result, "tokens_used")
        assert hasattr(result, "latency_ms")
        assert hasattr(result, "error")
        assert hasattr(result, "is_success")
