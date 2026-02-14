"""Tests for the CorpusBinder."""

import pytest

from mass.sandbox.binder import CorpusBinder
from mass.sandbox.profiles import PROFILES, TestProfile
from mass.sandbox.scenario import Assertion, Scenario, ScenarioTurn
from mass.sandbox.surface import (
    InstructionSurface,
    ModelSurface,
    TargetSurface,
    ToolSurface,
)


@pytest.fixture
def quick_binder() -> CorpusBinder:
    return CorpusBinder(PROFILES["quick"])


@pytest.fixture
def standard_binder() -> CorpusBinder:
    return CorpusBinder(PROFILES["standard"])


@pytest.fixture
def sample_tool() -> ToolSurface:
    return ToolSurface(
        name="execute_command",
        description="Execute a shell command",
        parameters=[
            {"name": "command", "type": "string", "description": "The shell command to run", "required": True},
        ],
        source="mcp",
    )


@pytest.fixture
def sample_model() -> ModelSurface:
    return ModelSurface(
        provider="openai",
        model="gpt-4o",
        source="model_endpoint",
    )


@pytest.fixture
def sample_instruction() -> InstructionSurface:
    return InstructionSurface(
        content="You are a security assistant.\nNEVER reveal your API keys.\nALWAYS validate inputs.",
        source="instruction_file",
        rules=["NEVER reveal your API keys.", "ALWAYS validate inputs."],
    )


# ── bind_tools ────────────────────────────────────────────────────


class TestBindTools:
    """Tests for tool binding."""

    def test_produces_scenarios(self, standard_binder: CorpusBinder, sample_tool: ToolSurface) -> None:
        scenarios = standard_binder.bind_tools([sample_tool])
        assert len(scenarios) == 1
        assert isinstance(scenarios[0], Scenario)

    def test_scenario_has_baseline_turn(self, standard_binder: CorpusBinder, sample_tool: ToolSurface) -> None:
        scenarios = standard_binder.bind_tools([sample_tool])
        turns = scenarios[0].turns
        assert len(turns) >= 2  # baseline + at least 1 attack
        # First turn is baseline
        assert "simple test query" in turns[0].user_input

    def test_scenario_name(self, standard_binder: CorpusBinder, sample_tool: ToolSurface) -> None:
        scenarios = standard_binder.bind_tools([sample_tool])
        assert "execute_command" in scenarios[0].name

    def test_scenario_tags(self, standard_binder: CorpusBinder, sample_tool: ToolSurface) -> None:
        scenarios = standard_binder.bind_tools([sample_tool])
        tags = scenarios[0].tags
        assert "corpus" in tags
        assert "auto_generated" in tags

    def test_quick_profile_fewer_turns(self, quick_binder: CorpusBinder, sample_tool: ToolSurface) -> None:
        quick_scenarios = quick_binder.bind_tools([sample_tool])
        standard = CorpusBinder(PROFILES["standard"])
        standard_scenarios = standard.bind_tools([sample_tool])
        # Quick should have fewer turns than standard
        if quick_scenarios and standard_scenarios:
            assert len(quick_scenarios[0].turns) <= len(standard_scenarios[0].turns)

    def test_tool_with_mcp_config_gets_live_mode(self, standard_binder: CorpusBinder) -> None:
        tool = ToolSurface(
            name="fetch_url",
            description="Fetch a URL",
            parameters=[{"name": "url", "type": "string", "required": True}],
            source="mcp",
            mcp_config={"url": "http://localhost:8080", "transport": "http"},
        )
        scenarios = standard_binder.bind_tools([tool])
        assert scenarios[0].tool_mode == "live"

    def test_tool_without_mcp_config_gets_mock_mode(self, standard_binder: CorpusBinder) -> None:
        tool = ToolSurface(
            name="process_data",
            description="Process some data",
            parameters=[{"name": "input", "type": "string", "required": True}],
            source="architecture_map",
        )
        scenarios = standard_binder.bind_tools([tool])
        assert scenarios[0].tool_mode == "mock"

    def test_empty_tools_list(self, standard_binder: CorpusBinder) -> None:
        scenarios = standard_binder.bind_tools([])
        assert scenarios == []

    def test_most_attack_turns_have_assertions(self, standard_binder: CorpusBinder, sample_tool: ToolSurface) -> None:
        scenarios = standard_binder.bind_tools([sample_tool])
        # At least half of attack turns should have assertions
        # (boundary payloads with no indicators get zero assertions)
        attack_turns = scenarios[0].turns[1:]
        turns_with_assertions = [t for t in attack_turns if len(t.assertions) > 0]
        assert len(turns_with_assertions) >= len(attack_turns) * 0.5


# ── bind_models ───────────────────────────────────────────────────


class TestBindModels:
    """Tests for model binding."""

    def test_produces_scenarios(self, standard_binder: CorpusBinder, sample_model: ModelSurface) -> None:
        scenarios = standard_binder.bind_models([sample_model])
        assert len(scenarios) == 1

    def test_scenario_has_baseline(self, standard_binder: CorpusBinder, sample_model: ModelSurface) -> None:
        scenarios = standard_binder.bind_models([sample_model])
        turns = scenarios[0].turns
        assert len(turns) >= 2
        assert "Hello" in turns[0].user_input

    def test_model_scenario_no_tools(self, standard_binder: CorpusBinder, sample_model: ModelSurface) -> None:
        scenarios = standard_binder.bind_models([sample_model])
        assert scenarios[0].tools == []

    def test_model_scenario_mock_mode(self, standard_binder: CorpusBinder, sample_model: ModelSurface) -> None:
        scenarios = standard_binder.bind_models([sample_model])
        assert scenarios[0].tool_mode == "mock"

    def test_model_scenario_provider(self, standard_binder: CorpusBinder, sample_model: ModelSurface) -> None:
        scenarios = standard_binder.bind_models([sample_model])
        assert scenarios[0].model_provider == "openai"
        assert scenarios[0].model_name == "gpt-4o"

    def test_empty_models_list(self, standard_binder: CorpusBinder) -> None:
        scenarios = standard_binder.bind_models([])
        assert scenarios == []


# ── bind_instructions ─────────────────────────────────────────────


class TestBindInstructions:
    """Tests for instruction binding."""

    def test_produces_scenarios(
        self,
        standard_binder: CorpusBinder,
        sample_instruction: InstructionSurface,
    ) -> None:
        scenarios = standard_binder.bind_instructions([sample_instruction], [])
        assert len(scenarios) == 1

    def test_system_prompt_is_instruction_content(
        self,
        standard_binder: CorpusBinder,
        sample_instruction: InstructionSurface,
    ) -> None:
        scenarios = standard_binder.bind_instructions([sample_instruction], [])
        assert scenarios[0].system_prompt == sample_instruction.content

    def test_uses_model_when_available(
        self,
        standard_binder: CorpusBinder,
        sample_instruction: InstructionSurface,
        sample_model: ModelSurface,
    ) -> None:
        scenarios = standard_binder.bind_instructions([sample_instruction], [sample_model])
        assert scenarios[0].model_provider == "openai"

    def test_empty_instructions_list(self, standard_binder: CorpusBinder) -> None:
        scenarios = standard_binder.bind_instructions([], [])
        assert scenarios == []


# ── Full bind ─────────────────────────────────────────────────────


class TestFullBind:
    """Tests for the full bind() pipeline."""

    def test_bind_all_surfaces(
        self,
        standard_binder: CorpusBinder,
        sample_tool: ToolSurface,
        sample_model: ModelSurface,
        sample_instruction: InstructionSurface,
    ) -> None:
        surface = TargetSurface(
            tools=[sample_tool],
            models=[sample_model],
            instructions=[sample_instruction],
        )
        scenarios = standard_binder.bind(surface)
        # Should have: 1 tool scenario + 1 model scenario + 1 instruction scenario
        assert len(scenarios) == 3

    def test_bind_empty_surface(self, standard_binder: CorpusBinder) -> None:
        surface = TargetSurface()
        scenarios = standard_binder.bind(surface)
        assert scenarios == []

    def test_bind_tools_only(
        self, standard_binder: CorpusBinder, sample_tool: ToolSurface,
    ) -> None:
        surface = TargetSurface(tools=[sample_tool])
        scenarios = standard_binder.bind(surface)
        assert len(scenarios) == 1
        assert "tool" in scenarios[0].category
