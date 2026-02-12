"""Load custom red team agents from YAML files.

Users can define custom attack strategies by placing YAML files in a
designated directory (default: data/strategies/). Each YAML file defines
one agent with one or more strategies. Files are validated and registered
with the global agent_registry at startup.

See data/strategies/_example.yaml for the expected format.
"""

import logging
from pathlib import Path
from typing import Any

import yaml

from mass.core.types import AttackCategory, Severity
from mass.interrogator.agents.base import (
    AgentRegistry,
    AttackStrategy,
    RedTeamAgent,
    agent_registry,
)

logger = logging.getLogger(__name__)

# Map string values to enums (case-insensitive)
_CATEGORY_MAP: dict[str, AttackCategory] = {v.value: v for v in AttackCategory}
_SEVERITY_MAP: dict[str, Severity] = {v.value: v for v in Severity}

# Default directory inside Docker container (mapped from ./data)
DEFAULT_STRATEGIES_DIR = Path("/app/data/strategies")


def _parse_strategy(raw: dict[str, Any], agent_name: str) -> AttackStrategy | None:
    """Parse a single strategy dict into an AttackStrategy."""
    name = raw.get("name")
    if not name or not isinstance(name, str):
        logger.warning("Custom agent '%s': strategy missing 'name', skipping", agent_name)
        return None

    system_prompt = raw.get("system_prompt", "")
    if not system_prompt:
        logger.warning("Custom agent '%s': strategy '%s' missing 'system_prompt', skipping", agent_name, name)
        return None

    return AttackStrategy(
        name=name.strip(),
        description=raw.get("description", ""),
        system_prompt=system_prompt,
        opening_prompt=raw.get("opening_prompt"),
        max_turns=int(raw.get("max_turns", 8)),
        success_indicators=raw.get("success_indicators", []),
    )


def _parse_agent_file(path: Path) -> RedTeamAgent | None:
    """Parse a YAML file into a RedTeamAgent."""
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)
    except Exception as e:
        logger.warning("Failed to parse custom strategy file %s: %s", path.name, e)
        return None

    if not isinstance(data, dict):
        logger.warning("Custom strategy file %s: expected a YAML mapping at top level", path.name)
        return None

    name = data.get("name")
    if not name or not isinstance(name, str):
        logger.warning("Custom strategy file %s: missing required 'name' field", path.name)
        return None

    # Category
    cat_str = str(data.get("category", "")).lower().strip()
    category = _CATEGORY_MAP.get(cat_str)
    if not category:
        logger.warning(
            "Custom agent '%s' (%s): unknown category '%s', valid values: %s",
            name, path.name, cat_str, ", ".join(_CATEGORY_MAP.keys()),
        )
        return None

    # Severity
    sev_str = str(data.get("severity", "medium")).lower().strip()
    severity = _SEVERITY_MAP.get(sev_str, Severity.MEDIUM)

    # Strategies
    raw_strategies = data.get("strategies", [])
    if not isinstance(raw_strategies, list) or not raw_strategies:
        logger.warning("Custom agent '%s' (%s): no strategies defined", name, path.name)
        return None

    strategies = []
    for raw in raw_strategies:
        if isinstance(raw, dict):
            strat = _parse_strategy(raw, name)
            if strat:
                strategies.append(strat)

    if not strategies:
        logger.warning("Custom agent '%s' (%s): no valid strategies after parsing", name, path.name)
        return None

    # Tags — always include "custom" and the source filename
    tags = list(data.get("tags", []))
    if "custom" not in tags:
        tags.insert(0, "custom")
    tags.append(f"file:{path.name}")

    return RedTeamAgent(
        name=name.strip(),
        category=category,
        description=data.get("description", ""),
        base_severity=severity,
        strategies=strategies,
        tags=tags,
        cwe_ids=data.get("cwe_ids", []),
        owasp_ids=data.get("owasp_ids", []),
        metadata={"source_file": path.name, "custom": True},
    )


def validate_yaml_content(content: str) -> tuple[RedTeamAgent | None, str]:
    """Validate raw YAML content without registering.

    Returns (agent, "") on success or (None, error_message) on failure.
    """
    try:
        data = yaml.safe_load(content)
    except yaml.YAMLError as e:
        return None, f"Invalid YAML syntax: {e}"

    if not isinstance(data, dict):
        return None, "Top level must be a YAML mapping"

    name = data.get("name")
    if not name:
        return None, "Missing required field: name"

    cat_str = str(data.get("category", "")).lower().strip()
    if cat_str not in _CATEGORY_MAP:
        return None, f"Unknown category '{cat_str}'. Valid: {', '.join(sorted(_CATEGORY_MAP.keys()))}"

    strategies = data.get("strategies", [])
    if not isinstance(strategies, list) or not strategies:
        return None, "Must define at least one strategy"

    for i, s in enumerate(strategies):
        if not isinstance(s, dict):
            return None, f"Strategy {i}: must be a mapping"
        if not s.get("name"):
            return None, f"Strategy {i}: missing 'name'"
        if not s.get("system_prompt"):
            return None, f"Strategy '{s.get('name', i)}': missing 'system_prompt'"

    # Full parse
    import tempfile

    with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False, encoding="utf-8") as tmp:
        tmp.write(content)
        tmp_path = Path(tmp.name)
    try:
        agent = _parse_agent_file(tmp_path)
    finally:
        tmp_path.unlink(missing_ok=True)

    if not agent:
        return None, "Parsing succeeded but no valid agent produced"
    return agent, ""


def load_custom_strategies(
    directory: Path | None = None,
    registry: AgentRegistry | None = None,
) -> int:
    """Load all YAML strategy files from a directory.

    Returns the number of agents successfully loaded.
    """
    directory = directory or DEFAULT_STRATEGIES_DIR
    registry = registry or agent_registry

    if not directory.is_dir():
        logger.debug("Custom strategies directory does not exist: %s", directory)
        return 0

    loaded = 0
    for path in sorted(directory.glob("*.y*ml")):
        if path.name.startswith("_"):
            continue  # Skip files prefixed with _ (examples, templates)

        agent = _parse_agent_file(path)
        if agent:
            registry.register(agent)
            loaded += 1
            strat_count = len(agent.strategies)
            logger.info(
                "Loaded custom agent '%s' from %s (%d strategies)",
                agent.name, path.name, strat_count,
            )

    if loaded:
        logger.info("Loaded %d custom agent(s) from %s", loaded, directory)
    return loaded


def reload_custom_strategies(
    directory: Path | None = None,
    registry: AgentRegistry | None = None,
) -> int:
    """Unregister all custom agents and reload from disk.

    Used after creating/updating/deleting custom YAML files via the API.
    """
    registry = registry or agent_registry

    # Remove all currently-registered custom agents
    for agent in list(registry.list_custom()):
        registry.unregister(agent.name)

    return load_custom_strategies(directory, registry)
