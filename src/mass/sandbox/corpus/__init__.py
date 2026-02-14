"""Attack payload corpus loader.

Merges built-in Python payloads with user-supplied custom YAML payloads
so the corpus can be extended without editing source code.

Custom payloads live under ``data/sandbox/corpus/`` (created on first use).
Each YAML file must declare ``mode`` (tool | model | instruction),
``category``, and a ``payloads`` list.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

import yaml

from mass.sandbox.corpus.payloads import Payload, TOOL_PAYLOADS

logger = logging.getLogger(__name__)

_CUSTOM_DIR = Path("data/sandbox/corpus")


class CorpusLoader:
    """Load and merge built-in + custom attack payloads."""

    @staticmethod
    def load_tool_corpus(custom_dir: Path | None = None) -> dict[str, list[Payload]]:
        """Return tool-testing payloads (built-in + custom)."""
        corpus = {cat: list(payloads) for cat, payloads in TOOL_PAYLOADS.items()}
        CorpusLoader._merge_custom(corpus, "tool", custom_dir or _CUSTOM_DIR)
        return corpus

    @staticmethod
    def load_model_corpus(custom_dir: Path | None = None) -> dict[str, list[Payload]]:
        """Return model-testing payloads (built-in + custom)."""
        from mass.sandbox.corpus.model_payloads import MODEL_PAYLOADS

        corpus = {cat: list(payloads) for cat, payloads in MODEL_PAYLOADS.items()}
        CorpusLoader._merge_custom(corpus, "model", custom_dir or _CUSTOM_DIR)
        return corpus

    @staticmethod
    def load_instruction_corpus(custom_dir: Path | None = None) -> dict[str, list[Payload]]:
        """Return instruction-testing payloads (built-in + custom)."""
        from mass.sandbox.corpus.instruction_payloads import INSTRUCTION_PAYLOADS

        corpus = {cat: list(payloads) for cat, payloads in INSTRUCTION_PAYLOADS.items()}
        CorpusLoader._merge_custom(corpus, "instruction", custom_dir or _CUSTOM_DIR)
        return corpus

    # ── Internal ─────────────────────────────────────────────────────

    @staticmethod
    def _merge_custom(
        corpus: dict[str, list[Payload]],
        mode: str,
        custom_dir: Path,
    ) -> None:
        """Scan *custom_dir* for YAML files matching *mode* and append payloads."""
        if not custom_dir.is_dir():
            return

        for yaml_file in sorted(custom_dir.glob("*.yaml")):
            try:
                data = yaml.safe_load(yaml_file.read_text(encoding="utf-8"))
                if not isinstance(data, dict):
                    continue
                if data.get("mode") != mode:
                    continue

                category = data.get("category", "custom")
                raw_payloads = data.get("payloads", [])
                for rp in raw_payloads:
                    if not isinstance(rp, dict) or "value" not in rp:
                        continue
                    payload = Payload(
                        value=rp["value"],
                        description=rp.get("description", "Custom payload"),
                        category=category,
                        severity=rp.get("severity", "medium"),
                        indicators=rp.get("indicators", []),
                        prompt_templates=rp.get("prompt_templates", []),
                    )
                    corpus.setdefault(category, []).append(payload)

                logger.debug(
                    "Loaded %d custom %s/%s payloads from %s",
                    len(raw_payloads), mode, category, yaml_file.name,
                )
            except Exception as exc:
                logger.warning("Failed to load custom corpus %s: %s", yaml_file, exc)
