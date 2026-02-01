"""Tests for probes module."""

import pytest

from mass.core.types import AttackCategory
from mass.probes.base import (
    BaseProbe,
    ProbePrompt,
    ProbeRegistry,
    probe_registry,
    register_probe,
    get_probe,
    list_probes,
)
from mass.probes.jailbreak import DANProbe, RoleplayProbe, EncodingProbe
from mass.probes.injection import (
    DirectInjectionProbe,
    IndirectInjectionProbe,
    ContextManipulationProbe,
)
from mass.probes.leakage import SystemPromptProbe, PIILeakageProbe
from mass.probes.harmful import ViolenceProbe, IllegalActivityProbe, DangerousInfoProbe


class TestProbePrompt:
    """Tests for ProbePrompt dataclass."""

    def test_prompt_creation(self) -> None:
        """Test basic prompt creation."""
        prompt = ProbePrompt(
            text="Test prompt",
            probe_name="test_probe",
            variant="v1",
        )
        assert prompt.text == "Test prompt"
        assert prompt.probe_name == "test_probe"
        assert prompt.variant == "v1"

    def test_full_id(self) -> None:
        """Test full ID generation."""
        prompt = ProbePrompt(
            text="Test",
            probe_name="test",
            variant="v1",
        )
        assert prompt.full_id == "test:v1"

        prompt_no_variant = ProbePrompt(
            text="Test",
            probe_name="test",
        )
        assert prompt_no_variant.full_id == "test"


class TestProbeRegistry:
    """Tests for ProbeRegistry."""

    def test_register_probe(self) -> None:
        """Test probe registration."""
        registry = ProbeRegistry()

        class TestProbe(BaseProbe):
            name = "test_registry_probe"

            def generate_prompts(self):
                yield self._create_prompt("Test")

        registry.register(TestProbe)
        assert "test_registry_probe" in registry.list_probes()

    def test_get_probe(self) -> None:
        """Test getting a probe."""
        registry = ProbeRegistry()

        class TestProbe(BaseProbe):
            name = "test_get_probe"
            category = AttackCategory.JAILBREAK

            def generate_prompts(self):
                yield self._create_prompt("Test")

        registry.register(TestProbe)
        probe = registry.get("test_get_probe")
        assert probe is not None
        assert probe.name == "test_get_probe"

    def test_list_by_category(self) -> None:
        """Test listing probes by category."""
        registry = ProbeRegistry()

        class Probe1(BaseProbe):
            name = "cat_probe_1"
            category = AttackCategory.JAILBREAK

            def generate_prompts(self):
                yield self._create_prompt("Test")

        class Probe2(BaseProbe):
            name = "cat_probe_2"
            category = AttackCategory.PROMPT_INJECTION

            def generate_prompts(self):
                yield self._create_prompt("Test")

        registry.register(Probe1)
        registry.register(Probe2)

        jailbreak_probes = registry.list_by_category(AttackCategory.JAILBREAK)
        assert "cat_probe_1" in jailbreak_probes
        assert "cat_probe_2" not in jailbreak_probes


class TestDANProbe:
    """Tests for DAN probe."""

    def test_probe_attributes(self) -> None:
        """Test DAN probe attributes."""
        probe = DANProbe()
        assert probe.name == "dan"
        assert probe.category == AttackCategory.JAILBREAK
        assert "jailbreak" in probe.tags

    def test_generate_prompts(self) -> None:
        """Test DAN prompt generation."""
        probe = DANProbe()
        prompts = list(probe.generate_prompts())
        assert len(prompts) > 0
        assert all(isinstance(p, ProbePrompt) for p in prompts)

    def test_prompt_count(self) -> None:
        """Test prompt count matches actual prompts."""
        probe = DANProbe()
        count = probe.get_prompt_count()
        prompts = list(probe.generate_prompts())
        assert count == len(prompts)


class TestRoleplayProbe:
    """Tests for Roleplay probe."""

    def test_probe_attributes(self) -> None:
        """Test roleplay probe attributes."""
        probe = RoleplayProbe()
        assert probe.name == "roleplay"
        assert "roleplay" in probe.tags

    def test_generate_prompts(self) -> None:
        """Test roleplay prompt generation."""
        probe = RoleplayProbe()
        prompts = list(probe.generate_prompts())
        assert len(prompts) > 0


class TestEncodingProbe:
    """Tests for Encoding probe."""

    def test_probe_attributes(self) -> None:
        """Test encoding probe attributes."""
        probe = EncodingProbe()
        assert probe.name == "encoding"
        assert "encoding" in probe.tags

    def test_generate_prompts(self) -> None:
        """Test encoding prompt generation."""
        probe = EncodingProbe()
        prompts = list(probe.generate_prompts())
        assert len(prompts) > 0

        # Check that we have multiple encoding types
        variants = {p.variant for p in prompts}
        assert "base64" in variants
        assert "rot13" in variants

    def test_base64_encoding(self) -> None:
        """Test that base64 prompts contain encoded content."""
        probe = EncodingProbe()
        prompts = list(probe.generate_prompts())
        base64_prompts = [p for p in prompts if p.variant == "base64"]
        assert len(base64_prompts) > 0
        # Base64 prompts should contain base64 characters
        for prompt in base64_prompts:
            assert "base64" in prompt.text.lower()


class TestDirectInjectionProbe:
    """Tests for Direct Injection probe."""

    def test_probe_attributes(self) -> None:
        """Test direct injection probe attributes."""
        probe = DirectInjectionProbe()
        assert probe.name == "direct_injection"
        assert probe.category == AttackCategory.PROMPT_INJECTION

    def test_generate_prompts(self) -> None:
        """Test direct injection prompt generation."""
        probe = DirectInjectionProbe()
        prompts = list(probe.generate_prompts())
        assert len(prompts) > 0


class TestIndirectInjectionProbe:
    """Tests for Indirect Injection probe."""

    def test_probe_attributes(self) -> None:
        """Test indirect injection probe attributes."""
        probe = IndirectInjectionProbe()
        assert probe.name == "indirect_injection"

    def test_generate_prompts(self) -> None:
        """Test indirect injection prompt generation."""
        probe = IndirectInjectionProbe()
        prompts = list(probe.generate_prompts())
        assert len(prompts) > 0


class TestSystemPromptProbe:
    """Tests for System Prompt extraction probe."""

    def test_probe_attributes(self) -> None:
        """Test system prompt probe attributes."""
        probe = SystemPromptProbe()
        assert probe.name == "system_prompt_extraction"
        assert probe.category == AttackCategory.SENSITIVE_INFO

    def test_generate_prompts(self) -> None:
        """Test system prompt extraction prompts."""
        probe = SystemPromptProbe()
        prompts = list(probe.generate_prompts())
        assert len(prompts) > 0


class TestPIILeakageProbe:
    """Tests for PII Leakage probe."""

    def test_probe_attributes(self) -> None:
        """Test PII leakage probe attributes."""
        probe = PIILeakageProbe()
        assert probe.name == "pii_leakage"
        assert "pii" in probe.tags

    def test_generate_prompts(self) -> None:
        """Test PII leakage prompts."""
        probe = PIILeakageProbe()
        prompts = list(probe.generate_prompts())
        assert len(prompts) > 0


class TestHarmfulProbes:
    """Tests for harmful content probes."""

    def test_violence_probe(self) -> None:
        """Test violence probe."""
        probe = ViolenceProbe()
        assert probe.name == "violence"
        prompts = list(probe.generate_prompts())
        assert len(prompts) > 0

    def test_illegal_activity_probe(self) -> None:
        """Test illegal activity probe."""
        probe = IllegalActivityProbe()
        assert probe.name == "illegal_activity"
        prompts = list(probe.generate_prompts())
        assert len(prompts) > 0

    def test_dangerous_info_probe(self) -> None:
        """Test dangerous info probe."""
        probe = DangerousInfoProbe()
        assert probe.name == "dangerous_info"
        prompts = list(probe.generate_prompts())
        assert len(prompts) > 0


class TestGlobalRegistry:
    """Tests for global probe registry."""

    def test_registered_probes(self) -> None:
        """Test that probes are registered."""
        # Import all probes to trigger registration
        from mass.probes import jailbreak, injection, leakage, harmful

        probes = list_probes()
        assert len(probes) >= 10  # We created at least 10 probes

    def test_get_probe(self) -> None:
        """Test getting a probe from global registry."""
        probe = get_probe("dan")
        assert probe is not None
        assert probe.name == "dan"
