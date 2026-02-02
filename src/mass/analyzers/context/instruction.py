"""Instruction analysis for context files.

Analyzes instruction patterns and structure in AI context files.
"""

import re
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any

from mass.core.types import Severity


class InstructionType(str, Enum):
    """Types of instructions."""
    BEHAVIORAL = "behavioral"  # How to behave
    CAPABILITY = "capability"  # What it can/cannot do
    PERSONA = "persona"  # Identity/character
    OUTPUT = "output"  # Output format
    SECURITY = "security"  # Security constraints
    INTERACTION = "interaction"  # User interaction rules
    TOOL_USE = "tool_use"  # Tool/function usage
    UNKNOWN = "unknown"


class InstructionRisk(str, Enum):
    """Risk levels for instructions."""
    SAFE = "safe"
    LOW_RISK = "low_risk"
    MEDIUM_RISK = "medium_risk"
    HIGH_RISK = "high_risk"
    DANGEROUS = "dangerous"


@dataclass
class Instruction:
    """A parsed instruction from a context file."""
    text: str
    instruction_type: InstructionType
    risk: InstructionRisk
    line_number: int | None = None
    confidence: float = 1.0
    analysis: dict[str, Any] = field(default_factory=dict)


@dataclass
class InstructionAnalysisResult:
    """Result of instruction analysis."""
    instructions: list[Instruction] = field(default_factory=list)
    summary: dict[str, Any] = field(default_factory=dict)
    risk_score: float = 0.0

    @property
    def dangerous_instructions(self) -> list[Instruction]:
        """Get dangerous instructions."""
        return [i for i in self.instructions if i.risk == InstructionRisk.DANGEROUS]

    @property
    def high_risk_instructions(self) -> list[Instruction]:
        """Get high risk instructions."""
        return [i for i in self.instructions if i.risk == InstructionRisk.HIGH_RISK]


# Patterns for instruction type detection
INSTRUCTION_TYPE_PATTERNS = {
    InstructionType.BEHAVIORAL: [
        r"(always|never|must|should|will)\s+(be|act|respond|behave)",
        r"(maintain|keep|stay)\s+(a\s+)?(professional|helpful|friendly)",
        r"(be\s+)(concise|brief|detailed|thorough)",
    ],
    InstructionType.CAPABILITY: [
        r"(can|cannot|able|unable)\s+(to\s+)?(do|perform|execute|access)",
        r"(have|has)\s+(access|ability|capability)",
        r"(enabled?|disabled?|allowed?|prohibited?)",
    ],
    InstructionType.PERSONA: [
        r"(you\s+are|act\s+as|pretend\s+to\s+be)\s+",
        r"(your\s+)?(name|identity|role|character)\s+(is|:)",
        r"(speak|talk|write)\s+(like|as)",
    ],
    InstructionType.OUTPUT: [
        r"(format|structure|output)\s+(as|in|using)",
        r"(respond|reply|answer)\s+(in|with|using)",
        r"(use|write)\s+(markdown|json|code|bullet)",
    ],
    InstructionType.SECURITY: [
        r"(never|do\s+not|don't)\s+(share|reveal|disclose|expose)",
        r"(keep|maintain)\s+(confidential|private|secret)",
        r"(protect|secure|safeguard)",
    ],
    InstructionType.INTERACTION: [
        r"(ask|request|prompt)\s+(for\s+)?(clarification|confirmation|input)",
        r"(wait|pause)\s+(for|until)\s+(user|input|response)",
        r"(engage|interact)\s+(with\s+)?(user|human)",
    ],
    InstructionType.TOOL_USE: [
        r"(use|call|invoke|execute)\s+(the\s+)?(tool|function|api)",
        r"(before|after)\s+(using|calling)\s+(tool|function)",
        r"(tool|function)\s+(usage|calling|invocation)",
    ],
}

# Risk patterns for instructions
RISK_PATTERNS = {
    InstructionRisk.DANGEROUS: [
        r"(ignore|bypass|disable)\s+(all\s+)?(safety|security|restrictions?)",
        r"(execute|run)\s+(any|arbitrary|all)\s+(code|commands?)",
        r"(no\s+)?(restrictions?|limits?|boundaries)",
    ],
    InstructionRisk.HIGH_RISK: [
        r"(always|unconditionally)\s+(trust|accept|execute)",
        r"(skip|bypass)\s+(validation|verification|checks?)",
        r"(full|complete|unlimited)\s+(access|permissions?|control)",
    ],
    InstructionRisk.MEDIUM_RISK: [
        r"(may|can)\s+(sometimes|occasionally)\s+(ignore|skip)",
        r"(prefer|prioritize)\s+(speed|efficiency)\s+over\s+(safety|security)",
        r"(relax|loosen)\s+(restrictions?|rules?)",
    ],
    InstructionRisk.LOW_RISK: [
        r"(generally|usually|typically)\s+(safe|ok|fine)",
        r"(minor|small)\s+(exceptions?|deviations?)",
    ],
}


class InstructionAnalyzer:
    """Analyzes instructions in context files.

    Parses and categorizes instructions, assessing their risk level
    and identifying potentially dangerous patterns.
    """

    def __init__(self):
        """Initialize instruction analyzer."""
        # Compile patterns
        self._type_patterns = {
            itype: [re.compile(p, re.IGNORECASE) for p in patterns]
            for itype, patterns in INSTRUCTION_TYPE_PATTERNS.items()
        }
        self._risk_patterns = {
            risk: [re.compile(p, re.IGNORECASE) for p in patterns]
            for risk, patterns in RISK_PATTERNS.items()
        }

    def analyze(self, content: str) -> InstructionAnalysisResult:
        """Analyze content for instructions.

        Args:
            content: Content to analyze.

        Returns:
            Instruction analysis result.
        """
        result = InstructionAnalysisResult()

        # Extract instruction-like sentences
        instructions = self._extract_instructions(content)

        for text, line_num in instructions:
            instruction = self._analyze_instruction(text, line_num)
            result.instructions.append(instruction)

        # Calculate summary
        result.summary = self._calculate_summary(result.instructions)
        result.risk_score = self._calculate_risk_score(result.instructions)

        return result

    def _extract_instructions(self, content: str) -> list[tuple[str, int]]:
        """Extract instruction-like sentences from content.

        Args:
            content: Content to parse.

        Returns:
            List of (instruction_text, line_number) tuples.
        """
        instructions = []
        lines = content.splitlines()

        # Patterns that indicate an instruction
        instruction_indicators = [
            r"^[-*]\s+",  # Bullet points
            r"^\d+\.\s+",  # Numbered lists
            r"^(must|should|always|never|do|don't|can|cannot)\b",
            r"^(you\s+are|you\s+will|you\s+must|you\s+should)\b",
        ]

        for i, line in enumerate(lines, 1):
            line = line.strip()
            if not line:
                continue

            # Check if line looks like an instruction
            for pattern in instruction_indicators:
                if re.match(pattern, line, re.IGNORECASE):
                    # Clean up the instruction text
                    cleaned = re.sub(r"^[-*\d.]+\s*", "", line)
                    if len(cleaned) > 10:  # Skip very short lines
                        instructions.append((cleaned, i))
                    break
            else:
                # Check for instructional sentences
                if self._looks_like_instruction(line):
                    instructions.append((line, i))

        return instructions

    def _looks_like_instruction(self, text: str) -> bool:
        """Check if text looks like an instruction.

        Args:
            text: Text to check.

        Returns:
            True if text appears to be an instruction.
        """
        # Key phrases that indicate instructions
        instruction_phrases = [
            r"\b(must|should|shall|will|always|never)\b",
            r"\b(ensure|make\s+sure|guarantee)\b",
            r"\b(do\s+not|don't|cannot|can't)\b",
            r"\b(required?|mandatory|necessary)\b",
            r"\b(prohibited?|forbidden|banned)\b",
        ]

        text_lower = text.lower()
        return any(re.search(p, text_lower) for p in instruction_phrases)

    def _analyze_instruction(
        self,
        text: str,
        line_number: int | None,
    ) -> Instruction:
        """Analyze a single instruction.

        Args:
            text: Instruction text.
            line_number: Line number in source.

        Returns:
            Analyzed instruction.
        """
        instruction_type = self._detect_type(text)
        risk = self._assess_risk(text)

        return Instruction(
            text=text,
            instruction_type=instruction_type,
            risk=risk,
            line_number=line_number,
            analysis={
                "length": len(text),
                "word_count": len(text.split()),
            },
        )

    def _detect_type(self, text: str) -> InstructionType:
        """Detect instruction type.

        Args:
            text: Instruction text.

        Returns:
            Detected instruction type.
        """
        best_match = InstructionType.UNKNOWN
        best_score = 0

        for itype, patterns in self._type_patterns.items():
            score = sum(1 for p in patterns if p.search(text))
            if score > best_score:
                best_score = score
                best_match = itype

        return best_match

    def _assess_risk(self, text: str) -> InstructionRisk:
        """Assess risk level of instruction.

        Args:
            text: Instruction text.

        Returns:
            Risk level.
        """
        # Check from most to least dangerous
        risk_order = [
            InstructionRisk.DANGEROUS,
            InstructionRisk.HIGH_RISK,
            InstructionRisk.MEDIUM_RISK,
            InstructionRisk.LOW_RISK,
        ]

        for risk in risk_order:
            patterns = self._risk_patterns.get(risk, [])
            if any(p.search(text) for p in patterns):
                return risk

        return InstructionRisk.SAFE

    def _calculate_summary(
        self,
        instructions: list[Instruction],
    ) -> dict[str, Any]:
        """Calculate summary statistics.

        Args:
            instructions: List of instructions.

        Returns:
            Summary dictionary.
        """
        by_type: dict[str, int] = {}
        by_risk: dict[str, int] = {}

        for inst in instructions:
            type_key = inst.instruction_type.value
            risk_key = inst.risk.value
            by_type[type_key] = by_type.get(type_key, 0) + 1
            by_risk[risk_key] = by_risk.get(risk_key, 0) + 1

        return {
            "total_instructions": len(instructions),
            "by_type": by_type,
            "by_risk": by_risk,
        }

    def _calculate_risk_score(
        self,
        instructions: list[Instruction],
    ) -> float:
        """Calculate overall risk score.

        Args:
            instructions: List of instructions.

        Returns:
            Risk score from 0.0 to 1.0.
        """
        if not instructions:
            return 0.0

        risk_weights = {
            InstructionRisk.SAFE: 0.0,
            InstructionRisk.LOW_RISK: 0.2,
            InstructionRisk.MEDIUM_RISK: 0.5,
            InstructionRisk.HIGH_RISK: 0.8,
            InstructionRisk.DANGEROUS: 1.0,
        }

        total_weight = sum(
            risk_weights.get(inst.risk, 0.0)
            for inst in instructions
        )

        # Normalize to 0-1 range
        max_possible = len(instructions) * 1.0
        return min(total_weight / max_possible, 1.0) if max_possible > 0 else 0.0
