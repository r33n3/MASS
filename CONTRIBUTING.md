# Contributing to MASS

Thank you for your interest in contributing to MASS! This document provides guidelines and information for contributors.

## Code of Conduct

Please be respectful and constructive in all interactions. We welcome contributors of all backgrounds and experience levels.

## Getting Started

### Development Setup

1. Fork and clone the repository:
   ```bash
   git clone https://github.com/YOUR_USERNAME/MASS.git
   cd MASS
   ```

2. Create a virtual environment:
   ```bash
   python -m venv .venv
   source .venv/bin/activate  # On Windows: .venv\Scripts\activate
   ```

3. Install development dependencies:
   ```bash
   pip install -e ".[dev]"
   ```

4. Install pre-commit hooks:
   ```bash
   pre-commit install
   ```

5. Run tests to verify setup:
   ```bash
   pytest
   ```

### Project Structure

```
MASS/
├── src/mass/           # Main package
│   ├── api/            # FastAPI application
│   ├── core/           # Core types and utilities
│   ├── analyzers/      # Analysis engines
│   ├── probes/         # Attack probe plugins
│   ├── detectors/      # Detection plugins
│   ├── compliance/     # Compliance frameworks
│   └── reporting/      # Report generation
├── cli/                # CLI package
├── sdk/                # Python SDK package
├── tests/              # Test suite
├── docs/               # Documentation
└── helm/               # Kubernetes deployment
```

## How to Contribute

### Reporting Bugs

1. Check existing issues to avoid duplicates
2. Use the bug report template
3. Include:
   - MASS version
   - Python version
   - Operating system
   - Steps to reproduce
   - Expected vs actual behavior
   - Relevant logs or error messages

### Suggesting Features

1. Check existing issues and discussions
2. Use the feature request template
3. Describe:
   - The problem you're trying to solve
   - Your proposed solution
   - Alternative approaches considered
   - Potential impact on existing functionality

### Submitting Code

1. **Create a branch** from `PROD`:
   ```bash
   git checkout PROD
   git checkout -b feature/your-feature-name
   ```

2. **Make your changes**:
   - Follow the code style (enforced by ruff)
   - Add type hints (enforced by mypy)
   - Write tests for new functionality
   - Update documentation as needed

3. **Run quality checks**:
   ```bash
   # Linting
   ruff check src/ tests/
   ruff format src/ tests/

   # Type checking
   mypy src/

   # Tests
   pytest --cov=src/mass
   ```

4. **Commit your changes**:
   - Use clear, descriptive commit messages
   - Reference related issues: `Fixes #123`

5. **Push and create a PR**:
   - Fill out the PR template
   - Link related issues
   - Request review from maintainers

### Writing Probes and Detectors

MASS uses a plugin architecture for probes (attack generators) and detectors (vulnerability identifiers).

#### Creating a Probe

```python
# src/mass/probes/custom/my_probe.py
from mass.probes.base import BaseProbe
from mass.core.types import AttackCategory

class MyCustomProbe(BaseProbe):
    """Description of what this probe tests."""

    name = "my_custom_probe"
    description = "Tests for specific vulnerability"
    category = AttackCategory.PROMPT_INJECTION
    tags = ["custom", "injection"]

    async def generate_prompts(self):
        """Generate test prompts."""
        yield "Test prompt 1"
        yield "Test prompt 2"

    def get_detectors(self) -> list[str]:
        """Compatible detectors."""
        return ["keyword", "llm_judge"]
```

#### Creating a Detector

```python
# src/mass/detectors/custom/my_detector.py
from mass.detectors.base import BaseDetector, DetectionResult

class MyCustomDetector(BaseDetector):
    """Description of what this detector identifies."""

    name = "my_custom_detector"
    description = "Detects specific vulnerability pattern"

    async def detect(self, prompt: str, response: str) -> DetectionResult:
        """Analyze response for vulnerability."""
        # Detection logic here
        return DetectionResult(
            detected=False,
            confidence=0.0,
            evidence=[]
        )
```

### Writing Tests

- Place unit tests in `tests/unit/`
- Place integration tests in `tests/integration/`
- Place end-to-end tests in `tests/e2e/`
- Use pytest fixtures from `conftest.py`
- Aim for >80% code coverage

Example test:
```python
# tests/unit/core/test_types.py
import pytest
from mass.core.types import RiskLevel, Severity

def test_risk_level_ordering():
    assert RiskLevel.CRITICAL.value == "critical"
    assert RiskLevel.SAFE.value == "safe"

def test_severity_enum():
    assert Severity.HIGH in Severity
```

## Code Style

- **Python**: Follow PEP 8, enforced by ruff
- **Type hints**: Required for all public APIs
- **Docstrings**: Google style for modules, classes, and functions
- **Line length**: 100 characters maximum
- **Imports**: Sorted by isort (via ruff)

## Documentation

- Update docstrings for API changes
- Update README for user-facing changes
- Add examples for new features
- Use Markdown for documentation files

## Release Process

1. Update `CHANGELOG.md`
2. Update version in `src/mass/version.py`
3. Create a release PR
4. After merge, tag the release
5. GitHub Actions handles PyPI publishing

## Getting Help

- Open a GitHub Discussion for questions
- Join our community channels (coming soon)
- Tag maintainers in issues for urgent matters

## Recognition

Contributors are recognized in:
- The CHANGELOG for their contributions
- The GitHub contributors page
- Release notes for significant contributions

Thank you for contributing to MASS!
