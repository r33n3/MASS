"""Risk questionnaire schemas.

Captures user-provided context about a target's deployment environment,
data sensitivity, and compliance requirements. Used to adjust threat
severity and focus the security analysis.
"""

from pydantic import BaseModel, ConfigDict, Field


class RiskQuestionnaire(BaseModel):
    """Risk context questionnaire for a target."""

    model_config = ConfigDict(extra="forbid")

    is_public_facing: bool | None = Field(
        default=None, description="Is this target accessible from the internet?"
    )
    user_count: str | None = Field(
        default=None,
        description="Approximate user base: internal_only, lt_100, 100_to_10k, 10k_plus",
    )
    data_sensitivity: str | None = Field(
        default=None,
        description="Data sensitivity: public, internal, confidential, regulated",
    )
    compliance_frameworks: list[str] | None = Field(
        default=None,
        description="Applicable compliance: soc2, hipaa, gdpr, pci, none",
    )
    handles_pii: bool | None = Field(
        default=None, description="Does this target process personally identifiable information?"
    )
    has_payment_data: bool | None = Field(
        default=None, description="Does this target process payment or financial data?"
    )
    deployment_environment: str | None = Field(
        default=None,
        description="Environment: development, staging, production",
    )


class QuestionnaireResponse(BaseModel):
    """Response after saving a risk questionnaire."""

    model_config = ConfigDict(extra="forbid")

    questionnaire: RiskQuestionnaire = Field(..., description="Saved questionnaire data")
    risk_multiplier: float = Field(..., description="Computed risk multiplier (1.0 = baseline)")
    risk_factors: list[str] = Field(default_factory=list, description="Human-readable risk factors")


def compute_risk_factors(q: RiskQuestionnaire) -> tuple[float, list[str]]:
    """Compute risk multiplier and human-readable factors from questionnaire.

    Returns:
        Tuple of (multiplier, list of factor descriptions).
    """
    multiplier = 1.0
    factors: list[str] = []

    if q.is_public_facing:
        multiplier += 0.4
        factors.append("Public-facing: exposed to internet-based attacks")

    if q.deployment_environment == "production":
        multiplier += 0.3
        factors.append("Production environment: real user impact")
    elif q.deployment_environment == "staging":
        multiplier += 0.1
        factors.append("Staging environment: may mirror production data")

    if q.data_sensitivity == "regulated":
        multiplier += 0.5
        factors.append("Regulated data: compliance violations carry legal risk")
    elif q.data_sensitivity == "confidential":
        multiplier += 0.3
        factors.append("Confidential data: breach would cause significant harm")
    elif q.data_sensitivity == "internal":
        multiplier += 0.1
        factors.append("Internal data: limited exposure but still sensitive")

    if q.handles_pii:
        multiplier += 0.3
        factors.append("Handles PII: data breach notification requirements apply")

    if q.has_payment_data:
        multiplier += 0.4
        factors.append("Payment data: PCI-DSS compliance required")

    if q.user_count == "10k_plus":
        multiplier += 0.3
        factors.append("Large user base (10k+): wide blast radius")
    elif q.user_count == "100_to_10k":
        multiplier += 0.2
        factors.append("Medium user base (100-10k): moderate blast radius")

    if q.compliance_frameworks:
        frameworks = [f for f in q.compliance_frameworks if f != "none"]
        if frameworks:
            multiplier += 0.1 * len(frameworks)
            factors.append(f"Compliance: {', '.join(f.upper() for f in frameworks)}")

    return round(multiplier, 2), factors
