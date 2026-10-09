from dataclasses import dataclass, field
from typing import Optional


@dataclass(slots=True)
class SecurityAssessment:
    """
    Structured security assessment produced by the Security Agent.

    SecurityEvent contains measured/deterministic facts.
    SecurityAssessment contains the security interpretation
    produced by the Security Agent.
    """ 

    # ==========================================================
    # Threat classification
    # ==========================================================

    threat_type: Optional[str] = None

    # LOW / MEDIUM / HIGH / CRITICAL / UNKNOWN
    risk_level: str = "UNKNOWN"

    # ==========================================================
    # Executive summary
    # ==========================================================

    summary: str = ""

    # ==========================================================
    # Evidence-based analysis
    # ==========================================================

    observed_facts: list[str] = field(default_factory=list)

    security_interpretation: str = ""

    # ==========================================================
    # Information that cannot be established
    # ==========================================================

    unknowns: list[str] = field(default_factory=list)

    # ==========================================================
    # Recommended investigation
    # ==========================================================

    investigation_steps: list[str] = field(default_factory=list)

    # ==========================================================
    # Recommended defensive actions
    # ==========================================================

    mitigation_actions: list[str] = field(default_factory=list)

    # ==========================================================
    # Agent confidence
    # ==========================================================

    confidence: Optional[float] = None