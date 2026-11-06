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

    threat_type: Optional[str] = None
    risk_level: str = "UNKNOWN"

    summary: str = ""

    observed_facts: list[str] = field(default_factory=list)

    security_interpretation: str = ""
    
    unknowns: list[str] = field(default_factory=list)

    investigation_steps: list[str] = field(default_factory=list)

    mitigation_actions: list[str] = field(default_factory=list)

    # ==========================================================
    # Agent confidence
    # ==========================================================

    confidence: Optional[float] = None
