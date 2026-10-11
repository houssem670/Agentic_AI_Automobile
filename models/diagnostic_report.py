
from dataclasses import dataclass, field


@dataclass(slots=True)
class DiagnosticReport:
    """Structured, evidence-based diagnostic report."""

    event_id: str = ""

    diagnostic_summary: str = ""

    probable_causes: list[str] = field(
        default_factory=list
    )

    supporting_evidence: list[str] = field(
        default_factory=list
    )

    unknowns: list[str] = field(
        default_factory=list
    )

    recommended_checks: list[str] = field(
        default_factory=list
    )

    root_cause_confirmed: bool = False

    confidence: float = 0.0

    analysis_method: str = "LLM"