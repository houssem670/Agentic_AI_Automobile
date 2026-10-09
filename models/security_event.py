from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Optional


@dataclass(slots=True)
class SecurityEvent:

    # ==========================================================
    # Event identification
    # ==========================================================

    event_id: str
    timestamp: datetime
    event_type: str

    # ==========================================================
    # CAN context
    # ==========================================================

    can_id: str
    channel: Optional[str] = None

    # ==========================================================
    # Traffic measurements
    # ==========================================================

    message_count: int = 0
    window_seconds: float = 0.0
    observed_rate: float = 0.0

    # ==========================================================
    # Detection information
    # ==========================================================

    detection_rule: str = ""
    threshold: Optional[float] = None
    anomaly: bool = False
    attack_type: Optional[str] = None  # ⚠️ Important : attack_type ici vient du détecteur déterministe, pas de Gemini.

    # ==========================================================
    # Evidence
    # ==========================================================

    evidence: list[str] = field(default_factory=list)

    # ==========================================================
    # Additional technical context
    # ==========================================================

    metadata: dict[str, Any] = field(default_factory=dict)