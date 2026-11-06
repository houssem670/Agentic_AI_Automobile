from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Optional


@dataclass(slots=True)
class SecurityEvent:

    event_id: str
    timestamp: datetime
    event_type: str

    can_id: str
    channel: Optional[str] = None

    message_count: int = 0
    window_seconds: float = 0.0
    observed_rate: float = 0.0

    detection_rule: str = ""
    threshold: Optional[float] = None
    anomaly: bool = False
    attack_type: Optional[str] = None  

    evidence: list[str] = field(default_factory=list)

    metadata: dict[str, Any] = field(default_factory=dict)
