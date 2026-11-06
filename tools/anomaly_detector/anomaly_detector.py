from datetime import datetime, timezone 

from models.security_event import SecurityEvent 


def detect_frequency_anomaly(
    can_id: str, 
    count: int, 
    window_seconds: float, 
    threshold: float = 100.0 
) -> SecurityEvent: 

    if count < 0:
        raise ValueError("count must be non-negative")

    if window_seconds <= 0:
        raise ValueError("window_seconds must be greater than 0")

    if threshold <= 0:
       raise ValueError("threshold must be greater than 0")

    observed_rate = count / window_seconds 
    anomaly = observed_rate > threshold 
    attack_type = "CAN_FLOODING" if anomaly else None

    evidence = [
        f"Message count: {count}",
        f"Observation window: {window_seconds:.2f} seconds",
        f"Observed rate: {observed_rate:.2f} msg/s",
        f"Detection threshold: {threshold:.2f} msg/s"
    ] 
    if anomaly:
        exceed_percentage = (
            (observed_rate - threshold) / threshold
        ) * 100 

        evidence.append(
            f"Observed rate exceeds threshold by "
            f"{exceed_percentage:.2f}%"
        )

    metadata = {
        "detector": "frequency_detector",
        "detector_version": "1.0",
        "rate_ratio": observed_rate / threshold
    }

    return SecurityEvent(
        event_id=f"CAN-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S%f')}",

        timestamp=datetime.now(timezone.utc),

        event_type=(
            "CAN_ANOMALY"
            if anomaly
            else "CAN_TRAFFIC"
        ),

        can_id=can_id,
        channel="vcan0",

        message_count=count,
        window_seconds=window_seconds,
        observed_rate=observed_rate,

        detection_rule="FREQUENCY_THRESHOLD",
        threshold=threshold,

        anomaly=anomaly,
        attack_type=attack_type,

        evidence=evidence,
        metadata=metadata
    )
