from datetime import datetime, timezone # import the datetime and timezone classes from the datetime module to handle timestamps in UTC

from models.security_event import SecurityEvent # import the SecurityEvent dataclass from the models.security_event module to represent detected anomalies in a structured format


def detect_frequency_anomaly(
    can_id: str, # quel CAN ID on analyse.
    count: int, # combien de messages ont été observés pour ce CAN ID.
    window_seconds: float, # combien de temps on a observé le trafic (5 secondes).
    threshold: float = 100.0 # le seuil de détection d'anomalie en messages par seconde (msg/s). Si le débit observé dépasse ce seuil, on considère qu'il y a une anomalie.
) -> SecurityEvent: # si le débit observé dépasse le seuil, on considère qu'il y a une anomalie. La fonction retourne un objet SecurityEvent qui contient les détails de l'anomalie détectée, y compris le CAN ID, le nombre de messages, le débit observé, le seuil, et d'autres informations pertinentes.

    if window_seconds <= 0:
        raise ValueError("window_seconds must be greater than 0")

    # ----------------------------------------------------------
    # Calculate observed traffic rate
    # ----------------------------------------------------------

    observed_rate = count / window_seconds # Calculate the observed traffic rate in messages per second (msg/s) by dividing the number of messages by the observation window in seconds.

    # ----------------------------------------------------------
    # Detect frequency anomaly
    # ----------------------------------------------------------

    anomaly = observed_rate > threshold # Determine if the observed traffic rate exceeds the specified threshold. If it does, set anomaly to True, indicating that an anomaly has been detected; otherwise, set it to False.

    attack_type = "CAN_FLOODING" if anomaly else None

    # ----------------------------------------------------------
    # Calculate evidence
    # ----------------------------------------------------------

    evidence = [
        f"Message count: {count}",
        f"Observation window: {window_seconds:.2f} seconds",
        f"Observed rate: {observed_rate:.2f} msg/s",
        f"Detection threshold: {threshold:.2f} msg/s"
    ] # On prépare des informations lisibles qui expliquent pourquoi l'anomalie a été détectée

    if anomaly:
        exceed_percentage = (
            (observed_rate - threshold) / threshold
        ) * 100 # Calculate the percentage by which the observed rate exceeds the threshold. This is done by subtracting the threshold from the observed rate, dividing by the threshold, and multiplying by 100 to convert it to a percentage. This value will be included in the evidence to provide additional context about the severity of the anomaly.

        evidence.append(
            f"Observed rate exceeds threshold by "
            f"{exceed_percentage:.2f}%"
        )

    # ----------------------------------------------------------
    # Additional technical metadata
    # ----------------------------------------------------------

    metadata = {
        "detector": "frequency_detector",
        "detector_version": "1.0",
        "rate_ratio": observed_rate / threshold
    } # Ici on garde des informations techniques supplémentaires.

    # ----------------------------------------------------------
    # Create standardized SecurityEvent
    # ----------------------------------------------------------

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