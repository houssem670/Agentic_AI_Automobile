def detect_frequency_anomaly(
    can_id: str,
    count: int,
    window_seconds: float,
    threshold: float = 100.0
): # This function detects frequency anomalies in CAN bus traffic based on the observed message count, observation window, and a specified threshold. It calculates the observed rate of messages per second and determines if it exceeds the threshold, indicating a potential anomaly.
    if window_seconds <= 0:
        raise ValueError("window_seconds must be greater than 0") # Validate that the observation window is a positive value to avoid division by zero or negative rates.

    rate = count / window_seconds # Calculate the observed rate of messages per second by dividing the total message count by the observation window in seconds.

    is_anomaly = rate > threshold # Determine if the observed rate exceeds the specified threshold, indicating a potential anomaly in the CAN bus traffic.

    return {
        "can_id": can_id,
        "message_count": count,
        "window_seconds": window_seconds,
        "observed_rate": rate,
        "threshold": threshold,
        "anomaly": is_anomaly,
        "attack_type": "CAN_FLOODING" if is_anomaly else None
    }