
import time
from collections import Counter

import can

from tools.anomaly_detector.anomaly_detector import detect_frequency_anomaly
from tools.anomaly_detector.replay_detector import detect_replay_attack


def analyze_can_traffic(window_seconds=5, threshold=100):
    bus = can.interface.Bus(
        channel="vcan0",
        interface="socketcan"
    )

    print(f"Listening on vcan0 for {window_seconds} seconds...")

    messages = []
    start_time = time.time()

    try:
        while time.time() - start_time < window_seconds:
            message = bus.recv(timeout=1)

            if message is not None:
                messages.append(message)

    finally:
        bus.shutdown()

    counts = Counter(
        hex(message.arbitration_id)
        for message in messages
    )

    detections = []

    # 1. Détection des anomalies de fréquence
    print("\n=== CAN TRAFFIC ===")

    for can_id, count in counts.items():
        print(f"{can_id} -> {count} messages")

        detection = detect_frequency_anomaly(
            can_id=can_id,
            count=count,
            window_seconds=window_seconds,
            threshold=threshold
        )

        print("Frequency detection:", detection)
        detections.append(detection)

    # 2. Détection des répétitions suspectes (Replay Detector)
    print("\n=== REPLAY DETECTION ===")

    replay_event = detect_replay_attack(
        messages=messages,
        channel="vcan0"
    )

    if replay_event is not None:
        print("Replay suspicion detected!")
        print(f"CAN ID: {replay_event.can_id}")
        print(f"Attack type: {replay_event.attack_type}")
        print(f"Repeated frames: {replay_event.message_count}")

        for evidence in replay_event.evidence:
            print(f"  - {evidence}")

        detections.append(replay_event)

    else:
        print("No suspicious consecutive frame repetition detected.")

    return detections