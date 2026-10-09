import time # mesurer les 5 secondes d'observation.
from collections import Counter # compter les messages par CAN ID

import can # bibliothèque python-can, qui permet de communiquer avec vcan0.n

from tools.anomaly_detector.anomaly_detector import detect_frequency_anomaly # notre détecteur qui décidera si le débit est anormal


def analyze_can_traffic(window_seconds=5,  threshold=100):  # coute le CAN pendant 5 secondes et considère qu'un débit supérieur à 100 messages/s est anormal

    bus = can.interface.Bus(
        channel="vcan0",
        interface="socketcan"
    ) # Connecte-toi à l'interface vcan0 en utilisant SocketCAN, l'interface CAN native de Linux

    print(f"Listening on vcan0 for {window_seconds} seconds...")

    messages = []  # Initialize an empty list to store received CAN messages

    start_time = time.time() # Record the start time to measure the elapsed time during the listening period

    try:
        while time.time() - start_time < window_seconds: # Continue à écouter tant que le temps écoulé est inférieur à 5 secondes
            message = bus.recv(timeout=1) # Wait for a CAN message with a timeout of 1 second. If no message is received within this time, it will return None.

            if message is not None: # If a message is received, append it to the messages list for later analysis.
                messages.append(message)

    finally:
        bus.shutdown() # Ferme proprement la connexion avec vcan0

    counts = Counter(
        hex(message.arbitration_id)
        for message in messages
    ) # Count the occurrences of each CAN ID in the received messages and store them in a Counter object. The CAN IDs are converted to hexadecimal format for better readability.

    detections = [] # Initialize an empty list to store the results of the anomaly detection for each CAN ID.

    print("\n=== CAN TRAFFIC ===")

    for can_id, count in counts.items():

        print(f"{can_id} -> {count} messages")

        detection = detect_frequency_anomaly( # Call the detect_frequency_anomaly function to analyze the frequency of messages for each CAN ID. It checks if the observed rate exceeds the specified threshold and returns a dictionary with the analysis results.
            can_id=can_id,
            count=count,
            window_seconds=window_seconds,
            threshold=threshold
        )

        print("Detection:", detection) # Print the detection results for each CAN ID, including the observed rate, whether an anomaly was detected, and the attack type if applicable.

        detections.append(detection) # Append the detection results to the detections list for later use in the security analysis.

    return detections # Return the list of detections, which contains the analysis results for each CAN ID, including whether an anomaly was detected and the associated attack type if applicable.