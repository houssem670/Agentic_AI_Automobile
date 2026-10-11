
from datetime import datetime, timezone
from typing import Optional, Sequence

import can

from models.security_event import SecurityEvent


def detect_replay_attack(
    messages: Sequence[can.Message], # List of CAN messages to analyze
    min_repetitions: int = 5, # Minimum number of identical consecutive frames to consider it a replay attack
    max_burst_seconds: float = 0.1, # Maximum duration of a burst of identical frames
    channel: str = "vcan0",
) -> Optional[SecurityEvent]: # Returns a SecurityEvent if a replay attack is suspected, otherwise None

    if min_repetitions < 2:
        raise ValueError("min_repetitions must be at least 2") # minimum of 2 repetitions required to consider it a replay attack

    if max_burst_seconds <= 0:
        raise ValueError("max_burst_seconds must be positive") # maximum burst duration must be positive

    best_run = [] # Crée une liste vide qui conservera la plus longue série de trames identiques trouvée jusqu'ici
    current_run = [] # Crée une deuxième liste vide. Elle contient la série de trames identiques que Python est en train d'analyser
    previous_signature = None # previous_signature doit mémoriser la signature de la trame précédente.

    for message in messages: # Pour chaque message dans la liste messages, exécute les instructions suivantes
        signature = (
            message.arbitration_id,
            bytes(message.data),
            message.is_extended_id,
        )  # La signature est une sorte de carte d'identité de la trame, construite avec trois informations.

        if signature != previous_signature:
            current_run = [message]
        else:
            current_run.append(message)
# Si les trois éléments sont identiques à ceux de la trame précédente, la trame est ajoutée à current_run. Sinon, une nouvelle série commenc
        previous_signature = signature  # Après la comparaison, Python mémorise la signature du message actuel.

        duration = (
            current_run[-1].timestamp - current_run[0].timestamp
        ) # Durée = heure de la dernière trame − heure de la première trame

        if duration < 0 or duration > max_burst_seconds:
            current_run = [message]

        if len(current_run) > len(best_run):
            best_run = current_run.copy()

    if len(best_run) < min_repetitions:
        return None

    duration = best_run[-1].timestamp - best_run[0].timestamp # Le code recalcule la durée de la meilleure série sauvegardée.

    if duration > max_burst_seconds:
        return None # Si cette série dépasse le temps maximal autorisé, aucune suspicion n'est retournée.

    can_id = hex(best_run[0].arbitration_id) # hex() convertit l'identifiant CAN en notation hexadécimale. Par exemple, 291 devient 0x123.

    evidence = [
        f"CAN ID: {can_id}",
        f"Identical consecutive frames: {len(best_run)}",
        f"Burst duration: {duration:.6f} seconds",
        "Repeated CAN ID, payload and frame format",
        "Replay suspicion requires further investigation",
    ]

    return SecurityEvent(
        event_id=(
            "CAN-REPLAY-"
            + datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S%f")
        ),
        timestamp=datetime.now(timezone.utc),
        event_type="CAN_ANOMALY",
        can_id=can_id,
        channel=channel,
        message_count=len(best_run),
        window_seconds=duration,
        observed_rate=(
            len(best_run) / duration if duration > 0 else 0.0
        ),
        detection_rule="CONSECUTIVE_FRAME_REPETITION",
        threshold=float(min_repetitions),
        anomaly=True,
        attack_type="REPLAY_SUSPECTED",
        evidence=evidence,
        metadata={
            "detector": "replay_detector",
            "detector_version": "1.0",
            "repetition_count": len(best_run),
            "heuristic": "CONSECUTIVE_IDENTICAL_FRAMES",
        },
    )