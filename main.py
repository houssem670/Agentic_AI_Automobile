from tools.can_analyzer.can_analyzer import analyze_can_traffic
from agents.security_agent.security_agent import security_agent


def main():

    print("===================================")
    print(" AUTOMOTIVE CAN SECURITY PLATFORM ")
    print("===================================\n")

    detections = analyze_can_traffic(
        window_seconds=5,
        threshold=100
    )

    print("\n=== SECURITY ANALYSIS ===")

    for detection in detections:

        if detection["anomaly"]:

            print("\nAnomaly detected!")

            result = security_agent(detection)

            print("\n--- Security Agent Result ---")
            print(result)

        else:

            print(
                f"\n{detection['can_id']} -> "
                "No anomaly detected."
            )


if __name__ == "__main__":
    main()