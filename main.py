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

        if detection.anomaly:

            print("\nAnomaly detected!")

            assessment = security_agent(detection)

            print("\n--- SECURITY ASSESSMENT ---")

            print(f"\nThreat Type: {assessment.threat_type}")
            print(f"Risk Level: {assessment.risk_level}")
            print(f"Confidence: {assessment.confidence}")

            print("\nSummary:")
            print(assessment.summary)

            print("\nObserved Facts:")
            for fact in assessment.observed_facts:
               print(f"  - {fact}")

            print("\nSecurity Interpretation:")
            print(assessment.security_interpretation)

            print("\nUnknown Information:")
            for unknown in assessment.unknowns:
               print(f"  - {unknown}")

            print("\nRecommended Investigation:")
            for step in assessment.investigation_steps:
               print(f"  {step}")

            print("\nRecommended Mitigation:")
            for action in assessment.mitigation_actions:
                print(f"  {action}")

        else:

            print(
                f"\n{detection.can_id} -> "
                "No anomaly detected."
            )


if __name__ == "__main__":
    main()