
from tools.can_analyzer.can_analyzer import analyze_can_traffic
from agents.security_agent.security_agent import security_agent
from agents.diagnostic_agent.diagnostic_agent import diagnostic_agent
from agents.report_agent.report_agent import (
    generate_security_report,
    save_security_report,
)
from models.security_assessment import SecurityAssessment
from models.diagnostic_report import DiagnosticReport


def main():
    print("=" * 45)
    print(" AUTOMOTIVE CAN SECURITY PLATFORM ")
    print("=" * 45)

    # 1. Capture CAN traffic and run deterministic detectors
    detections = analyze_can_traffic(
        window_seconds=5,
        threshold=100,
    )

    print("\n=== SECURITY ANALYSIS & DIAGNOSTICS ===")

    reports = []

    # 2. Analyze every detected anomaly
    for detection in detections:
        if not detection.anomaly:
            continue

        print(f"\n{'=' * 45}")
        print(f"Anomaly detected: {detection.attack_type}")
        print(f"CAN ID: {detection.can_id}")
        print(f"Detection rule: {detection.detection_rule}")

        # 3. Security Agent
        try:
            assessment = security_agent(detection)
        except Exception as exc:
            print(f"[Security Agent] Failed: {exc}")
            assessment = SecurityAssessment(
                threat_type=detection.attack_type,
                risk_level="UNKNOWN",
                summary="Security assessment could not be completed.",
                unknowns=[f"Security Agent error: {type(exc).__name__}"],
            )

        print("\n--- SECURITY ASSESSMENT ---")
        print(f"Threat type: {assessment.threat_type}")
        print(f"Risk level: {assessment.risk_level}")
        print(f"Summary: {assessment.summary}")

        # 4. Diagnostic Agent
        try:
            diagnostic = diagnostic_agent(detection)

            print("\n--- DIAGNOSTIC AGENT ---")
            print(f"Analysis method: {diagnostic.analysis_method}")
            print(f"Confidence: {diagnostic.confidence:.2f}")
            print(f"Root cause confirmed: {diagnostic.root_cause_confirmed}")
            print(diagnostic.diagnostic_summary)

        except Exception as exc:
            print(f"[Diagnostic Agent] Failed: {exc}")

            diagnostic = DiagnosticReport(
                event_id=detection.event_id,
                diagnostic_summary=(
                    "Diagnostic analysis could not be completed."
                ),
                unknowns=[
                    f"Diagnostic Agent error: {type(exc).__name__}"
                ],
                root_cause_confirmed=False,
                analysis_method="ERROR",
            )

        # 5. Report Agent
        try:
            report = generate_security_report(
                event=detection,
                assessment=assessment,
                diagnostic=diagnostic,
            )
            reports.append(report)
            print("[Report Agent] Report generated successfully.")

        except Exception as exc:
            print(
                f"[Report Agent] Failed: "
                f"{type(exc).__name__}: {exc}"
            )

    # 6. Save all generated reports into one Markdown file
    if reports:
        combined_report = "\n\n---\n\n".join(reports)

        try:
            output_path = save_security_report(
                combined_report,
                "reports/security_report.md",
            )
            print(f"\nReport saved to: {output_path}")

        except Exception as exc:
            print(
                f"[Report Agent] Could not save report: "
                f"{type(exc).__name__}: {exc}"
            )
    else:
        print("\nNo anomalous events to report.")

    print("\n=== ANALYSIS COMPLETE ===")


if __name__ == "__main__":
    main()