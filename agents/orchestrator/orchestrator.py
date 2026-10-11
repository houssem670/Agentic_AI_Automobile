from typing import TypedDict

from langgraph.graph import StateGraph, START, END

from models.security_event import SecurityEvent
from models.security_assessment import SecurityAssessment
from models.diagnostic_report import DiagnosticReport

from agents.security_agent.security_agent import security_agent
from agents.diagnostic_agent.diagnostic_agent import diagnostic_agent
from agents.report_agent.report_agent import (
    generate_security_report,
    save_security_report,
)


class WorkflowState(TypedDict):
    event: SecurityEvent
    assessment: SecurityAssessment
    diagnostic: DiagnosticReport
    report: str
    report_path: str
    errors: list[str]


def security_node(state: WorkflowState) -> dict:
    try:
        assessment = security_agent(state["event"])
        return {"assessment": assessment}

    except Exception as exc:
        error = (
            f"Security Agent failed: "
            f"{type(exc).__name__}: {exc}"
        )
        print(f"[Orchestrator] {error}")

        assessment = SecurityAssessment(
            threat_type=state["event"].attack_type,
            risk_level="UNKNOWN",
            summary=(
                "Security assessment unavailable. "
                "Manual investigation is required."
            ),
            observed_facts=[
                f"CAN ID: {state['event'].can_id}",
                f"Detection rule: {state['event'].detection_rule}",
            ],
            unknowns=[
                "The security assessment could not be completed."
            ],
        )

        return {
            "assessment": assessment,
            "errors": state.get("errors", []) + [error],
        }


def diagnostic_node(state: WorkflowState) -> dict:
    try:
        diagnostic = diagnostic_agent(state["event"])
        return {"diagnostic": diagnostic}

    except Exception as exc:
        error = (
            f"Diagnostic Agent failed: "
            f"{type(exc).__name__}: {exc}"
        )
        print(f"[Orchestrator] {error}")

        diagnostic = DiagnosticReport(
            event_id=state["event"].event_id,
            diagnostic_summary=(
                "Diagnostic analysis unavailable. "
                "Manual investigation is required."
            ),
            unknowns=[
                "The Diagnostic Agent could not complete its analysis."
            ],
            recommended_checks=[
                "Inspect the captured CAN frames.",
                "Compare the traffic with a trusted normal baseline.",
            ],
            root_cause_confirmed=False,
            confidence=0.0,
            analysis_method="FALLBACK",
        )

        return {
            "diagnostic": diagnostic,
            "errors": state.get("errors", []) + [error],
        }


def report_node(state: WorkflowState) -> dict:
    errors = list(state.get("errors", []))

    try:
        report = generate_security_report(
            event=state["event"],
            assessment=state["assessment"],
            diagnostic=state["diagnostic"],
        )

    except Exception as exc:
        error = (
            f"Report generation failed: "
            f"{type(exc).__name__}: {exc}"
        )
        errors.append(error)
        print(f"[Orchestrator] {error}")

        event = state["event"]
        assessment = state["assessment"]
        diagnostic = state["diagnostic"]

        report = f"""# Automotive CAN Security Report

## Detection
- Event ID: {event.event_id}
- CAN ID: {event.can_id}
- Channel: {event.channel}
- Attack suspicion: {event.attack_type}
- Detection rule: {event.detection_rule}
- Message count: {event.message_count}

## Security Assessment
- Risk level: {assessment.risk_level}
- Summary: {assessment.summary}

## Diagnostic Analysis
- Summary: {diagnostic.diagnostic_summary}
- Root cause confirmed: {diagnostic.root_cause_confirmed}
- Confidence: {diagnostic.confidence}

## Errors and Limitations
{chr(10).join('- ' + item for item in errors) or '- None'}
"""

    if errors:
        report += (
            "\n\n## Orchestrator Errors and Limitations\n\n"
            + "\n".join(f"- {error}" for error in errors)
            + "\n"
        )

    try:
        report_path = save_security_report(
            report,
            "reports/security_report.md",
        )
        print(f"[Report Agent] Report saved: {report_path}")

    except Exception as exc:
        error = (
            f"Report saving failed: "
            f"{type(exc).__name__}: {exc}"
        )
        errors.append(error)
        report_path = ""
        print(f"[Orchestrator] {error}")
        print("[Orchestrator] Report content remains available in memory.")

    return {
        "report": report,
        "report_path": report_path,
        "errors": errors,
    }


def build_workflow():
    workflow = StateGraph(WorkflowState)

    workflow.add_node("security", security_node)
    workflow.add_node("diagnostic", diagnostic_node)
    workflow.add_node("report", report_node)

    workflow.add_edge(START, "security")
    workflow.add_edge("security", "diagnostic")
    workflow.add_edge("diagnostic", "report")
    workflow.add_edge("report", END)

    return workflow.compile()


def run_workflow(event: SecurityEvent) -> WorkflowState:
    app = build_workflow()

    initial_state: WorkflowState = {
        "event": event,
        "assessment": SecurityAssessment(),
        "diagnostic": DiagnosticReport(),
        "report": "",
        "report_path": "",
        "errors": [],
    }

    return app.invoke(initial_state)
