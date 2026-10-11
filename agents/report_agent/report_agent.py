
from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from models.security_event import SecurityEvent
from models.security_assessment import SecurityAssessment
from models.diagnostic_report import DiagnosticReport


DEFAULT_OUTPUT_PATH = Path("reports/security_report.md")


def _format_list(items: Optional[list[str]]) -> str:
    """Format a list of observations as Markdown."""
    if not items:
        return "- None provided"

    return "\n".join(
        f"- {str(item)}" for item in items
    )


def _format_confidence(value: object) -> str:
    """Format confidence only when it is a valid value in [0, 1]."""
    if value is None or isinstance(value, bool):
        return "Not available"

    try:
        confidence = float(value)
    except (TypeError, ValueError):
        return "Not available"

    if not 0.0 <= confidence <= 1.0:
        return "Not available"

    return f"{confidence:.0%}"


def _format_timestamp(value: object) -> str:
    """Format a timestamp without assuming it is always a datetime."""
    if isinstance(value, datetime):
        return value.isoformat()

    return str(value) if value is not None else "Unknown"


def generate_security_report(
    event: SecurityEvent,
    assessment: SecurityAssessment,
    diagnostic: DiagnosticReport,
) -> str:
    """
    Generate a Markdown report from existing detector and agent results.

    This function does not call an LLM and does not infer new findings.
    """
    generated_at = datetime.now(timezone.utc).strftime(
        "%Y-%m-%d %H:%M:%S UTC"
    )

    threat_type = (
        assessment.threat_type
        or event.attack_type
        or "Unknown"
    )
    risk_level = assessment.risk_level or "UNKNOWN"

    report = f"""# Automotive CAN Security Report

> Generated automatically by the Agentic Automotive Security Platform.

## 1. Report Information

| Field | Value |
|---|---|
| Generated at | {generated_at} |
| Event ID | {event.event_id} |
| Event timestamp | {_format_timestamp(event.timestamp)} |
| CAN interface | {event.channel or "Unknown"} |
| CAN ID | {event.can_id} |
| Detection rule | {event.detection_rule or "Unknown"} |

## 2. Executive Summary

{assessment.summary or "No security summary provided."}

## 3. Detection Evidence

| Metric | Value |
|---|---|
| Event type | {event.event_type} |
| Detector attack label | {event.attack_type or "Unknown"} |
| Anomaly flagged | {event.anomaly} |
| Message count | {event.message_count} |
| Observation duration | {event.window_seconds:.6f} seconds |
| Observed rate | {event.observed_rate:.2f} messages/second |
| Detector threshold | {event.threshold if event.threshold is not None else "Not specified"} |

### Evidence recorded by the detector

{_format_list(event.evidence)}

## 4. Security Assessment

| Field | Value |
|---|---|
| Threat classification | {threat_type} |
| Assessed risk level | {risk_level} |
| Assessment confidence | {_format_confidence(assessment.confidence)} |

### Observed facts

{_format_list(assessment.observed_facts)}

### Security interpretation

{assessment.security_interpretation or "No security interpretation provided."}

### Unknowns and limitations

{_format_list(assessment.unknowns)}

### Recommended investigation steps

{_format_list(assessment.investigation_steps)}

### Recommended defensive actions

{_format_list(assessment.mitigation_actions)}

## 5. Diagnostic Analysis

| Field | Value |
|---|---|
| Diagnostic event ID | {diagnostic.event_id or "Not specified"} |
| Diagnostic confidence | {_format_confidence(diagnostic.confidence)} |
| Analysis method | {diagnostic.analysis_method or "Unknown"} |
| Root cause confirmed | {diagnostic.root_cause_confirmed} |

### Diagnostic summary

{diagnostic.diagnostic_summary or "No diagnostic summary provided."}

### Probable causes — hypotheses, not confirmed facts

{_format_list(diagnostic.probable_causes)}

### Supporting evidence

{_format_list(diagnostic.supporting_evidence)}

### Diagnostic unknowns

{_format_list(diagnostic.unknowns)}

### Recommended diagnostic checks

{_format_list(diagnostic.recommended_checks)}

## 6. Conclusion and Limitations

This report consolidates the deterministic CAN detection results,
the Security Agent's assessment, and the Diagnostic Agent's analysis.

A suspected replay attack or another anomaly is not, by itself,
proof of malicious activity, ECU compromise, or a confirmed vehicle fault.

Confidence values represent the agents' reported confidence scores.
They are not calibrated probabilities that an attack occurred.

Recommended checks may not have been performed, and recommended
mitigations may not have been deployed. Further investigation is
required before drawing operational or safety-related conclusions.
"""

    return report


def save_security_report(
    report: str,
    output_path: str | Path = DEFAULT_OUTPUT_PATH,
) -> str:
    """Save a generated report and return its absolute file path."""
    if not isinstance(report, str) or not report.strip():
        raise ValueError("The report must be a non-empty string.")

    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(report, encoding="utf-8")

    return str(path.resolve())
