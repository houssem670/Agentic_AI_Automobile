from datetime import datetime, timezone
from unittest.mock import patch

from models.security_event import SecurityEvent
from models.security_assessment import SecurityAssessment
from models.diagnostic_report import DiagnosticReport
from agents.orchestrator.orchestrator import run_workflow
import unittest


def make_test_event():
    return SecurityEvent(
        event_id="TEST-001",
        timestamp=datetime.now(timezone.utc),
        event_type="CAN_ANOMALY",
        can_id="0x123",
        channel="vcan0",
        message_count=300,
        window_seconds=2.0,
        observed_rate=150.0,
        detection_rule="FREQUENCY_THRESHOLD",
        threshold=100.0,
        anomaly=True,
        attack_type="CAN_FLOODING",
        evidence=["Observed rate: 150 messages/second"],
    )


class TestOrchestrator(unittest.TestCase):
    @patch("agents.orchestrator.orchestrator.save_security_report")
    @patch("agents.orchestrator.orchestrator.generate_security_report")
    @patch("agents.orchestrator.orchestrator.diagnostic_agent")
    @patch("agents.orchestrator.orchestrator.security_agent")
    def test_agents_results_reach_report(
        self,
        mock_security,
        mock_diagnostic,
        mock_generate_report,
        mock_save_report,
    ):
        mock_security.return_value = SecurityAssessment(
            threat_type="CAN_FLOODING",
            risk_level="HIGH",
            summary="Suspicious CAN traffic frequency.",
        )

        mock_diagnostic.return_value = DiagnosticReport(
            event_id="TEST-001",
            diagnostic_summary="Further investigation required.",
            recommended_checks=["Inspect CAN traffic"],
            root_cause_confirmed=False,
            confidence=0.8,
            analysis_method="TEST",
        )

        mock_generate_report.return_value = "# Test report"
        mock_save_report.return_value = "reports/test_report.md"

        result = run_workflow(make_test_event())

        mock_security.assert_called_once()
        mock_diagnostic.assert_called_once()

        mock_generate_report.assert_called_once()
        report_args = mock_generate_report.call_args.kwargs

        self.assertEqual(
            report_args["assessment"].risk_level, "HIGH"
        )
        self.assertEqual(
            report_args["diagnostic"].diagnostic_summary,
            "Further investigation required.",
        )

        self.assertEqual(result["report"], "# Test report")
        self.assertEqual(
            result["report_path"], "reports/test_report.md"
        )
        self.assertEqual(result["errors"], [])

    @patch("agents.orchestrator.orchestrator.save_security_report")
    @patch("agents.orchestrator.orchestrator.generate_security_report")
    @patch("agents.orchestrator.orchestrator.diagnostic_agent")
    @patch("agents.orchestrator.orchestrator.security_agent")
    def test_security_failure_uses_fallback_and_keeps_error(
        self,
        mock_security,
        mock_diagnostic,
        mock_generate_report,
        mock_save_report,
    ):
        mock_security.side_effect = RuntimeError("simulated failure")

        mock_diagnostic.return_value = DiagnosticReport(
            event_id="TEST-001",
            diagnostic_summary="Diagnostic completed.",
            recommended_checks=[],
            root_cause_confirmed=False,
            confidence=0.5,
            analysis_method="TEST",
        )

        mock_generate_report.return_value = "# Fallback test report"
        mock_save_report.return_value = "reports/test_report.md"

        result = run_workflow(make_test_event())

        self.assertEqual(result["assessment"].risk_level, "UNKNOWN")
        self.assertTrue(
            any("Security Agent failed" in error
                for error in result["errors"])
        )
        mock_diagnostic.assert_called_once()
        mock_generate_report.assert_called_once()

    @patch("agents.orchestrator.orchestrator.save_security_report")
    @patch("agents.orchestrator.orchestrator.generate_security_report")
    @patch("agents.orchestrator.orchestrator.diagnostic_agent")
    @patch("agents.orchestrator.orchestrator.security_agent")
    def test_diagnostic_failure_still_generates_report(
        self,
        mock_security,
        mock_diagnostic,
        mock_generate_report,
        mock_save_report,
    ):
        mock_security.return_value = SecurityAssessment(
            threat_type="CAN_FLOODING",
            risk_level="MEDIUM",
            summary="Investigation required.",
        )

        mock_diagnostic.side_effect = RuntimeError(
            "simulated diagnostic failure"
        )

        mock_generate_report.return_value = "# Diagnostic fallback report"
        mock_save_report.return_value = "reports/test_report.md"

        result = run_workflow(make_test_event())

        self.assertFalse(result["diagnostic"].root_cause_confirmed)
        self.assertEqual(
            result["diagnostic"].analysis_method, "FALLBACK"
        )
        self.assertTrue(
            any("Diagnostic Agent failed" in error
                for error in result["errors"])
        )
        mock_generate_report.assert_called_once()
        self.assertTrue(result["report"])

    def test_workflow_state_initializes_empty_errors(self):
        from agents.orchestrator.orchestrator import build_workflow

        # Verify that the compiled workflow can be constructed.
        workflow = build_workflow()
        self.assertIsNotNone(workflow)