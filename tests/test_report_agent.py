import unittest
from datetime import datetime, timezone

from models.security_event import SecurityEvent
from models.security_assessment import SecurityAssessment
from models.diagnostic_report import DiagnosticReport
from agents.report_agent.report_agent import (
    generate_security_report,
    save_security_report,
)


class TestReportAgent(unittest.TestCase):

    def setUp(self):
        self.event = SecurityEvent(
            event_id="TEST-001",
            timestamp=datetime.now(timezone.utc),
            event_type="CAN_ANOMALY",
            can_id="0x123",
            channel="vcan0",
            message_count=6,
            window_seconds=0.05,
            observed_rate=120.0,
            detection_rule="CONSECUTIVE_FRAME_REPETITION",
            threshold=5.0,
            anomaly=True,
            attack_type="REPLAY_SUSPECTED",
            evidence=["Six identical consecutive frames"],
        )

        self.assessment = SecurityAssessment(
            threat_type="Replay suspicion",
            risk_level="MEDIUM",
            summary="Repeated CAN frames detected.",
            confidence=0.8,
        )

        self.diagnostic = DiagnosticReport(
            event_id="TEST-001",
            diagnostic_summary="Further investigation is required.",
            confidence=0.7,
            root_cause_confirmed=False,
        )

    def test_report_contains_key_information(self):
        report = generate_security_report(
            self.event, self.assessment, self.diagnostic
        )

        self.assertIn("Automotive CAN Security Report", report)
        self.assertIn("TEST-001", report)
        self.assertIn("0x123", report)
        self.assertIn("REPLAY_SUSPECTED", report)
        self.assertIn("MEDIUM", report)

    def test_report_handles_missing_information(self):
        assessment = SecurityAssessment()
        diagnostic = DiagnosticReport()

        report = generate_security_report(
            self.event, assessment, diagnostic
        )

        self.assertIn("No security summary provided.", report)
        self.assertIn("Not available", report)

    def test_save_report_creates_file(self):
        from pathlib import Path
        from tempfile import TemporaryDirectory

        report = generate_security_report(
            self.event, self.assessment, self.diagnostic
        )

        with TemporaryDirectory() as tmp:
            path = Path(tmp) / "security_report.md"
            saved_path = save_security_report(report, path)

            self.assertTrue(path.exists())
            self.assertEqual(Path(saved_path).read_text(encoding="utf-8"), report)

    def test_empty_report_is_rejected(self):
        with self.assertRaises(ValueError):
            save_security_report("   ", "reports/empty_test.md")


if __name__ == "__main__":
    unittest.main()
