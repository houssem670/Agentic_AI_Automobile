import json
import unittest
from datetime import datetime, timezone
from unittest.mock import patch, MagicMock

from models.security_event import SecurityEvent
from agents.security_agent.security_agent import security_agent


class TestSecurityAgent(unittest.TestCase):

    def setUp(self):
        self.event = SecurityEvent(
            event_id="TEST-SEC-001",
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
            evidence=["Six trames identiques"],
            metadata={"test": True},
        )

        self.valid_response = {
            "threat_type": "OTHER_VALUE",
            "risk_level": "MEDIUM",
            "summary": "Suspicion de répétition de trames.",
            "observed_facts": ["Six trames identiques observées"],
            "security_interpretation": "Une investigation est nécessaire.",
            "unknowns": ["L'intention malveillante n'est pas établie"],
            "investigation_steps": ["Comparer au trafic normal"],
            "mitigation_actions": ["Continuer la surveillance"],
            "confidence": 0.7,
        }

    @patch("agents.security_agent.security_agent.build_rag_context")
    @patch("agents.security_agent.security_agent.ollama_llm")
    @patch("agents.security_agent.security_agent.gemini_client")
    def test_valid_gemini_response(self, gemini, ollama, rag):
        rag.return_value = {"results": [], "context": "Test RAG"}
        response = MagicMock()
        response.text = json.dumps(self.valid_response)
        gemini.models.generate_content.return_value = response

        result = security_agent(self.event)

        self.assertEqual(result.threat_type, "REPLAY_SUSPECTED")
        self.assertEqual(result.risk_level, "MEDIUM")
        self.assertEqual(result.confidence, 0.7)
        ollama.invoke.assert_not_called()

    @patch("agents.security_agent.security_agent.build_rag_context")
    @patch("agents.security_agent.security_agent.ollama_llm")
    @patch("agents.security_agent.security_agent.gemini_client")
    def test_gemini_failure_uses_ollama(self, gemini, ollama, rag):
        rag.return_value = {"results": [], "context": "Test RAG"}
        gemini.models.generate_content.side_effect = RuntimeError("Test failure")
        ollama.invoke.return_value.content = json.dumps(self.valid_response)

        result = security_agent(self.event)

        self.assertEqual(result.threat_type, "REPLAY_SUSPECTED")
        ollama.invoke.assert_called_once()

    @patch("agents.security_agent.security_agent.build_rag_context")
    @patch("agents.security_agent.security_agent.ollama_llm")
    @patch("agents.security_agent.security_agent.gemini_client")
    def test_invalid_gemini_json_uses_ollama(self, gemini, ollama, rag):
        rag.return_value = {"results": [], "context": "Test RAG"}

        response = MagicMock()
        response.text = "{invalid json"
        gemini.models.generate_content.return_value = response
        ollama.invoke.return_value.content = json.dumps(self.valid_response)

        result = security_agent(self.event)

        self.assertEqual(result.threat_type, "REPLAY_SUSPECTED")
        self.assertEqual(result.risk_level, "MEDIUM")
        ollama.invoke.assert_called_once()


if __name__ == "__main__":
    unittest.main()
