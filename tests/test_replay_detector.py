import unittest
import can

from tools.anomaly_detector.replay_detector import detect_replay_attack


class TestReplayDetector(unittest.TestCase):

    def create_messages(self, data_list, interval=0.01):
        return [
            can.Message(
                arbitration_id=0x123,
                data=data,
                is_extended_id=False,
                timestamp=i * interval
            )
            for i, data in enumerate(data_list)
        ]

    def test_identical_consecutive_frames(self):
        messages = self.create_messages([[1, 2, 3, 4]] * 6)
        event = detect_replay_attack(messages)

        self.assertIsNotNone(event)
        self.assertEqual(event.attack_type, "REPLAY_SUSPECTED")

    def test_different_frames(self):
        messages = self.create_messages(
            [[i, 2, 3, 4] for i in range(6)]
        )
        event = detect_replay_attack(messages)

        self.assertIsNone(event)

    def test_repetitions_too_slow(self):
        messages = self.create_messages(
            [[1, 2, 3, 4]] * 6,
            interval=0.2
        )
        event = detect_replay_attack(messages)

        self.assertIsNone(event)

    def test_invalid_min_repetitions(self):
        with self.assertRaises(ValueError):
            detect_replay_attack([], min_repetitions=1)

    def test_invalid_burst_duration(self):
        with self.assertRaises(ValueError):
            detect_replay_attack([], max_burst_seconds=0)


if __name__ == "__main__":
    unittest.main()
