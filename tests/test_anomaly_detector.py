import unittest
from tools.anomaly_detector.anomaly_detector import detect_frequency_anomaly


class TestFrequencyAnomalyDetector(unittest.TestCase):

    def test_rate_below_threshold(self):
        event = detect_frequency_anomaly(
            can_id="0x123", count=50,
            window_seconds=2, threshold=100
        )
        self.assertEqual(event.observed_rate, 25)
        self.assertFalse(event.anomaly)
        self.assertIsNone(event.attack_type)

    def test_rate_equal_threshold(self):
        event = detect_frequency_anomaly(
            can_id="0x123", count=200,
            window_seconds=2, threshold=100
        )
        self.assertEqual(event.observed_rate, 100)
        self.assertFalse(event.anomaly)
        self.assertIsNone(event.attack_type)

    def test_rate_above_threshold(self):
        event = detect_frequency_anomaly(
            can_id="0x123", count=300,
            window_seconds=2, threshold=100
        )
        self.assertEqual(event.observed_rate, 150)
        self.assertTrue(event.anomaly)
        self.assertEqual(event.attack_type, "CAN_FLOODING")

    def test_zero_window_raises_error(self):
        with self.assertRaises(ValueError):
            detect_frequency_anomaly(
                can_id="0x123", count=50,
                window_seconds=0, threshold=100
            )

    def test_negative_window_raises_error(self):
        with self.assertRaises(ValueError):
            detect_frequency_anomaly(
                can_id="0x123", count=50,
                window_seconds=-1, threshold=100
            )

    def test_zero_threshold_raises_error(self):
        with self.assertRaises(ValueError):
            detect_frequency_anomaly(
                can_id="0x123", count=50,
                window_seconds=2, threshold=0
            )

    def test_negative_count_raises_error(self):
        with self.assertRaises(ValueError):
            detect_frequency_anomaly(
                can_id="0x123", count=-1,
                window_seconds=2, threshold=100
            )

    def test_negative_threshold_raises_error(self):
        with self.assertRaises(ValueError):
            detect_frequency_anomaly(
                can_id="0x123", count=50,
                window_seconds=2, threshold=-1
            )


if __name__ == "__main__":
    unittest.main()