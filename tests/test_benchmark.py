"""
test_benchmark.py — Unit tests for DEFA 12-Step Automated Forensic Benchmark Engine
"""

import unittest
from defa.benchmark import run_forensic_benchmark


class TestForensicBenchmark(unittest.TestCase):

    def test_run_forensic_benchmark_executes_12_steps_with_100_percent_accuracy(self):
        result = run_forensic_benchmark()

        # Overall status checks
        self.assertIsInstance(result, dict)
        self.assertTrue(result.get("success"))
        self.assertEqual(result.get("accuracy_percentage"), 100.0)

        # 12 steps verification
        steps_passed = result.get("steps_passed", [])
        steps_failed = result.get("steps_failed", [])
        self.assertEqual(len(steps_failed), 0)
        self.assertGreaterEqual(len(steps_passed), 12)

        # Performance metrics checks
        metrics = result.get("metrics", {})
        self.assertIn("files_scanned", metrics)
        self.assertIn("throughput_mb_per_second", metrics)
        self.assertIn("files_per_second", metrics)
        self.assertTrue(metrics.get("duplicate_detection_verified"))
        self.assertTrue(metrics.get("baseline_accuracy_verified"))
        self.assertGreater(metrics["files_per_second"], 0)
        self.assertGreaterEqual(metrics["throughput_mb_per_second"], 0)


if __name__ == "__main__":
    unittest.main()
