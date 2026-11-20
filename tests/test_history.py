"""
test_history.py — Unit tests for scan history tracking and comparison.
"""

import tempfile
import unittest
from pathlib import Path

import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from defa.history import load_history, record_scan_history, compare_scans


class TestScanHistory(unittest.TestCase):

    def setUp(self):
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.history_file = Path(self.tmp_dir.name) / "scan_history.json"

    def tearDown(self):
        self.tmp_dir.cleanup()

    def test_load_empty_history(self):
        records = load_history(self.history_file)
        self.assertEqual(records, [])

    def test_record_and_load_history(self):
        scan_report = {
            "scanned_at": "2026-11-20T10:00:00+00:00",
            "directory": "/evidence/case_01",
            "total_files": 10,
            "hashed_successfully": 10,
            "hash_failed": 0,
            "duplicate_groups": 1,
            "duplicate_files": 2,
            "files": [
                {"relative_path": "a.txt", "size_bytes": 100, "sha256": "hash_a"},
                {"relative_path": "b.txt", "size_bytes": 200, "sha256": "hash_b"},
            ],
        }

        entry = record_scan_history(scan_report, self.history_file)
        self.assertIn("id", entry)
        self.assertEqual(entry["total_size_bytes"], 300)

        history = load_history(self.history_file)
        self.assertEqual(len(history), 1)
        self.assertEqual(history[0]["id"], entry["id"])
        self.assertEqual(history[0]["total_files"], 10)

    def test_compare_scans(self):
        older = {
            "scanned_at": "2026-11-20T09:00:00+00:00",
            "directory": "/evidence",
            "files": [
                {"relative_path": "same.txt", "sha256": "hash_same", "size_bytes": 50},
                {"relative_path": "modify.txt", "sha256": "hash_old", "size_bytes": 50},
                {"relative_path": "deleted.txt", "sha256": "hash_del", "size_bytes": 50},
            ],
        }
        newer = {
            "scanned_at": "2026-11-20T10:00:00+00:00",
            "directory": "/evidence",
            "files": [
                {"relative_path": "same.txt", "sha256": "hash_same", "size_bytes": 50},
                {"relative_path": "modify.txt", "sha256": "hash_new", "size_bytes": 60},
                {"relative_path": "added.txt", "sha256": "hash_add", "size_bytes": 70},
            ],
        }

        diff = compare_scans(older, newer)
        self.assertEqual(diff["added"], ["added.txt"])
        self.assertEqual(diff["removed"], ["deleted.txt"])
        self.assertEqual(len(diff["modified"]), 1)
        self.assertEqual(diff["modified"][0]["path"], "modify.txt")
        self.assertEqual(diff["unchanged_count"], 1)


if __name__ == "__main__":
    unittest.main()

