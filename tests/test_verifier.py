"""
test_verifier.py — Unit tests for the verifier (baseline comparison) module.
"""

import json
import tempfile
import unittest
from pathlib import Path

import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from defa.verifier import load_baseline, compare_with_baseline


def _make_baseline(files: list[dict], directory: str = "/tmp/test") -> dict:
    """Build a minimal baseline dict (simulates what reporter.save_baseline writes)."""
    return {
        "tool": "DEFA",
        "version": "1.0.0",
        "scanned_at": "2024-01-01T00:00:00+00:00",
        "directory": directory,
        "files": files,
    }


def _record(rel_path: str, sha256: str) -> dict:
    """Create a minimal file record."""
    return {
        "name": Path(rel_path).name,
        "relative_path": rel_path,
        "sha256": sha256,
        "size_bytes": 100,
        "scan_status": "hashed",
    }


class TestLoadBaseline(unittest.TestCase):

    def test_loads_valid_baseline(self):
        baseline = _make_baseline([_record("file.txt", "abc123")])
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False, encoding="utf-8"
        ) as f:
            json.dump(baseline, f)
            tmp_path = f.name
        try:
            result = load_baseline(tmp_path)
            self.assertEqual(len(result["files"]), 1)
        finally:
            Path(tmp_path).unlink()

    def test_raises_for_missing_file(self):
        with self.assertRaises(FileNotFoundError):
            load_baseline("/no/such/baseline_xyz.json")

    def test_raises_for_invalid_json(self):
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False, encoding="utf-8"
        ) as f:
            f.write("NOT VALID JSON {{{{")
            tmp_path = f.name
        try:
            with self.assertRaises(ValueError):
                load_baseline(tmp_path)
        finally:
            Path(tmp_path).unlink()

    def test_raises_when_files_key_missing(self):
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False, encoding="utf-8"
        ) as f:
            json.dump({"tool": "DEFA"}, f)   # no 'files' key
            tmp_path = f.name
        try:
            with self.assertRaises(ValueError):
                load_baseline(tmp_path)
        finally:
            Path(tmp_path).unlink()


class TestCompareWithBaseline(unittest.TestCase):

    # ------------------------------------------------------------------
    def test_all_unchanged(self):
        """Same files, same hashes → all unchanged."""
        files = [_record("a.txt", "hash_a"), _record("b.txt", "hash_b")]
        baseline = _make_baseline(files)
        result = compare_with_baseline(files, baseline)
        self.assertEqual(len(result["unchanged"]), 2)
        self.assertEqual(len(result["new"]), 0)
        self.assertEqual(len(result["missing"]), 0)
        self.assertEqual(len(result["modified"]), 0)

    # ------------------------------------------------------------------
    def test_detects_new_file(self):
        """A file present now but not in the baseline is 'new'."""
        baseline = _make_baseline([_record("a.txt", "hash_a")])
        current = [_record("a.txt", "hash_a"), _record("b.txt", "hash_b")]
        result = compare_with_baseline(current, baseline)
        self.assertEqual(len(result["new"]), 1)
        self.assertEqual(result["new"][0]["relative_path"], "b.txt")

    # ------------------------------------------------------------------
    def test_detects_missing_file(self):
        """A file in the baseline but absent now is 'missing'."""
        baseline = _make_baseline([
            _record("a.txt", "hash_a"),
            _record("b.txt", "hash_b"),
        ])
        current = [_record("a.txt", "hash_a")]   # b.txt is gone
        result = compare_with_baseline(current, baseline)
        self.assertEqual(len(result["missing"]), 1)
        self.assertEqual(result["missing"][0]["relative_path"], "b.txt")

    # ------------------------------------------------------------------
    def test_detects_modified_file(self):
        """Same path but different hash → 'modified'."""
        baseline = _make_baseline([_record("a.txt", "original_hash")])
        current = [_record("a.txt", "changed_hash")]
        result = compare_with_baseline(current, baseline)
        self.assertEqual(len(result["modified"]), 1)
        self.assertEqual(len(result["unchanged"]), 0)

    # ------------------------------------------------------------------
    def test_modified_entry_contains_both_hashes(self):
        """Modified entries must include both current and baseline records."""
        baseline = _make_baseline([_record("x.txt", "old_hash")])
        current = [_record("x.txt", "new_hash")]
        result = compare_with_baseline(current, baseline)
        entry = result["modified"][0]
        self.assertIn("current", entry)
        self.assertIn("baseline", entry)
        self.assertEqual(entry["current"]["sha256"], "new_hash")
        self.assertEqual(entry["baseline"]["sha256"], "old_hash")

    # ------------------------------------------------------------------
    def test_empty_current_all_missing(self):
        """If the directory is empty now, every baseline file is missing."""
        baseline = _make_baseline([
            _record("a.txt", "hash_a"),
            _record("b.txt", "hash_b"),
        ])
        result = compare_with_baseline([], baseline)
        self.assertEqual(len(result["missing"]), 2)
        self.assertEqual(len(result["new"]), 0)

    # ------------------------------------------------------------------
    def test_empty_baseline_all_new(self):
        """If baseline is empty, every current file is new."""
        baseline = _make_baseline([])
        current = [_record("a.txt", "hash_a"), _record("b.txt", "hash_b")]
        result = compare_with_baseline(current, baseline)
        self.assertEqual(len(result["new"]), 2)
        self.assertEqual(len(result["missing"]), 0)

    # ------------------------------------------------------------------
    def test_mixed_scenario(self):
        """Real-world scenario: some new, some missing, some modified, some unchanged."""
        baseline = _make_baseline([
            _record("keep.txt", "hash_k"),       # unchanged
            _record("modify.txt", "old_hash"),   # will be modified
            _record("delete.txt", "hash_d"),     # will be missing
        ])
        current = [
            _record("keep.txt", "hash_k"),       # unchanged
            _record("modify.txt", "new_hash"),   # modified
            _record("new_file.txt", "hash_n"),   # new
        ]
        result = compare_with_baseline(current, baseline)
        self.assertEqual(len(result["unchanged"]), 1)
        self.assertEqual(len(result["modified"]), 1)
        self.assertEqual(len(result["missing"]), 1)
        self.assertEqual(len(result["new"]), 1)


if __name__ == "__main__":
    unittest.main()

