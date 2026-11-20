"""
test_duplicates.py — Unit tests for the duplicate detection module.
"""

import unittest

import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from defa.duplicates import find_duplicates


def _make_record(name: str, sha256: str | None, path: str = None) -> dict:
    """Helper to quickly create a minimal file record."""
    return {
        "name": name,
        "relative_path": path or name,
        "sha256": sha256,
        "size_bytes": 100,
    }


class TestFindDuplicates(unittest.TestCase):

    # ------------------------------------------------------------------
    def test_no_duplicates_returns_empty_list(self):
        """Unique hashes → no duplicate groups."""
        records = [
            _make_record("a.txt", "hash_aaa"),
            _make_record("b.txt", "hash_bbb"),
            _make_record("c.txt", "hash_ccc"),
        ]
        result = find_duplicates(records)
        self.assertEqual(result, [])

    # ------------------------------------------------------------------
    def test_two_identical_files_form_one_group(self):
        """Two files with the same hash → one group with two members."""
        records = [
            _make_record("a.txt", "same_hash"),
            _make_record("b.txt", "same_hash"),
            _make_record("c.txt", "different_hash"),
        ]
        result = find_duplicates(records)
        self.assertEqual(len(result), 1)
        self.assertEqual(len(result[0]), 2)

    # ------------------------------------------------------------------
    def test_three_identical_files_form_one_group_of_three(self):
        """Three files with the same hash → one group with three members."""
        records = [
            _make_record("x.txt", "triple_hash"),
            _make_record("y.txt", "triple_hash"),
            _make_record("z.txt", "triple_hash"),
        ]
        result = find_duplicates(records)
        self.assertEqual(len(result), 1)
        self.assertEqual(len(result[0]), 3)

    # ------------------------------------------------------------------
    def test_two_separate_duplicate_groups(self):
        """Two distinct pairs of duplicates → two groups."""
        records = [
            _make_record("a.txt", "hash_A"),
            _make_record("b.txt", "hash_A"),
            _make_record("c.txt", "hash_B"),
            _make_record("d.txt", "hash_B"),
        ]
        result = find_duplicates(records)
        self.assertEqual(len(result), 2)

    # ------------------------------------------------------------------
    def test_records_with_none_hash_are_skipped(self):
        """Records where sha256 is None must not raise an error or be grouped."""
        records = [
            _make_record("a.txt", None),
            _make_record("b.txt", None),
            _make_record("c.txt", "real_hash"),
        ]
        result = find_duplicates(records)
        self.assertEqual(result, [])

    # ------------------------------------------------------------------
    def test_empty_list_returns_empty_list(self):
        """Empty input → empty output."""
        self.assertEqual(find_duplicates([]), [])

    # ------------------------------------------------------------------
    def test_single_file_is_not_a_duplicate(self):
        """A group of one is not a duplicate."""
        records = [_make_record("only.txt", "lone_hash")]
        result = find_duplicates(records)
        self.assertEqual(result, [])

    # ------------------------------------------------------------------
    def test_group_members_have_correct_hash(self):
        """Members returned in a group should all share the same sha256."""
        shared = "shared_sha256_value"
        records = [
            _make_record("p.txt", shared),
            _make_record("q.txt", shared),
        ]
        result = find_duplicates(records)
        self.assertEqual(len(result), 1)
        for member in result[0]:
            self.assertEqual(member["sha256"], shared)


if __name__ == "__main__":
    unittest.main()

