"""
test_scanner.py — Unit tests for the scanner module.
"""

import tempfile
import unittest
from pathlib import Path

import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from defa.scanner import scan_directory, collect_file_metadata


class TestScanDirectory(unittest.TestCase):

    def setUp(self):
        """Create a temporary directory tree for each test."""
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp_dir.name)

    def tearDown(self):
        self.tmp_dir.cleanup()

    # ------------------------------------------------------------------
    def test_finds_files_in_root(self):
        """Files directly in the root should be yielded."""
        (self.root / "file1.txt").write_text("hello")
        (self.root / "file2.log").write_text("world")

        records = list(scan_directory(self.root))
        names = {r["name"] for r in records}
        self.assertIn("file1.txt", names)
        self.assertIn("file2.log", names)

    # ------------------------------------------------------------------
    def test_finds_files_recursively(self):
        """Files in nested subdirectories should also be found."""
        sub = self.root / "sub" / "deep"
        sub.mkdir(parents=True)
        (sub / "nested.txt").write_text("nested content")

        records = list(scan_directory(self.root))
        names = {r["name"] for r in records}
        self.assertIn("nested.txt", names)

    # ------------------------------------------------------------------
    def test_empty_directory_returns_no_records(self):
        """An empty directory should yield zero records."""
        records = list(scan_directory(self.root))
        self.assertEqual(records, [])

    # ------------------------------------------------------------------
    def test_record_contains_expected_keys(self):
        """Each record must have the standard set of keys."""
        (self.root / "sample.txt").write_text("data")
        records = list(scan_directory(self.root))
        required_keys = {
            "name", "extension", "absolute_path", "relative_path",
            "size_bytes", "created_at", "modified_at", "accessed_at",
            "accessible",
        }
        for key in required_keys:
            self.assertIn(key, records[0])

    # ------------------------------------------------------------------
    def test_relative_path_is_relative_to_root(self):
        """relative_path must not contain the absolute root prefix."""
        (self.root / "check.txt").write_text("check")
        records = list(scan_directory(self.root))
        rel = records[0]["relative_path"]
        self.assertFalse(Path(rel).is_absolute())

    # ------------------------------------------------------------------
    def test_raises_for_nonexistent_directory(self):
        """scan_directory must raise FileNotFoundError for missing paths."""
        with self.assertRaises(FileNotFoundError):
            list(scan_directory("/path/that/does/not/exist_xyz"))

    # ------------------------------------------------------------------
    def test_raises_for_file_instead_of_directory(self):
        """scan_directory must raise NotADirectoryError when given a file."""
        f = self.root / "not_a_dir.txt"
        f.write_text("I am a file")
        with self.assertRaises(NotADirectoryError):
            list(scan_directory(f))

    # ------------------------------------------------------------------
    def test_extension_is_lowercase(self):
        """Extensions should be normalised to lowercase."""
        (self.root / "IMAGE.JPG").write_text("fake jpg")
        records = list(scan_directory(self.root))
        self.assertEqual(records[0]["extension"], ".jpg")

    # ------------------------------------------------------------------
    def test_size_bytes_matches_actual_size(self):
        """size_bytes must match the actual file size in bytes."""
        content = b"exactly 20 bytes!!"  # 18 bytes actually — let's be precise
        f = self.root / "sized.bin"
        f.write_bytes(content)
        records = list(scan_directory(self.root))
        self.assertEqual(records[0]["size_bytes"], len(content))


class TestCollectFileMetadata(unittest.TestCase):

    def setUp(self):
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp_dir.name)

    def tearDown(self):
        self.tmp_dir.cleanup()

    def test_accessible_true_for_readable_file(self):
        f = self.root / "readable.txt"
        f.write_text("readable")
        meta = collect_file_metadata(f, self.root)
        self.assertTrue(meta["accessible"])

    def test_name_matches_filename(self):
        f = self.root / "myfile.csv"
        f.write_text("a,b,c")
        meta = collect_file_metadata(f, self.root)
        self.assertEqual(meta["name"], "myfile.csv")


if __name__ == "__main__":
    unittest.main()

