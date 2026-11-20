"""
test_hasher.py — Unit tests for the hasher module.

All tests use temporary files so no personal files are touched.
"""

import hashlib
import tempfile
import unittest
from pathlib import Path

# Allow running tests from the project root (d:\digitalforensics\defa)
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from defa.hasher import compute_sha256, CHUNK_SIZE


class TestComputeSHA256(unittest.TestCase):

    def _write_temp_file(self, content: bytes) -> Path:
        """Helper: write bytes to a temp file and return its Path."""
        tmp = tempfile.NamedTemporaryFile(delete=False)
        tmp.write(content)
        tmp.close()
        return Path(tmp.name)

    # ------------------------------------------------------------------
    def test_known_hash_matches_hashlib_directly(self):
        """SHA-256 of a known string must match Python's hashlib output."""
        content = b"Hello, DEFA!"
        expected = hashlib.sha256(content).hexdigest()

        path = self._write_temp_file(content)
        try:
            result = compute_sha256(path)
            self.assertEqual(result, expected)
        finally:
            path.unlink()

    # ------------------------------------------------------------------
    def test_empty_file_has_known_hash(self):
        """SHA-256 of an empty file is the well-known empty-string hash."""
        # SHA-256("") = e3b0c44298fc1c149afbf4c8996fb924...
        expected = hashlib.sha256(b"").hexdigest()
        path = self._write_temp_file(b"")
        try:
            result = compute_sha256(path)
            self.assertEqual(result, expected)
        finally:
            path.unlink()

    # ------------------------------------------------------------------
    def test_different_content_gives_different_hash(self):
        """Two files with different content must produce different hashes."""
        path_a = self._write_temp_file(b"File A content")
        path_b = self._write_temp_file(b"File B content")
        try:
            hash_a = compute_sha256(path_a)
            hash_b = compute_sha256(path_b)
            self.assertNotEqual(hash_a, hash_b)
        finally:
            path_a.unlink()
            path_b.unlink()

    # ------------------------------------------------------------------
    def test_identical_content_gives_same_hash(self):
        """Two files with identical content must produce the same hash."""
        content = b"Identical content for duplicate detection"
        path_a = self._write_temp_file(content)
        path_b = self._write_temp_file(content)
        try:
            self.assertEqual(compute_sha256(path_a), compute_sha256(path_b))
        finally:
            path_a.unlink()
            path_b.unlink()

    # ------------------------------------------------------------------
    def test_nonexistent_file_returns_none(self):
        """compute_sha256 must return None for a path that does not exist."""
        result = compute_sha256("/this/path/definitely/does/not/exist_xyz.bin")
        self.assertIsNone(result)

    # ------------------------------------------------------------------
    def test_large_file_hashed_correctly(self):
        """A file larger than CHUNK_SIZE should still hash correctly."""
        # Write 3× the chunk size so multiple read iterations are exercised
        content = b"X" * (CHUNK_SIZE * 3)
        expected = hashlib.sha256(content).hexdigest()
        path = self._write_temp_file(content)
        try:
            result = compute_sha256(path)
            self.assertEqual(result, expected)
        finally:
            path.unlink()

    # ------------------------------------------------------------------
    def test_returns_64_char_hex_string(self):
        """SHA-256 digest must always be a 64-character hex string."""
        path = self._write_temp_file(b"test")
        try:
            result = compute_sha256(path)
            self.assertIsNotNone(result)
            self.assertEqual(len(result), 64)
            self.assertTrue(all(c in "0123456789abcdef" for c in result))
        finally:
            path.unlink()


if __name__ == "__main__":
    unittest.main()

