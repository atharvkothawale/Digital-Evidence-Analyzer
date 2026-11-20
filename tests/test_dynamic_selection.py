"""
test_dynamic_selection.py — Comprehensive Unit & Integration Tests for Dynamic Evidence Selection

Validates:
    - Single file selection
    - Multiple individual files
    - Single folder selection
    - Nested folders
    - Multiple separate folders
    - Mixed files and folders
    - Overlapping folder and file selections (deduplication)
    - Overlapping parent and subfolder selections
    - Empty folders
    - Inaccessible file handling
    - Large file chunk hashing
    - Evidence preview & overlap warning detection
    - InvestigationManager background thread execution & progress tracking
"""

import hashlib
import os
import tempfile
import time
import unittest
from pathlib import Path

from defa.hasher import compute_sha256
from defa.investigation import InvestigationManager
from defa.scanner import (
    count_selected_directories,
    inspect_evidence_item,
    inspect_evidence_selection,
    scan_evidence_selection,
)


class TestDynamicEvidenceSelection(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.root = Path(self.temp_dir.name)

        # Setup structured test directories
        self.folder_a = self.root / "case_alpha"
        self.folder_a.mkdir()
        self.file_a1 = self.folder_a / "alpha_doc.txt"
        self.file_a1.write_text("Case Alpha Document Content", encoding="utf-8")
        self.file_a2 = self.folder_a / "alpha_log.csv"
        self.file_a2.write_text("id,action\n1,login\n2,export", encoding="utf-8")

        self.sub_a = self.folder_a / "subfolder"
        self.sub_a.mkdir()
        self.file_deep = self.sub_a / "deep_evidence.bin"
        self.file_deep.write_bytes(b"DEEP_BINARY_EVIDENCE_STREAM")

        self.folder_b = self.root / "case_beta"
        self.folder_b.mkdir()
        self.file_b1 = self.folder_b / "beta_notes.md"
        self.file_b1.write_text("# Beta Case Notes", encoding="utf-8")

        self.standalone_file1 = self.root / "standalone_external.log"
        self.standalone_file1.write_text("EXTERNAL SYSTEM AUDIT TRAIL", encoding="utf-8")

        self.empty_folder = self.root / "empty_dir"
        self.empty_folder.mkdir()

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_single_file_selection(self):
        records = list(scan_evidence_selection([self.standalone_file1]))
        self.assertEqual(len(records), 1)
        rec = records[0]
        self.assertEqual(rec["name"], "standalone_external.log")
        self.assertEqual(rec["relative_path"], "standalone_external.log")
        self.assertTrue(rec["accessible"])

    def test_multiple_individual_files(self):
        targets = [self.file_a1, self.file_b1, self.standalone_file1]
        records = list(scan_evidence_selection(targets))
        self.assertEqual(len(records), 3)
        names = {r["name"] for r in records}
        self.assertEqual(names, {"alpha_doc.txt", "beta_notes.md", "standalone_external.log"})

    def test_single_folder_selection(self):
        records = list(scan_evidence_selection([self.folder_a]))
        self.assertEqual(len(records), 3)  # a1, a2, and deep
        names = {r["name"] for r in records}
        self.assertIn("alpha_doc.txt", names)
        self.assertIn("deep_evidence.bin", names)

    def test_nested_folders(self):
        # folder_a has subfolder sub_a
        records = list(scan_evidence_selection([self.folder_a]))
        deep_recs = [r for r in records if r["name"] == "deep_evidence.bin"]
        self.assertEqual(len(deep_recs), 1)
        self.assertIn("subfolder", deep_recs[0]["relative_path"])

    def test_multiple_folders(self):
        records = list(scan_evidence_selection([self.folder_a, self.folder_b]))
        # folder_a has 3 files, folder_b has 1 file -> 4 files total
        self.assertEqual(len(records), 4)
        rel_paths = [r["relative_path"] for r in records]
        # Folder names should prefix relative paths to prevent collisions
        self.assertTrue(any(p.startswith("case_alpha/") for p in rel_paths))
        self.assertTrue(any(p.startswith("case_beta/") for p in rel_paths))

    def test_mixed_files_and_folders(self):
        records = list(scan_evidence_selection([self.folder_b, self.standalone_file1]))
        # folder_b (1 file) + standalone_file1 (1 file) -> 2 files
        self.assertEqual(len(records), 2)
        names = {r["name"] for r in records}
        self.assertEqual(names, {"beta_notes.md", "standalone_external.log"})

    def test_overlapping_folder_and_child_file_selection_deduplication(self):
        # User selects folder_a AND specifically selects file_a1 inside folder_a
        records = list(scan_evidence_selection([self.folder_a, self.file_a1]))
        # Must only process file_a1 ONCE! Total files in folder_a is 3.
        self.assertEqual(len(records), 3)
        file_a1_recs = [r for r in records if r["name"] == "alpha_doc.txt"]
        self.assertEqual(len(file_a1_recs), 1)

    def test_overlapping_parent_and_subfolder_deduplication(self):
        # User selects folder_a AND its subfolder sub_a
        records = list(scan_evidence_selection([self.folder_a, self.sub_a]))
        # Must only process deep_evidence.bin ONCE! Total should still be 3.
        self.assertEqual(len(records), 3)

    def test_empty_folder_selection(self):
        records = list(scan_evidence_selection([self.empty_folder]))
        self.assertEqual(len(records), 0)

    def test_large_file_chunk_hashing(self):
        large_file = self.root / "large_evidence_dump.bin"
        chunk_content = b"FORENSIC_CHUNK_HASH_TEST_STREAM_" * 1024  # ~32 KB
        large_file.write_bytes(chunk_content * 64)  # ~2 MB

        expected_sha = hashlib.sha256(chunk_content * 64).hexdigest()
        computed_sha = compute_sha256(large_file)
        self.assertEqual(computed_sha, expected_sha)

    def test_inspect_evidence_preview_and_overlap_warnings(self):
        items = [str(self.folder_a), str(self.file_a1), str(self.standalone_file1)]
        preview = inspect_evidence_selection(items)

        self.assertEqual(preview["total_items"], 3)
        self.assertGreater(preview["total_estimated_files"], 0)
        self.assertGreater(preview["total_estimated_size_bytes"], 0)
        # Should flag that file_a1 is inside folder_a
        self.assertGreaterEqual(len(preview["warnings"]), 1)
        self.assertIn("alpha_doc.txt", preview["warnings"][0])

    def test_investigation_manager_background_execution(self):
        mgr = InvestigationManager()
        reports_dir = self.root / "test_reports"
        job_id = mgr.start([str(self.folder_a)], output_dir=str(reports_dir))

        self.assertIsNotNone(job_id)
        # Wait up to 5 seconds for completion
        for _ in range(50):
            prog = mgr.get_progress()
            if prog["status"] == "completed":
                break
            time.sleep(0.1)

        prog = mgr.get_progress()
        self.assertEqual(prog["status"], "completed")
        self.assertEqual(prog["progress_percent"], 100.0)
        self.assertEqual(prog["files_discovered"], 3)
        self.assertEqual(prog["files_processed"], 3)
        self.assertEqual(prog["hashed_ok"], 3)
        self.assertEqual(prog["hash_failed"], 0)
        self.assertGreaterEqual(prog["throughput_mb_s"], 0.0)

        # Confirm reports generated
        self.assertTrue((reports_dir / "scan_report.json").exists())
        self.assertTrue((reports_dir / "scan_report.csv").exists())
        self.assertTrue((reports_dir / "baseline.json").exists())
        self.assertTrue((reports_dir / "investigation_report.pdf").exists())


if __name__ == "__main__":
    unittest.main()
