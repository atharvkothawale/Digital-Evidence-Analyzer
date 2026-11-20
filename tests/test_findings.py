"""
test_findings.py — Unit tests for DEFA Forensic Findings & Anomaly Detection Engine
"""

import tempfile
import unittest
from pathlib import Path

from defa.findings import (
    check_magic_byte_mismatch,
    generate_forensic_findings,
    MAGIC_SIGNATURES,
    DECEPTIVE_EXTENSION_PATTERNS,
)


class TestMagicByteDetection(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.dir_path = Path(self.temp_dir.name)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_pe_executable_disguised_as_jpg(self):
        fake_jpg = self.dir_path / "invoice.jpg"
        # MZ header (Windows PE)
        fake_jpg.write_bytes(b"MZ\x90\x00\x03\x00\x00\x00\x04\x00")

        mismatch = check_magic_byte_mismatch(fake_jpg, ".jpg")
        self.assertIsNotNone(mismatch)
        self.assertEqual(mismatch["detected_type"], "PE / Windows Executable")
        self.assertEqual(mismatch["declared_extension"], ".jpg")
        self.assertIn("File signature matches PE / Windows Executable", mismatch["reason"])

    def test_pdf_document_disguised_as_txt(self):
        fake_txt = self.dir_path / "secret.txt"
        fake_txt.write_bytes(b"%PDF-1.5\n%Header comment")

        mismatch = check_magic_byte_mismatch(fake_txt, ".txt")
        self.assertIsNotNone(mismatch)
        self.assertEqual(mismatch["detected_type"], "PDF Document")
        self.assertEqual(mismatch["declared_extension"], ".txt")

    def test_legitimate_pdf_returns_none(self):
        real_pdf = self.dir_path / "contract.pdf"
        real_pdf.write_bytes(b"%PDF-1.7\nValid pdf header bytes")

        mismatch = check_magic_byte_mismatch(real_pdf, ".pdf")
        self.assertIsNone(mismatch)

    def test_nonexistent_file_returns_none(self):
        mismatch = check_magic_byte_mismatch(self.dir_path / "missing.bin", ".bin")
        self.assertIsNone(mismatch)


class TestForensicFindingsEngine(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.dir_path = Path(self.temp_dir.name)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_deceptive_double_extension_detection(self):
        records = [
            {
                "name": "financial_report.pdf.exe",
                "relative_path": "financial_report.pdf.exe",
                "extension": ".exe",
                "size_bytes": 1024,
                "accessible": True,
                "scan_status": "hashed",
            }
        ]
        findings = generate_forensic_findings(records, duplicate_groups=[])
        self.assertTrue(any(f["severity"] == "High" and "Double File Extension" in f["title"] for f in findings))

    def test_filename_whitespace_padding_detection(self):
        records = [
            {
                "name": "statement   .pdf",
                "relative_path": "statement   .pdf",
                "extension": ".pdf",
                "size_bytes": 500,
                "accessible": True,
                "scan_status": "hashed",
            }
        ]
        findings = generate_forensic_findings(records, duplicate_groups=[])
        self.assertTrue(any(f["severity"] == "High" and "Deceptive Filename Padding" in f["title"] for f in findings))

    def test_hidden_file_detection(self):
        records = [
            {
                "name": ".bash_history",
                "relative_path": ".bash_history",
                "extension": "",
                "size_bytes": 250,
                "accessible": True,
                "scan_status": "hashed",
            }
        ]
        findings = generate_forensic_findings(records, duplicate_groups=[])
        self.assertTrue(any(f["severity"] == "Low" and "Hidden File Discovered" in f["title"] for f in findings))

    def test_inaccessible_file_produces_medium_finding(self):
        records = [
            {
                "name": "locked_vault.db",
                "relative_path": "locked_vault.db",
                "extension": ".db",
                "size_bytes": 0,
                "accessible": False,
                "scan_status": "hash_failed",
            }
        ]
        findings = generate_forensic_findings(records, duplicate_groups=[])
        self.assertTrue(any(f["severity"] == "Medium" and "Unreadable Evidence File" in f["title"] for f in findings))

    def test_duplicate_cluster_findings(self):
        group = [
            {"relative_path": "folder1/doc.pdf", "sha256": "abc12345678901234567890123456789", "size_bytes": 2048, "extension": ".pdf"},
            {"relative_path": "folder2/doc_copy.pdf", "sha256": "abc12345678901234567890123456789", "size_bytes": 2048, "extension": ".pdf"},
        ]
        findings = generate_forensic_findings([], duplicate_groups=[group])
        self.assertTrue(any("Cryptographically Identical Duplicate Files" in f["title"] for f in findings))

    def test_baseline_verification_findings_integration(self):
        verification_result = {
            "modified": [
                {
                    "current": {"relative_path": "altered.txt", "sha256": "1111"},
                    "baseline": {"relative_path": "altered.txt", "sha256": "2222"},
                }
            ],
            "new": [
                {"relative_path": "injected_payload.ps1", "extension": ".ps1"}
            ],
            "missing": [
                {"relative_path": "purged_log.txt"}
            ],
            "unchanged": [],
        }

        findings = generate_forensic_findings([], duplicate_groups=[], verification_result=verification_result)
        titles = [f["title"] for f in findings]
        self.assertIn("Integrity Verification Mismatch (Modified File)", titles)
        self.assertIn("New Unbaselined File Introduced", titles)
        self.assertIn("Baseline Evidence File Missing (Deleted)", titles)

    def test_findings_sorted_by_severity_hierarchy(self):
        records = [
            {"name": "huge_dump.raw", "relative_path": "huge_dump.raw", "extension": ".raw", "size_bytes": 60 * 1024 * 1024, "accessible": True, "scan_status": "hashed"},
            {"name": "deceptive.doc.exe", "relative_path": "deceptive.doc.exe", "extension": ".exe", "size_bytes": 1024, "accessible": True, "scan_status": "hashed"},
            {"name": ".hidden_config", "relative_path": ".hidden_config", "extension": "", "size_bytes": 100, "accessible": True, "scan_status": "hashed"},
        ]
        findings = generate_forensic_findings(records, duplicate_groups=[])
        severities = [f["severity"] for f in findings]
        # Should be High before Low and Informational
        high_idx = severities.index("High")
        low_idx = severities.index("Low")
        info_idx = severities.index("Informational")
        self.assertLess(high_idx, low_idx)
        self.assertLess(low_idx, info_idx)


if __name__ == "__main__":
    unittest.main()

