"""
test_pdf_report.py — Unit tests for Pure-Python Forensic PDF Report Generator
"""

import tempfile
import unittest
from pathlib import Path

from defa.pdf_report import generate_pdf_report, _escape_pdf_str


class TestPdfReportGenerator(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.output_dir = Path(self.temp_dir.name)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_escape_pdf_str(self):
        raw = "Case (Alpha) with \\backslashes\\ and (nested) parens"
        escaped = _escape_pdf_str(raw)
        self.assertIn("\\(", escaped)
        self.assertIn("\\)", escaped)
        self.assertIn("\\\\", escaped)

    def test_generate_pdf_report_creates_valid_pdf_structure(self):
        pdf_out = self.output_dir / "test_investigation.pdf"
        scan_report = {
            "directory": "D:/evidence/sample",
            "total_files": 12,
            "hashed_successfully": 12,
            "hash_failed": 0,
            "duplicate_groups": 1,
            "duplicate_files": 2,
            "files": [
                {"name": "evidence1.txt", "size_bytes": 1024, "relative_path": "evidence1.txt"},
                {"name": "evidence2.txt", "size_bytes": 2048, "relative_path": "evidence2.txt"},
            ],
        }
        findings = [
            {
                "id": "FIND-001",
                "title": "Suspicious Double File Extension",
                "severity": "High",
                "related_file": "trojan.pdf.exe",
                "reason": "Double extension pattern detected.",
                "recommended_action": "Quarantine metadata.",
            }
        ]
        verification_result = {
            "summary": {"unchanged": 10, "new": 1, "missing": 1, "modified": 0}
        }

        generated_path = generate_pdf_report(
            case_name="CASE-2026-X99",
            investigator="Special Agent Miller",
            scan_report=scan_report,
            findings=findings,
            output_path=pdf_out,
            verification_result=verification_result,
        )

        self.assertTrue(generated_path.exists())
        self.assertGreater(generated_path.stat().st_size, 1000)

        raw_bytes = generated_path.read_bytes()
        # Conforms to PDF specification
        self.assertTrue(raw_bytes.startswith(b"%PDF-1.4\n"))
        self.assertTrue(raw_bytes.rstrip().endswith(b"%%EOF"))
        self.assertIn(b"CASE-2026-X99", raw_bytes)
        self.assertIn(b"Special Agent Miller", raw_bytes)

    def test_generate_pdf_report_with_empty_findings(self):
        pdf_out = self.output_dir / "empty_findings.pdf"
        scan_report = {
            "directory": "D:/evidence/clean",
            "total_files": 5,
            "hashed_successfully": 5,
            "hash_failed": 0,
            "duplicate_groups": 0,
            "duplicate_files": 0,
            "files": [],
        }

        generated_path = generate_pdf_report(
            case_name="CASE-CLEAN",
            investigator="Examiner Doe",
            scan_report=scan_report,
            findings=[],
            output_path=pdf_out,
            verification_result=None,
        )

        self.assertTrue(generated_path.exists())
        raw_bytes = generated_path.read_bytes()
        self.assertTrue(raw_bytes.startswith(b"%PDF-1.4\n"))
        self.assertTrue(raw_bytes.rstrip().endswith(b"%%EOF"))


if __name__ == "__main__":
    unittest.main()

