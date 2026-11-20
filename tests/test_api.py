"""
test_api.py — Unit tests for DEFA 2.0 FastAPI REST API Endpoints.
Directly tests endpoint logic and handlers for maximum speed, test isolation,
and zero external network dependencies.
"""

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch, MagicMock

import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from fastapi import HTTPException
from fastapi.responses import FileResponse
from defa.api.routes import (
    get_health,
    trigger_scan,
    get_latest_scan,
    get_findings,
    execute_benchmark,
    get_files,
    get_file_detail,
    get_duplicates,
    trigger_verify,
    get_latest_verification,
    get_history,
    compare_history_scans,
    get_ai_status,
    ai_chat,
    get_settings,
    update_settings,
    export_report,
)
from defa.api.schemas import (
    ScanRequest,
    VerifyRequest,
    ChatRequest,
    ChatMessage,
    SettingsModel,
    CompareRequest,
)


class TestAPIEndpoints(unittest.TestCase):

    def setUp(self):
        self.sample_dir = Path(__file__).resolve().parent.parent / "sample_data"

    def test_health_endpoint(self):
        data = get_health()
        self.assertEqual(data["status"], "online")
        self.assertEqual(data["version"], "2.0.0")

    def test_scan_invalid_directory_raises_400(self):
        req = ScanRequest(directory="/this/path/does/not/exist_xyz123")
        with self.assertRaises(HTTPException) as ctx:
            trigger_scan(req)
        self.assertEqual(ctx.exception.status_code, 400)
        self.assertIn("Directory does not exist", ctx.exception.detail)

    def test_scan_valid_sample_data(self):
        req = ScanRequest(directory=str(self.sample_dir), output_dir="reports")
        data = trigger_scan(req)
        self.assertTrue(data["success"])
        self.assertGreater(data["summary"]["total_files"], 0)
        self.assertIn("performance", data["summary"])

    def test_get_latest_scan(self):
        data = get_latest_scan()
        self.assertIn("files", data)
        self.assertIn("total_files", data)

    def test_get_findings_all_and_filtered(self):
        data_all = get_findings(severity="all")
        self.assertIn("findings", data_all)
        self.assertIn("counts", data_all)
        self.assertIn("High", data_all["counts"])
        self.assertIn("Medium", data_all["counts"])

        data_high = get_findings(severity="High")
        for f in data_high["findings"]:
            self.assertEqual(f["severity"], "High")

    def test_benchmark_endpoint(self):
        res = execute_benchmark()
        self.assertTrue(res["success"])
        self.assertEqual(res["accuracy_percentage"], 100.0)
        self.assertIn("metrics", res)
        self.assertTrue(res["metrics"]["duplicate_detection_verified"])
        self.assertTrue(res["metrics"]["baseline_accuracy_verified"])

    def test_get_files_with_filters(self):
        data = get_files(category="documents", limit=10)
        self.assertIn("files", data)
        self.assertIn("total", data)
        for f in data["files"]:
            self.assertIn(f["extension"], [".txt", ".md", ".csv", ".json", ".pdf", ".xml"])

    def test_get_file_detail_success(self):
        files_data = get_files(limit=1)
        if files_data["files"]:
            rel_path = files_data["files"][0]["relative_path"]
            detail = get_file_detail(path=rel_path)
            self.assertEqual(detail["relative_path"], rel_path)
            self.assertIn("sha256", detail)
            self.assertIn("size_bytes", detail)

    def test_get_file_detail_not_found_raises_404(self):
        with self.assertRaises(HTTPException) as ctx:
            get_file_detail(path="nonexistent_xyz.bin")
        self.assertEqual(ctx.exception.status_code, 404)

    def test_get_duplicates(self):
        data = get_duplicates()
        self.assertIn("duplicate_groups", data)
        self.assertIn("total_groups", data)
        self.assertIn("estimated_wasted_bytes", data)

    def test_get_history(self):
        data = get_history()
        self.assertIn("history", data)
        self.assertIn("total", data)

    def test_settings_get_and_post(self):
        settings = get_settings()
        self.assertIn("ollama_url", settings)
        self.assertIn("default_model", settings)

        updated = update_settings(SettingsModel(
            ollama_url="http://localhost:11434",
            default_model="mistral",
            ai_enabled=True,
        ))
        self.assertTrue(updated["success"])
        self.assertEqual(updated["settings"]["default_model"], "mistral")

    @patch("defa.ai.client.OllamaClient.check_health")
    def test_ai_status(self, mock_health):
        mock_health.return_value = {
            "online": False,
            "version": None,
            "base_url": "http://localhost:11434",
            "error": "Ollama service is not reachable",
        }
        data = get_ai_status()
        self.assertFalse(data["online"])
        self.assertIn("Ollama service is not reachable", data["error"])

    @patch("defa.ai.client.OllamaClient.chat")
    def test_ai_chat_mocked(self, mock_chat):
        mock_chat.return_value = {
            "success": True,
            "reply": "Forensic scan summary: 14 files analyzed.",
            "model": "llama3.2",
            "error": None,
        }
        req = ChatRequest(messages=[ChatMessage(role="user", content="Summarize scan")])
        res = ai_chat(req)
        self.assertTrue(res["success"])
        self.assertIn("Forensic scan summary", res["reply"])

    def test_export_report_pdf(self):
        res = export_report(report_type="pdf", case="TEST-CASE", investigator="Examiner")
        self.assertIsInstance(res, FileResponse)
        self.assertEqual(res.media_type, "application/pdf")

    def test_export_report_invalid_type_raises_400(self):
        with self.assertRaises(HTTPException) as ctx:
            export_report(report_type="unsupported_format")
        self.assertEqual(ctx.exception.status_code, 400)


if __name__ == "__main__":
    unittest.main()
