"""
test_ai.py — Unit tests for Local AI Ollama client and forensic context builder.
Mocks all network requests so tests never depend on an active Ollama service.
"""

import unittest
from unittest.mock import patch, MagicMock
import io
import urllib.error

import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from defa.ai.client import OllamaClient
from defa.ai.context import build_forensic_context, format_bytes, SYSTEM_PROMPT


class TestForensicContextBuilder(unittest.TestCase):

    def test_format_bytes(self):
        self.assertEqual(format_bytes(500), "500.0 B")
        self.assertEqual(format_bytes(2048), "2.0 KB")
        self.assertEqual(format_bytes(1048576 * 3), "3.0 MB")

    def test_context_with_no_scan(self):
        ctx = build_forensic_context(None)
        self.assertIn("No scan has been performed", ctx)

    def test_context_with_scan_report(self):
        scan_report = {
            "scanned_at": "2026-11-20T12:00:00+00:00",
            "directory": "/evidence/test",
            "total_files": 2,
            "hashed_successfully": 2,
            "hash_failed": 0,
            "duplicate_groups": 1,
            "files": [
                {"relative_path": "doc1.txt", "size_bytes": 100, "sha256": "abc1234567890123456", "extension": ".txt"},
                {"relative_path": "doc2.txt", "size_bytes": 100, "sha256": "abc1234567890123456", "extension": ".txt"},
            ],
            "duplicates": [
                {"sha256": "abc1234567890123456", "count": 2, "files": ["doc1.txt", "doc2.txt"]}
            ],
        }
        ctx = build_forensic_context(scan_report)
        self.assertIn("Target Directory: /evidence/test", ctx)
        self.assertIn("Total Files Analyzed: 2", ctx)
        self.assertIn("Duplicate Groups: 1", ctx)
        self.assertIn("doc1.txt", ctx)

    def test_context_includes_verification_results(self):
        scan_report = {"files": [], "duplicates": []}
        verif_report = {
            "verified_at": "2026-11-20T13:00:00+00:00",
            "baseline_used": "reports/baseline.json",
            "summary": {"new": 1, "missing": 0, "modified": 1, "unchanged": 5},
            "details": {
                "new": [{"relative_path": "suspicious.exe"}],
                "modified": [{
                    "current": {"relative_path": "tampered.txt", "sha256": "newhash123"},
                    "baseline": {"relative_path": "tampered.txt", "sha256": "oldhash123"},
                }],
                "missing": [],
                "unchanged": [],
            },
        }
        ctx = build_forensic_context(scan_report, verif_report)
        self.assertIn("BASELINE INTEGRITY VERIFICATION RESULTS", ctx)
        self.assertIn("suspicious.exe", ctx)
        self.assertIn("tampered.txt", ctx)


class TestOllamaClient(unittest.TestCase):

    def setUp(self):
        self.client = OllamaClient(base_url="http://localhost:11434", default_model="llama3.2")

    @patch.object(OllamaClient, "_is_port_reachable", return_value=True)
    @patch("urllib.request.urlopen")
    def test_check_health_online(self, mock_urlopen, mock_port):
        mock_response = MagicMock()
        mock_response.status = 200
        mock_response.read.return_value = b'{"version": "0.3.14"}'
        mock_urlopen.return_value.__enter__.return_value = mock_response

        status = self.client.check_health()
        self.assertTrue(status["online"])
        self.assertEqual(status["version"], "0.3.14")
        self.assertIsNone(status["error"])

    @patch.object(OllamaClient, "_is_port_reachable", return_value=False)
    def test_check_health_offline_graceful(self, mock_port):
        status = self.client.check_health()
        self.assertFalse(status["online"])
        self.assertIsNone(status["version"])
        self.assertIn("not reachable", status["error"])

    @patch("urllib.request.urlopen")
    def test_list_models(self, mock_urlopen):
        mock_response = MagicMock()
        mock_response.status = 200
        mock_response.read.return_value = b'{"models": [{"name": "llama3.2:latest"}, {"name": "mistral:7b"}]}'
        mock_urlopen.return_value.__enter__.return_value = mock_response

        models = self.client.list_models()
        self.assertEqual(models, ["llama3.2:latest", "mistral:7b"])

    @patch.object(OllamaClient, "_is_port_reachable", return_value=True)
    @patch("urllib.request.urlopen")
    def test_chat_success(self, mock_urlopen, mock_port):
        # Health check call
        mock_health_resp = MagicMock()
        mock_health_resp.status = 200
        mock_health_resp.read.return_value = b'{"version": "0.3.14"}'

        # Chat call
        mock_chat_resp = MagicMock()
        mock_chat_resp.status = 200
        mock_chat_resp.read.return_value = b'{"message": {"role": "assistant", "content": "Analysis completed."}}'

        mock_urlopen.return_value.__enter__.side_effect = [mock_health_resp, mock_chat_resp]

        resp = self.client.chat(messages=[{"role": "user", "content": "Summarize scan"}])
        self.assertTrue(resp["success"])
        self.assertEqual(resp["reply"], "Analysis completed.")
        self.assertIsNone(resp["error"])

    @patch.object(OllamaClient, "_is_port_reachable", return_value=False)
    def test_chat_offline_returns_helpful_error(self, mock_port):
        resp = self.client.chat(messages=[{"role": "user", "content": "Summarize scan"}])
        self.assertFalse(resp["success"])
        self.assertIn("Ollama is not running", resp["error"])


if __name__ == "__main__":
    unittest.main()
