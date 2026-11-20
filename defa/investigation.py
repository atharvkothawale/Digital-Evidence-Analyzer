"""
investigation.py — Dynamic Evidence Investigation Manager & Progress Engine

Responsibility:
    - Coordinates dynamic evidence selection (folders, files, mixed, overlapping).
    - Executes real-time forensic scanning and chunked SHA-256 hashing in a background thread.
    - Tracks and exposes fine-grained progress metrics (discovered, processed, remaining,
      current file, hashing progress, failed files, overall percentage, and throughput).
    - Interfaces with native operating system folder/file picker dialogs.
    - Handles permission/IO failures gracefully without stopping the overall investigation.
"""

import logging
import os
import threading
import time
import uuid
from pathlib import Path
from typing import Any

from defa.duplicates import find_duplicates
from defa.findings import generate_forensic_findings
from defa.hasher import compute_sha256
from defa.history import record_scan_history
from defa.pdf_report import generate_pdf_report
from defa.reporter import save_baseline, save_csv_report, save_json_report
from defa.scanner import count_selected_directories, scan_evidence_selection

logger = logging.getLogger(__name__)


def open_native_folder_dialog(title: str = "Select Forensic Evidence Folder") -> str | None:
    """
    Open native Windows / OS folder selection dialog.
    Returns the selected folder path string, or None if cancelled/failed.
    """
    try:
        import tkinter as tk
        from tkinter import filedialog
        root = tk.Tk()
        root.withdraw()
        root.attributes("-topmost", True)
        folder = filedialog.askdirectory(title=title)
        root.destroy()
        return str(Path(folder).resolve()) if folder else None
    except Exception as exc:
        logger.warning("Native folder dialog invocation failed: %s", exc)
        return None


def open_native_files_dialog(title: str = "Select Forensic Evidence Files") -> list[str]:
    """
    Open native Windows / OS file selection dialog supporting multiple selections.
    Returns a list of selected file path strings, or empty list if cancelled/failed.
    """
    try:
        import tkinter as tk
        from tkinter import filedialog
        root = tk.Tk()
        root.withdraw()
        root.attributes("-topmost", True)
        files = filedialog.askopenfilenames(title=title)
        root.destroy()
        return [str(Path(f).resolve()) for f in files] if files else []
    except Exception as exc:
        logger.warning("Native files dialog invocation failed: %s", exc)
        return []


class InvestigationManager:
    """
    Thread-safe background investigation controller with live progress tracking.
    """

    def __init__(self):
        self._lock = threading.Lock()
        self.job_id: str | None = None
        self.status: str = "idle"  # "idle", "discovering", "hashing", "analyzing", "completed", "error"
        self.selected_items: list[str] = []
        self.output_dir: str = "reports"
        self.files_discovered: int = 0
        self.files_processed: int = 0
        self.files_remaining: int = 0
        self.current_file: str = ""
        self.hashed_ok: int = 0
        self.hash_failed: int = 0
        self.total_bytes: int = 0
        self.total_folders: int = 0
        self.progress_percent: float = 0.0
        self.start_time: float = 0.0
        self.duration_seconds: float = 0.0
        self.throughput_mb_s: float = 0.0
        self.error_message: str | None = None
        self.summary: dict[str, Any] | None = None
        self.active_scan: dict[str, Any] | None = None
        self.active_findings: list[dict[str, Any]] = []

    def get_progress(self) -> dict[str, Any]:
        """Return a thread-safe snapshot of the current progress."""
        with self._lock:
            return {
                "job_id": self.job_id,
                "status": self.status,
                "selected_items": list(self.selected_items),
                "files_discovered": self.files_discovered,
                "files_processed": self.files_processed,
                "files_remaining": self.files_remaining,
                "current_file": self.current_file,
                "hashed_ok": self.hashed_ok,
                "hash_failed": self.hash_failed,
                "total_bytes": self.total_bytes,
                "total_folders": self.total_folders,
                "progress_percent": round(self.progress_percent, 1),
                "duration_seconds": round(self.duration_seconds, 2),
                "throughput_mb_s": round(self.throughput_mb_s, 2),
                "error": self.error_message,
                "summary": self.summary,
            }

    def start(self, items: list[str], output_dir: str = "reports") -> str:
        """
        Initiate an investigation on the given list of files/folders in a background thread.
        Returns the unique job_id.
        """
        with self._lock:
            if self.status in ("discovering", "hashing", "analyzing"):
                raise RuntimeError("An investigation is already in progress.")

            self.job_id = f"job-{uuid.uuid4().hex[:8]}"
            self.status = "discovering"
            self.selected_items = [str(Path(p).resolve()) for p in items if p]
            self.output_dir = output_dir
            self.files_discovered = 0
            self.files_processed = 0
            self.files_remaining = 0
            self.current_file = ""
            self.hashed_ok = 0
            self.hash_failed = 0
            self.total_bytes = 0
            self.total_folders = 0
            self.progress_percent = 0.0
            self.start_time = time.perf_counter()
            self.duration_seconds = 0.0
            self.throughput_mb_s = 0.0
            self.error_message = None
            self.summary = None

        thread = threading.Thread(target=self._run_investigation, daemon=True)
        thread.start()
        return self.job_id

    def _run_investigation(self) -> None:
        """Internal worker executing the forensic scanning pipeline."""
        try:
            out_dir = Path(self.output_dir)
            out_dir.mkdir(parents=True, exist_ok=True)

            # ── Phase 1: Dynamic Discovery (Deduplicating Overlaps) ──
            discovered_records: list[dict[str, Any]] = []
            for record in scan_evidence_selection(self.selected_items):
                discovered_records.append(record)
                with self._lock:
                    self.files_discovered = len(discovered_records)

            total_folders = count_selected_directories(self.selected_items)
            total_count = len(discovered_records)

            with self._lock:
                self.total_folders = total_folders
                self.files_remaining = total_count
                self.status = "hashing" if total_count > 0 else "analyzing"
                if total_count == 0:
                    self.progress_percent = 100.0

            # ── Phase 2: Chunk-Based Cryptographic Hashing ──
            hashed_records: list[dict[str, Any]] = []
            total_bytes_scanned = 0

            for idx, rec in enumerate(discovered_records, start=1):
                with self._lock:
                    self.current_file = rec.get("relative_path", rec["name"])

                file_size = rec.get("size_bytes", 0)
                total_bytes_scanned += file_size

                if rec.get("accessible", False):
                    sha = compute_sha256(rec["absolute_path"])
                    rec["sha256"] = sha
                    rec["scan_status"] = "hashed" if sha else "hash_failed"
                    if sha:
                        with self._lock:
                            self.hashed_ok += 1
                    else:
                        with self._lock:
                            self.hash_failed += 1
                else:
                    rec["sha256"] = None
                    rec["scan_status"] = "inaccessible"
                    with self._lock:
                        self.hash_failed += 1

                hashed_records.append(rec)

                # Update live progress
                now = time.perf_counter()
                elapsed = max(now - self.start_time, 0.001)
                mb_processed = total_bytes_scanned / (1024 * 1024)

                with self._lock:
                    self.files_processed = idx
                    self.files_remaining = total_count - idx
                    self.total_bytes = total_bytes_scanned
                    self.duration_seconds = elapsed
                    self.throughput_mb_s = mb_processed / elapsed
                    self.progress_percent = (idx / total_count) * 90.0  # 90% allocated to hashing

            # ── Phase 3: Forensic Findings & Anomaly Detection ──
            with self._lock:
                self.status = "analyzing"
                self.current_file = "Generating forensic anomaly findings & duplicate analysis..."

            dup_groups = find_duplicates(hashed_records)
            findings = generate_forensic_findings(hashed_records, dup_groups)

            # Performance Metrics
            total_elapsed = max(time.perf_counter() - self.start_time, 0.001)
            total_mb = total_bytes_scanned / (1024 * 1024)
            perf_metrics = {
                "duration_seconds": round(total_elapsed, 3),
                "total_megabytes": round(total_mb, 2),
                "files_per_second": round(len(hashed_records) / total_elapsed, 1),
                "throughput_mb_per_second": round(total_mb / total_elapsed, 2),
            }

            # ── Phase 4: Report Generation & Persistence ──
            target_display = (
                self.selected_items[0]
                if len(self.selected_items) == 1
                else f"{len(self.selected_items)} selected evidence locations"
            )

            json_path = save_json_report(
                file_records=hashed_records,
                duplicate_groups=dup_groups,
                directory=target_display,
                output_dir=out_dir,
                findings=findings,
                performance_metrics=perf_metrics,
                total_folders=total_folders,
                selected_paths=self.selected_items,
            )
            save_csv_report(hashed_records, out_dir)
            save_baseline(hashed_records, target_display, out_dir)

            import json
            with json_path.open("r", encoding="utf-8") as f:
                scan_data = json.load(f)

            # Generate court-admissible PDF
            try:
                generate_pdf_report(
                    case_name="ACTIVE-EVIDENCE-INVESTIGATION",
                    investigator="Forensic Examiner",
                    scan_report=scan_data,
                    findings=findings,
                    output_path=out_dir / "investigation_report.pdf",
                )
            except Exception as exc:
                logger.warning("PDF report generation failed: %s", exc)

            record_scan_history(scan_data)

            with self._lock:
                self.status = "completed"
                self.progress_percent = 100.0
                self.duration_seconds = total_elapsed
                self.throughput_mb_s = round(total_mb / total_elapsed, 2)
                self.current_file = "Investigation complete."
                self.active_scan = scan_data
                self.active_findings = findings
                self.summary = {
                    "total_files": len(hashed_records),
                    "total_folders": total_folders,
                    "total_bytes": total_bytes_scanned,
                    "hashed_successfully": self.hashed_ok,
                    "hash_failed": self.hash_failed,
                    "duplicate_groups": len(dup_groups),
                    "duplicate_files": sum(len(g) for g in dup_groups),
                    "findings_count": len(findings),
                    "selected_items": self.selected_items,
                    "performance": perf_metrics,
                }

        except Exception as exc:
            logger.exception("Investigation execution encountered an error: %s", exc)
            with self._lock:
                self.status = "error"
                self.error_message = str(exc)
                self.current_file = "Investigation halted due to error."


# Global investigation controller instance
investigation_manager = InvestigationManager()

