"""
reporter.py — Report Generation Module

Responsibility:
    Write scan results to JSON and CSV files, and save a baseline JSON
    that can be used by the verifier in future runs.

Key concepts used:
    - json   : human-readable, structured data format
    - csv    : spreadsheet-compatible tabular format
    - pathlib: safe, cross-platform path construction
    - datetime: timestamp for report metadata

JSON vs CSV:
    JSON preserves nested structure (e.g., verification results, metadata).
    CSV is flat — each row is one file — perfect for opening in Excel.
    Both are generated so the user can choose the tool that fits their need.
"""

import csv
import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

# CSV columns in the order they appear in the output file
CSV_COLUMNS: list[str] = [
    "name",
    "relative_path",
    "extension",
    "size_bytes",
    "sha256",
    "created_at",
    "modified_at",
    "accessed_at",
    "accessible",
    "is_hidden",
    "scan_status",
]


def _now_utc() -> str:
    """Return the current UTC time as an ISO-8601 string."""
    return datetime.now(tz=timezone.utc).isoformat()


def _ensure_output_dir(output_dir: str | Path) -> Path:
    """Create the output directory if it does not already exist."""
    path = Path(output_dir)
    path.mkdir(parents=True, exist_ok=True)
    return path


def save_json_report(
    file_records: list[dict[str, Any]],
    duplicate_groups: list[list[dict[str, Any]]],
    directory: str,
    output_dir: str | Path,
    filename: str = "scan_report.json",
    findings: list[dict[str, Any]] | None = None,
    performance_metrics: dict[str, Any] | None = None,
    total_folders: int = 0,
) -> Path:
    """
    Write a full forensic scan report to a JSON file.

    Args:
        file_records:        All file records from the scan.
        duplicate_groups:    Grouped duplicate records.
        directory:           The directory that was scanned (for metadata).
        output_dir:          Folder where the JSON file will be saved.
        filename:            Output file name (default: scan_report.json).
        findings:            Forensic findings from findings engine.
        performance_metrics: Scan duration and throughput metrics.
        total_folders:       Count of subdirectories discovered.

    Returns:
        Path to the created JSON file.
    """
    out_dir = _ensure_output_dir(output_dir)
    out_path = out_dir / filename

    # Summarise duplicate data for the report
    duplicate_summary = [
        {
            "sha256": group[0].get("sha256"),
            "count": len(group),
            "files": [r["relative_path"] for r in group],
        }
        for group in duplicate_groups
    ]

    report = {
        "tool": "DEFA — Digital Evidence Forensics & Investigation System",
        "version": "2.0.0",
        "scanned_at": _now_utc(),
        "directory": str(directory),
        "total_files": len(file_records),
        "total_folders": total_folders,
        "hashed_successfully": sum(1 for r in file_records if r.get("sha256")),
        "hash_failed": sum(1 for r in file_records if not r.get("sha256")),
        "duplicate_groups": len(duplicate_groups),
        "duplicate_files": sum(len(g) for g in duplicate_groups),
        "performance": performance_metrics or {},
        "files": file_records,
        "duplicates": duplicate_summary,
        "findings": findings or [],
    }

    with out_path.open("w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2, ensure_ascii=False)

    logger.info("JSON report saved: %s", out_path)
    return out_path


def save_csv_report(
    file_records: list[dict[str, Any]],
    output_dir: str | Path,
    filename: str = "scan_report.csv",
) -> Path:
    """
    Write a flat scan report to a CSV file (one row per file).

    Args:
        file_records: All file records from the scan.
        output_dir:   Folder where the CSV file will be saved.
        filename:     Output file name (default: scan_report.csv).

    Returns:
        Path to the created CSV file.
    """
    out_dir = _ensure_output_dir(output_dir)
    out_path = out_dir / filename

    with out_path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=CSV_COLUMNS, extrasaction="ignore")
        writer.writeheader()
        for record in file_records:
            writer.writerow(record)

    logger.info("CSV report saved: %s", out_path)
    return out_path


def save_baseline(
    file_records: list[dict[str, Any]],
    directory: str,
    output_dir: str | Path,
    filename: str = "baseline.json",
) -> Path:
    """
    Save a baseline snapshot for future integrity verification.

    The baseline is a JSON file containing every file's relative path and
    SHA-256 hash.  The verifier compares a new scan against this snapshot.

    Args:
        file_records: All file records from the scan.
        directory:    The directory that was scanned.
        output_dir:   Folder where the baseline file will be saved.
        filename:     Output file name (default: baseline.json).

    Returns:
        Path to the created baseline file.
    """
    out_dir = _ensure_output_dir(output_dir)
    out_path = out_dir / filename

    baseline = {
        "tool": "DEFA — Digital Evidence File Analyzer",
        "version": "1.0.0",
        "scanned_at": _now_utc(),
        "directory": str(directory),
        "files": file_records,
    }

    with out_path.open("w", encoding="utf-8") as fh:
        json.dump(baseline, fh, indent=2, ensure_ascii=False)

    logger.info("Baseline saved: %s", out_path)
    return out_path


def save_verification_report(
    verification_result: dict[str, list[Any]],
    directory: str,
    baseline_path: str,
    output_dir: str | Path,
    filename: str = "verification_report.json",
) -> Path:
    """
    Write the result of a baseline comparison to a JSON file.

    Args:
        verification_result: Dict from verifier.compare_with_baseline().
        directory:           The directory that was re-scanned.
        baseline_path:       Path to the baseline file that was used.
        output_dir:          Folder where the report will be saved.
        filename:            Output file name.

    Returns:
        Path to the created verification report.
    """
    out_dir = _ensure_output_dir(output_dir)
    out_path = out_dir / filename

    report = {
        "tool": "DEFA — Digital Evidence File Analyzer",
        "version": "1.0.0",
        "verified_at": _now_utc(),
        "directory": str(directory),
        "baseline_used": str(baseline_path),
        "summary": {
            "new": len(verification_result["new"]),
            "missing": len(verification_result["missing"]),
            "modified": len(verification_result["modified"]),
            "unchanged": len(verification_result["unchanged"]),
        },
        "details": verification_result,
    }

    with out_path.open("w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2, ensure_ascii=False)

    logger.info("Verification report saved: %s", out_path)
    return out_path

