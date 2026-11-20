"""
history.py — Scan History Tracking & Comparison Module

Responsibility:
    Persist scan summaries to a history log and provide utilities
    to list past scans and compare two historical scans.

Key concepts used:
    - json: structured local storage in reports/scan_history.json
    - pathlib: cross-platform path handling
    - datetime: ISO-8601 timestamps
"""

import json
import logging
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

DEFAULT_HISTORY_FILE = "reports/scan_history.json"


def _now_utc() -> str:
    return datetime.now(tz=timezone.utc).isoformat()


def load_history(history_file: str | Path = DEFAULT_HISTORY_FILE) -> list[dict[str, Any]]:
    """
    Load all scan history records from disk.

    Returns:
        List of scan history dicts, newest first.
    """
    path = Path(history_file)
    if not path.exists():
        return []

    try:
        with path.open("r", encoding="utf-8") as f:
            data = json.load(f)
            if isinstance(data, list):
                # Return newest first
                return sorted(data, key=lambda x: x.get("timestamp", ""), reverse=True)
            return []
    except (json.JSONDecodeError, OSError) as exc:
        logger.warning("Could not read scan history from %s: %s", path, exc)
        return []


def record_scan_history(
    scan_report: dict[str, Any],
    history_file: str | Path = DEFAULT_HISTORY_FILE,
) -> dict[str, Any]:
    """
    Append a scan summary to the history log.

    Args:
        scan_report: Full scan report dict from reporter.save_json_report()
        history_file: Path to history JSON file

    Returns:
        The newly created history summary record.
    """
    path = Path(history_file)
    path.parent.mkdir(parents=True, exist_ok=True)

    history = load_history(path)

    # Compute total bytes scanned
    files = scan_report.get("files", [])
    total_bytes = sum(f.get("size_bytes", 0) for f in files)

    entry = {
        "id": str(uuid.uuid4())[:8],
        "timestamp": scan_report.get("scanned_at", _now_utc()),
        "directory": scan_report.get("directory", "Unknown"),
        "total_files": scan_report.get("total_files", len(files)),
        "hashed_successfully": scan_report.get("hashed_successfully", 0),
        "hash_failed": scan_report.get("hash_failed", 0),
        "duplicate_groups": scan_report.get("duplicate_groups", 0),
        "duplicate_files": scan_report.get("duplicate_files", 0),
        "total_size_bytes": total_bytes,
    }

    # Prepend new entry
    history.insert(0, entry)

    try:
        with path.open("w", encoding="utf-8") as f:
            json.dump(history, f, indent=2, ensure_ascii=False)
        logger.info("Recorded scan history entry %s for %s", entry["id"], entry["directory"])
    except OSError as exc:
        logger.error("Failed to write scan history: %s", exc)

    return entry


def compare_scans(
    older_report: dict[str, Any],
    newer_report: dict[str, Any],
) -> dict[str, Any]:
    """
    Compare two historical scan reports.

    Returns:
        A dict with file delta counts and summary comparison.
    """
    old_files = {f["relative_path"]: f for f in older_report.get("files", [])}
    new_files = {f["relative_path"]: f for f in newer_report.get("files", [])}

    old_paths = set(old_files.keys())
    new_paths = set(new_files.keys())

    added_paths = new_paths - old_paths
    removed_paths = old_paths - new_paths
    common_paths = new_paths & old_paths

    modified_paths = []
    unchanged_paths = []

    for p in common_paths:
        old_hash = old_files[p].get("sha256")
        new_hash = new_files[p].get("sha256")
        if old_hash and new_hash and old_hash != new_hash:
            modified_paths.append({
                "path": p,
                "old_hash": old_hash,
                "new_hash": new_hash,
                "old_size": old_files[p].get("size_bytes", 0),
                "new_size": new_files[p].get("size_bytes", 0),
            })
        else:
            unchanged_paths.append(p)

    return {
        "older_timestamp": older_report.get("scanned_at"),
        "newer_timestamp": newer_report.get("scanned_at"),
        "older_directory": older_report.get("directory"),
        "newer_directory": newer_report.get("directory"),
        "added": sorted(list(added_paths)),
        "removed": sorted(list(removed_paths)),
        "modified": modified_paths,
        "unchanged_count": len(unchanged_paths),
        "summary": {
            "added_count": len(added_paths),
            "removed_count": len(removed_paths),
            "modified_count": len(modified_paths),
            "unchanged_count": len(unchanged_paths),
        },
    }

