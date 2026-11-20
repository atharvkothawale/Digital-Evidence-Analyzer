"""
verifier.py — Baseline Comparison Module

Responsibility:
    Compare a fresh scan of a directory against a previously saved baseline
    to identify what has changed: new files, deleted files, modified files,
    and unchanged files.

Key concepts used:
    - dict  : relative_path → record lookups in O(1) time
    - set   : fast membership testing and set algebra (difference, intersection)
    - json  : loading the saved baseline from disk

Why this matters in forensics?
    After securing a scene, investigators create a baseline (a 'known-good'
    snapshot) of all files and their hashes.  Any deviation from that
    baseline — even a single changed byte — is immediately visible.
    This technique is called 'integrity monitoring'.
"""

import json
import logging
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


def load_baseline(baseline_path: str | Path) -> dict[str, Any]:
    """
    Read a baseline JSON file saved by a previous scan.

    Args:
        baseline_path: Path to the baseline.json file.

    Returns:
        The parsed baseline dictionary with keys:
            'scanned_at', 'directory', 'files' (list of records).

    Raises:
        FileNotFoundError: If the baseline file does not exist.
        ValueError: If the JSON is malformed or missing 'files' key.
    """
    path = Path(baseline_path)
    if not path.exists():
        raise FileNotFoundError(f"Baseline file not found: {path}")

    try:
        with path.open("r", encoding="utf-8") as fh:
            data = json.load(fh)
    except json.JSONDecodeError as exc:
        raise ValueError(f"Baseline file is not valid JSON: {exc}") from exc

    if "files" not in data:
        raise ValueError("Baseline JSON is missing the 'files' key.")

    logger.info("Loaded baseline from: %s (%d records)", path, len(data["files"]))
    return data


def compare_with_baseline(
    current_records: list[dict[str, Any]],
    baseline: dict[str, Any],
) -> dict[str, list[Any]]:
    """
    Compare current scan results against a saved baseline.

    Args:
        current_records: File records from the current scan (list of dicts).
        baseline: Baseline dict loaded with load_baseline().

    Returns:
        A dict with four keys:
            'new'       — files present now but not in the baseline
            'missing'   — files in the baseline but not found now
            'modified'  — files present in both but with a different SHA-256
            'unchanged' — files present in both with the same SHA-256

    Algorithm:
        1. Build lookup dicts: relative_path → record for both sides.
        2. Compute set differences and intersections using path keys.
        3. For the intersection, compare hashes to split into modified/unchanged.
    """
    # Build dicts keyed by relative_path for fast O(1) lookup
    current_map: dict[str, dict] = {
        r["relative_path"]: r for r in current_records
    }
    baseline_map: dict[str, dict] = {
        r["relative_path"]: r for r in baseline["files"]
    }

    current_paths: set[str] = set(current_map.keys())
    baseline_paths: set[str] = set(baseline_map.keys())

    new_paths = current_paths - baseline_paths          # in current, not in baseline
    missing_paths = baseline_paths - current_paths      # in baseline, not in current
    common_paths = current_paths & baseline_paths       # in both

    result: dict[str, list] = {
        "new": [],
        "missing": [],
        "modified": [],
        "unchanged": [],
    }

    for path in sorted(new_paths):
        result["new"].append(current_map[path])

    for path in sorted(missing_paths):
        result["missing"].append(baseline_map[path])

    for path in sorted(common_paths):
        current_hash = current_map[path].get("sha256")
        baseline_hash = baseline_map[path].get("sha256")

        if current_hash != baseline_hash:
            result["modified"].append({
                "current": current_map[path],
                "baseline": baseline_map[path],
            })
        else:
            result["unchanged"].append(current_map[path])

    logger.info(
        "Verification complete — new: %d, missing: %d, modified: %d, unchanged: %d",
        len(result["new"]),
        len(result["missing"]),
        len(result["modified"]),
        len(result["unchanged"]),
    )

    return result

