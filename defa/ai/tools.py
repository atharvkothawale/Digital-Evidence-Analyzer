"""
tools.py — Forensic Tool Dispatcher for Local AI Assistant

Responsibility:
    Expose actual DEFA forensic engine functions to the AI assistant
    so that queries are grounded in verified, real scan data.
    Prevents hallucination of filenames, hashes, or statistics.
"""

from typing import Any
from defa.ai.context import format_bytes


def defa_search_evidence(active_scan: dict[str, Any] | None, query: str, limit: int = 10) -> list[dict[str, Any]]:
    """Search files in active evidence scan by name or path."""
    if not active_scan:
        return []
    files = active_scan.get("files", [])
    q = query.lower().strip()
    matches = []
    for f in files:
        if q in f.get("name", "").lower() or q in f.get("relative_path", "").lower() or q in f.get("extension", "").lower():
            matches.append({
                "name": f.get("name"),
                "relative_path": f.get("relative_path"),
                "extension": f.get("extension"),
                "size_formatted": format_bytes(f.get("size_bytes", 0)),
                "sha256": f.get("sha256"),
                "modified_at": f.get("modified_at"),
            })
            if len(matches) >= limit:
                break
    return matches


def defa_get_file_details(active_scan: dict[str, Any] | None, relative_path: str) -> dict[str, Any] | None:
    """Retrieve complete metadata and hash for a specific file path."""
    if not active_scan:
        return None
    files = active_scan.get("files", [])
    target = relative_path.replace("\\", "/").strip().lower()
    for f in files:
        cur = f.get("relative_path", "").replace("\\", "/").strip().lower()
        if cur == target or cur.endswith("/" + target) or f.get("name", "").lower() == target:
            return {
                "name": f.get("name"),
                "relative_path": f.get("relative_path"),
                "size_bytes": f.get("size_bytes"),
                "size_formatted": format_bytes(f.get("size_bytes", 0)),
                "sha256": f.get("sha256"),
                "extension": f.get("extension"),
                "created_at": f.get("created_at"),
                "modified_at": f.get("modified_at"),
                "scan_status": f.get("scan_status"),
            }
    return None


def defa_get_scan_statistics(active_scan: dict[str, Any] | None) -> dict[str, Any]:
    """Retrieve summary counts, sizes, and hashing statistics of current evidence."""
    if not active_scan:
        return {"status": "No active evidence scan loaded."}
    files = active_scan.get("files", [])
    total_bytes = sum(f.get("size_bytes", 0) for f in files)
    return {
        "directory": active_scan.get("directory"),
        "scanned_at": active_scan.get("scanned_at"),
        "total_files": len(files),
        "total_storage_bytes": total_bytes,
        "total_storage_formatted": format_bytes(total_bytes),
        "hashed_successfully": active_scan.get("hashed_successfully", 0),
        "hash_failed": active_scan.get("hash_failed", 0),
        "duplicate_groups": active_scan.get("duplicate_groups", 0),
        "duplicate_files": active_scan.get("duplicate_files", 0),
    }


def defa_get_duplicate_groups(active_scan: dict[str, Any] | None) -> list[dict[str, Any]]:
    """Retrieve all duplicate file groups sharing identical SHA-256 digests."""
    if not active_scan:
        return []
    return active_scan.get("duplicates", [])


def defa_get_largest_files(active_scan: dict[str, Any] | None, limit: int = 5) -> list[dict[str, Any]]:
    """Retrieve the top largest files by volume from the active scan."""
    if not active_scan:
        return []
    files = active_scan.get("files", [])
    sorted_files = sorted(files, key=lambda x: x.get("size_bytes", 0), reverse=True)[:limit]
    return [
        {
            "name": f.get("name"),
            "relative_path": f.get("relative_path"),
            "size_formatted": format_bytes(f.get("size_bytes", 0)),
            "sha256": f.get("sha256"),
        }
        for f in sorted_files
    ]


def defa_get_findings(findings_list: list[dict[str, Any]], severity: str = "all") -> list[dict[str, Any]]:
    """Retrieve investigative findings, optionally filtered by severity."""
    if severity == "all":
        return findings_list
    return [f for f in findings_list if f.get("severity", "").lower() == severity.lower()]


def defa_compare_baselines(verification_report: dict[str, Any] | None) -> dict[str, Any]:
    """Retrieve current baseline integrity verification results."""
    if not verification_report:
        return {"status": "No verification report loaded. Baseline comparison has not been executed."}
    return {
        "verified_at": verification_report.get("verified_at"),
        "baseline_used": verification_report.get("baseline_used"),
        "summary": verification_report.get("summary"),
        "modified_count": len(verification_report.get("details", {}).get("modified", [])),
        "new_count": len(verification_report.get("details", {}).get("new", [])),
        "missing_count": len(verification_report.get("details", {}).get("missing", [])),
    }

