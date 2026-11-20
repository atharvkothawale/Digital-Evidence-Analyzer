"""
scanner.py — Directory and Evidence Selection Scanner Module

Responsibility:
    Walk selected directories, individual files, or mixed forensic evidence
    and collect metadata for every file found.
    Deduplicates overlapping folder/file selections and never modifies,
    moves, or deletes files.

Key concepts used:
    - pathlib.Path  : modern, OS-independent path handling
    - os.stat       : access file metadata (size, timestamps)
    - logging       : record skipped files and errors non-intrusively
"""

import logging
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Generator

logger = logging.getLogger(__name__)


def _format_timestamp(epoch_seconds: float) -> str:
    """
    Convert a POSIX timestamp (float) to a readable ISO-8601 UTC string.

    Args:
        epoch_seconds: Seconds since the Unix epoch (1970-01-01 00:00:00 UTC).

    Returns:
        A string like '2024-06-15T10:30:00+00:00'.
    """
    return datetime.fromtimestamp(epoch_seconds, tz=timezone.utc).isoformat()


def collect_file_metadata(file_path: Path, base_dir: Path | None = None) -> dict[str, Any]:
    """
    Gather file metadata for one file and return it as a dictionary.

    Args:
        file_path: Absolute path to the file being inspected.
        base_dir:  Root directory of the scan; used to compute relative paths.

    Returns:
        A dict with keys: name, extension, absolute_path, relative_path,
        size_bytes, created_at, modified_at, accessed_at, accessible, is_hidden.

    Notes:
        'accessible' is False when a PermissionError or OSError is raised.
        The original file is never modified.
    """
    rel_path = file_path.name
    if base_dir:
        try:
            rel_path = str(file_path.relative_to(base_dir))
        except ValueError:
            rel_path = file_path.name

    result: dict[str, Any] = {
        "name": file_path.name,
        "extension": file_path.suffix.lower(),
        "absolute_path": str(file_path.resolve()),
        "relative_path": rel_path,
        "size_bytes": 0,
        "created_at": None,
        "modified_at": None,
        "accessed_at": None,
        "accessible": False,
        "is_hidden": file_path.name.startswith("."),
    }

    try:
        stat = file_path.stat()
        result["size_bytes"] = stat.st_size
        result["modified_at"] = _format_timestamp(stat.st_mtime)
        result["accessed_at"] = _format_timestamp(stat.st_atime)
        # st_birthtime exists on macOS/Windows; fall back to st_ctime on Linux
        created_epoch = getattr(stat, "st_birthtime", stat.st_ctime)
        result["created_at"] = _format_timestamp(created_epoch)
        result["accessible"] = True

        # Check Windows hidden attribute if applicable
        if os.name == "nt":
            import stat as stat_mod
            if hasattr(stat_mod, "FILE_ATTRIBUTE_HIDDEN") and hasattr(stat, "st_file_attributes"):
                if stat.st_file_attributes & stat_mod.FILE_ATTRIBUTE_HIDDEN:
                    result["is_hidden"] = True
    except PermissionError:
        logger.warning("Permission denied reading metadata: %s", file_path)
    except OSError as exc:
        logger.warning("OS error reading metadata for %s: %s", file_path, exc)

    return result


def scan_directory(directory: str | Path) -> Generator[dict[str, Any], None, None]:
    """
    Recursively yield one metadata dictionary per file in *directory*.

    Args:
        directory: Path to the root directory to scan (string or Path).

    Yields:
        One dict per file (see collect_file_metadata for the schema).

    Raises:
        FileNotFoundError: If *directory* does not exist.
        NotADirectoryError: If *directory* is not a directory.
    """
    root = Path(directory).resolve()

    if not root.exists():
        raise FileNotFoundError(f"Directory not found: {root}")
    if not root.is_dir():
        raise NotADirectoryError(f"Not a directory: {root}")

    logger.info("Starting directory scan: %s", root)

    for entry in root.rglob("*"):
        if entry.is_file():
            metadata = collect_file_metadata(entry, root)
            yield metadata

    logger.info("Directory scan complete: %s", root)


def scan_evidence_selection(items: list[str | Path]) -> Generator[dict[str, Any], None, None]:
    """
    Recursively discover and yield metadata for files within a dynamic selection
    of directories and individual files.

    Guarantees:
        - Resolves all paths canonically.
        - Deduplicates overlapping selections (e.g. parent folder and child file,
          or identical files/folders selected multiple times).
        - Handles permission errors / unreadable items gracefully without crashing.
        - Preserves read-only integrity (never modifies or moves files).
    """
    if not items:
        return

    # If exactly one directory is passed, delegate cleanly to scan_directory
    if len(items) == 1:
        single = Path(items[0]).resolve()
        if single.is_dir():
            yield from scan_directory(single)
            return

    seen_canonical_files: set[str] = set()

    # Normalize and sort selections
    resolved_items: list[Path] = []
    for raw in items:
        p = Path(raw).resolve()
        if p.exists():
            resolved_items.append(p)
        else:
            logger.warning("Selected evidence path does not exist: %s", raw)

    for item in resolved_items:
        if item.is_file():
            canon = str(item)
            if canon in seen_canonical_files:
                continue
            seen_canonical_files.add(canon)
            metadata = collect_file_metadata(item, base_dir=item.parent)
            metadata["relative_path"] = item.name
            yield metadata

        elif item.is_dir():
            try:
                for entry in item.rglob("*"):
                    if entry.is_file():
                        canon = str(entry.resolve())
                        if canon in seen_canonical_files:
                            continue
                        seen_canonical_files.add(canon)

                        metadata = collect_file_metadata(entry, base_dir=item)
                        rel_posix = entry.relative_to(item).as_posix()
                        metadata["relative_path"] = f"{item.name}/{rel_posix}"
                        yield metadata
            except PermissionError:
                logger.warning("Permission denied walking directory: %s", item)
            except OSError as exc:
                logger.warning("OS error walking directory %s: %s", item, exc)


def inspect_evidence_item(item_path: str | Path) -> dict[str, Any]:
    """
    Inspect a single evidence item (file or folder) and return its summary metadata.
    """
    p = Path(item_path).resolve()
    if not p.exists():
        return {
            "path": str(p),
            "name": p.name or str(p),
            "type": "unknown",
            "exists": False,
            "accessible": False,
            "estimated_files": 0,
            "estimated_size_bytes": 0,
        }

    is_dir = p.is_dir()
    accessible = os.access(p, os.R_OK)

    if not is_dir:
        size = 0
        try:
            size = p.stat().st_size
        except Exception:
            pass
        return {
            "path": str(p),
            "name": p.name,
            "type": "file",
            "exists": True,
            "accessible": accessible,
            "estimated_files": 1,
            "estimated_size_bytes": size,
        }
    else:
        file_count = 0
        total_size = 0
        try:
            for entry in p.rglob("*"):
                if entry.is_file():
                    file_count += 1
                    try:
                        total_size += entry.stat().st_size
                    except Exception:
                        pass
        except Exception:
            pass

        return {
            "path": str(p),
            "name": p.name or str(p),
            "type": "folder",
            "exists": True,
            "accessible": accessible,
            "estimated_files": file_count,
            "estimated_size_bytes": total_size,
        }


def inspect_evidence_selection(items: list[str | Path]) -> dict[str, Any]:
    """
    Preview and summarize a list of selected evidence paths before scanning.
    Calculates estimated files, estimated size, item types, and flags overlapping paths.
    """
    inspected = []
    seen_paths = set()
    overlapping_warnings = []
    resolved_paths: list[Path] = []

    for raw in items:
        p = Path(raw).resolve()
        canon = str(p)
        if canon in seen_paths:
            continue
        seen_paths.add(canon)
        info = inspect_evidence_item(p)
        inspected.append(info)
        resolved_paths.append(p)

    # Check for hierarchical overlaps
    for i, p1 in enumerate(resolved_paths):
        for j, p2 in enumerate(resolved_paths):
            if i != j and p1.is_dir():
                try:
                    if p2.is_relative_to(p1):
                        overlapping_warnings.append(
                            f"Item '{p2.name}' is inside folder '{p1.name}'. It will only be scanned once (no duplicate processing)."
                        )
                except AttributeError:
                    pass

    return {
        "items": inspected,
        "total_items": len(inspected),
        "total_estimated_files": sum(it["estimated_files"] for it in inspected),
        "total_estimated_size_bytes": sum(it["estimated_size_bytes"] for it in inspected),
        "warnings": overlapping_warnings,
    }


def count_directories(directory: str | Path) -> int:
    """
    Count the total number of subdirectories contained within *directory*.
    """
    root = Path(directory).resolve()
    if not root.exists() or not root.is_dir():
        return 0
    return sum(1 for entry in root.rglob("*") if entry.is_dir())


def count_selected_directories(items: list[str | Path]) -> int:
    """
    Count total unique directories across all selected items.
    """
    total = 0
    seen_dirs = set()
    for raw in items:
        p = Path(raw).resolve()
        if p.exists() and p.is_dir():
            if str(p) not in seen_dirs:
                seen_dirs.add(str(p))
                total += 1
            for entry in p.rglob("*"):
                if entry.is_dir() and str(entry.resolve()) not in seen_dirs:
                    seen_dirs.add(str(entry.resolve()))
                    total += 1
    return total
