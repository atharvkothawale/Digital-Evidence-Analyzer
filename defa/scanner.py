"""
scanner.py — Directory Scanner Module

Responsibility:
    Walk a directory tree and collect metadata for every file found.
    This module never modifies, moves, or deletes files.

Key concepts used:
    - pathlib.Path  : modern, OS-independent path handling
    - os.stat       : access file metadata (size, timestamps)
    - logging       : record skipped files and errors non-intrusively
"""

import logging
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Generator

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


def collect_file_metadata(file_path: Path, base_dir: Path) -> dict:
    """
    Gather file metadata for one file and return it as a dictionary.

    Args:
        file_path: Absolute path to the file being inspected.
        base_dir:  Root directory of the scan; used to compute relative paths.

    Returns:
        A dict with keys: name, extension, absolute_path, relative_path,
        size_bytes, created_at, modified_at, accessed_at, accessible.

    Notes:
        'accessible' is False when a PermissionError or OSError is raised.
        The original file is never modified.
    """
    result: dict = {
        "name": file_path.name,
        "extension": file_path.suffix.lower(),
        "absolute_path": str(file_path.resolve()),
        "relative_path": str(file_path.relative_to(base_dir)),
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


def scan_directory(directory: str | Path) -> Generator[dict, None, None]:
    """
    Recursively yield one metadata dictionary per file in *directory*.

    Args:
        directory: Path to the root directory to scan (string or Path).

    Yields:
        One dict per file (see collect_file_metadata for the schema).

    Raises:
        FileNotFoundError: If *directory* does not exist.
        NotADirectoryError: If *directory* is not a directory.

    Notes:
        - Symbolic links are followed by default (pathlib rglob behaviour).
        - Files that cannot be accessed are still yielded with accessible=False.
        - The generator yields lazily, so large directories are memory-efficient.
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


def count_directories(directory: str | Path) -> int:
    """
    Count the total number of subdirectories contained within *directory*.
    """
    root = Path(directory).resolve()
    if not root.exists() or not root.is_dir():
        return 0
    return sum(1 for entry in root.rglob("*") if entry.is_dir())


