"""
duplicates.py — Duplicate File Detection Module

Responsibility:
    Given a list of file records (each with a sha256 field), group files
    that share the same hash — those files have identical content.

Key concepts used:
    - dict  : hash → list of file records (grouping by hash value)
    - list comprehension : filter groups with more than one member

Why SHA-256 for duplicates?
    Two files are truly identical in content if and only if their SHA-256
    hashes match.  File names, paths, and timestamps are irrelevant.
    Hash collisions (two different files with the same SHA-256) are
    computationally infeasible with current hardware, making this approach
    extremely reliable.

Limitations:
    Files whose hash is None (unreadable) are excluded from comparison.
"""

import logging
from typing import Any

logger = logging.getLogger(__name__)


def find_duplicates(file_records: list[dict[str, Any]]) -> list[list[dict[str, Any]]]:
    """
    Detect files that have identical SHA-256 hashes.

    Args:
        file_records: List of dicts produced by the scanner + hasher.
                      Each dict must contain a 'sha256' key.

    Returns:
        A list of groups.  Each group is itself a list of file records
        that share the same hash.  Only groups with 2 or more members
        are returned (single-file hashes are not duplicates).

        Example:
            [
                [{"name": "a.txt", "sha256": "abc..."}, {"name": "b.txt", "sha256": "abc..."}],
                [{"name": "c.jpg", "sha256": "def..."}, {"name": "d.jpg", "sha256": "def..."}],
            ]

    Notes:
        - Records with sha256 == None are silently skipped.
        - The original list is not modified.
    """
    # Build a mapping: sha256 hex string → list of records with that hash
    hash_groups: dict[str, list[dict[str, Any]]] = {}

    for record in file_records:
        file_hash = record.get("sha256")
        if file_hash is None:
            continue  # skip unreadable files

        if file_hash not in hash_groups:
            hash_groups[file_hash] = []
        hash_groups[file_hash].append(record)

    # Keep only groups that have more than one file (genuine duplicates)
    duplicate_groups = [
        group for group in hash_groups.values() if len(group) > 1
    ]

    total_duplicate_files = sum(len(g) for g in duplicate_groups)
    logger.info(
        "Duplicate detection complete: %d group(s), %d file(s) involved",
        len(duplicate_groups),
        total_duplicate_files,
    )

    return duplicate_groups

