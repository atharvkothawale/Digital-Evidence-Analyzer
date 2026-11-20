"""
hasher.py — File Hashing Module

Responsibility:
    Compute the SHA-256 cryptographic hash of any file.
    Files are read in fixed-size chunks to avoid loading large files
    entirely into memory — a common best practice in forensics tools.

Key concepts used:
    - hashlib.sha256  : industry-standard cryptographic hash function
    - Chunk reading   : memory-efficient file processing
    - logging         : record failures without crashing the program

What is SHA-256?
    SHA-256 (Secure Hash Algorithm, 256-bit output) produces a fixed-length
    64-character hexadecimal string from any input.  Even a single changed
    byte produces a completely different hash — making it ideal for detecting
    file tampering or verifying integrity.

Why chunks?
    A forensic examiner may scan a 10 GB disk image.  Reading the whole file
    into memory at once would exhaust RAM.  Reading 65,536-byte chunks keeps
    memory usage constant regardless of file size.
"""

import hashlib
import logging
from pathlib import Path

logger = logging.getLogger(__name__)

# 64 KB per read — a common balance between I/O calls and memory usage.
CHUNK_SIZE: int = 65_536  # bytes


def compute_sha256(file_path: str | Path) -> str | None:
    """
    Read *file_path* in chunks and return its SHA-256 hex digest.

    Args:
        file_path: Path to the file to hash (string or Path object).

    Returns:
        A 64-character lowercase hex string, e.g.
        'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'
        Returns None if the file cannot be read (permission error, missing, etc.).

    Notes:
        - The file is opened in binary read mode ('rb'); no data is written.
        - 'rb' ensures consistent behaviour across Windows and Unix line endings.
    """
    path = Path(file_path)
    hasher = hashlib.sha256()

    try:
        with path.open("rb") as file_handle:
            while True:
                chunk = file_handle.read(CHUNK_SIZE)
                if not chunk:          # empty chunk means end-of-file
                    break
                hasher.update(chunk)   # feed chunk into the hash state machine

        digest = hasher.hexdigest()
        logger.debug("SHA-256 for %s: %s", path.name, digest)
        return digest

    except PermissionError:
        logger.warning("Permission denied hashing: %s", path)
        return None
    except FileNotFoundError:
        logger.warning("File not found during hashing: %s", path)
        return None
    except OSError as exc:
        logger.warning("OS error hashing %s: %s", path, exc)
        return None

