"""
findings.py — Forensic Findings & Anomaly Detection Engine

Responsibility:
    Analyze scanned file records, metadata, cryptographic hashes,
    and baseline verification diffs to generate actionable investigative
    findings classified by severity (Informational, Low, Medium, High).

Principles:
    - Findings are investigative leads, NOT definitive malware verdicts.
    - Purely derived from real scan data and byte header inspections.
    - Never modifies evidence.
"""

import logging
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

# Known magic bytes signatures for common file formats
MAGIC_SIGNATURES: list[dict[str, Any]] = [
    {
        "type": "PE / Windows Executable",
        "header": b"MZ",
        "offset": 0,
        "expected_extensions": {".exe", ".dll", ".sys", ".scr", ".cpl", ".ocx"},
        "incompatible_extensions": {".jpg", ".jpeg", ".png", ".gif", ".txt", ".csv", ".pdf", ".mp3", ".docx", ".xlsx"},
    },
    {
        "type": "PDF Document",
        "header": b"%PDF",
        "offset": 0,
        "expected_extensions": {".pdf"},
        "incompatible_extensions": {".jpg", ".png", ".exe", ".txt", ".mp3", ".doc"},
    },
    {
        "type": "ZIP / Office OpenXML Archive",
        "header": b"PK\x03\x04",
        "offset": 0,
        "expected_extensions": {".zip", ".docx", ".xlsx", ".pptx", ".jar", ".apk", ".odt"},
        "incompatible_extensions": {".txt", ".jpg", ".png", ".pdf", ".exe"},
    },
    {
        "type": "PNG Image",
        "header": b"\x89PNG\r\n\x1a\n",
        "offset": 0,
        "expected_extensions": {".png"},
        "incompatible_extensions": {".txt", ".pdf", ".exe", ".doc", ".jpg"},
    },
    {
        "type": "JPEG Image",
        "header": b"\xff\xd8\xff",
        "offset": 0,
        "expected_extensions": {".jpg", ".jpeg", ".jpe"},
        "incompatible_extensions": {".txt", ".pdf", ".exe", ".png", ".zip"},
    },
    {
        "type": "ELF Executable (Linux / Unix)",
        "header": b"\x7fELF",
        "offset": 0,
        "expected_extensions": {"", ".so", ".bin"},
        "incompatible_extensions": {".txt", ".jpg", ".png", ".pdf", ".docx"},
    },
]

# Suspicious script / executable extensions often misused for delivery
EXECUTABLE_SCRIPT_EXTENSIONS = {
    ".exe", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".jse", ".wsf", ".hta", ".scr", ".pif"
}

# Suspicious double extension patterns (e.g. report.pdf.exe)
DECEPTIVE_EXTENSION_PATTERNS = [
    ".pdf.exe", ".doc.exe", ".docx.exe", ".xls.exe", ".xlsx.exe",
    ".txt.exe", ".jpg.exe", ".png.exe", ".zip.exe",
    ".pdf.vbs", ".doc.vbs", ".txt.vbs", ".pdf.bat", ".jpg.scr"
]


def check_magic_byte_mismatch(file_path: str | Path, declared_extension: str) -> dict[str, str] | None:
    """
    Read the first 16 bytes of a file to check for obvious extension/header mismatches.
    Returns mismatch details if detected, or None.
    """
    path = Path(file_path)
    if not path.exists() or not path.is_file():
        return None

    try:
        with path.open("rb") as f:
            header_bytes = f.read(16)
    except Exception:
        return None

    ext = declared_extension.lower()
    for sig in MAGIC_SIGNATURES:
        hdr = sig["header"]
        offset = sig["offset"]
        if len(header_bytes) >= offset + len(hdr) and header_bytes[offset : offset + len(hdr)] == hdr:
            if ext in sig["incompatible_extensions"]:
                return {
                    "detected_type": sig["type"],
                    "declared_extension": ext,
                    "reason": f"File signature matches {sig['type']} but extension is declared as '{ext}'."
                }
    return None


def generate_forensic_findings(
    file_records: list[dict[str, Any]],
    duplicate_groups: list[list[dict[str, Any]]],
    verification_result: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    """
    Evaluate scanned file records and produce prioritized forensic findings.

    Returns:
        List of finding dictionaries sorted by severity: High -> Medium -> Low -> Informational.
    """
    findings: list[dict[str, Any]] = []
    finding_counter = 1

    def add_finding(
        title: str,
        description: str,
        severity: str,
        related_file: str,
        reason: str,
        recommended_action: str,
    ) -> None:
        nonlocal finding_counter
        findings.append({
            "id": f"FIND-{finding_counter:03d}",
            "title": title,
            "description": description,
            "severity": severity,
            "related_file": related_file,
            "reason": reason,
            "recommended_action": recommended_action,
        })
        finding_counter += 1

    # 1. Hashing Failures / Inaccessible Files
    for rec in file_records:
        if not rec.get("accessible") or rec.get("scan_status") == "hash_failed":
            add_finding(
                title="Unreadable Evidence File (Hash Failure)",
                description=f"File '{rec['name']}' could not be opened or hashed.",
                severity="Medium",
                related_file=rec.get("relative_path", rec.get("name")),
                reason="Permission denied or I/O failure prevented cryptographic hash calculation.",
                recommended_action="Inspect file system permissions or acquire file under elevated forensic privileges.",
            )

    # 2. Duplicate File Clusters
    for grp in duplicate_groups:
        if len(grp) >= 2:
            paths = [r["relative_path"] for r in grp]
            first_hash = grp[0].get("sha256", "N/A")
            total_size = sum(r.get("size_bytes", 0) for r in grp)
            add_finding(
                title=f"Cryptographically Identical Duplicate Files ({len(grp)} instances)",
                description=f"Found {len(grp)} files sharing identical SHA-256 hash: {first_hash[:16]}...",
                severity="Medium" if any(r.get("extension") in EXECUTABLE_SCRIPT_EXTENSIONS for r in grp) else "Informational",
                related_file=grp[0]["relative_path"],
                reason=f"Identical content distributed across multiple paths: {', '.join(paths)}.",
                recommended_action="Review file placement history to determine if copies indicate staging, distribution, or routine backup.",
            )

    # 3. Double Extensions & Deceptive Filenames
    for rec in file_records:
        name_lower = rec["name"].lower()
        rel_path = rec.get("relative_path", rec["name"])

        # Check deceptive double extensions
        for pattern in DECEPTIVE_EXTENSION_PATTERNS:
            if name_lower.endswith(pattern):
                add_finding(
                    title="Suspicious Double File Extension Detected",
                    description=f"File '{rec['name']}' uses a double extension pattern ({pattern}).",
                    severity="High",
                    related_file=rel_path,
                    reason="Double extensions are commonly employed to deceive users into executing malicious code.",
                    recommended_action="Quarantine file metadata, inspect byte contents, and check execution logs.",
                )
                break

        # Check for trailing whitespace padding before extension (e.g. "evidence   .exe")
        stem = Path(rec["name"]).stem
        if stem.endswith(" ") or stem.endswith("\t"):
            add_finding(
                title="Deceptive Filename Padding Detected",
                description=f"File name contains whitespace before the extension: '{rec['name']}'.",
                severity="High",
                related_file=rel_path,
                reason="Whitespace padding can hide dangerous extensions in file managers.",
                recommended_action="Analyze execution context and verify genuine file type.",
            )

        # Check for hidden files (dotfiles)
        if rec["name"].startswith(".") and len(rec["name"]) > 1:
            add_finding(
                title="Hidden File Discovered",
                description=f"File '{rec['name']}' begins with a dot prefix, hiding it in standard directory listings.",
                severity="Low",
                related_file=rel_path,
                reason="Dotfiles are typically hidden from end-users on Unix/macOS and certain Windows tools.",
                recommended_action="Inspect the purpose of this hidden configuration or storage file.",
            )

        # Check for executable scripts in document/image directories
        parent_dir = Path(rel_path).parent.as_posix().lower()
        if rec.get("extension") in EXECUTABLE_SCRIPT_EXTENSIONS:
            if any(folder in parent_dir for folder in ["document", "image", "photo", "download", "temp", "tmp"]):
                add_finding(
                    title="Executable / Script Located in Non-Binary Directory",
                    description=f"Executable file '{rec['name']}' found inside folder '{parent_dir}'.",
                    severity="Medium",
                    related_file=rel_path,
                    reason="Executables and scripts located in document or temporary directories warrant forensic scrutiny.",
                    recommended_action="Cross-reference timestamp with system event logs to verify author and execution history.",
                )

        # Check for magic byte mismatch if absolute path is available
        abs_path = rec.get("absolute_path")
        if abs_path and rec.get("accessible") and rec.get("size_bytes", 0) > 0:
            mismatch = check_magic_byte_mismatch(abs_path, rec.get("extension", ""))
            if mismatch:
                add_finding(
                    title="File Extension / Signature Inconsistency (Spoofed Extension)",
                    description=mismatch["reason"],
                    severity="High",
                    related_file=rel_path,
                    reason=f"Declared extension does not match internal file header ({mismatch['detected_type']}).",
                    recommended_action="Examine genuine file format using full forensic carving tools and check for masquerading attacks.",
                )

        # Check for unusually large files (> 50 MB)
        if rec.get("size_bytes", 0) > 50 * 1024 * 1024:
            size_mb = rec["size_bytes"] / (1024 * 1024)
            add_finding(
                title=f"Unusually Large Evidence File ({size_mb:.1f} MB)",
                description=f"File '{rec['name']}' exceeds standard file volume threshold (> 50 MB).",
                severity="Informational",
                related_file=rel_path,
                reason="High-volume files may represent databases, archives, memory dumps, or container disks.",
                recommended_action="Assess whether the file constitutes a sub-evidence container requiring forensic mounting.",
            )

    # 4. Baseline Integrity Verification Findings (if available)
    if verification_result:
        modified_list = verification_result.get("modified", [])
        for m in modified_list:
            cur = m.get("current", {})
            base = m.get("baseline", {})
            add_finding(
                title="Integrity Verification Mismatch (Modified File)",
                description=f"File '{cur.get('relative_path')}' has diverged from baseline.",
                severity="High",
                related_file=cur.get("relative_path"),
                reason=f"Baseline SHA-256 ({base.get('sha256', '')[:16]}...) does not match current SHA-256 ({cur.get('sha256', '')[:16]}...).",
                recommended_action="Investigate timeline between baseline creation and current scan to isolate unauthorized file modification.",
            )

        new_list = verification_result.get("new", [])
        for n in new_list:
            add_finding(
                title="New Unbaselined File Introduced",
                description=f"File '{n.get('relative_path')}' was introduced after baseline creation.",
                severity="Medium" if n.get("extension") in EXECUTABLE_SCRIPT_EXTENSIONS else "Low",
                related_file=n.get("relative_path"),
                reason="File does not exist in the recorded baseline snapshot.",
                recommended_action="Verify creation timestamp and determine origin of newly introduced evidence.",
            )

        missing_list = verification_result.get("missing", [])
        for mis in missing_list:
            add_finding(
                title="Baseline Evidence File Missing (Deleted)",
                description=f"File '{mis.get('relative_path')}' was present in baseline but is now missing.",
                severity="Medium",
                related_file=mis.get("relative_path"),
                reason="File was removed or deleted from the evidence directory since baseline creation.",
                recommended_action="Consult file system journal or recycle bin artifacts to verify deletion circumstance.",
            )

    # Sort findings by severity priority: High -> Medium -> Low -> Informational
    severity_order = {"High": 1, "Medium": 2, "Low": 3, "Informational": 4}
    findings.sort(key=lambda x: severity_order.get(x["severity"], 5))

    return findings

