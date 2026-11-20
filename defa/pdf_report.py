"""
pdf_report.py — Pure-Python Forensic PDF Report Generator

Responsibility:
    Generate professional, court-admissible-styled PDF reports directly
    using Python standard library without requiring external C libraries
    or heavyweight third-party PDF dependencies.
"""

from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def _escape_pdf_str(text: str) -> str:
    """Escape parenthesis and backslashes for PDF string literal."""
    return str(text).replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")


def generate_pdf_report(
    case_name: str,
    investigator: str,
    scan_report: dict[str, Any],
    findings: list[dict[str, Any]],
    output_path: str | Path,
    verification_result: dict[str, Any] | None = None,
) -> Path:
    """
    Generate a clean, professional, multi-section digital forensics investigation PDF report.
    """
    out_file = Path(output_path)
    out_file.parent.mkdir(parents=True, exist_ok=True)

    date_str = datetime.now(tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    target_dir = scan_report.get("directory", "Unknown")
    total_files = scan_report.get("total_files", 0)
    hashed_ok = scan_report.get("hashed_successfully", 0)
    failed = scan_report.get("hash_failed", 0)
    dup_groups = scan_report.get("duplicate_groups", 0)
    dup_files = scan_report.get("duplicate_files", 0)
    files = scan_report.get("files", [])
    total_bytes = sum(f.get("size_bytes", 0) for f in files)
    total_mb = total_bytes / (1024 * 1024)

    # Build text stream lines (in PDF points, page height 792 pt, width 612 pt)
    content_lines = []

    # Draw header banner box
    content_lines.append("0.08 0.12 0.18 rg")  # Dark banner fill
    content_lines.append("36 720 540 45 re f")
    content_lines.append("0 0 0 rg")  # Reset to black

    # Title
    content_lines.append("BT")
    content_lines.append("/F2 16 Tf")
    content_lines.append("1 1 1 rg")  # White text
    content_lines.append("48 736 Td")
    content_lines.append(f"(DIGITAL EVIDENCE FORENSIC INVESTIGATION REPORT) Tj")
    content_lines.append("ET")

    # Metadata Header
    content_lines.append("BT")
    content_lines.append("/F2 10 Tf")
    content_lines.append("0.1 0.1 0.1 rg")
    content_lines.append("36 695 Td")
    content_lines.append(f"(Case Reference: ) Tj")
    content_lines.append("/F1 10 Tf")
    content_lines.append(f"({_escape_pdf_str(case_name)}) Tj")
    content_lines.append("/F2 10 Tf")
    content_lines.append(f"(    |    Lead Investigator: ) Tj")
    content_lines.append("/F1 10 Tf")
    content_lines.append(f"({_escape_pdf_str(investigator)}) Tj")
    content_lines.append("ET")

    content_lines.append("BT")
    content_lines.append("/F2 10 Tf")
    content_lines.append("36 680 Td")
    content_lines.append(f"(Report Generated: ) Tj")
    content_lines.append("/F1 10 Tf")
    content_lines.append(f"({date_str}) Tj")
    content_lines.append("/F2 10 Tf")
    content_lines.append(f"(    |    Tool: ) Tj")
    content_lines.append("/F1 10 Tf")
    content_lines.append(f"(DEFA v2.0 - SHA-256 Engine) Tj")
    content_lines.append("ET")

    # Horizontal rule
    content_lines.append("0.8 0.8 0.8 RG")
    content_lines.append("36 670 m 576 670 l S")

    # Section 1: Executive Evidence Summary
    content_lines.append("BT")
    content_lines.append("/F2 12 Tf")
    content_lines.append("0.15 0.35 0.7 rg")  # Primary blue
    content_lines.append("36 650 Td")
    content_lines.append("(1. Executive Evidence Summary) Tj")
    content_lines.append("ET")

    summary_items = [
        f"Target Evidence Directory: {_escape_pdf_str(target_dir)}",
        f"Total Scanned Files: {total_files} files",
        f"Total Evidence Volume: {total_mb:.2f} MB ({total_bytes:,} bytes)",
        f"Cryptographic Algorithm: SHA-256 (NIST FIPS 180-4 compliant)",
        f"Successfully Hashed: {hashed_ok} files  |  Failed / Inaccessible: {failed} files",
        f"Identical Duplicate Clusters: {dup_groups} groups ({dup_files} total duplicate files)",
    ]

    y = 632
    for item in summary_items:
        content_lines.append("BT")
        content_lines.append("/F1 9 Tf")
        content_lines.append("0.1 0.1 0.1 rg")
        content_lines.append(f"48 {y} Td")
        content_lines.append(f"(- {item}) Tj")
        content_lines.append("ET")
        y -= 14

    # Section 2: Key Forensic Findings
    y -= 8
    content_lines.append("BT")
    content_lines.append("/F2 12 Tf")
    content_lines.append("0.15 0.35 0.7 rg")
    content_lines.append(f"36 {y} Td")
    content_lines.append("(2. Prioritized Forensic Findings & Investigative Leads) Tj")
    content_lines.append("ET")
    y -= 18

    if findings:
        for f in findings[:8]:  # Top 8 findings
            sev = f.get("severity", "Informational")
            fid = f.get("id", "")
            title = _escape_pdf_str(f.get("title", ""))
            rel_file = _escape_pdf_str(f.get("related_file", ""))
            reason = _escape_pdf_str(f.get("reason", ""))

            # Severity badge text
            content_lines.append("BT")
            content_lines.append("/F2 8.5 Tf")
            if sev == "High":
                content_lines.append("0.8 0.1 0.1 rg")
            elif sev == "Medium":
                content_lines.append("0.7 0.4 0.0 rg")
            else:
                content_lines.append("0.1 0.5 0.2 rg")

            content_lines.append(f"48 {y} Td")
            content_lines.append(f"([{sev.upper()}] {fid}: {title}) Tj")
            content_lines.append("ET")
            y -= 12

            content_lines.append("BT")
            content_lines.append("/F1 8 Tf")
            content_lines.append("0.2 0.2 0.2 rg")
            content_lines.append(f"60 {y} Td")
            content_lines.append(f"(Evidence File: {rel_file}) Tj")
            content_lines.append("ET")
            y -= 11

            content_lines.append("BT")
            content_lines.append("/F1 7.5 Tf")
            content_lines.append("0.35 0.35 0.35 rg")
            content_lines.append(f"60 {y} Td")
            content_lines.append(f"(Reason: {reason[:85]}...) Tj" if len(reason) > 85 else f"(Reason: {reason}) Tj")
            content_lines.append("ET")
            y -= 15
    else:
        content_lines.append("BT")
        content_lines.append("/F1 9 Tf")
        content_lines.append("0.3 0.3 0.3 rg")
        content_lines.append(f"48 {y} Td")
        content_lines.append("(No high or medium priority anomalies detected in evidence.) Tj")
        content_lines.append("ET")
        y -= 20

    # Section 3: Baseline Verification
    y -= 6
    content_lines.append("BT")
    content_lines.append("/F2 12 Tf")
    content_lines.append("0.15 0.35 0.7 rg")
    content_lines.append(f"36 {y} Td")
    content_lines.append("(3. Baseline Integrity Verification) Tj")
    content_lines.append("ET")
    y -= 16

    if verification_result:
        summary = verification_result.get("summary", {})
        verif_text = (
            f"Baseline Status: Unchanged: {summary.get('unchanged', 0)} | "
            f"New: {summary.get('new', 0)} | "
            f"Missing: {summary.get('missing', 0)} | "
            f"Modified: {summary.get('modified', 0)}"
        )
    else:
        verif_text = "Baseline Status: Initial baseline snapshot created. Zero tampering detected at baseline recording."

    content_lines.append("BT")
    content_lines.append("/F1 9 Tf")
    content_lines.append("0.1 0.1 0.1 rg")
    content_lines.append(f"48 {y} Td")
    content_lines.append(f"({_escape_pdf_str(verif_text)}) Tj")
    content_lines.append("ET")
    y -= 24

    # Section 4: Forensic Chain of Custody & Disclaimers
    content_lines.append("0.8 0.8 0.8 RG")
    content_lines.append(f"36 {y} m 576 {y} l S")
    y -= 16

    content_lines.append("BT")
    content_lines.append("/F2 9 Tf")
    content_lines.append("0.3 0.3 0.3 rg")
    content_lines.append(f"36 {y} Td")
    content_lines.append("(Evidence Preservation & Legal Notice:) Tj")
    content_lines.append("ET")
    y -= 12

    disclaimer = (
        "DEFA accessed all files in read-only binary mode. Original evidence files were not modified, moved, "
        "or deleted. SHA-256 proves content integrity relative to the comparison hash. This report was generated "
        "algorithmically from real physical disk analysis."
    )
    content_lines.append("BT")
    content_lines.append("/F1 7.5 Tf")
    content_lines.append("0.4 0.4 0.4 rg")
    content_lines.append(f"36 {y} Td")
    content_lines.append(f"({_escape_pdf_str(disclaimer)}) Tj")
    content_lines.append("ET")

    stream_content = "\n".join(content_lines)
    stream_bytes = stream_content.encode("latin-1", errors="replace")

    # Construct complete valid PDF 1.4 document
    objects = []
    objects.append(b"<< /Type /Catalog /Pages 2 0 R >>")
    objects.append(b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>")
    objects.append(b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << /Font << /F1 4 0 R /F2 5 0 R >> >> /Contents 6 0 R >>")
    objects.append(b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>")
    objects.append(b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold >>")
    objects.append(f"<< /Length {len(stream_bytes)} >>\nstream\n".encode("latin-1") + stream_bytes + b"\nendstream")

    pdf_body = bytearray(b"%PDF-1.4\n")
    xref_offsets = [0]

    for i, obj in enumerate(objects, 1):
        xref_offsets.append(len(pdf_body))
        pdf_body.extend(f"{i} 0 obj\n".encode("latin-1"))
        pdf_body.extend(obj)
        pdf_body.extend(b"\nendobj\n")

    xref_start = len(pdf_body)
    pdf_body.extend(f"xref\n0 {len(objects) + 1}\n".encode("latin-1"))
    pdf_body.extend(b"0000000000 65535 f \n")
    for offset in xref_offsets[1:]:
        pdf_body.extend(f"{offset:010d} 00000 n \n".encode("latin-1"))

    pdf_body.extend(
        f"trailer\n<< /Size {len(objects) + 1} /Root 1 0 R >>\nstartxref\n{xref_start}\n%%EOF\n".encode("latin-1")
    )

    out_file.write_bytes(pdf_body)
    return out_file

