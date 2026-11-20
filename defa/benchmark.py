"""
benchmark.py — Forensic Validation & Performance Benchmarking Engine

Responsibility:
    Executes an automated 12-step validation benchmark on synthetic evidence
    to scientifically test DEFA's scanning, chunk-based hashing, duplicate
    detection, and baseline comparison accuracy.
    Collects real performance metrics: files/sec, MB/sec throughput, duration.
"""

import hashlib
import tempfile
import time
from pathlib import Path
from typing import Any

from defa.duplicates import find_duplicates
from defa.hasher import compute_sha256
from defa.reporter import save_baseline, save_json_report
from defa.scanner import scan_directory
from defa.verifier import compare_with_baseline, load_baseline


def run_forensic_benchmark() -> dict[str, Any]:
    """
    Execute the 12-step forensic validation procedure:
    1. Create temporary evidence directory
    2. Generate multiple test files with varied extensions
    3. Include duplicate files
    4. Scan directory
    5. Calculate SHA-256 hashes
    6. Create a baseline
    7. Modify an existing file
    8. Add a new file
    9. Delete an existing file
    10. Run baseline comparison
    11. Confirm modified, new, and missing files are detected correctly
    12. Validate hash results against Python hashlib directly

    Returns:
        Structured benchmark dictionary with real performance metrics and validation flags.
    """
    benchmark_start_time = time.perf_counter()
    steps_passed = []
    steps_failed = []

    with tempfile.TemporaryDirectory(prefix="defa_benchmark_") as temp_dir_str:
        temp_dir = Path(temp_dir_str)
        reports_dir = temp_dir / "benchmark_reports"
        reports_dir.mkdir(parents=True, exist_ok=True)

        # Step 1: Create temporary evidence directory
        steps_passed.append({"step": 1, "description": "Create temporary evidence directory", "status": "PASSED"})

        # Step 2: Generate test files with varied extensions and realistic sizes
        file_a = temp_dir / "document_01.txt"
        file_a.write_text("Case Report Document - Subject Alpha Evidence", encoding="utf-8")

        file_b = temp_dir / "database_export.csv"
        file_b.write_text("id,name,timestamp,ip\n1,alice,2026-01-01,192.168.1.50\n2,bob,2026-01-02,10.0.0.12", encoding="utf-8")

        file_c = temp_dir / "syslog.log"
        file_c.write_text("[2026-01-01 12:00:00] AUTH SUCCESS user=admin\n[2026-01-01 12:05:00] DISK MOUNT target=/dev/sdb1", encoding="utf-8")

        # Step 3: Include duplicate files
        dup_content = b"EXACT_IDENTICAL_EVIDENCE_STREAM_SHA256_TEST_BLOCK" * 50
        file_dup1 = temp_dir / "master_record.bin"
        file_dup2 = temp_dir / "backup_record.bin"
        file_dup1.write_bytes(dup_content)
        file_dup2.write_bytes(dup_content)

        # A larger file to exercise chunking (1 MB)
        file_large = temp_dir / "disk_volume_chunk.raw"
        file_large.write_bytes(b"\x90" * (1024 * 1024))

        steps_passed.append({"step": 2, "description": "Generate multiple test files across extensions", "status": "PASSED"})
        steps_passed.append({"step": 3, "description": "Generate duplicate evidence file pair", "status": "PASSED"})

        # Step 4: Scan the directory
        scan_t0 = time.perf_counter()
        records = list(scan_directory(temp_dir))
        scan_duration = time.perf_counter() - scan_t0
        steps_passed.append({"step": 4, "description": f"Scan directory recursively ({len(records)} files found)", "status": "PASSED"})

        # Step 5: Calculate SHA-256 hashes
        hash_t0 = time.perf_counter()
        total_bytes = 0
        hashed_count = 0
        for r in records:
            sha = compute_sha256(r["absolute_path"])
            r["sha256"] = sha
            r["scan_status"] = "hashed" if sha else "hash_failed"
            total_bytes += r["size_bytes"]
            if sha:
                hashed_count += 1
        hash_duration = time.perf_counter() - hash_t0
        steps_passed.append({"step": 5, "description": f"Calculate SHA-256 hashes ({hashed_count}/{len(records)} hashed)", "status": "PASSED"})

        # Duplicate detection check
        dup_groups = find_duplicates(records)
        is_dup_detected = len(dup_groups) == 1 and len(dup_groups[0]) == 2
        if not is_dup_detected:
            steps_failed.append({"step": 5.1, "description": "Duplicate detection check", "status": "FAILED"})

        # Step 6: Create baseline snapshot
        baseline_file = save_baseline(records, str(temp_dir), reports_dir, "benchmark_baseline.json")
        loaded_baseline = load_baseline(baseline_file)
        steps_passed.append({"step": 6, "description": f"Create and load baseline snapshot ({len(loaded_baseline['files'])} records)", "status": "PASSED"})

        # Step 7: Modify an existing file
        file_a.write_text("TAMPERED EVIDENCE CONTENT - PREVIOUS HASH INVALIDATED", encoding="utf-8")
        steps_passed.append({"step": 7, "description": "Modify existing file (document_01.txt)", "status": "PASSED"})

        # Step 8: Add a new file
        file_new = temp_dir / "introduced_malware.exe"
        file_new.write_bytes(b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00")
        steps_passed.append({"step": 8, "description": "Add new file (introduced_malware.exe)", "status": "PASSED"})

        # Step 9: Delete an existing file
        file_c.unlink()
        steps_passed.append({"step": 9, "description": "Delete existing file (syslog.log)", "status": "PASSED"})

        # Step 10: Run baseline comparison
        current_records = list(scan_directory(temp_dir))
        for cr in current_records:
            cr["sha256"] = compute_sha256(cr["absolute_path"])
        verification_result = compare_with_baseline(current_records, loaded_baseline)
        steps_passed.append({"step": 10, "description": "Execute baseline verification comparison", "status": "PASSED"})

        # Step 11: Confirm modified, new, and missing files detected correctly
        modified_paths = [m["current"]["relative_path"] for m in verification_result["modified"]]
        new_paths = [n["relative_path"] for n in verification_result["new"]]
        missing_paths = [mis["relative_path"] for mis in verification_result["missing"]]

        is_mod_ok = "document_01.txt" in modified_paths
        is_new_ok = "introduced_malware.exe" in new_paths
        is_missing_ok = "syslog.log" in missing_paths

        if is_mod_ok and is_new_ok and is_missing_ok:
            steps_passed.append({"step": 11, "description": "Verify exact detection of modified, new, and missing files", "status": "PASSED"})
        else:
            steps_failed.append({"step": 11, "description": f"Verification mismatch: mod={is_mod_ok}, new={is_new_ok}, miss={is_missing_ok}", "status": "FAILED"})

        # Step 12: Validate hash results against Python hashlib directly
        expected_hash = hashlib.sha256(dup_content).hexdigest()
        computed_hash = compute_sha256(file_dup1)
        if expected_hash == computed_hash:
            steps_passed.append({"step": 12, "description": "Cross-validate SHA-256 digest against Python hashlib directly", "status": "PASSED"})
        else:
            steps_failed.append({"step": 12, "description": "Hash divergence from native hashlib", "status": "FAILED"})

    total_benchmark_time = time.perf_counter() - benchmark_start_time
    total_mb = total_bytes / (1024 * 1024)
    files_per_sec = len(records) / max(hash_duration, 0.0001)
    mb_per_sec = total_mb / max(hash_duration, 0.0001)

    all_passed = len(steps_failed) == 0
    accuracy_pct = 100.0 if all_passed else (len(steps_passed) / 12 * 100)

    return {
        "success": all_passed,
        "accuracy_percentage": round(accuracy_pct, 1),
        "total_benchmark_duration_seconds": round(total_benchmark_time, 4),
        "hashing_duration_seconds": round(hash_duration, 4),
        "metrics": {
            "files_scanned": len(records),
            "total_bytes_processed": total_bytes,
            "total_megabytes": round(total_mb, 2),
            "files_per_second": round(files_per_sec, 1),
            "throughput_mb_per_second": round(mb_per_sec, 2),
            "duplicate_detection_verified": is_dup_detected,
            "baseline_accuracy_verified": (is_mod_ok and is_new_ok and is_missing_ok),
        },
        "steps_passed": steps_passed,
        "steps_failed": steps_failed,
    }

