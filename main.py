"""
main.py — DEFA Command-Line Entry Point

This is the file you run.  It wires together:
    - argparse  : parses the command and options the user types
    - scanner   : walks directories and collects file metadata
    - hasher    : computes SHA-256 for every file
    - duplicates: groups files with identical hashes
    - verifier  : compares a scan against a saved baseline
    - reporter  : writes JSON, CSV, and baseline files

Usage:
    python main.py scan ./sample_data --output reports
    python main.py verify ./sample_data --baseline reports/baseline.json
    python main.py --help
"""

import argparse
import logging
import sys
from pathlib import Path

from defa.duplicates import find_duplicates
from defa.hasher import compute_sha256
from defa.reporter import (
    save_baseline,
    save_csv_report,
    save_json_report,
    save_verification_report,
)
from defa.scanner import scan_directory
from defa.verifier import compare_with_baseline, load_baseline

# ──────────────────────────────────────────────
# Logging setup
# ──────────────────────────────────────────────

def configure_logging(verbose: bool) -> None:
    """
    Configure the root logger.

    Args:
        verbose: If True, show DEBUG messages; otherwise show WARNING+.
    """
    level = logging.DEBUG if verbose else logging.WARNING
    logging.basicConfig(
        level=level,
        format="%(levelname)-8s %(name)s: %(message)s",
    )


# ──────────────────────────────────────────────
# Display helpers
# ──────────────────────────────────────────────

BANNER = """
=============================================
       DIGITAL EVIDENCE FILE ANALYZER
=============================================
"""


def print_banner() -> None:
    print(BANNER)


def print_separator() -> None:
    print("-" * 45)


# ──────────────────────────────────────────────
# Core command implementations
# ──────────────────────────────────────────────

def cmd_scan(args: argparse.Namespace) -> int:
    """
    Execute the 'scan' command.

    Steps:
        1. Walk the directory and collect file metadata.
        2. Compute SHA-256 for each file.
        3. Detect duplicates.
        4. Write JSON report, CSV report, and baseline.

    Returns:
        0 on success, 1 on critical error.
    """
    print_banner()
    raw_targets = getattr(args, "targets", None) or [args.directory]
    targets = [Path(t).resolve() for t in raw_targets]
    output_dir = Path(args.output)

    if len(targets) == 1:
        print(f"  Target     : {targets[0]}")
    else:
        print(f"  Targets    : {len(targets)} selected evidence locations")
        for t in targets[:3]:
            print(f"               - {t}")
        if len(targets) > 3:
            print(f"               - ... and {len(targets) - 3} more")
    print(f"  Output     : {output_dir}")
    print_separator()
    print("  Scanning files ...\n")

    # ── 1. Scan ──────────────────────────────
    from defa.scanner import scan_evidence_selection, count_selected_directories
    try:
        file_records = list(scan_evidence_selection(targets))
    except (FileNotFoundError, NotADirectoryError) as exc:
        print(f"\n  [ERROR] {exc}")
        return 1

    if not file_records:
        print("  No files found in the specified evidence selection.")
        return 0

    # ── 2. Hash each file ────────────────────
    hashed = 0
    failed = 0
    for record in file_records:
        if record["accessible"]:
            sha = compute_sha256(record["absolute_path"])
            record["sha256"] = sha
            record["scan_status"] = "hashed" if sha else "hash_failed"
            if sha:
                hashed += 1
            else:
                failed += 1
                print(f"  [WARN] Could not hash: {record['relative_path']}")
        else:
            record["sha256"] = None
            record["scan_status"] = "inaccessible"
            failed += 1
            print(f"  [WARN] Inaccessible: {record['relative_path']}")

    # ── 3. Detect duplicates ─────────────────
    duplicate_groups = find_duplicates(file_records)

    # ── 4. Generate forensic findings ────────
    from defa.findings import generate_forensic_findings
    from defa.pdf_report import generate_pdf_report
    from defa.scanner import count_directories
    findings = generate_forensic_findings(file_records, duplicate_groups)

    # ── 5. Generate reports ──────────────────
    total_folders = count_selected_directories(targets)
    target_display = str(targets[0]) if len(targets) == 1 else f"{len(targets)} selected evidence locations"
    selected_paths = [str(t) for t in targets]

    json_path = save_json_report(
        file_records=file_records,
        duplicate_groups=duplicate_groups,
        directory=target_display,
        output_dir=output_dir,
        findings=findings,
        total_folders=total_folders,
        selected_paths=selected_paths,
    )
    csv_path = save_csv_report(file_records, output_dir)
    baseline_path = save_baseline(file_records, target_display, output_dir)
    
    # Generate PDF report
    pdf_path = output_dir / "investigation_report.pdf"
    try:
        generate_pdf_report(
            case_name="DEMO-INVESTIGATION",
            investigator="Forensic Examiner",
            scan_report={"directory": target_display, "total_files": len(file_records), "files": file_records, "hashed_successfully": hashed, "hash_failed": failed, "duplicate_groups": len(duplicate_groups), "duplicate_files": sum(len(g) for g in duplicate_groups)},
            findings=findings,
            output_path=pdf_path,
        )
    except Exception:
        pass

    # ── 6. Print summary ─────────────────────
    print(f"  Files analyzed       : {len(file_records)}")
    print(f"  Folders discovered   : {total_folders}")
    print(f"  Successfully hashed  : {hashed}")
    print(f"  Failed / inaccessible: {failed}")
    print(f"  Duplicate groups     : {len(duplicate_groups)}")
    print(f"  Duplicate files      : {sum(len(g) for g in duplicate_groups)}")
    print(f"  Forensic findings    : {len(findings)} (High: {sum(1 for f in findings if f['severity'] == 'High')}, Med: {sum(1 for f in findings if f['severity'] == 'Medium')})")

    if duplicate_groups:
        print_separator()
        print("  Duplicate groups detected:")
        for i, group in enumerate(duplicate_groups, start=1):
            print(f"\n  Group {i} (SHA-256: {group[0]['sha256'][:16]}...):")
            for rec in group:
                print(f"    - {rec['relative_path']}  ({rec['size_bytes']} bytes)")

    print_separator()
    print("  Reports generated:")
    print(f"    - {json_path}")
    print(f"    - {csv_path}")
    print(f"    - {baseline_path}")
    if pdf_path.exists():
        print(f"    - {pdf_path}")
    print_separator()

    return 0


def cmd_verify(args: argparse.Namespace) -> int:
    """
    Execute the 'verify' command.

    Steps:
        1. Load the saved baseline.
        2. Rescan the directory and recompute hashes.
        3. Compare current state against the baseline.
        4. Display and save verification results.

    Returns:
        0 on success, 1 on critical error.
    """
    print_banner()
    raw_targets = getattr(args, "targets", None) or [args.directory]
    targets = [Path(t).resolve() for t in raw_targets]
    baseline_path = Path(args.baseline)
    output_dir = Path(args.output)

    if len(targets) == 1:
        print(f"  Target     : {targets[0]}")
    else:
        print(f"  Targets    : {len(targets)} selected evidence locations")
    print(f"  Baseline   : {baseline_path}")
    print(f"  Output     : {output_dir}")
    print_separator()

    # ── 1. Load baseline ─────────────────────
    try:
        baseline = load_baseline(baseline_path)
    except (FileNotFoundError, ValueError) as exc:
        print(f"\n  [ERROR] {exc}")
        return 1

    print(f"  Baseline created at: {baseline.get('scanned_at', 'unknown')}\n")
    print("  Re-scanning evidence ...")

    # ── 2. Rescan + hash ─────────────────────
    from defa.scanner import scan_evidence_selection
    try:
        current_records = list(scan_evidence_selection(targets))
    except (FileNotFoundError, NotADirectoryError) as exc:
        print(f"\n  [ERROR] {exc}")
        return 1

    for record in current_records:
        if record["accessible"]:
            sha = compute_sha256(record["absolute_path"])
            record["sha256"] = sha
            record["scan_status"] = "hashed" if sha else "hash_failed"
        else:
            record["sha256"] = None
            record["scan_status"] = "inaccessible"

    # ── 3. Compare ───────────────────────────
    result = compare_with_baseline(current_records, baseline)

    # ── 4. Save verification report ──────────
    report_path = save_verification_report(
        result, str(directory), str(baseline_path), output_dir
    )

    # ── 5. Print results ─────────────────────
    print_separator()
    print("  VERIFICATION RESULTS")
    print_separator()
    print(f"  New files      : {len(result['new'])}")
    print(f"  Missing files  : {len(result['missing'])}")
    print(f"  Modified files : {len(result['modified'])}")
    print(f"  Unchanged files: {len(result['unchanged'])}")

    if result["new"]:
        print("\n  [NEW FILES]")
        for rec in result["new"]:
            print(f"    + {rec['relative_path']}")

    if result["missing"]:
        print("\n  [MISSING FILES]")
        for rec in result["missing"]:
            print(f"    - {rec['relative_path']}")

    if result["modified"]:
        print("\n  [MODIFIED FILES]")
        for entry in result["modified"]:
            print(f"    ~ {entry['current']['relative_path']}")
            print(f"      baseline hash: {entry['baseline'].get('sha256', 'N/A')[:32]}...")
            print(f"      current  hash: {entry['current'].get('sha256', 'N/A')[:32]}...")

    print_separator()
    print(f"  Verification report saved: {report_path}")
    print_separator()

    return 0


def cmd_benchmark(args: argparse.Namespace) -> int:
    """
    Execute the 12-step forensic validation and performance benchmark.
    """
    print_banner()
    print("  EXECUTING 12-STEP FORENSIC VALIDATION & BENCHMARK")
    print_separator()
    print("  Running scientific validation suite...")

    from defa.benchmark import run_forensic_benchmark
    res = run_forensic_benchmark()

    print("\n  Validation Steps:")
    for step in res["steps_passed"]:
        print(f"    [PASS] Step {step['step']}: {step['description']}")
    for step in res["steps_failed"]:
        print(f"    [FAIL] Step {step['step']}: {step['description']}")

    m = res["metrics"]
    print_separator()
    print(f"  Benchmark Results:")
    print(f"    - Accuracy           : {res['accuracy_percentage']}%")
    print(f"    - Total duration     : {res['total_benchmark_duration_seconds']}s")
    print(f"    - Hashing duration   : {res['hashing_duration_seconds']}s")
    print(f"    - Files processed    : {m['files_scanned']} files")
    print(f"    - Data throughput    : {m['throughput_mb_per_second']} MB/s ({m['files_per_second']} files/sec)")
    print(f"    - Duplicate check    : {'VERIFIED' if m['duplicate_detection_verified'] else 'FAILED'}")
    print(f"    - Baseline integrity : {'VERIFIED' if m['baseline_accuracy_verified'] else 'FAILED'}")
    print_separator()

    return 0 if res["success"] else 1


def cmd_serve(args: argparse.Namespace) -> int:
    """
    Launch the interactive DEFA 2.0 Web Dashboard using FastAPI and Uvicorn.
    """
    print_banner()
    host = args.host
    port = args.port

    print(f"  DEFA 2.0 Interactive Dashboard starting...")
    print(f"  Local URL  : http://{host}:{port}")
    print(f"  API Docs   : http://{host}:{port}/docs")
    print(f"  Bind Addr  : {host} (Local loopback only for security)")
    print_separator()
    print("  Press Ctrl+C to stop the dashboard server.\n")

    try:
        import uvicorn
        from defa.api.routes import app
        uvicorn.run(app, host=host, port=port, log_level="warning")
        return 0
    except ImportError:
        print("  [ERROR] uvicorn is not installed. Please install with: pip install uvicorn fastapi")
        return 1
    except KeyboardInterrupt:
        print("\n  Dashboard server stopped.")
        return 0
    except Exception as exc:
        print(f"\n  [ERROR] Failed to start web dashboard: {exc}")
        return 1


# ──────────────────────────────────────────────
# Argument parser setup
# ──────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    """
    Build and return the top-level argument parser with sub-commands.

    Sub-commands:
        scan   — analyse a directory and generate reports
        verify — compare a directory against a saved baseline
        serve  — launch the interactive web dashboard (DEFA 2.0)
    """
    parser = argparse.ArgumentParser(
        prog="defa",
        description="DEFA 2.0 — Digital Evidence File Analyzer\n"
                    "Forensic file analysis, integrity checks, and interactive web dashboard with local AI.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python main.py scan ./sample_data --output reports\n"
            "  python main.py verify ./sample_data --baseline reports/baseline.json\n"
            "  python main.py serve --port 8000\n"
        ),
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Show debug-level log messages.",
    )

    subparsers = parser.add_subparsers(dest="command", metavar="COMMAND")
    subparsers.required = True

    # ── scan sub-command ──────────────────────
    scan_parser = subparsers.add_parser(
        "scan",
        help="Scan a directory, compute hashes, detect duplicates, and save a baseline.",
        description="Scan a directory for forensic analysis.",
    )
    scan_parser.add_argument(
        "targets",
        nargs="+",
        metavar="PATH",
        help="Path(s) to directory, folder(s), or individual file(s) to scan.",
    )
    scan_parser.add_argument(
        "--output", "-o",
        default="reports",
        metavar="DIR",
        help="Folder to write reports and baseline (default: reports).",
    )

    # ── verify sub-command ────────────────────
    verify_parser = subparsers.add_parser(
        "verify",
        help="Re-scan a directory and compare it against a saved baseline.",
        description="Verify file integrity against a known-good baseline.",
    )
    verify_parser.add_argument(
        "targets",
        nargs="+",
        metavar="PATH",
        help="Path(s) to directory, folder(s), or file(s) to re-scan.",
    )
    verify_parser.add_argument(
        "--baseline", "-b",
        required=True,
        metavar="FILE",
        help="Path to the baseline.json file from a previous scan.",
    )
    verify_parser.add_argument(
        "--output", "-o",
        default="reports",
        metavar="DIR",
        help="Folder to write the verification report (default: reports).",
    )

    # ── benchmark sub-command ────────────────
    benchmark_parser = subparsers.add_parser(
        "benchmark",
        help="Run the 12-step automated forensic validation & performance benchmark.",
        description="Execute scientific validation test of hashing, baseline comparison, and throughput.",
    )

    # ── serve / ui sub-command ────────────────
    serve_parser = subparsers.add_parser(
        "serve",
        aliases=["ui"],
        help="Launch the DEFA 2.0 interactive forensics web dashboard.",
        description="Start local web server hosting the interactive dashboard and API.",
    )
    serve_parser.add_argument(
        "--host",
        default="127.0.0.1",
        help="Host address to bind to (default: 127.0.0.1).",
    )
    serve_parser.add_argument(
        "--port", "-p",
        type=int,
        default=8000,
        help="Port number to listen on (default: 8000).",
    )

    return parser


# ──────────────────────────────────────────────
# Entry point
# ──────────────────────────────────────────────

def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    configure_logging(args.verbose)

    dispatch = {
        "scan": cmd_scan,
        "verify": cmd_verify,
        "benchmark": cmd_benchmark,
        "serve": cmd_serve,
        "ui": cmd_serve,
    }

    exit_code = dispatch[args.command](args)
    sys.exit(exit_code)


if __name__ == "__main__":
    main()

