"""
routes.py — FastAPI Application & Endpoints for DEFA Forensic System

Integrates:
    - defa.scanner
    - defa.hasher
    - defa.duplicates
    - defa.verifier
    - defa.reporter
    - defa.history
    - defa.findings
    - defa.benchmark
    - defa.pdf_report
    - defa.ai (with tool grounded interaction)
"""

import json
import logging
import time
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException, Query, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles

from defa import __version__
from defa.ai.client import OllamaClient
from defa.ai.context import SYSTEM_PROMPT, build_forensic_context
from defa.ai.tools import (
    defa_compare_baselines,
    defa_get_duplicate_groups,
    defa_get_file_details,
    defa_get_findings,
    defa_get_largest_files,
    defa_get_scan_statistics,
    defa_search_evidence,
)
from defa.api.schemas import (
    ChatRequest,
    CompareRequest,
    ScanRequest,
    SettingsModel,
    VerifyRequest,
)
from defa.benchmark import run_forensic_benchmark
from defa.duplicates import find_duplicates
from defa.findings import generate_forensic_findings
from defa.hasher import compute_sha256
from defa.history import compare_scans, load_history, record_scan_history
from defa.pdf_report import generate_pdf_report
from defa.reporter import (
    save_baseline,
    save_csv_report,
    save_json_report,
    save_verification_report,
)
from defa.scanner import count_directories, scan_directory
from defa.verifier import compare_with_baseline, load_baseline

logger = logging.getLogger("defa.api")

app = FastAPI(
    title="DEFA — Digital Evidence Forensics & Investigation System",
    description="Interactive Forensic Investigation Workstation & Grounded AI Assistant",
    version=__version__,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app_settings = SettingsModel()
ai_client = OllamaClient(base_url=app_settings.ollama_url, default_model=app_settings.default_model)

_active_scan: dict[str, Any] | None = None
_active_verification: dict[str, Any] | None = None
_active_findings: list[dict[str, Any]] = []


def _load_initial_reports():
    global _active_scan, _active_verification, _active_findings
    scan_file = Path("reports/scan_report.json")
    if scan_file.exists():
        try:
            with scan_file.open("r", encoding="utf-8") as f:
                _active_scan = json.load(f)
                _active_findings = _active_scan.get("findings", [])
        except Exception:
            pass

    verif_file = Path("reports/verification_report.json")
    if verif_file.exists():
        try:
            with verif_file.open("r", encoding="utf-8") as f:
                _active_verification = json.load(f)
        except Exception:
            pass

    # Re-generate findings if findings list is empty and scan is present
    if _active_scan and not _active_findings:
        files = _active_scan.get("files", [])
        dups = _active_scan.get("duplicates", [])
        dup_groups = []
        files_map = {f["relative_path"]: f for f in files}
        for d in dups:
            dup_groups.append([files_map[p] for p in d.get("files", []) if p in files_map])
        _active_findings = generate_forensic_findings(files, dup_groups, _active_verification)


_load_initial_reports()


# ──────────────────────────────────────────────
# System & Health
# ──────────────────────────────────────────────

@app.get("/api/health")
def get_health():
    return {
        "status": "online",
        "tool": "DEFA — Digital Evidence Forensics & Investigation System",
        "version": __version__,
        "has_active_scan": _active_scan is not None,
    }


# ──────────────────────────────────────────────
# Scanning & Reports
# ──────────────────────────────────────────────

@app.post("/api/scan")
def trigger_scan(req: ScanRequest):
    global _active_scan, _active_findings
    target_path = Path(req.directory).resolve()

    if not target_path.exists():
        raise HTTPException(status_code=400, detail=f"Directory does not exist: {target_path}")
    if not target_path.is_dir():
        raise HTTPException(status_code=400, detail=f"Target path is not a directory: {target_path}")

    output_dir = Path(req.output_dir)
    scan_t0 = time.perf_counter()

    try:
        file_records = list(scan_directory(target_path))
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Error scanning directory: {exc}")

    # Count subdirectories
    total_folders = count_directories(target_path)

    # Compute SHA-256 for each accessible file
    hashed = 0
    failed = 0
    total_bytes = 0
    for record in file_records:
        total_bytes += record.get("size_bytes", 0)
        if record["accessible"]:
            sha = compute_sha256(record["absolute_path"])
            record["sha256"] = sha
            record["scan_status"] = "hashed" if sha else "hash_failed"
            if sha:
                hashed += 1
            else:
                failed += 1
        else:
            record["sha256"] = None
            record["scan_status"] = "inaccessible"
            failed += 1

    # Detect duplicates
    duplicate_groups = find_duplicates(file_records)

    # Generate forensic findings
    _active_findings = generate_forensic_findings(file_records, duplicate_groups, _active_verification)

    # Calculate real performance metrics
    duration_sec = max(time.perf_counter() - scan_t0, 0.0001)
    total_mb = total_bytes / (1024 * 1024)
    perf_metrics = {
        "duration_seconds": round(duration_sec, 3),
        "total_megabytes": round(total_mb, 2),
        "files_per_second": round(len(file_records) / duration_sec, 1),
        "throughput_mb_per_second": round(total_mb / duration_sec, 2),
    }

    # Save reports
    json_path = save_json_report(
        file_records=file_records,
        duplicate_groups=duplicate_groups,
        directory=str(target_path),
        output_dir=output_dir,
        findings=_active_findings,
        performance_metrics=perf_metrics,
        total_folders=total_folders,
    )
    save_csv_report(file_records, output_dir)
    save_baseline(file_records, str(target_path), output_dir)

    with json_path.open("r", encoding="utf-8") as f:
        _active_scan = json.load(f)

    # Generate investigation PDF
    try:
        generate_pdf_report(
            case_name="ACTIVE-EVIDENCE-INVESTIGATION",
            investigator="Forensic Examiner",
            scan_report=_active_scan,
            findings=_active_findings,
            output_path=output_dir / "investigation_report.pdf",
            verification_result=_active_verification,
        )
    except Exception as exc:
        logger.warning("Could not generate PDF report: %s", exc)

    # Record in scan history
    record_scan_history(_active_scan)

    return {
        "success": True,
        "message": f"Successfully analyzed {len(file_records)} files across {total_folders} subdirectories.",
        "summary": {
            "directory": str(target_path),
            "total_files": len(file_records),
            "total_folders": total_folders,
            "total_bytes": total_bytes,
            "hashed_successfully": hashed,
            "hash_failed": failed,
            "duplicate_groups": len(duplicate_groups),
            "duplicate_files": sum(len(g) for g in duplicate_groups),
            "findings_count": len(_active_findings),
            "performance": perf_metrics,
        },
    }


@app.get("/api/scan/latest")
def get_latest_scan():
    if not _active_scan:
        raise HTTPException(status_code=404, detail="No scan report available. Run a scan first.")
    return _active_scan


# ──────────────────────────────────────────────
# Forensic Findings Engine
# ──────────────────────────────────────────────

@app.get("/api/findings")
def get_findings(
    severity: str = Query(default="all", description="all, High, Medium, Low, Informational"),
):
    findings = _active_findings
    if severity != "all":
        findings = [f for f in findings if f.get("severity", "").lower() == severity.lower()]

    counts = {
        "High": sum(1 for f in _active_findings if f.get("severity") == "High"),
        "Medium": sum(1 for f in _active_findings if f.get("severity") == "Medium"),
        "Low": sum(1 for f in _active_findings if f.get("severity") == "Low"),
        "Informational": sum(1 for f in _active_findings if f.get("severity") == "Informational"),
        "total": len(_active_findings),
    }

    return {
        "findings": findings,
        "counts": counts,
    }


# ──────────────────────────────────────────────
# Forensic Validation & Benchmarking
# ──────────────────────────────────────────────

@app.post("/api/benchmark")
def execute_benchmark():
    """Run the automated 12-step forensic validation and performance benchmark."""
    try:
        results = run_forensic_benchmark()
        return results
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Benchmark execution failed: {exc}")


# ──────────────────────────────────────────────
# File Explorer & Filtering
# ──────────────────────────────────────────────

def _param_val(val: Any, default: Any) -> Any:
    if hasattr(val, "default"):
        return val.default if val.default is not ... else default
    return val if val is not None else default


@app.get("/api/files")
def get_files(
    search: str = Query(default="", description="Search by file name or path"),
    ext: str = Query(default="", description="Filter by extension (e.g. .txt)"),
    category: str = Query(default="all", description="all, documents, code, images, logs, other"),
    size_category: str = Query(default="all", description="all, tiny, small, medium, large"),
    status: str = Query(default="all", description="all, hashed, hash_failed, inaccessible"),
    duplicate_only: bool = Query(default=False, description="Show only duplicate files"),
    sort_by: str = Query(default="name", description="name, size, ext, modified"),
    sort_order: str = Query(default="asc", description="asc or desc"),
    limit: int = Query(default=100, ge=1, le=1000),
    offset: int = Query(default=0, ge=0),
):
    search = _param_val(search, "")
    ext = _param_val(ext, "")
    category = _param_val(category, "all")
    size_category = _param_val(size_category, "all")
    status = _param_val(status, "all")
    duplicate_only = _param_val(duplicate_only, False)
    sort_by = _param_val(sort_by, "name")
    sort_order = _param_val(sort_order, "asc")
    limit = _param_val(limit, 100)
    offset = _param_val(offset, 0)

    if not _active_scan:
        return {"total": 0, "files": [], "offset": offset, "limit": limit}

    files = _active_scan.get("files", [])
    duplicates = _active_scan.get("duplicates", [])

    dup_paths = set()
    for d in duplicates:
        for p in d.get("files", []):
            dup_paths.add(p)

    ext_cats = {
        "documents": {".txt", ".md", ".pdf", ".doc", ".docx", ".csv", ".xlsx", ".json", ".xml"},
        "code": {".py", ".js", ".ts", ".html", ".css", ".c", ".cpp", ".java", ".go", ".rs", ".sh", ".bat", ".ps1"},
        "images": {".jpg", ".jpeg", ".png", ".gif", ".bmp", ".svg", ".webp", ".ico"},
        "logs": {".log", ".out", ".audit"},
    }

    filtered = []
    for f in files:
        if search:
            s = search.lower()
            if s not in f["name"].lower() and s not in f["relative_path"].lower():
                continue

        if ext and f["extension"].lower() != ext.lower():
            continue

        f_ext = f["extension"].lower()
        if category != "all":
            if category in ext_cats and f_ext not in ext_cats[category]:
                continue
            elif category == "other":
                all_known = set.union(*ext_cats.values())
                if f_ext in all_known:
                    continue

        # Size category filter
        sz = f.get("size_bytes", 0)
        if size_category == "tiny" and sz >= 10240:  # >= 10 KB
            continue
        elif size_category == "small" and (sz < 10240 or sz >= 1048576):  # 10KB - 1MB
            continue
        elif size_category == "medium" and (sz < 1048576 or sz >= 52428800):  # 1MB - 50MB
            continue
        elif size_category == "large" and sz < 52428800:  # > 50MB
            continue

        if status != "all" and f["scan_status"] != status:
            continue

        is_dup = f["relative_path"] in dup_paths
        if duplicate_only and not is_dup:
            continue

        file_copy = dict(f)
        file_copy["is_duplicate"] = is_dup
        filtered.append(file_copy)

    reverse = (sort_order.lower() == "desc")
    if sort_by == "size":
        filtered.sort(key=lambda x: x.get("size_bytes", 0), reverse=reverse)
    elif sort_by == "ext":
        filtered.sort(key=lambda x: x.get("extension", ""), reverse=reverse)
    elif sort_by == "modified":
        filtered.sort(key=lambda x: x.get("modified_at") or "", reverse=reverse)
    else:
        filtered.sort(key=lambda x: x.get("name", "").lower(), reverse=reverse)

    total_matches = len(filtered)
    paged_files = filtered[offset : offset + limit]

    return {
        "total": total_matches,
        "offset": offset,
        "limit": limit,
        "files": paged_files,
    }


@app.get("/api/files/detail")
def get_file_detail(path: str = Query(..., description="Relative path of file")):
    if not _active_scan:
        raise HTTPException(status_code=404, detail="No scan report available.")

    files = _active_scan.get("files", [])
    duplicates = _active_scan.get("duplicates", [])

    matched = None
    for f in files:
        if f["relative_path"] == path:
            matched = dict(f)
            break

    if not matched:
        raise HTTPException(status_code=404, detail="File not found in current scan.")

    # Duplicate group info
    dup_group = None
    for idx, grp in enumerate(duplicates, 1):
        if path in grp.get("files", []):
            dup_group = {
                "group_number": idx,
                "sha256": grp.get("sha256"),
                "total_identical": grp.get("count"),
                "other_copies": [p for p in grp.get("files", []) if p != path],
            }
            break
    matched["duplicate_info"] = dup_group

    # Associated findings for this specific file
    matched_findings = [f for f in _active_findings if f.get("related_file") == path]
    matched["associated_findings"] = matched_findings

    return matched


# ──────────────────────────────────────────────
# Duplicate Analysis
# ──────────────────────────────────────────────

@app.get("/api/duplicates")
def get_duplicates():
    if not _active_scan:
        return {"duplicate_groups": [], "total_groups": 0, "total_duplicate_files": 0, "estimated_wasted_bytes": 0}

    duplicates = _active_scan.get("duplicates", [])
    files_map = {f["relative_path"]: f for f in _active_scan.get("files", [])}

    enhanced_groups = []
    total_wasted_bytes = 0

    for idx, grp in enumerate(duplicates, 1):
        sha = grp.get("sha256")
        flist = grp.get("files", [])
        file_details = []
        group_size = 0
        for fp in flist:
            rec = files_map.get(fp, {})
            sz = rec.get("size_bytes", 0)
            group_size = sz
            file_details.append({
                "relative_path": fp,
                "size_bytes": sz,
                "modified_at": rec.get("modified_at"),
                "extension": rec.get("extension"),
            })

        wasted = max(0, (len(flist) - 1) * group_size)
        total_wasted_bytes += wasted

        enhanced_groups.append({
            "group_id": idx,
            "sha256": sha,
            "count": len(flist),
            "file_size_bytes": group_size,
            "wasted_bytes": wasted,
            "files": file_details,
        })

    return {
        "total_groups": len(enhanced_groups),
        "total_duplicate_files": sum(g["count"] for g in enhanced_groups),
        "estimated_wasted_bytes": total_wasted_bytes,
        "duplicate_groups": enhanced_groups,
    }


# ──────────────────────────────────────────────
# Integrity Verification
# ──────────────────────────────────────────────

@app.post("/api/verify")
def trigger_verify(req: VerifyRequest):
    global _active_verification, _active_findings
    target_path = Path(req.directory).resolve()
    baseline_path = Path(req.baseline_path).resolve()
    output_dir = Path(req.output_dir)

    if not target_path.exists() or not target_path.is_dir():
        raise HTTPException(status_code=400, detail=f"Target directory invalid: {target_path}")
    if not baseline_path.exists():
        raise HTTPException(status_code=400, detail=f"Baseline file not found: {baseline_path}")

    try:
        baseline = load_baseline(baseline_path)
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"Error loading baseline: {exc}")

    try:
        current_records = list(scan_directory(target_path))
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Error scanning directory for verify: {exc}")

    for record in current_records:
        if record["accessible"]:
            sha = compute_sha256(record["absolute_path"])
            record["sha256"] = sha
            record["scan_status"] = "hashed" if sha else "hash_failed"
        else:
            record["sha256"] = None
            record["scan_status"] = "inaccessible"

    result = compare_with_baseline(current_records, baseline)
    report_path = save_verification_report(result, str(target_path), str(baseline_path), output_dir)

    with report_path.open("r", encoding="utf-8") as f:
        _active_verification = json.load(f)

    # Re-evaluate findings incorporating the baseline verification results
    if _active_scan:
        files = _active_scan.get("files", [])
        dups = _active_scan.get("duplicates", [])
        dup_groups = []
        files_map = {f["relative_path"]: f for f in files}
        for d in dups:
            dup_groups.append([files_map[p] for p in d.get("files", []) if p in files_map])
        _active_findings = generate_forensic_findings(files, dup_groups, _active_verification)

    return {
        "success": True,
        "summary": _active_verification.get("summary"),
        "verified_at": _active_verification.get("verified_at"),
        "baseline_used": str(baseline_path),
        "details": result,
    }


@app.get("/api/verify/latest")
def get_latest_verification():
    if not _active_verification:
        raise HTTPException(status_code=404, detail="No verification report available. Run verification first.")
    return _active_verification


# ──────────────────────────────────────────────
# Scan History
# ──────────────────────────────────────────────

@app.get("/api/history")
def get_history():
    history = load_history()
    return {"history": history, "total": len(history)}


@app.post("/api/history/compare")
def compare_history_scans(req: CompareRequest):
    history = load_history()
    older = next((h for h in history if h["id"] == req.older_id), None)
    newer = next((h for h in history if h["id"] == req.newer_id), None)

    if not older or not newer:
        raise HTTPException(status_code=404, detail="One or both scan IDs not found in history.")

    return {
        "older_id": older["id"],
        "newer_id": newer["id"],
        "older_timestamp": older["timestamp"],
        "newer_timestamp": newer["timestamp"],
        "file_count_delta": newer["total_files"] - older["total_files"],
        "size_delta_bytes": newer["total_size_bytes"] - older["total_size_bytes"],
        "duplicate_count_delta": newer["duplicate_files"] - older["duplicate_files"],
        "older_summary": older,
        "newer_summary": newer,
    }


# ──────────────────────────────────────────────
# Local AI Assistant (Ollama with Tool Grounding)
# ──────────────────────────────────────────────

@app.get("/api/ai/status")
def get_ai_status():
    health = ai_client.check_health()
    models = ai_client.list_models() if health["online"] else []
    return {
        "online": health["online"],
        "version": health["version"],
        "base_url": ai_client.base_url,
        "current_model": ai_client.default_model,
        "installed_models": models,
        "error": health["error"],
    }


@app.post("/api/ai/chat")
def ai_chat(req: ChatRequest):
    if not app_settings.ai_enabled:
        raise HTTPException(status_code=400, detail="AI Assistant is currently disabled in settings.")

    latest_user_msg = req.messages[-1].content.lower() if req.messages else ""

    # Tool execution grounding: dynamically augment context based on user query
    tool_grounding = []
    if any(k in latest_user_msg for k in ["largest", "biggest", "size"]):
        largest = defa_get_largest_files(_active_scan, limit=5)
        tool_grounding.append(f"[TOOL: defa_get_largest_files] Result: {json.dumps(largest)}")

    if any(k in latest_user_msg for k in ["duplicate", "copies", "identical"]):
        dups = defa_get_duplicate_groups(_active_scan)
        tool_grounding.append(f"[TOOL: defa_get_duplicate_groups] Result: {len(dups)} groups found: {json.dumps(dups)}")

    if any(k in latest_user_msg for k in ["finding", "anomaly", "suspicious", "severity", "warning"]):
        findings = defa_get_findings(_active_findings, severity="all")
        tool_grounding.append(f"[TOOL: defa_get_findings] Result: {len(findings)} findings: {json.dumps(findings[:6])}")

    if any(k in latest_user_msg for k in ["baseline", "verify", "changed", "tamper", "missing"]):
        verif_data = defa_compare_baselines(_active_verification)
        tool_grounding.append(f"[TOOL: defa_compare_baselines] Result: {json.dumps(verif_data)}")

    # Construct context
    context_text = build_forensic_context(_active_scan, _active_verification, _active_findings)
    if tool_grounding:
        context_text += "\n\n--- VERIFIED FORENSIC TOOL QUERY EXECUTION ---\n" + "\n".join(tool_grounding)

    full_system_prompt = f"{SYSTEM_PROMPT}\n\n{context_text}"
    messages = [{"role": m.role, "content": m.content} for m in req.messages]
    chosen_model = req.model or app_settings.default_model

    resp = ai_client.chat(messages=messages, model=chosen_model, system_prompt=full_system_prompt)

    if not resp["success"]:
        return {
            "success": False,
            "reply": "",
            "model": chosen_model,
            "error": resp["error"],
        }

    return {
        "success": True,
        "reply": resp["reply"],
        "model": resp["model"],
        "error": None,
    }


# ──────────────────────────────────────────────
# Settings
# ──────────────────────────────────────────────

@app.get("/api/settings")
def get_settings():
    return app_settings.model_dump()


@app.post("/api/settings")
def update_settings(new_settings: SettingsModel):
    global app_settings, ai_client
    app_settings = new_settings
    ai_client = OllamaClient(base_url=app_settings.ollama_url, default_model=app_settings.default_model)
    return {"success": True, "settings": app_settings.model_dump()}


# ──────────────────────────────────────────────
# Export Files & PDF Generator
# ──────────────────────────────────────────────

@app.get("/api/export/{report_type}")
def export_report(
    report_type: str,
    case: str = Query(default="ACTIVE-EVIDENCE-INVESTIGATION"),
    investigator: str = Query(default="Forensic Examiner"),
):
    if report_type == "pdf":
        pdf_path = Path("reports/investigation_report.pdf")
        if not pdf_path.exists() and _active_scan:
            generate_pdf_report(
                case_name=case,
                investigator=investigator,
                scan_report=_active_scan,
                findings=_active_findings,
                output_path=pdf_path,
                verification_result=_active_verification,
            )
        if not pdf_path.exists():
            raise HTTPException(status_code=404, detail="No scan report available to generate PDF.")
        return FileResponse(path=pdf_path, media_type="application/pdf", filename=f"{case}_Forensic_Report.pdf")

    file_map = {
        "json": ("reports/scan_report.json", "application/json", "scan_report.json"),
        "csv": ("reports/scan_report.csv", "text/csv", "scan_report.csv"),
        "baseline": ("reports/baseline.json", "application/json", "baseline.json"),
        "verification": ("reports/verification_report.json", "application/json", "verification_report.json"),
        "html": ("reports/dashboard.html", "text/html", "dashboard.html"),
    }

    if report_type not in file_map:
        raise HTTPException(status_code=400, detail=f"Invalid report type: {report_type}")

    path_str, media_type, filename = file_map[report_type]
    path = Path(path_str)
    if not path.exists():
        raise HTTPException(status_code=404, detail=f"Report file {filename} not generated yet.")

    return FileResponse(path=path, media_type=media_type, filename=filename)


# ──────────────────────────────────────────────
# Frontend Static Files & SPA Root
# ──────────────────────────────────────────────

WEB_DIR = Path(__file__).resolve().parent.parent / "web"
STATIC_DIR = WEB_DIR / "static"

if STATIC_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")


@app.get("/", response_class=HTMLResponse)
def serve_index():
    index_file = WEB_DIR / "index.html"
    if not index_file.exists():
        return HTMLResponse(
            "<h2>DEFA — Digital Evidence Forensics & Investigation System</h2><p>Dashboard UI initializing...</p>"
        )
    return HTMLResponse(index_file.read_text(encoding="utf-8"))
