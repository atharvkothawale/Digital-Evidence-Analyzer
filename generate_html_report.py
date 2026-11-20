"""
generate_html_report.py — HTML Dashboard Generator

Reads the JSON scan and verification reports produced by DEFA and
generates a single self-contained HTML file — a visual dashboard
you can open in any browser.

Usage:
    python generate_html_report.py
    python generate_html_report.py --scan reports/scan_report.json
    python generate_html_report.py --scan reports/scan_report.json --verify reports/verification_report.json
    python generate_html_report.py --output reports/dashboard.html
"""

import argparse
import json
from datetime import datetime
from pathlib import Path


# ── Colour palette ─────────────────────────────────────────────────────────
COLORS = {
    "bg": "#0f1117",
    "card": "#1a1d27",
    "border": "#2a2d3e",
    "accent": "#4f8ef7",
    "green": "#22c55e",
    "yellow": "#f59e0b",
    "red": "#ef4444",
    "muted": "#6b7280",
    "text": "#e2e8f0",
    "subtext": "#94a3b8",
}


def _ext_color(ext: str) -> str:
    """Return a badge colour based on file extension category."""
    ext = ext.lower()
    if ext in {".txt", ".md", ".log"}:
        return "#3b82f6"
    if ext in {".json", ".xml", ".yaml", ".yml"}:
        return "#8b5cf6"
    if ext in {".csv", ".xlsx", ".xls"}:
        return "#22c55e"
    if ext in {".jpg", ".jpeg", ".png", ".gif", ".bmp"}:
        return "#f59e0b"
    if ext in {".exe", ".dll", ".bat", ".ps1", ".sh"}:
        return "#ef4444"
    return "#6b7280"


def _fmt_bytes(n: int) -> str:
    """Human-readable file size."""
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024:
            return f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} TB"


def _fmt_time(iso: str | None) -> str:
    if not iso:
        return "—"
    try:
        dt = datetime.fromisoformat(iso)
        return dt.strftime("%Y-%m-%d %H:%M UTC")
    except Exception:
        return iso


def build_html(scan: dict, verify: dict | None) -> str:
    files = scan.get("files", [])
    duplicates = scan.get("duplicates", [])

    total = scan.get("total_files", 0)
    hashed = scan.get("hashed_successfully", 0)
    failed = scan.get("hash_failed", 0)
    dup_groups = scan.get("duplicate_groups", 0)
    dup_files = scan.get("duplicate_files", 0)
    scanned_at = _fmt_time(scan.get("scanned_at"))
    directory = scan.get("directory", "—")

    # Extension breakdown
    ext_counts: dict[str, int] = {}
    for f in files:
        e = f.get("extension") or "(none)"
        ext_counts[e] = ext_counts.get(e, 0) + 1
    ext_sorted = sorted(ext_counts.items(), key=lambda x: -x[1])

    # ── File rows ─────────────────────────────────────────────────────────
    file_rows = ""
    for f in files:
        ext = f.get("extension") or ""
        color = _ext_color(ext)
        sha = f.get("sha256") or "N/A"
        status = f.get("scan_status", "")
        status_color = COLORS["green"] if status == "hashed" else COLORS["red"]
        file_rows += f"""
        <tr>
          <td><span class="badge" style="background:{color}22;color:{color};">{ext or "—"}</span></td>
          <td class="mono path-cell" title="{f.get('relative_path','')}">
            {f.get('relative_path', '')}
          </td>
          <td class="mono">{_fmt_bytes(f.get('size_bytes', 0))}</td>
          <td class="mono hash-cell" title="{sha}">{sha[:24]}…</td>
          <td class="mono">{_fmt_time(f.get('modified_at'))}</td>
          <td><span class="badge" style="background:{status_color}22;color:{status_color};">{status}</span></td>
        </tr>"""

    # ── Duplicate rows ────────────────────────────────────────────────────
    dup_section = ""
    if duplicates:
        dup_rows = ""
        for i, group in enumerate(duplicates, 1):
            sha = group.get("sha256", "")
            count = group.get("count", 0)
            files_in_group = group.get("files", [])
            files_html = "".join(
                f'<div class="dup-file">📄 {fp}</div>' for fp in files_in_group
            )
            dup_rows += f"""
            <div class="dup-card">
              <div class="dup-header">
                <span class="dup-index">Group {i}</span>
                <span class="dup-count">{count} identical files</span>
                <span class="mono dup-hash" title="{sha}">{sha[:32]}…</span>
              </div>
              <div class="dup-files">{files_html}</div>
            </div>"""

        dup_section = f"""
        <section class="section">
          <h2 class="section-title">🔁 Duplicate Files</h2>
          <p class="section-desc">These files have identical SHA-256 hashes — their content is exactly the same.</p>
          {dup_rows}
        </section>"""

    # ── Extension chart (CSS bar chart) ───────────────────────────────────
    max_count = ext_sorted[0][1] if ext_sorted else 1
    ext_bars = ""
    for ext, count in ext_sorted[:10]:
        pct = round(count / max_count * 100)
        color = _ext_color(ext)
        ext_bars += f"""
        <div class="bar-row">
          <span class="bar-label">{ext}</span>
          <div class="bar-track">
            <div class="bar-fill" style="width:{pct}%;background:{color};"></div>
          </div>
          <span class="bar-count">{count}</span>
        </div>"""

    # ── Verification section ──────────────────────────────────────────────
    verify_section = ""
    if verify:
        summary = verify.get("summary", {})
        v_new = summary.get("new", 0)
        v_missing = summary.get("missing", 0)
        v_modified = summary.get("modified", 0)
        v_unchanged = summary.get("unchanged", 0)
        v_at = _fmt_time(verify.get("verified_at"))
        details = verify.get("details", {})

        status_icon = "✅" if (v_new == 0 and v_missing == 0 and v_modified == 0) else "⚠️"
        status_label = "All files intact" if status_icon == "✅" else "Changes detected"
        status_col = COLORS["green"] if status_icon == "✅" else COLORS["yellow"]

        new_list = "".join(
            f'<div class="change-item new">+ {r.get("relative_path","")}</div>'
            for r in details.get("new", [])
        )
        missing_list = "".join(
            f'<div class="change-item missing">− {r.get("relative_path","")}</div>'
            for r in details.get("missing", [])
        )
        modified_list = "".join(
            f'<div class="change-item modified">~ {entry.get("current",{}).get("relative_path","")}</div>'
            for entry in details.get("modified", [])
        )

        verify_section = f"""
        <section class="section">
          <h2 class="section-title">🔐 Integrity Verification</h2>
          <p class="section-desc">Verified at {v_at} against baseline.</p>
          <div class="verify-status" style="border-color:{status_col};">
            <span style="font-size:1.5rem;">{status_icon}</span>
            <span style="color:{status_col};font-weight:600;">{status_label}</span>
          </div>
          <div class="stat-row" style="margin-top:1.5rem;">
            <div class="stat-card"><div class="stat-num" style="color:{COLORS['green']}">{v_unchanged}</div><div class="stat-label">Unchanged</div></div>
            <div class="stat-card"><div class="stat-num" style="color:{COLORS['accent']}">{v_new}</div><div class="stat-label">New</div></div>
            <div class="stat-card"><div class="stat-num" style="color:{COLORS['red']}">{v_missing}</div><div class="stat-label">Missing</div></div>
            <div class="stat-card"><div class="stat-num" style="color:{COLORS['yellow']}">{v_modified}</div><div class="stat-label">Modified</div></div>
          </div>
          {new_list}{missing_list}{modified_list}
        </section>"""

    # ── Full HTML ─────────────────────────────────────────────────────────
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>DEFA — Digital Evidence File Analyzer</title>
<style>
  *, *::before, *::after {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ font-family: 'Segoe UI', system-ui, sans-serif; background: {COLORS['bg']}; color: {COLORS['text']}; min-height: 100vh; }}

  /* Header */
  .header {{ background: linear-gradient(135deg, #1a1d27 0%, #0f1117 100%);
             border-bottom: 1px solid {COLORS['border']}; padding: 2rem; }}
  .header h1 {{ font-size: 1.6rem; font-weight: 700; color: {COLORS['accent']}; letter-spacing: .5px; }}
  .header .meta {{ color: {COLORS['subtext']}; font-size: .85rem; margin-top: .4rem; }}
  .header .dir  {{ color: {COLORS['muted']}; font-size: .8rem; margin-top: .2rem; font-family: monospace; }}

  /* Layout */
  .container {{ max-width: 1200px; margin: 0 auto; padding: 2rem 1.5rem; }}
  .section {{ margin-bottom: 2.5rem; }}
  .section-title {{ font-size: 1.1rem; font-weight: 600; margin-bottom: .4rem; }}
  .section-desc {{ color: {COLORS['subtext']}; font-size: .85rem; margin-bottom: 1.2rem; }}

  /* Stats */
  .stat-row {{ display: flex; gap: 1rem; flex-wrap: wrap; margin-bottom: 2rem; }}
  .stat-card {{ flex: 1; min-width: 130px; background: {COLORS['card']}; border: 1px solid {COLORS['border']};
                border-radius: 10px; padding: 1.2rem; text-align: center; }}
  .stat-num {{ font-size: 2rem; font-weight: 700; color: {COLORS['accent']}; }}
  .stat-label {{ color: {COLORS['subtext']}; font-size: .8rem; margin-top: .3rem; text-transform: uppercase; letter-spacing: .5px; }}

  /* Table */
  .table-wrap {{ overflow-x: auto; border-radius: 10px; border: 1px solid {COLORS['border']}; }}
  table {{ width: 100%; border-collapse: collapse; font-size: .85rem; }}
  thead {{ background: {COLORS['card']}; }}
  th {{ padding: .75rem 1rem; text-align: left; color: {COLORS['subtext']}; font-weight: 500;
        border-bottom: 1px solid {COLORS['border']}; white-space: nowrap; }}
  td {{ padding: .65rem 1rem; border-bottom: 1px solid {COLORS['border']}22; vertical-align: middle; }}
  tr:last-child td {{ border-bottom: none; }}
  tr:hover td {{ background: {COLORS['card']}; }}
  .path-cell {{ max-width: 220px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }}
  .hash-cell {{ max-width: 180px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }}

  /* Badges */
  .badge {{ display: inline-block; padding: .15rem .55rem; border-radius: 999px; font-size: .75rem; font-weight: 500; }}

  /* Mono */
  .mono {{ font-family: 'Cascadia Code', 'Consolas', monospace; font-size: .8rem; color: {COLORS['subtext']}; }}

  /* Bar chart */
  .bar-row {{ display: flex; align-items: center; gap: .75rem; margin-bottom: .5rem; }}
  .bar-label {{ width: 70px; font-size: .82rem; font-family: monospace; color: {COLORS['subtext']}; text-align: right; }}
  .bar-track {{ flex: 1; height: 10px; background: {COLORS['border']}; border-radius: 999px; overflow: hidden; }}
  .bar-fill {{ height: 100%; border-radius: 999px; transition: width .4s; }}
  .bar-count {{ width: 30px; font-size: .8rem; color: {COLORS['muted']}; text-align: right; }}

  /* Duplicates */
  .dup-card {{ background: {COLORS['card']}; border: 1px solid {COLORS['yellow']}44;
               border-left: 3px solid {COLORS['yellow']}; border-radius: 8px;
               padding: 1rem 1.2rem; margin-bottom: 1rem; }}
  .dup-header {{ display: flex; align-items: center; gap: 1rem; flex-wrap: wrap; margin-bottom: .6rem; }}
  .dup-index {{ font-weight: 600; color: {COLORS['yellow']}; }}
  .dup-count {{ font-size: .82rem; color: {COLORS['subtext']}; }}
  .dup-hash {{ font-size: .78rem; color: {COLORS['muted']}; }}
  .dup-file {{ font-family: monospace; font-size: .82rem; color: {COLORS['text']}; padding: .2rem 0; }}

  /* Verify */
  .verify-status {{ display: flex; align-items: center; gap: 1rem; background: {COLORS['card']};
                    border: 1px solid; border-radius: 10px; padding: 1rem 1.5rem; }}
  .change-item {{ font-family: monospace; font-size: .83rem; padding: .25rem .5rem;
                  border-radius: 4px; margin-bottom: .3rem; }}
  .change-item.new      {{ background: {COLORS['accent']}18; color: {COLORS['accent']}; }}
  .change-item.missing  {{ background: {COLORS['red']}18;    color: {COLORS['red']}; }}
  .change-item.modified {{ background: {COLORS['yellow']}18; color: {COLORS['yellow']}; }}

  /* Two-col layout */
  .two-col {{ display: grid; grid-template-columns: 1fr 1fr; gap: 1.5rem; }}
  @media (max-width: 700px) {{ .two-col {{ grid-template-columns: 1fr; }} }}

  /* Footer */
  .footer {{ text-align: center; padding: 2rem; color: {COLORS['muted']}; font-size: .8rem;
             border-top: 1px solid {COLORS['border']}; }}
</style>
</head>
<body>

<header class="header">
  <h1>🔍 DEFA — Digital Evidence File Analyzer</h1>
  <div class="meta">Scan completed at {scanned_at}</div>
  <div class="dir">📁 {directory}</div>
</header>

<div class="container">

  <!-- Summary stats -->
  <section class="section">
    <h2 class="section-title">📊 Scan Summary</h2>
    <div class="stat-row">
      <div class="stat-card">
        <div class="stat-num" style="color:{COLORS['accent']}">{total}</div>
        <div class="stat-label">Files Analyzed</div>
      </div>
      <div class="stat-card">
        <div class="stat-num" style="color:{COLORS['green']}">{hashed}</div>
        <div class="stat-label">Hashed OK</div>
      </div>
      <div class="stat-card">
        <div class="stat-num" style="color:{COLORS['red']}">{failed}</div>
        <div class="stat-label">Failed</div>
      </div>
      <div class="stat-card">
        <div class="stat-num" style="color:{COLORS['yellow']}">{dup_groups}</div>
        <div class="stat-label">Dup Groups</div>
      </div>
      <div class="stat-card">
        <div class="stat-num" style="color:{COLORS['yellow']}">{dup_files}</div>
        <div class="stat-label">Dup Files</div>
      </div>
    </div>
  </section>

  <!-- Two-col: ext chart + info -->
  <div class="two-col" style="margin-bottom:2.5rem;">
    <div>
      <h2 class="section-title">📂 File Types</h2>
      <p class="section-desc">Distribution of file extensions found.</p>
      {ext_bars}
    </div>
    <div>
      <h2 class="section-title">ℹ️ About This Report</h2>
      <p class="section-desc" style="line-height:1.7;">
        Each file was read in <strong>64 KB chunks</strong> and fed into
        <strong>SHA-256</strong> — a cryptographic hash function that produces a
        unique 64-character fingerprint per file.<br><br>
        Even a single changed byte produces a completely different hash,
        making this tool reliable for detecting tampering, corruption, or
        unauthorised modifications.
      </p>
    </div>
  </div>

  {dup_section}

  {verify_section}

  <!-- Full file table -->
  <section class="section">
    <h2 class="section-title">📋 File Inventory ({total} files)</h2>
    <p class="section-desc">Complete list of all scanned files with their SHA-256 hashes and metadata.</p>
    <div class="table-wrap">
      <table>
        <thead>
          <tr>
            <th>Type</th>
            <th>Path</th>
            <th>Size</th>
            <th>SHA-256</th>
            <th>Modified</th>
            <th>Status</th>
          </tr>
        </thead>
        <tbody>
          {file_rows}
        </tbody>
      </table>
    </div>
  </section>

</div>

<footer class="footer">
  Generated by DEFA v1.0.0 — Digital Evidence File Analyzer &nbsp;|&nbsp;
  Python standard library only &nbsp;|&nbsp;
  <a href="https://github.com" style="color:{COLORS['accent']};">github.com/yourusername/defa</a>
</footer>

</body>
</html>"""


def main() -> None:
    parser = argparse.ArgumentParser(
        description="DEFA — Generate an HTML dashboard from scan reports.",
    )
    parser.add_argument(
        "--scan", default="reports/scan_report.json",
        help="Path to scan_report.json (default: reports/scan_report.json)",
    )
    parser.add_argument(
        "--verify", default="reports/verification_report.json",
        help="Path to verification_report.json (optional)",
    )
    parser.add_argument(
        "--output", "-o", default="reports/dashboard.html",
        help="Output HTML file (default: reports/dashboard.html)",
    )
    args = parser.parse_args()

    # Load scan report
    scan_path = Path(args.scan)
    if not scan_path.exists():
        print(f"[ERROR] Scan report not found: {scan_path}")
        print("  Run:  python main.py scan ./sample_data --output reports")
        return

    with scan_path.open(encoding="utf-8") as f:
        scan_data = json.load(f)

    # Load verification report (optional)
    verify_data = None
    verify_path = Path(args.verify)
    if verify_path.exists():
        with verify_path.open(encoding="utf-8") as f:
            verify_data = json.load(f)

    # Generate HTML
    html = build_html(scan_data, verify_data)

    out_path = Path(args.output)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(html, encoding="utf-8")

    print(f"\n  ✅  Dashboard generated: {out_path.resolve()}")
    print(f"  Open it in your browser — it works offline.\n")


if __name__ == "__main__":
    main()

