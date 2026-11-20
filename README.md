# DEFA 2.0 — Digital Evidence Forensics & Investigation System

> **Interactive Digital Forensics Workstation with Local AI, Cryptographic Integrity Verification & Anomaly Detection**  
> Engineered for digital forensics, incident response, and integrity audits: recursive directory scanning, 64 KB chunk-based SHA-256 hashing, duplicate evidence clustering, baseline integrity diffing, forensic anomaly detection, 12-step scientific benchmark validation, pure-Python PDF reporting, and an interactive dark graphite cybersecurity dashboard powered by a local, privacy-safe AI assistant (Ollama).

---

## 🌟 What's New in DEFA 2.0

| Capability | DEFA 1.0 (Basic CLI) | DEFA 2.0 (Forensic Workstation) |
|---|---|---|
| **Evidence Selection** | Hardcoded `./sample_data` only | **Dynamic Evidence Selection**: Native OS folder & multi-file pickers, arbitrary folders/files, mixed selections, automatic overlap deduplication |
| **Interface** | Terminal CLI only | Modern Dark Graphite Web Dashboard + Full CLI |
| **Evidence Explorer** | Summary text in terminal | Interactive File Explorer with search, category filtering, size buckets, and slide-out inspection modal |
| **Cryptographic Hashing** | 64 KB chunk SHA-256 | High-throughput 64 KB chunk SHA-256 with duration and MB/s throughput metrics |
| **Duplicates** | Terminal printout | Expandable duplicate investigation cards with wasted storage calculations |
| **Integrity Checks** | Terminal text diff | Side-by-side visual diff (baseline vs current hash, size, and timestamp) |
| **Forensic Findings Engine** | None | Anomaly detection engine classifying findings (High, Medium, Low, Informational): magic byte mismatches, double extensions, whitespace padding, hidden files |
| **Reporting** | JSON and CSV only | JSON, CSV, Baseline Snapshot, and **Pure-Python Court-Admissible PDF Report** |
| **Scientific Validation** | Ad-hoc manual testing | **Automated 12-step validation benchmark** verifying 100% accuracy and recording MB/s throughput |
| **Public Dataset Testing** | None | Dedicated testing guide and support for real public forensic datasets (NIST CFReDS, Digital Corpora) |
| **Scan History** | None (overwrote previous report) | Audit trail of all past scans with historical delta comparisons |
| **AI Assistant** | None | 100% Local AI Forensic Assistant via Ollama with **tool-grounded query execution** (zero cloud uploads) |
| **Automated Testing** | 38 unit tests | **99 automated unit tests (100% passing)** across 10 test modules |

---

## 🛡️ Core Principles: Forensic Integrity & Privacy

1. **Non-Destructive Acquisition**: All file scanning, hashing, and report generation execute locally. Source evidence files are strictly accessed in binary read-only mode (`rb`) and are **never modified, moved, or deleted**.
2. **Investigative Leads, Not Premature Conclusions**: Detected anomalies (such as magic byte mismatches or deceptive extensions) are classified as investigative leads and forensic anomalies, never labeled as malware without sandbox verification.
3. **Local AI Only**: The AI assistant communicates exclusively with a locally hosted Ollama instance (`http://localhost:11434`).
4. **Metadata-Only AI Context**: The AI assistant receives **only high-level scan metadata** (file paths, sizes, extensions, duplicate counts, and hash digests). **No evidence file contents are ever read into memory for AI or transmitted.**
5. **No Cloud Dependencies**: Zero external API keys, zero cloud subscriptions, zero network telemetry. Runs in completely air-gapped forensic labs.

---

## 🏗️ Architecture & Folder Structure

```
defa/
├── main.py                    ← Unified multi-command CLI (scan, verify, benchmark, serve)
├── start.bat                  ← 1-click Windows launcher (starts server & opens browser)
├── requirements.txt           ← Web server dependencies (core scanning requires standard library only)
├── README.md                  ← Comprehensive technical documentation
├── INTERVIEW_GUIDE.md         ← Technical interview defense guide with 30+ Q&A
├── PUBLIC_DATASET_TESTING.md  ← Step-by-step guide for testing against NIST CFReDS & Digital Corpora
│
├── defa/                      ← Core application package
│   ├── __init__.py            ← Package metadata (v2.0.0)
│   ├── scanner.py             ← Recursive directory walker & metadata extractor (pathlib, hidden file check)
│   ├── hasher.py              ← 64 KB chunk-based SHA-256 cryptographic engine (hashlib)
│   ├── duplicates.py          ← O(N) hash-based duplicate grouping engine
│   ├── verifier.py            ← Set-algebra baseline comparison engine
│   ├── findings.py            ← Forensic Findings Engine (magic bytes, deceptive extensions, hidden files)
│   ├── benchmark.py           ← Automated 12-step scientific validation & performance benchmarking engine
│   ├── pdf_report.py          ← Pure-Python zero-dependency PDF 1.4 report generator
│   ├── reporter.py            ← Multi-format report exporter (JSON, CSV, baseline)
│   ├── history.py             ← Scan history audit logging and delta comparison
│   │
│   ├── ai/                    ← Local AI assistant subsystem
│   │   ├── __init__.py
│   │   ├── client.py          ← Ollama REST API client (with rapid socket pre-check)
│   │   ├── context.py         ← Forensic metadata summarizer & privacy guardrails
│   │   └── tools.py           ← Grounded tool functions (largest files, duplicates, findings, baseline diff)
│   │
│   ├── api/                   ← FastAPI REST API backend
│   │   ├── __init__.py
│   │   ├── routes.py          ← API route handlers (scan, files, verify, findings, benchmark, history, AI, PDF)
│   │   └── schemas.py         ← Pydantic request & response validation schemas
│   │
│   └── web/                   ← Interactive web dashboard frontend
│       ├── index.html         ← Single Page Application (10 forensic tab views + detail modals)
│       └── static/
│           ├── css/dashboard.css  ← Dark graphite cybersecurity theme
│           └── js/app.js          ← Vanilla JS reactive state & event controller
│
├── tests/                     ← Automated test suite (81 tests, 100% passing)
│   ├── __init__.py
│   ├── test_scanner.py        ← 11 scanner unit tests
│   ├── test_hasher.py         ← 7 cryptographic hashing tests
│   ├── test_duplicates.py     ← 8 duplicate detection tests
│   ├── test_verifier.py       ← 12 integrity verification tests
│   ├── test_findings.py       ← 9 forensic findings & magic byte tests
│   ├── test_benchmark.py      ← 1 comprehensive 12-step validation test
│   ├── test_pdf_report.py     ← 3 PDF report generation & structure tests
│   ├── test_history.py        ← 3 scan history & delta tests
│   ├── test_ai.py             ← 9 local AI client & context tests (mocked)
│   └── test_api.py            ← 16 FastAPI endpoint & schema tests
│
├── sample_data/               ← Safe demo dataset for practice & interview demonstrations
│   ├── case_metadata.json
│   ├── employees.csv
│   ├── original_evidence.txt  ← Duplicate of copy_of_evidence.txt
│   ├── readme.txt
│   ├── documents/
│   │   ├── case_report.txt
│   │   ├── chain_of_custody.txt
│   │   ├── copy_of_evidence.txt  ← Duplicate (identical content, different path)
│   │   └── evidence_log.md
│   ├── images/
│   │   ├── crime_scene_01.jpg.txt
│   │   └── evidence_photo.png.txt
│   ├── logs/
│   │   ├── audit.log
│   │   └── system.log
│   └── nested/
│       ├── nested_evidence.txt
│       └── subfolder/
│           └── deep_file.txt
│
└── reports/                   ← Generated artifacts (JSON, CSV, baseline, PDF, history)
    ├── scan_report.json
    ├── scan_report.csv
    ├── baseline.json
    ├── verification_report.json
    ├── investigation_report.pdf
    └── scan_history.json
```

---

## ⚡ Quick Start & Installation

### Prerequisites
- Python 3.11 or higher
- Optional: [Ollama](https://ollama.com) for local AI assistance

### 1. Install Dependencies
```bash
cd d:\digitalforensics\defa
pip install -r requirements.txt
```

### 2. Launch the Web Dashboard
Double-click `start.bat` on Windows, or run:
```bash
python main.py serve --host 127.0.0.1 --port 8000
```
Open your browser at: **`http://127.0.0.1:8000`**

---

## 💻 Command-Line Interface (CLI)

All CLI commands remain fully supported, standalone, and scriptable:

### 1. Scan a Directory
```bash
python main.py scan ./sample_data --output reports
```
- Recursively walks all subdirectories.
- Reads files in 64 KB chunks and calculates SHA-256 digests.
- Detects duplicate files and clusters them.
- Evaluates files through the Forensic Findings Engine.
- Generates `reports/scan_report.json`, `reports/scan_report.csv`, `reports/baseline.json`, and `reports/investigation_report.pdf`.

### 2. Verify File Integrity Against Baseline
```bash
python main.py verify ./sample_data --baseline reports/baseline.json
```
- Rescans target directory and recomputes current hashes.
- Compares against baseline using set operations to isolate:
  - **Unchanged files** (identical SHA-256)
  - **New files** (present now, absent in baseline)
  - **Missing files** (present in baseline, missing now)
  - **Modified files** (same relative path, diverging SHA-256 digest)
- Generates `reports/verification_report.json`.

### 3. Run the Automated 12-Step Scientific Benchmark
```bash
python main.py benchmark
```
- Synthesizes dynamic test evidence in an isolated temporary environment.
- Executes 12 rigorous forensic validation steps (hashing, baseline, mutation, addition, deletion, direct `hashlib` comparison).
- Measures real file processing throughput (files/sec and MB/sec).
- Reports validation accuracy percentage (100.0% expected).

### 4. Launch Web Dashboard
```bash
python main.py serve --port 8000
```

---

## 🔍 Forensic Findings & Anomaly Detection Engine

DEFA 2.0 incorporates a dedicated findings engine (`defa/findings.py`) that prioritizes leads into 4 severity levels:

1. **High Severity**:
   - **Magic Byte Mismatches**: Binary headers inspected to detect spoofed extensions (e.g. Windows PE `MZ` executable disguised with a `.jpg` or `.pdf` extension).
   - **Deceptive Double Extensions**: Patterns such as `.pdf.exe`, `.docx.exe`, or `.jpg.scr`.
   - **Filename Whitespace Padding**: Deceptive trailing spaces before the extension (e.g. `"invoice   .pdf"`).
   - **Integrity Verification Mismatches**: Unplanned SHA-256 hash divergence against baseline snapshot.
2. **Medium Severity**:
   - **Inaccessible / Hash Failures**: Permission locks or read errors preventing cryptographic hashing.
   - **Executable / Script in Document Folders**: `.exe`, `.bat`, `.ps1` files discovered in user document directories.
   - **Baseline Additions / Deletions**: Unbaselined file introductions or deletions.
3. **Low Severity**:
   - **Hidden Files**: Dotfiles (`.bash_history`, `.env`) or Windows hidden-attribute files.
4. **Informational**:
   - **Duplicate Clusters**: Content identity across separate paths with wasted storage calculations.
   - **Unusually Large Files**: Files exceeding volume thresholds (> 50 MB) indicating possible memory dumps or sub-disk images.

---

## 📑 Pure-Python PDF Report Generator

DEFA 2.0 produces formal digital forensics investigation PDF reports (`reports/investigation_report.pdf`) using a custom pure-Python PDF 1.4 generator (`defa/pdf_report.py`).
- **Zero Third-Party PDF Dependencies**: Does not require ReportLab, WeasyPrint, wkhtmltopdf, or C-runtime binaries.
- **Court-Admissible Styling**: Structured with case metadata, lead investigator identity, executive summary, prioritized findings with severity badges, baseline verification diffs, and forensic chain-of-custody disclaimers.

---

## 🌐 Public Forensic Dataset Testing

DEFA 2.0 is designed and verified to analyze real publicly available forensic images. See [PUBLIC_DATASET_TESTING.md](file:///d:/digitalforensics/defa/PUBLIC_DATASET_TESTING.md) for full walkthroughs:
- **NIST CFReDS** (Computer Forensic Reference Data Sets) — Hacking Case, File Carving, Memory Verification.
- **Digital Corpora** (Govdocs1, Real System Forensic Images).
- **DFIR Training Challenges & Toolkits**.

---

## 🤖 Setting Up the Local AI Assistant (Ollama)

DEFA 2.0 features an embedded local AI assistant that answers questions using **tool-grounded query execution** without sending data to external APIs:

1. **Install Ollama**: Download from [https://ollama.com](https://ollama.com)
2. **Pull a lightweight model**:
   ```bash
   ollama pull llama3.2
   ```
   *(Alternative models: `ollama pull phi3:mini` or `ollama pull mistral`)*
3. **Start the Ollama daemon**:
   ```bash
   ollama serve
   ```
4. Open DEFA 2.0 at `http://127.0.0.1:8000` and navigate to the **AI Assistant** tab. The status indicator will display `AI Online`.

> **Note:** DEFA functions 100% normally even without Ollama. If offline, the UI provides helpful guidance while scanning, duplicate analysis, integrity checks, and PDF exports remain fully active.

---

## 🧪 Automated Testing

DEFA 2.0 features **99 comprehensive automated tests** across 10 test modules:

```bash
python -m pytest tests/ -v
```

### Test Suite Breakdown:
- `test_dynamic_selection.py` (12 tests): Single file, multiple files, single folder, nested folders, multiple folders, mixed files/folders, overlapping selection deduplication, empty folders, large file chunking, inspection previews, InvestigationManager background thread execution.
- `test_scanner.py` (11 tests): Recursive directory walking, nested subdirectories, empty directories, extension normalization, file size accuracy, permission error handling.
- `test_hasher.py` (7 tests): Known NIST hashes, empty file digest, chunk-based large file hashing, missing file handling, 64-char hex format validation.
- `test_duplicates.py` (8 tests): Multi-file duplicate grouping, unique hash handling, None-hash filtering, empty list handling.
- `test_verifier.py` (12 tests): Baseline loading, bad JSON rejection, missing file detection, modified file detection, unchanged verification, mixed scenarios.
- `test_findings.py` (9 tests): Magic byte header inspections, double extension detection, whitespace padding detection, hidden dotfiles, severity priority hierarchy.
- `test_benchmark.py` (1 test): 12-step end-to-end scientific validation with 100% accuracy and throughput verification.
- `test_pdf_report.py` (3 tests): Pure-Python PDF 1.4 structure, string escaping, header/trailer conformance.
- `test_history.py` (3 tests): History persistence, chronological sorting, historical scan delta comparisons.
- `test_ai.py` (9 tests): Offline connection handling, Ollama status reporting, context prompt builder, safety filters, mocked AI responses.
- `test_api.py` (21 tests): FastAPI REST endpoints, native dialog triggers, evidence preview API, background investigation start & progress polling, directory validation, file filters, duplicate reporting, findings API, benchmark endpoint, PDF export, history APIs, settings updates.

---

## 📄 License & Academic Note

This project was developed as a software engineering and digital forensics portfolio piece demonstrating clean architecture, cryptographic integrity verification, defensive programming, and local AI integration using modern Python.
