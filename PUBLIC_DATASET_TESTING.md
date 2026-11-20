# DEFA — Public Forensic Dataset Testing Guide

> A practical, beginner-friendly guide to testing and validating the **DEFA Digital Evidence Forensics & Investigation System** using verified, publicly available digital forensics datasets.

---

## 1. Why Test with Public Forensic Datasets?

When presenting DEFA during technical interviews, portfolio evaluations, or client demonstrations, using real-world public evidence collections proves that:
1. DEFA reliably catalogs thousands of files and nested directory trees.
2. The chunk-based SHA-256 engine handles large files without memory exhaustion.
3. The duplicate detection algorithm accurately groups identical files across disparate folders.
4. The findings engine flags deceptive filenames, double extensions, and signature mismatches.
5. All operations are safe and strictly non-destructive.

---

## 2. Recommended Public Forensic Dataset Repositories

| Repository | URL | Description & Best Use Case |
|---|---|---|
| **NIST CFReDS** | [https://cfreds-archive.nist.gov/](https://cfreds-archive.nist.gov/) | National Institute of Standards & Technology Computer Forensic Reference Datasets (Hacking case, memory, file carving tests) |
| **Digital Corpora** | [https://digitalcorpora.org/](https://digitalcorpora.org/) | Universally cited academic and DFIR corpora (m57-patents, Govdocs1, real email and document archives) |
| **DFIR Toolkit** | [https://dfir-toolkit.github.io/index.html](https://dfir-toolkit.github.io/index.html) | Curated collection of incident response datasets, malware artifact samples, and memory dumps |
| **Forensic Case Challenges** | [https://www.ahmedalzaidy.com/datasets/](https://www.ahmedalzaidy.com/datasets/) | Practical hands-on investigation cases (insider threat, data exfiltration, USB forensics) |

---

## 3. Important: Extracted Files vs. Raw Disk Images

Digital forensic evidence is typically distributed in one of two formats:

```
Evidence Formats:
├── 1. Extracted File Systems / Folders (Directly Analyzable by DEFA)
│   └── Normal directories containing documents, logs, images, executables.
│
└── 2. Raw / Forensic Disk Images (Requires 1-Step Mounting or Extraction)
    ├── .E01 (Expert Witness / EnCase format)
    ├── .RAW / .DD / .IMG (Raw bitstream sector copy)
    └── .VHD / .VMDK (Virtual hard drive containers)
```

> ⚠️ **Forensic Principle:** DEFA is a file-system analysis and integrity verification engine. It operates on **accessible directories and files**. It does **not** directly parse unmounted raw disk sectors or proprietary E01 compression containers.  
> To analyze a disk image with DEFA, first **mount or extract the image as read-only** using standard forensic tools.

---

## 4. How to Mount or Extract Disk Images Read-Only

### On Windows:

#### Method A: Using 7-Zip (Fastest for `.raw`, `.dd`, `.vhd`, `.iso`)
1. Download and install [7-Zip](https://www.7-zip.org/) (free, open source).
2. Right-click the `.raw`, `.dd`, or `.vhd` image file.
3. Select **7-Zip &rarr; Extract to "extracted_evidence\"**.
4. 7-Zip extracts the filesystem partitions into standard folders.
5. In DEFA, select the `extracted_evidence` folder to scan!

#### Method B: Using FTK Imager (Standard Digital Forensics Practice)
1. Download **FTK Imager Lite** (free from Exterro / AccessData).
2. Click **File &rarr; Image Mounting**.
3. Browse to your `.E01` or `.raw` image.
4. Set Mount Type to **Block Device / Read-Only** (prevents altering evidence).
5. FTK Imager assigns a drive letter (e.g., `E:\`).
6. In DEFA, enter `E:\` as the evidence directory to scan!

#### Method C: Arsenal Image Mounter
1. Mounts `.E01`, `.raw`, and `.vhd` with write-blocking drivers as a standard Windows volume.

---

### On Linux / macOS:

```bash
# 1. Mount raw .dd / .raw bitstream image read-only
sudo mkdir -p /mnt/evidence
sudo mount -o ro,loop forensic_image.dd /mnt/evidence

# 2. For .E01 files, use ewfmount (libewf)
sudo mkdir -p /mnt/ewf /mnt/evidence
sudo ewfmount evidence.E01 /mnt/ewf
sudo mount -o ro,loop /mnt/ewf/ewf1 /mnt/evidence

# 3. Analyze /mnt/evidence in DEFA:
python main.py scan /mnt/evidence --output reports
```

---

## 5. Step-by-Step Walkthrough: Testing NIST CFReDS Hacking Case

Here is an end-to-end example you can demonstrate during an interview:

### Step 1: Download a Sample Dataset
Visit [https://cfreds-archive.nist.gov/](https://cfreds-archive.nist.gov/) and select a test case (e.g. *Hacking Case* or *File Deletion Challenge*), or download a Govdocs1 slice from [Digital Corpora](https://digitalcorpora.org/corpora/files).

### Step 2: Extract to a Local Folder
Extract the archive into your working directory (e.g., `D:\evidence\nist_test`).

### Step 3: Run DEFA Forensic Scan
Open DEFA 2.0 at `http://127.0.0.1:8000`, click **New Scan**, and enter `D:\evidence\nist_test` (or run in CLI):
```powershell
python main.py scan D:\evidence\nist_test --output reports
```

### Step 4: Examine Evidence in the Dashboard
1. **Overview:** View total evidence volume, files analyzed, and extension distribution.
2. **Evidence Explorer:** Filter by `.exe` or `.pdf`, sort by file size to identify anomalous items.
3. **Forensic Findings:** Inspect flagged items (e.g. extension mismatches, hidden files, duplicate files).
4. **Duplicate Analysis:** Identify redundant files staged in multiple directories.
5. **AI Assistant:** Ask:
   - *"Summarize this evidence collection."*
   - *"Which files are duplicates, and what storage do they consume?"*
   - *"What are the most significant forensic findings in this dataset?"*

### Step 5: Establish Baseline & Verify Integrity
```powershell
# Verify that evidence has remained untouched:
python main.py verify D:\evidence\nist_test --baseline reports/baseline.json
```
Result confirms 100% file integrity (`Unchanged: 100%`).

---

## 6. Synthetic Benchmark Verification (Built-in)

If you do not have an internet connection to download multi-gigabyte forensic images, you can run DEFA's **built-in 12-step validation benchmark**:

```powershell
python main.py benchmark
```

This automatically generates synthetic evidence, computes SHA-256 hashes, creates a baseline, introduces modifications, additions, and deletions, and validates that DEFA detects all variations with **100% precision**.

