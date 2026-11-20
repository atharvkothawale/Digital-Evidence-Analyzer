/**
 * DEFA — Digital Evidence Forensics & Investigation System
 * Frontend Application Controller
 * Vanilla JS, lightweight, responsive, zero external framework dependencies.
 */

// Global State
const state = {
  currentTab: 'overview',
  activeScan: null,
  activeVerification: null,
  activeFindings: [],
  findingsFilter: 'all',
  stagedEvidence: [],
  investigationPollingInterval: null,
  aiStatus: { online: false, version: null, current_model: 'llama3.2', installed_models: [] },
  chatMessages: [],
  fileFilters: {
    search: '',
    ext: '',
    category: 'all',
    size_category: 'all',
    status: 'all',
    duplicate_only: false,
    sort_by: 'name',
    sort_order: 'asc',
  },
};

// ──────────────────────────────────────────────
// Initialization
// ──────────────────────────────────────────────

document.addEventListener('DOMContentLoaded', () => {
  setupNavigation();
  setupEventListeners();
  loadInitialData();
});

function setupNavigation() {
  const navLinks = document.querySelectorAll('.nav-link');
  navLinks.forEach(link => {
    link.addEventListener('click', e => {
      e.preventDefault();
      const targetTab = link.getAttribute('data-tab');
      switchTab(targetTab);
    });
  });

  const validTabs = ['overview', 'files', 'findings', 'duplicates', 'verification', 'reports', 'ai', 'benchmark', 'history', 'settings'];
  const initialHash = window.location.hash.replace('#', '');
  if (validTabs.includes(initialHash)) {
    switchTab(initialHash);
  } else {
    switchTab('overview');
  }
}

function switchTab(tabId) {
  state.currentTab = tabId;
  window.location.hash = tabId;

  document.querySelectorAll('.nav-link').forEach(link => {
    if (link.getAttribute('data-tab') === tabId) {
      link.classList.add('active');
    } else {
      link.classList.remove('active');
    }
  });

  document.querySelectorAll('.tab-pane').forEach(pane => {
    pane.classList.remove('active');
  });
  const activePane = document.getElementById(`tab-${tabId}`);
  if (activePane) {
    activePane.classList.add('active');
  }

  if (tabId === 'files') {
    loadFiles();
  } else if (tabId === 'findings') {
    loadFindings();
  } else if (tabId === 'duplicates') {
    loadDuplicates();
  } else if (tabId === 'verification') {
    loadVerification();
  } else if (tabId === 'history') {
    loadHistory();
  } else if (tabId === 'ai') {
    checkAIStatus();
  }
}

function setupEventListeners() {
  // Evidence Selection Modal
  const openScanBtn = document.getElementById('btn-open-scan-modal');
  const closeScanBtn = document.getElementById('btn-close-scan-modal');
  const cancelScanBtn = document.getElementById('btn-cancel-scan-modal');
  const scanModal = document.getElementById('scan-modal');

  if (openScanBtn && scanModal) {
    openScanBtn.addEventListener('click', () => {
      scanModal.classList.add('active');
      if (state.stagedEvidence.length === 0) {
        // Pre-load sample data if nothing is staged yet
        loadSamplePreset(false);
      }
    });
  }
  if (closeScanBtn && scanModal) {
    closeScanBtn.addEventListener('click', () => scanModal.classList.remove('active'));
  }
  if (cancelScanBtn && scanModal) {
    cancelScanBtn.addEventListener('click', () => scanModal.classList.remove('active'));
  }

  // Dynamic selection buttons
  const pickFolderBtn = document.getElementById('btn-pick-folder');
  if (pickFolderBtn) {
    pickFolderBtn.addEventListener('click', pickNativeFolder);
  }

  const pickFilesBtn = document.getElementById('btn-pick-files');
  if (pickFilesBtn) {
    pickFilesBtn.addEventListener('click', pickNativeFiles);
  }

  const addManualPathBtn = document.getElementById('btn-add-manual-path');
  const manualPathInput = document.getElementById('manual-path-input');
  if (addManualPathBtn) {
    addManualPathBtn.addEventListener('click', addManualPath);
  }
  if (manualPathInput) {
    manualPathInput.addEventListener('keydown', e => {
      if (e.key === 'Enter') {
        e.preventDefault();
        addManualPath();
      }
    });
  }

  const sampleDataPresetBtn = document.getElementById('btn-preset-sample');
  if (sampleDataPresetBtn) {
    sampleDataPresetBtn.addEventListener('click', () => loadSamplePreset(true));
  }

  const clearStagedBtn = document.getElementById('btn-clear-staged');
  if (clearStagedBtn) {
    clearStagedBtn.addEventListener('click', clearStagedEvidence);
  }

  const startInvestBtn = document.getElementById('btn-start-investigation');
  if (startInvestBtn) {
    startInvestBtn.addEventListener('click', startDynamicInvestigation);
  }

  // File detail modal close
  const closeDetailBtn = document.getElementById('btn-close-detail-modal');
  const detailModal = document.getElementById('file-detail-modal');
  if (closeDetailBtn && detailModal) {
    closeDetailBtn.addEventListener('click', () => detailModal.classList.remove('active'));
  }

  // File explorer filters
  const fileSearchInput = document.getElementById('file-search-input');
  if (fileSearchInput) {
    fileSearchInput.addEventListener('input', debounce(() => {
      state.fileFilters.search = fileSearchInput.value.trim();
      loadFiles();
    }, 250));
  }

  const categorySelect = document.getElementById('file-category-select');
  if (categorySelect) {
    categorySelect.addEventListener('change', () => {
      state.fileFilters.category = categorySelect.value;
      loadFiles();
    });
  }

  const sizeSelect = document.getElementById('file-size-select');
  if (sizeSelect) {
    sizeSelect.addEventListener('change', () => {
      state.fileFilters.size_category = sizeSelect.value;
      loadFiles();
    });
  }

  const statusSelect = document.getElementById('file-status-select');
  if (statusSelect) {
    statusSelect.addEventListener('change', () => {
      state.fileFilters.status = statusSelect.value;
      loadFiles();
    });
  }

  const duplicateOnlyCheckbox = document.getElementById('file-duplicate-toggle');
  if (duplicateOnlyCheckbox) {
    duplicateOnlyCheckbox.addEventListener('change', () => {
      state.fileFilters.duplicate_only = duplicateOnlyCheckbox.checked;
      loadFiles();
    });
  }

  const sortSelect = document.getElementById('file-sort-select');
  if (sortSelect) {
    sortSelect.addEventListener('change', () => {
      const [by, order] = sortSelect.value.split(':');
      state.fileFilters.sort_by = by;
      state.fileFilters.sort_order = order;
      loadFiles();
    });
  }

  // Verification button
  const runVerifyBtn = document.getElementById('btn-run-verify');
  if (runVerifyBtn) {
    runVerifyBtn.addEventListener('click', executeVerification);
  }

  // AI chat input
  const chatInput = document.getElementById('chat-input-text');
  const chatSendBtn = document.getElementById('btn-chat-send');
  const chatClearBtn = document.getElementById('btn-chat-clear');

  if (chatSendBtn && chatInput) {
    chatSendBtn.addEventListener('click', sendUserChatMessage);
    chatInput.addEventListener('keydown', e => {
      if (e.key === 'Enter' && !e.shiftKey) {
        e.preventDefault();
        sendUserChatMessage();
      }
    });
  }

  if (chatClearBtn) {
    chatClearBtn.addEventListener('click', clearChat);
  }

  // AI Prompt Chips
  document.querySelectorAll('.prompt-chip').forEach(chip => {
    chip.addEventListener('click', () => {
      const prompt = chip.getAttribute('data-prompt');
      if (prompt && chatInput) {
        chatInput.value = prompt;
        sendUserChatMessage();
      }
    });
  });

  // Settings Save & Test
  const saveSettingsBtn = document.getElementById('btn-save-settings');
  if (saveSettingsBtn) {
    saveSettingsBtn.addEventListener('click', saveSettings);
  }
  const testOllamaBtn = document.getElementById('btn-test-ollama');
  if (testOllamaBtn) {
    testOllamaBtn.addEventListener('click', testOllamaConnection);
  }
}

// ──────────────────────────────────────────────
// API Calls & Data Loading
// ──────────────────────────────────────────────

async function loadInitialData() {
  await checkHealth();
  await checkAIStatus();
  await loadOverview();
  await loadFindings();
}

async function checkHealth() {
  try {
    const res = await fetch('/api/health');
    const data = await res.json();
    document.getElementById('app-version-badge').textContent = `v${data.version}`;
  } catch (err) {
    console.warn('Could not contact API health endpoint:', err);
  }
}

async function checkAIStatus() {
  try {
    const res = await fetch('/api/ai/status');
    const data = await res.json();
    state.aiStatus = data;

    const dot = document.getElementById('ai-status-dot');
    const text = document.getElementById('ai-status-text');
    const modelSelect = document.getElementById('ai-model-select');
    const offlineNotice = document.getElementById('ai-offline-notice');

    if (data.online) {
      dot.className = 'status-dot online';
      text.textContent = `AI Online (${data.current_model})`;
      if (offlineNotice) offlineNotice.style.display = 'none';

      if (modelSelect && data.installed_models && data.installed_models.length > 0) {
        modelSelect.innerHTML = '';
        data.installed_models.forEach(m => {
          const opt = document.createElement('option');
          opt.value = m;
          opt.textContent = m;
          if (m.includes(data.current_model) || m === data.current_model) opt.selected = true;
          modelSelect.appendChild(opt);
        });
      }
    } else {
      dot.className = 'status-dot offline';
      text.textContent = 'AI Offline (Ollama)';
      if (offlineNotice) offlineNotice.style.display = 'block';
    }
  } catch (err) {
    console.warn('AI status check failed:', err);
  }
}

async function loadOverview() {
  try {
    const res = await fetch('/api/scan/latest');
    if (!res.ok) {
      document.getElementById('overview-empty-state').style.display = 'block';
      document.getElementById('overview-content').style.display = 'none';
      return;
    }
    const data = await res.json();
    state.activeScan = data;

    document.getElementById('overview-empty-state').style.display = 'none';
    document.getElementById('overview-content').style.display = 'block';

    const dirIndicator = document.getElementById('top-dir-indicator');
    if (dirIndicator) {
      dirIndicator.textContent = `📁 ${data.directory || 'Unknown'}`;
      dirIndicator.title = data.directory || '';
    }

    document.getElementById('metric-total-files').textContent = data.total_files || 0;
    document.getElementById('metric-folders-sub').textContent = `${data.total_folders || 0} subdirectories traversed`;

    document.getElementById('metric-hashed-ok').textContent = data.hashed_successfully || 0;
    document.getElementById('metric-failed').textContent = data.hash_failed || 0;
    document.getElementById('metric-dup-groups').textContent = data.duplicate_groups || 0;
    document.getElementById('metric-dup-files-sub').textContent = `${data.duplicate_files || 0} identical files`;

    const totalBytes = (data.files || []).reduce((acc, f) => acc + (f.size_bytes || 0), 0);
    document.getElementById('metric-total-size').textContent = formatBytes(totalBytes);

    const perf = data.performance || {};
    if (perf.throughput_mb_per_second) {
      document.getElementById('metric-throughput-sub').textContent = `${perf.throughput_mb_per_second} MB/s (${perf.files_per_second} files/s)`;
    }

    const findings = data.findings || [];
    document.getElementById('metric-findings-count').textContent = findings.length;
    const highCount = findings.filter(f => f.severity === 'High').length;
    document.getElementById('metric-findings-high-sub').textContent = `${highCount} high severity leads`;

    renderExtensionChart(data.files || []);
    renderSizeDistribution(data.files || []);
    renderLargestFiles(data.files || []);
  } catch (err) {
    console.error('Error loading overview:', err);
  }
}

function renderExtensionChart(files) {
  const chartContainer = document.getElementById('ext-chart-container');
  if (!chartContainer) return;

  const counts = {};
  files.forEach(f => {
    const ext = f.extension || '(none)';
    counts[ext] = (counts[ext] || 0) + 1;
  });

  const sorted = Object.entries(counts).sort((a, b) => b[1] - a[1]);
  const max = sorted[0] ? sorted[0][1] : 1;

  let html = '';
  sorted.slice(0, 8).forEach(([ext, count]) => {
    const pct = Math.round((count / max) * 100);
    html += `
      <div class="chart-bar-row">
        <span class="chart-label" title="${ext}">${ext}</span>
        <div class="chart-track">
          <div class="chart-fill" style="width: ${pct}%"></div>
        </div>
        <span class="chart-val">${count}</span>
      </div>
    `;
  });
  chartContainer.innerHTML = html || '<p class="text-muted">No files scanned.</p>';
}

function renderSizeDistribution(files) {
  const container = document.getElementById('size-dist-container');
  if (!container) return;

  const buckets = {
    '< 10 KB': 0,
    '10 KB - 1 MB': 0,
    '1 MB - 50 MB': 0,
    '> 50 MB': 0,
  };

  files.forEach(f => {
    const sz = f.size_bytes || 0;
    if (sz < 10240) buckets['< 10 KB']++;
    else if (sz < 1048576) buckets['10 KB - 1 MB']++;
    else if (sz < 52428800) buckets['1 MB - 50 MB']++;
    else buckets['> 50 MB']++;
  });

  const max = Math.max(...Object.values(buckets), 1);
  let html = '';
  Object.entries(buckets).forEach(([label, count]) => {
    const pct = Math.round((count / max) * 100);
    html += `
      <div class="chart-bar-row">
        <span class="chart-label">${label}</span>
        <div class="chart-track">
          <div class="chart-fill" style="width: ${pct}%; background-color: var(--accent-purple);"></div>
        </div>
        <span class="chart-val">${count}</span>
      </div>
    `;
  });
  container.innerHTML = html;
}

function renderLargestFiles(files) {
  const tbody = document.getElementById('largest-files-tbody');
  if (!tbody) return;

  const sorted = [...files].sort((a, b) => (b.size_bytes || 0) - (a.size_bytes || 0)).slice(0, 5);
  let html = '';
  sorted.forEach(f => {
    html += `
      <tr class="table-row-clickable" onclick="openFileDetail('${escapeQuotes(f.relative_path)}')">
        <td class="mono">${f.relative_path}</td>
        <td class="mono">${formatBytes(f.size_bytes || 0)}</td>
        <td class="mono">${(f.sha256 || 'N/A').substring(0, 16)}...</td>
      </tr>
    `;
  });
  tbody.innerHTML = html || '<tr><td colspan="3">No files found.</td></tr>';
}

// ──────────────────────────────────────────────
// Evidence File Explorer
// ──────────────────────────────────────────────

async function loadFiles() {
  const tbody = document.getElementById('files-table-tbody');
  if (!tbody) return;

  tbody.innerHTML = '<tr><td colspan="6" style="text-align: center; padding: 2rem;">Loading evidence files...</td></tr>';

  const params = new URLSearchParams({
    search: state.fileFilters.search,
    category: state.fileFilters.category,
    size_category: state.fileFilters.size_category,
    status: state.fileFilters.status,
    duplicate_only: state.fileFilters.duplicate_only,
    sort_by: state.fileFilters.sort_by,
    sort_order: state.fileFilters.sort_order,
    limit: 200,
  });

  try {
    const res = await fetch(`/api/files?${params.toString()}`);
    const data = await res.json();

    document.getElementById('files-count-badge').textContent = `Showing ${data.files.length} of ${data.total} files`;

    if (!data.files || data.files.length === 0) {
      tbody.innerHTML = '<tr><td colspan="6" style="text-align: center; padding: 2rem; color: var(--text-muted);">No matching evidence files found.</td></tr>';
      return;
    }

    let html = '';
    data.files.forEach(f => {
      const isDup = f.is_duplicate;
      const dupBadge = isDup ? '<span class="badge badge-warning" style="margin-left: 0.35rem;">Duplicate</span>' : '';
      const statusBadge = f.scan_status === 'hashed'
        ? '<span class="badge badge-success">Hashed</span>'
        : '<span class="badge badge-danger">Failed</span>';

      html += `
        <tr class="table-row-clickable" onclick="openFileDetail('${escapeQuotes(f.relative_path)}')">
          <td><span class="badge badge-info">${f.extension || '—'}</span></td>
          <td class="mono">
            <strong>${f.name}</strong>
            <div style="font-size: 0.75rem; color: var(--text-muted);">${f.relative_path}</div>
          </td>
          <td class="mono">${formatBytes(f.size_bytes || 0)}</td>
          <td class="mono">
            ${(f.sha256 || 'N/A').substring(0, 18)}...
            <button class="copy-btn" onclick="copyHash(event, '${f.sha256}')" title="Copy SHA-256">📋</button>
          </td>
          <td class="mono" style="font-size: 0.78rem;">${formatDate(f.modified_at)}</td>
          <td>${statusBadge} ${dupBadge}</td>
        </tr>
      `;
    });
    tbody.innerHTML = html;
  } catch (err) {
    console.error('Error fetching files:', err);
    tbody.innerHTML = '<tr><td colspan="6" style="color: var(--accent-red);">Error loading file list.</td></tr>';
  }
}

async function openFileDetail(relativePath) {
  try {
    const res = await fetch(`/api/files/detail?path=${encodeURIComponent(relativePath)}`);
    if (!res.ok) return;
    const f = await res.json();

    document.getElementById('modal-file-name').textContent = f.name;
    document.getElementById('modal-rel-path').textContent = f.relative_path;
    document.getElementById('modal-abs-path').textContent = f.absolute_path;
    document.getElementById('modal-size').textContent = `${formatBytes(f.size_bytes)} (${f.size_bytes.toLocaleString()} bytes)`;
    document.getElementById('modal-sha256').textContent = f.sha256 || 'N/A';
    document.getElementById('modal-created').textContent = formatDate(f.created_at);
    document.getElementById('modal-modified').textContent = formatDate(f.modified_at);
    document.getElementById('modal-status').textContent = f.scan_status;

    // Duplicate info
    const dupContainer = document.getElementById('modal-duplicate-info');
    if (f.duplicate_info) {
      dupContainer.innerHTML = `
        <div class="callout callout-warning" style="margin-top: 0.5rem;">
          <div>
            <strong>Identical file detected (Group #${f.duplicate_info.group_number})</strong>
            <p style="font-size: 0.8rem; margin-top: 0.2rem;">Other copies sharing this exact SHA-256:</p>
            <ul style="font-family: var(--font-mono); font-size: 0.8rem; margin: 0.3rem 0 0 1.2rem;">
              ${f.duplicate_info.other_copies.map(p => `<li>${p}</li>`).join('')}
            </ul>
          </div>
        </div>
      `;
    } else {
      dupContainer.innerHTML = '<span class="badge badge-success">Unique file (no duplicates detected)</span>';
    }

    // Associated findings info
    const findingsContainer = document.getElementById('modal-findings-info');
    const fileFindings = f.associated_findings || [];
    if (fileFindings.length > 0) {
      findingsContainer.innerHTML = fileFindings.map(find => `
        <div style="background: rgba(210, 153, 34, 0.1); border-left: 3px solid var(--accent-amber); padding: 0.5rem 0.75rem; margin-bottom: 0.4rem; border-radius: 4px; font-size: 0.8rem;">
          <strong>[${find.severity}] ${find.title}</strong>
          <div style="color: var(--text-muted); margin-top: 0.2rem;">${find.reason}</div>
          <div style="color: var(--accent-blue); margin-top: 0.2rem;">Action: ${find.recommended_action}</div>
        </div>
      `).join('');
    } else {
      findingsContainer.innerHTML = '<span class="text-muted" style="font-size: 0.8rem;">No anomalies flagged for this item.</span>';
    }

    const copyBtn = document.getElementById('btn-modal-copy-hash');
    if (copyBtn) {
      copyBtn.onclick = (e) => copyHash(e, f.sha256);
    }

    document.getElementById('file-detail-modal').classList.add('active');
  } catch (err) {
    console.error('Error opening file detail:', err);
  }
}

// ──────────────────────────────────────────────
// Forensic Findings Engine
// ──────────────────────────────────────────────

async function loadFindings(severity = 'all') {
  state.findingsFilter = severity;
  const container = document.getElementById('findings-cards-container');
  if (!container) return;

  container.innerHTML = '<p class="text-muted">Analyzing evidence findings...</p>';

  try {
    const res = await fetch(`/api/findings?severity=${severity}`);
    const data = await res.json();
    state.activeFindings = data.findings || [];

    if (!data.findings || data.findings.length === 0) {
      container.innerHTML = `
        <div class="panel" style="text-align: center; padding: 3rem 1rem;">
          <h3 style="color: var(--accent-green); margin-bottom: 0.5rem;">✅ No Anomalous Findings Flagged</h3>
          <p class="text-muted">No high-risk double extensions, signature mismatches, or file deviations identified in current evidence.</p>
        </div>
      `;
      return;
    }

    let html = '';
    data.findings.forEach(f => {
      let sevColor = 'var(--text-muted)';
      let sevBg = 'var(--bg-card)';
      let borderCol = 'var(--border-color)';

      if (f.severity === 'High') {
        sevColor = 'var(--accent-red)';
        borderCol = 'var(--accent-red)';
        sevBg = 'rgba(248, 81, 73, 0.1)';
      } else if (f.severity === 'Medium') {
        sevColor = 'var(--accent-amber)';
        borderCol = 'var(--accent-amber)';
        sevBg = 'rgba(210, 153, 34, 0.1)';
      } else if (f.severity === 'Low') {
        sevColor = 'var(--accent-blue)';
        borderCol = 'var(--accent-blue)';
        sevBg = 'rgba(56, 139, 253, 0.1)';
      }

      html += `
        <div class="dup-group-card" style="border-left: 4px solid ${borderCol};">
          <div class="dup-group-header">
            <div>
              <span class="badge" style="background:${sevBg}; color:${sevColor}; margin-right: 0.5rem; font-weight:700;">${f.severity.toUpperCase()}</span>
              <strong style="color: var(--text-bright);">${f.title}</strong>
              <span class="text-muted" style="margin-left: 0.5rem; font-size: 0.78rem;">(${f.id})</span>
            </div>
            <span class="mono" style="font-size: 0.8rem; color: var(--accent-blue);">📄 ${f.related_file}</span>
          </div>
          <div class="dup-group-body" style="font-size: 0.85rem; line-height: 1.6;">
            <p style="margin-bottom: 0.4rem;"><strong>Observation:</strong> ${f.description}</p>
            <p style="color: var(--text-muted); margin-bottom: 0.4rem;"><strong>Reason for Detection:</strong> ${f.reason}</p>
            <p style="color: #79c0ff;"><strong>Recommended Action:</strong> ${f.recommended_action}</p>
          </div>
        </div>
      `;
    });
    container.innerHTML = html;
  } catch (err) {
    console.error('Error fetching findings:', err);
    container.innerHTML = '<p style="color: var(--accent-red);">Error loading findings.</p>';
  }
}

function filterFindings(sev) {
  loadFindings(sev);
}

// ──────────────────────────────────────────────
// Automated Benchmark Runner
// ──────────────────────────────────────────────

async function executeBenchmark() {
  const btn = document.getElementById('btn-run-benchmark');
  btn.disabled = true;
  btn.textContent = 'Running Scientific Benchmark...';

  const container = document.getElementById('benchmark-results-container');
  container.style.display = 'block';

  try {
    const res = await fetch('/api/benchmark', { method: 'POST' });
    const data = await res.json();

    document.getElementById('bench-accuracy').textContent = `${data.accuracy_percentage}%`;
    document.getElementById('bench-throughput').textContent = `${data.metrics.throughput_mb_per_second} MB/s`;
    document.getElementById('bench-files-sec').textContent = `${data.metrics.files_per_second} files/sec`;
    document.getElementById('bench-hashing-time').textContent = `${data.hashing_duration_seconds}s`;
    document.getElementById('bench-total-time').textContent = `${data.total_benchmark_duration_seconds}s`;

    const tbody = document.getElementById('benchmark-steps-tbody');
    let html = '';
    data.steps_passed.forEach(s => {
      html += `
        <tr>
          <td class="mono">Step ${s.step}</td>
          <td>${s.description}</td>
          <td><span class="badge badge-success">PASSED</span></td>
        </tr>
      `;
    });
    data.steps_failed.forEach(s => {
      html += `
        <tr>
          <td class="mono">Step ${s.step}</td>
          <td>${s.description}</td>
          <td><span class="badge badge-danger">FAILED</span></td>
        </tr>
      `;
    });
    tbody.innerHTML = html;
  } catch (err) {
    alert(`Benchmark error: ${err}`);
  } finally {
    btn.disabled = false;
    btn.textContent = 'Run Automated Benchmark';
  }
}

// ──────────────────────────────────────────────
// Custom PDF Export
// ──────────────────────────────────────────────

function downloadCustomPdf() {
  const caseName = encodeURIComponent(document.getElementById('report-case-name').value.trim() || 'CASE-2026-DEMO-001');
  const investigator = encodeURIComponent(document.getElementById('report-investigator').value.trim() || 'Digital Forensic Examiner');
  window.location.href = `/api/export/pdf?case=${caseName}&investigator=${investigator}`;
}

// ──────────────────────────────────────────────
// Duplicate Analysis
// ──────────────────────────────────────────────

async function loadDuplicates() {
  const container = document.getElementById('duplicates-container');
  if (!container) return;

  container.innerHTML = '<p class="text-muted">Loading duplicates...</p>';

  try {
    const res = await fetch('/api/duplicates');
    const data = await res.json();

    document.getElementById('dup-total-groups').textContent = data.total_groups || 0;
    document.getElementById('dup-total-files').textContent = data.total_duplicate_files || 0;
    document.getElementById('dup-wasted-space').textContent = formatBytes(data.estimated_wasted_bytes || 0);

    if (!data.duplicate_groups || data.duplicate_groups.length === 0) {
      container.innerHTML = `
        <div class="panel" style="text-align: center; padding: 3rem 1rem;">
          <h3 style="color: var(--accent-green); margin-bottom: 0.5rem;">✅ No Duplicate Files Detected</h3>
          <p class="text-muted">All scanned evidence files possess distinct cryptographic SHA-256 signatures.</p>
        </div>
      `;
      return;
    }

    let html = '';
    data.duplicate_groups.forEach(grp => {
      html += `
        <div class="dup-group-card">
          <div class="dup-group-header">
            <div>
              <span class="badge badge-warning" style="margin-right: 0.5rem;">Group #${grp.group_id}</span>
              <strong style="color: var(--text-bright);">${grp.count} Identical Copies</strong>
              <span class="text-muted" style="margin-left: 0.75rem; font-size: 0.8rem;">(${formatBytes(grp.file_size_bytes)} each)</span>
            </div>
            <div style="display: flex; align-items: center; gap: 0.75rem;">
              <span class="mono" style="font-size: 0.8rem; color: var(--text-muted);">${(grp.sha256 || '').substring(0, 24)}...</span>
              <button class="copy-btn" onclick="copyHash(event, '${grp.sha256}')" title="Copy Full Hash">📋</button>
            </div>
          </div>
          <div class="dup-group-body">
            <p style="font-size: 0.78rem; color: var(--text-muted); margin-bottom: 0.6rem;">
              Full SHA-256: <span class="mono">${grp.sha256}</span> &nbsp;|&nbsp; Estimated duplicate space: ${formatBytes(grp.wasted_bytes)}
            </p>
            <div class="table-container">
              <table>
                <thead>
                  <tr>
                    <th>Relative File Path</th>
                    <th>Size</th>
                    <th>Modified Date</th>
                  </tr>
                </thead>
                <tbody>
                  ${grp.files.map(f => `
                    <tr>
                      <td class="mono">📄 ${f.relative_path}</td>
                      <td class="mono">${formatBytes(f.size_bytes)}</td>
                      <td class="mono" style="font-size: 0.8rem;">${formatDate(f.modified_at)}</td>
                    </tr>
                  `).join('')}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      `;
    });
    container.innerHTML = html;
  } catch (err) {
    console.error('Error fetching duplicates:', err);
    container.innerHTML = '<p style="color: var(--accent-red);">Error loading duplicate report.</p>';
  }
}

// ──────────────────────────────────────────────
// Integrity Verification
// ──────────────────────────────────────────────

async function loadVerification() {
  try {
    const res = await fetch('/api/verify/latest');
    if (!res.ok) {
      document.getElementById('verify-empty-state').style.display = 'block';
      document.getElementById('verify-results-content').style.display = 'none';
      return;
    }
    const data = await res.json();
    renderVerificationResults(data);
  } catch (err) {
    console.warn('No active verification report found:', err);
  }
}

async function executeVerification() {
  const dir = document.getElementById('verify-dir-input').value.trim() || './sample_data';
  const baseline = document.getElementById('verify-baseline-input').value.trim() || 'reports/baseline.json';
  const btn = document.getElementById('btn-run-verify');

  btn.disabled = true;
  btn.textContent = 'Verifying...';

  try {
    const res = await fetch('/api/verify', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ directory: dir, baseline_path: baseline }),
    });
    const data = await res.json();
    if (!res.ok) {
      alert(`Verification failed: ${data.detail || 'Unknown error'}`);
      return;
    }
    renderVerificationResults(data);
    await loadFindings();
  } catch (err) {
    alert(`Network error during verification: ${err}`);
  } finally {
    btn.disabled = false;
    btn.textContent = 'Run Verification';
  }
}

function renderVerificationResults(data) {
  document.getElementById('verify-empty-state').style.display = 'none';
  document.getElementById('verify-results-content').style.display = 'block';

  const summary = data.summary || {};
  document.getElementById('verif-unchanged-count').textContent = summary.unchanged || 0;
  document.getElementById('verif-new-count').textContent = summary.new || 0;
  document.getElementById('verif-missing-count').textContent = summary.missing || 0;
  document.getElementById('verif-modified-count').textContent = summary.modified || 0;

  const statusBanner = document.getElementById('verif-status-banner');
  const hasChanges = (summary.new || 0) > 0 || (summary.missing || 0) > 0 || (summary.modified || 0) > 0;
  if (hasChanges) {
    statusBanner.className = 'callout callout-warning';
    statusBanner.innerHTML = `<strong>⚠️ Integrity Deviation Detected</strong> — Directory state does not match baseline snapshot. See detailed discrepancies below.`;
  } else {
    statusBanner.className = 'callout callout-info';
    statusBanner.innerHTML = `<strong>✅ Integrity Intact</strong> — All files match the baseline snapshot exactly.`;
  }

  const modifiedTbody = document.getElementById('verif-modified-tbody');
  const modifiedList = (data.details && data.details.modified) || [];
  if (modifiedList.length > 0) {
    document.getElementById('verif-modified-section').style.display = 'block';
    let html = '';
    modifiedList.forEach(m => {
      const cur = m.current || {};
      const base = m.baseline || {};
      html += `
        <tr>
          <td class="mono"><strong>${cur.relative_path}</strong></td>
          <td class="mono" style="font-size: 0.78rem;">
            <div>Baseline: <span style="color: var(--accent-green);">${(base.sha256 || 'N/A').substring(0, 18)}...</span></div>
            <div>Current: &nbsp;<span style="color: var(--accent-amber);">${(cur.sha256 || 'N/A').substring(0, 18)}...</span></div>
          </td>
          <td class="mono">${formatBytes(base.size_bytes)} &rarr; ${formatBytes(cur.size_bytes)}</td>
        </tr>
      `;
    });
    modifiedTbody.innerHTML = html;
  } else {
    document.getElementById('verif-modified-section').style.display = 'none';
  }

  const newContainer = document.getElementById('verif-new-container');
  const newList = (data.details && data.details.new) || [];
  if (newList.length > 0) {
    document.getElementById('verif-new-section').style.display = 'block';
    newContainer.innerHTML = newList.map(f => `<div class="mono" style="padding: 0.25rem 0;">+ ${f.relative_path}</div>`).join('');
  } else {
    document.getElementById('verif-new-section').style.display = 'none';
  }

  const missingContainer = document.getElementById('verif-missing-container');
  const missingList = (data.details && data.details.missing) || [];
  if (missingList.length > 0) {
    document.getElementById('verif-missing-section').style.display = 'block';
    missingContainer.innerHTML = missingList.map(f => `<div class="mono" style="padding: 0.25rem 0; color: var(--accent-red);">- ${f.relative_path}</div>`).join('');
  } else {
    document.getElementById('verif-missing-section').style.display = 'none';
  }
}

// ──────────────────────────────────────────────
// Scan History
// ──────────────────────────────────────────────

async function loadHistory() {
  const tbody = document.getElementById('history-table-tbody');
  if (!tbody) return;

  tbody.innerHTML = '<tr><td colspan="6">Loading history...</td></tr>';

  try {
    const res = await fetch('/api/history');
    const data = await res.json();
    const history = data.history || [];

    if (history.length === 0) {
      tbody.innerHTML = '<tr><td colspan="6" style="text-align: center; color: var(--text-muted); padding: 2rem;">No scan history recorded yet.</td></tr>';
      return;
    }

    let html = '';
    history.forEach(h => {
      html += `
        <tr>
          <td class="mono" style="font-size: 0.8rem;">${formatDate(h.timestamp)}</td>
          <td class="mono">${h.directory}</td>
          <td class="mono">${h.total_files}</td>
          <td class="mono">${h.duplicate_files}</td>
          <td class="mono">${formatBytes(h.total_size_bytes || 0)}</td>
          <td>
            <span class="badge badge-success">Completed</span>
          </td>
        </tr>
      `;
    });
    tbody.innerHTML = html;
  } catch (err) {
    console.error('Error fetching history:', err);
  }
}

// ──────────────────────────────────────────────
// Local AI Assistant
// ──────────────────────────────────────────────

async function sendUserChatMessage() {
  const input = document.getElementById('chat-input-text');
  const message = input.value.trim();
  if (!message) return;

  appendChatBubble('user', message);
  state.chatMessages.push({ role: 'user', content: message });
  input.value = '';

  const typingId = appendTypingIndicator();
  const sendBtn = document.getElementById('btn-chat-send');
  sendBtn.disabled = true;

  try {
    const modelSelect = document.getElementById('ai-model-select');
    const selectedModel = modelSelect ? modelSelect.value : null;

    const res = await fetch('/api/ai/chat', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        messages: state.chatMessages,
        model: selectedModel,
      }),
    });

    removeTypingIndicator(typingId);
    const data = await res.json();

    if (!data.success) {
      appendChatBubble('assistant', `⚠️ **AI Notice:** ${data.error || 'Failed to generate response.'}`);
    } else {
      appendChatBubble('assistant', data.reply);
      state.chatMessages.push({ role: 'assistant', content: data.reply });
    }
  } catch (err) {
    removeTypingIndicator(typingId);
    appendChatBubble('assistant', `⚠️ **Network Error:** Could not contact DEFA backend (${err.message})`);
  } finally {
    sendBtn.disabled = false;
  }
}

function appendChatBubble(role, content) {
  const chatMessagesContainer = document.getElementById('chat-messages');
  if (!chatMessagesContainer) return;

  const bubble = document.createElement('div');
  bubble.className = `chat-bubble ${role}`;
  bubble.innerHTML = renderMarkdown(content);

  chatMessagesContainer.appendChild(bubble);
  chatMessagesContainer.scrollTop = chatMessagesContainer.scrollHeight;
}

function appendTypingIndicator() {
  const id = `typing-${Date.now()}`;
  const container = document.getElementById('chat-messages');
  if (!container) return id;

  const typing = document.createElement('div');
  typing.id = id;
  typing.className = 'chat-bubble assistant';
  typing.innerHTML = '<span class="text-muted">Querying evidence tools & analyzing metadata...</span>';
  container.appendChild(typing);
  container.scrollTop = container.scrollHeight;
  return id;
}

function removeTypingIndicator(id) {
  const el = document.getElementById(id);
  if (el) el.remove();
}

function clearChat() {
  state.chatMessages = [];
  const container = document.getElementById('chat-messages');
  if (container) {
    container.innerHTML = `
      <div class="chat-bubble assistant">
        <strong>DEFA Local Forensic AI Assistant</strong><br>
        Ready to analyze the active evidence scan metadata and findings engine. Ask questions regarding evidence volume, duplicate file clusters, anomalous extensions, or baseline deviations.
      </div>
    `;
  }
}

// ──────────────────────────────────────────────
// Dynamic Evidence Selection & Real-Time Investigation
// ──────────────────────────────────────────────

async function pickNativeFolder() {
  const btn = document.getElementById('btn-pick-folder');
  const originalText = btn.innerHTML;
  btn.disabled = true;
  btn.innerHTML = '<span>⏳</span> Opening Folder Dialog...';

  try {
    const res = await fetch('/api/dialog/folder', { method: 'POST' });
    const data = await res.json();
    if (!data.cancelled && data.path) {
      addStagedPath(data.path);
    }
  } catch (err) {
    alert(`Error opening folder dialog: ${err}`);
  } finally {
    btn.disabled = false;
    btn.innerHTML = originalText;
  }
}

async function pickNativeFiles() {
  const btn = document.getElementById('btn-pick-files');
  const originalText = btn.innerHTML;
  btn.disabled = true;
  btn.innerHTML = '<span>⏳</span> Opening File Dialog...';

  try {
    const res = await fetch('/api/dialog/files', { method: 'POST' });
    const data = await res.json();
    if (!data.cancelled && data.paths && data.paths.length > 0) {
      data.paths.forEach(p => addStagedPath(p));
    }
  } catch (err) {
    alert(`Error opening files dialog: ${err}`);
  } finally {
    btn.disabled = false;
    btn.innerHTML = originalText;
  }
}

async function addManualPath() {
  const input = document.getElementById('manual-path-input');
  const rawPath = input.value.trim();
  if (!rawPath) {
    alert('Please enter a valid directory or file path.');
    return;
  }

  const added = addStagedPath(rawPath);
  if (added) {
    input.value = '';
  }
}

async function loadSamplePreset(notify = true) {
  const samplePath = './sample_data';
  const added = addStagedPath(samplePath);
  if (notify && !added) {
    alert('Sample data is already staged.');
  }
}

function addStagedPath(pathStr) {
  const normalized = pathStr.trim();
  if (!normalized) return false;

  // Prevent duplicate additions
  if (state.stagedEvidence.includes(normalized)) {
    alert(`'${normalized}' is already in your selected evidence list.`);
    return false;
  }

  state.stagedEvidence.push(normalized);
  previewStagedEvidence();
  return true;
}

function removeStagedItem(index) {
  if (index >= 0 && index < state.stagedEvidence.length) {
    state.stagedEvidence.splice(index, 1);
    previewStagedEvidence();
  }
}

function clearStagedEvidence() {
  state.stagedEvidence = [];
  previewStagedEvidence();
}

async function previewStagedEvidence() {
  const placeholder = document.getElementById('staged-empty-placeholder');
  const listContainer = document.getElementById('staged-list-container');
  const countBadge = document.getElementById('staged-count-badge');
  const filesBadge = document.getElementById('staged-files-badge');
  const sizeBadge = document.getElementById('staged-size-badge');
  const overlapAlert = document.getElementById('staged-overlap-alert');

  if (!placeholder || !listContainer) return;

  if (state.stagedEvidence.length === 0) {
    placeholder.style.display = 'block';
    listContainer.style.display = 'none';
    listContainer.innerHTML = '';
    countBadge.textContent = '0 items';
    filesBadge.textContent = '0';
    sizeBadge.textContent = '0 B';
    if (overlapAlert) overlapAlert.style.display = 'none';
    return;
  }

  placeholder.style.display = 'none';
  listContainer.style.display = 'block';
  listContainer.innerHTML = '<div style="padding: 1rem; color: var(--text-muted); font-size: 0.8rem;">Analyzing selected evidence paths...</div>';

  try {
    const res = await fetch('/api/evidence/preview', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ items: state.stagedEvidence }),
    });
    const preview = await res.json();

    countBadge.textContent = `${preview.total_items} item${preview.total_items === 1 ? '' : 's'}`;
    filesBadge.textContent = preview.total_estimated_files.toLocaleString();
    sizeBadge.textContent = formatBytes(preview.total_estimated_size_bytes);

    if (overlapAlert) {
      if (preview.warnings && preview.warnings.length > 0) {
        overlapAlert.style.display = 'block';
        overlapAlert.innerHTML = `<strong>⚠️ Overlapping Selections Detected:</strong><br>${preview.warnings.map(w => `• ${w}`).join('<br>')}`;
      } else {
        overlapAlert.style.display = 'none';
      }
    }

    let html = '';
    preview.items.forEach((item, idx) => {
      const isFolder = item.type === 'folder';
      const icon = isFolder ? '📁' : '📄';
      const typeBadge = isFolder
        ? '<span class="badge badge-info">FOLDER</span>'
        : '<span class="badge badge-purple">FILE</span>';
      const existsBadge = item.exists
        ? '<span class="badge badge-success">READY</span>'
        : '<span class="badge badge-danger">NOT FOUND</span>';

      html += `
        <div class="evidence-row-item">
          <div class="evidence-row-left">
            <span style="font-size: 1.1rem;">${icon}</span>
            <div>
              <div style="font-weight: 600; color: var(--text-bright);">${item.name} ${typeBadge} ${existsBadge}</div>
              <div class="evidence-path-text" title="${item.path}">${item.path}</div>
            </div>
          </div>
          <div class="evidence-row-right">
            <span class="mono" style="font-size: 0.78rem; color: var(--text-muted);">
              ${item.estimated_files} file${item.estimated_files === 1 ? '' : 's'} (${formatBytes(item.estimated_size_bytes)})
            </span>
            <button class="btn-secondary" style="padding: 0.2rem 0.5rem; font-size: 0.75rem; color: var(--accent-red);" onclick="removeStagedItem(${idx})" title="Remove from selection">
              ❌ Remove
            </button>
          </div>
        </div>
      `;
    });
    listContainer.innerHTML = html;
  } catch (err) {
    console.error('Error previewing evidence:', err);
    listContainer.innerHTML = `<div style="padding: 1rem; color: var(--accent-red); font-size: 0.8rem;">Error inspecting evidence: ${err}</div>`;
  }
}

async function startDynamicInvestigation() {
  if (state.stagedEvidence.length === 0) {
    alert('Please select at least one folder or file to investigate.');
    return;
  }

  const startBtn = document.getElementById('btn-start-investigation');
  startBtn.disabled = true;
  startBtn.innerHTML = '<span>⏳</span> Starting...';

  const progressBox = document.getElementById('investigation-progress-box');
  progressBox.style.display = 'block';

  // Reset progress UI
  document.getElementById('prog-bar-fill').style.width = '0%';
  document.getElementById('prog-percentage-badge').textContent = '0%';
  document.getElementById('prog-status-badge').className = 'badge badge-info';
  document.getElementById('prog-status-badge').textContent = 'DISCOVERING';
  document.getElementById('prog-current-phase').textContent = 'Phase 1: Discovering files across evidence locations...';
  document.getElementById('prog-ticker-text').textContent = 'Starting file traversal...';
  document.getElementById('prog-val-discovered').textContent = '0';
  document.getElementById('prog-val-processed').textContent = '0';
  document.getElementById('prog-val-remaining').textContent = '0';
  document.getElementById('prog-val-hashed').textContent = '0';
  document.getElementById('prog-val-failed').textContent = '0';
  document.getElementById('prog-val-throughput').textContent = '0 MB/s';

  try {
    const res = await fetch('/api/investigate/start', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        items: state.stagedEvidence,
        output_dir: 'reports',
      }),
    });
    const data = await res.json();
    if (!res.ok) {
      alert(`Could not start investigation: ${data.detail || 'Unknown error'}`);
      progressBox.style.display = 'none';
      startBtn.disabled = false;
      startBtn.innerHTML = '<span>🚀</span> Start Forensic Investigation';
      return;
    }

    // Begin polling progress
    pollInvestigationProgress();
  } catch (err) {
    alert(`Network error starting investigation: ${err}`);
    progressBox.style.display = 'none';
    startBtn.disabled = false;
    startBtn.innerHTML = '<span>🚀</span> Start Forensic Investigation';
  }
}

function pollInvestigationProgress() {
  if (state.investigationPollingInterval) {
    clearInterval(state.investigationPollingInterval);
  }

  const startBtn = document.getElementById('btn-start-investigation');

  state.investigationPollingInterval = setInterval(async () => {
    try {
      const res = await fetch('/api/investigate/progress');
      if (!res.ok) return;
      const prog = await res.json();

      const pct = prog.progress_percent || 0;
      document.getElementById('prog-bar-fill').style.width = `${pct}%`;
      document.getElementById('prog-percentage-badge').textContent = `${pct}%`;

      document.getElementById('prog-val-discovered').textContent = prog.files_discovered || 0;
      document.getElementById('prog-val-processed').textContent = prog.files_processed || 0;
      document.getElementById('prog-val-remaining').textContent = prog.files_remaining || 0;
      document.getElementById('prog-val-hashed').textContent = prog.hashed_ok || 0;
      document.getElementById('prog-val-failed').textContent = prog.hash_failed || 0;
      document.getElementById('prog-val-throughput').textContent = `${prog.throughput_mb_s || 0} MB/s`;

      if (prog.current_file) {
        document.getElementById('prog-ticker-text').textContent = prog.current_file;
      }

      if (prog.status === 'discovering') {
        document.getElementById('prog-status-badge').className = 'badge badge-info';
        document.getElementById('prog-status-badge').textContent = 'DISCOVERING';
        document.getElementById('prog-current-phase').textContent = 'Phase 1: Recursive File Discovery';
      } else if (prog.status === 'hashing') {
        document.getElementById('prog-status-badge').className = 'badge badge-warning';
        document.getElementById('prog-status-badge').textContent = 'HASHING SHA-256';
        document.getElementById('prog-current-phase').textContent = `Phase 2: Chunk-Based Hashing (${prog.files_processed} / ${prog.files_discovered})`;
      } else if (prog.status === 'analyzing') {
        document.getElementById('prog-status-badge').className = 'badge badge-purple';
        document.getElementById('prog-status-badge').textContent = 'ANALYZING';
        document.getElementById('prog-current-phase').textContent = 'Phase 3: Anomaly Detection & Reporting';
      } else if (prog.status === 'completed') {
        clearInterval(state.investigationPollingInterval);
        state.investigationPollingInterval = null;

        document.getElementById('prog-bar-fill').style.width = '100%';
        document.getElementById('prog-bar-fill').style.background = 'var(--accent-green)';
        document.getElementById('prog-percentage-badge').textContent = '100%';
        document.getElementById('prog-status-badge').className = 'badge badge-success';
        document.getElementById('prog-status-badge').textContent = 'COMPLETED';
        document.getElementById('prog-current-phase').textContent = 'Investigation Complete! All reports generated.';
        document.getElementById('prog-ticker-text').textContent = `Analyzed ${prog.files_processed} files in ${prog.duration_seconds}s (${prog.throughput_mb_s} MB/s).`;

        startBtn.disabled = false;
        startBtn.innerHTML = '<span>🚀</span> Start Another Investigation';

        // Refresh all dashboard tabs with new investigation findings
        await loadOverview();
        await loadFindings();
        if (state.currentTab === 'files') loadFiles();
        if (state.currentTab === 'duplicates') loadDuplicates();

        setTimeout(() => {
          const scanModal = document.getElementById('scan-modal');
          if (scanModal) scanModal.classList.remove('active');
        }, 1500);
      } else if (prog.status === 'error') {
        clearInterval(state.investigationPollingInterval);
        state.investigationPollingInterval = null;

        document.getElementById('prog-status-badge').className = 'badge badge-danger';
        document.getElementById('prog-status-badge').textContent = 'ERROR';
        document.getElementById('prog-current-phase').textContent = `Failed: ${prog.error || 'Unknown error'}`;
        startBtn.disabled = false;
        startBtn.innerHTML = '<span>🚀</span> Retry Investigation';
      }
    } catch (err) {
      console.warn('Progress poll error:', err);
    }
  }, 250);
}

// ──────────────────────────────────────────────
// Settings
// ──────────────────────────────────────────────

async function saveSettings() {
  const ollamaUrl = document.getElementById('setting-ollama-url').value.trim();
  const defaultModel = document.getElementById('setting-default-model').value.trim();
  const aiEnabled = document.getElementById('setting-ai-enabled').checked;

  try {
    const res = await fetch('/api/settings', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        ollama_url: ollamaUrl,
        default_model: defaultModel,
        ai_enabled: aiEnabled,
      }),
    });
    if (res.ok) {
      alert('Settings saved successfully.');
      checkAIStatus();
    }
  } catch (err) {
    alert(`Failed to save settings: ${err}`);
  }
}

async function testOllamaConnection() {
  const statusSpan = document.getElementById('ollama-test-result');
  statusSpan.textContent = 'Connecting...';
  statusSpan.style.color = 'var(--text-muted)';

  try {
    const res = await fetch('/api/ai/status');
    const data = await res.json();
    if (data.online) {
      statusSpan.textContent = `Online (Version: ${data.version})`;
      statusSpan.style.color = 'var(--accent-green)';
    } else {
      statusSpan.textContent = `Offline: ${data.error}`;
      statusSpan.style.color = 'var(--accent-amber)';
    }
  } catch (err) {
    statusSpan.textContent = `Error: ${err}`;
    statusSpan.style.color = 'var(--accent-red)';
  }
}

// ──────────────────────────────────────────────
// Helpers
// ──────────────────────────────────────────────

function copyHash(event, hashText) {
  if (event) event.stopPropagation();
  if (!hashText || hashText === 'N/A') return;
  navigator.clipboard.writeText(hashText).then(() => {
    const target = event.target;
    if (target) {
      const original = target.textContent;
      target.textContent = '✅';
      setTimeout(() => { target.textContent = original; }, 1200);
    }
  });
}

function formatBytes(bytes) {
  if (bytes === 0) return '0 B';
  if (!bytes) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + (sizes[i] || 'TB');
}

function formatDate(isoString) {
  if (!isoString) return '—';
  try {
    const d = new Date(isoString);
    return d.toISOString().replace('T', ' ').substring(0, 19) + ' UTC';
  } catch (e) {
    return isoString;
  }
}

function escapeQuotes(str) {
  if (!str) return '';
  return str.replace(/\\/g, '\\\\').replace(/'/g, "\\'");
}

function debounce(fn, ms) {
  let timer;
  return function (...args) {
    clearTimeout(timer);
    timer = setTimeout(() => fn.apply(this, args), ms);
  };
}

function renderMarkdown(text) {
  if (!text) return '';
  let escaped = text
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;');

  escaped = escaped.replace(/```([\s\S]*?)```/g, '<pre><code>$1</code></pre>');
  escaped = escaped.replace(/`([^`]+)`/g, '<code>$1</code>');
  escaped = escaped.replace(/\*\*([^*]+)\*\*/g, '<strong>$1</strong>');
  escaped = escaped.replace(/\n/g, '<br>');
  return escaped;
}
