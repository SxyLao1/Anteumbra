/* Trident v1.9.1: scanner module */
// All functions intentionally global — HTML onclick handlers depend on them
/* ============================================================
   v1.9.0: Manual Scanner (defined globally — innerHTML doesn't exec <script>)
   ============================================================ */

var _scanSSE = null;
var _scanFindings = [];
var _scanResultsTab = 'new';
var _scanStartTime = 0;
var _scanComplete = false;
var _scanLastId = '';
var _scanJobId = '';
var _scanSelected = new Set();
var _scanQuarantined = new Set();

function startScan() {
  var dir = document.getElementById('scan-target-dir');
  if (!dir) return;
  dir = dir.value.trim();
  if (!dir) { alert('Please enter a target directory.'); return; }

  var recursive = document.getElementById('scan-recursive')?.checked ? '1' : '0';
  var extensions = document.getElementById('scan-extensions')?.value?.trim() || '';

  // Reset state
  _scanFindings = [];
  _scanComplete = false;
  _scanJobId = '';
  _scanStartTime = Date.now();
  var tbody = document.getElementById('results-tbody');
  if (tbody) tbody.innerHTML = '';

  // Show/hide cards
  var configCard = document.getElementById('scan-config-card');
  var progressCard = document.getElementById('scan-progress-card');
  var resultsCard = document.getElementById('scan-results-card');
  var reportBtn = document.getElementById('scan-report-btn');
  if (configCard) configCard.style.display = 'none';
  if (progressCard) progressCard.style.display = 'flex';
  if (resultsCard) resultsCard.style.display = 'none';
  if (reportBtn) reportBtn.style.display = 'none';

  // Reset stats
  ['stat-new','stat-known','stat-clean','stat-errors'].forEach(function(id) {
    var el = document.getElementById(id); if (el) el.textContent = '0';
  });
  ['tab-new-count','tab-known-count','tab-all-count'].forEach(function(id) {
    var el = document.getElementById(id); if (el) el.textContent = '0';
  });
  document.getElementById('scan-progress-bar')?.style && (document.getElementById('scan-progress-bar').style.width = '0%');
  var pt = document.getElementById('scan-progress-text'); if (pt) pt.textContent = '0 / ?';

  var csrf = document.querySelector('meta[name="csrf-token"]');
  var csrfToken = csrf ? csrf.content : '';
  var body = 'target_dir=' + encodeURIComponent(dir)
          + '&recursive=' + recursive
          + '&extensions=' + encodeURIComponent(extensions);

  fetch('/admin/scanner/run', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'X-CSRFToken': csrfToken },
    body: body
  })
  .then(function(r) {
    return r.json().then(function(d) {
      if (!r.ok || !d.success) throw new Error(d.error || ('HTTP ' + r.status));
      return d;
    });
  })
  .then(function(d) {
    _scanJobId = d.scan_id;
    _scanSSE = new EventSource(d.stream_url, { withCredentials: true });

    _scanSSE.onmessage = function(event) {
      try { var data = JSON.parse(event.data); handleScanEvent(data); }
      catch(e) { console.error('SSE parse error:', e); }
    };

    _scanSSE.onerror = function() {
      if (!_scanComplete) {
        var tb = document.getElementById('results-tbody');
        if (tb) tb.innerHTML += '<tr><td colspan="7" style="color:#ff4444;padding:12px;">SSE connection lost.</td></tr>';
      }
      if (_scanSSE) { _scanSSE.close(); _scanSSE = null; }
    };
  })
  .catch(function(e) {
    var tb = document.getElementById('results-tbody');
    if (tb) tb.innerHTML = '<tr><td colspan="7" style="color:#ff4444;padding:12px;">Start failed: ' + _escHtml(e.message) + '</td></tr>';
  });
}

function handleScanEvent(data) {
  switch (data.event) {
    case 'init':
      var pt = document.getElementById('scan-progress-text');
      if (pt) pt.textContent = '0 / ' + (data.total_files || '?');
      break;
    case 'progress':
      var pct = data.total > 0 ? Math.round(data.scanned / data.total * 100) : 0;
      var pb = document.getElementById('scan-progress-bar');
      if (pb) pb.style.width = pct + '%';
      var pt2 = document.getElementById('scan-progress-text');
      if (pt2) pt2.textContent = data.scanned + ' / ' + data.total;
      var el = document.getElementById('scan-elapsed');
      if (el) el.textContent = Math.round((Date.now() - _scanStartTime) / 1000) + 's';
      var sn = document.getElementById('stat-new'); if (sn) sn.textContent = data.new_findings || 0;
      var sk = document.getElementById('stat-known'); if (sk) sk.textContent = data.known_findings || 0;
      var sc = document.getElementById('stat-clean'); if (sc) sc.textContent = data.clean || 0;
      var se = document.getElementById('stat-errors'); if (se) se.textContent = data.errors || 0;
      break;
    case 'finding':
      _scanFindings.push(data);
      addResultRow(data);
      updateResultCounts();
      break;
    case 'complete':
      _scanComplete = true;
      _scanLastId = data.scan_id;
      var pb2 = document.getElementById('scan-progress-bar');
      if (pb2) pb2.style.width = '100%';
      var pt3 = document.getElementById('scan-progress-text');
      if (pt3) pt3.textContent = data.scanned_files + ' / ' + data.total_files;
      var el2 = document.getElementById('scan-elapsed');
      if (el2) el2.textContent = data.duration + 's';
      var sn2 = document.getElementById('stat-new'); if (sn2) sn2.textContent = data.new_findings;
      var sk2 = document.getElementById('stat-known'); if (sk2) sk2.textContent = data.known_findings;
      var sc2 = document.getElementById('stat-clean'); if (sc2) sc2.textContent = data.clean;
      var se2 = document.getElementById('stat-errors'); if (se2) se2.textContent = data.errors;
      if (data.new_findings > 0 || data.known_findings > 0) {
        var rb = document.getElementById('scan-report-btn');
        if (rb) rb.style.display = '';
      }
      if (_scanSSE) { _scanSSE.close(); _scanSSE = null; }
      break;
    case 'error':
      var tb2 = document.getElementById('results-tbody');
      if (tb2) tb2.innerHTML += '<tr><td colspan="6" style="color:#ff4444;padding:12px;">Error: ' + (data.message || 'Unknown') + '</td></tr>';
      if (_scanSSE) { _scanSSE.close(); _scanSSE = null; }
      break;
  }
}

function addResultRow(finding) {
  var resultsCard = document.getElementById('scan-results-card');
  if (resultsCard && resultsCard.style.display === 'none') resultsCard.style.display = 'flex';

  var isNew = finding.classification === 'new';
  var isQuarantined = !!finding.quarantine_id;
  var rowClass = isNew ? 'result-new' : 'result-known';
  var esc = _escJs;

  // v2.0: Show quarantine status instead of New/Known classification
  var qStatusHtml;
  if (isQuarantined) {
    qStatusHtml = '<span class="badge badge-success" style="font-size:9px;">Quarantined</span>';
  } else if (finding.quarantine_id) {
    qStatusHtml = '<span class="badge badge-warning" style="font-size:9px;">Q: ' + _escHtml(finding.quarantine_id.substring(0, 10)) + '</span>';
  } else {
    qStatusHtml = '<span style="color:#ff4444;font-size:9px;">Active</span>';
  }

  var actions = '<span style="display:inline-flex;gap:3px;white-space:nowrap;">'
    + '<button class="btn btn-ghost btn-sm" style="font-size:9px;padding:2px 5px;" onclick="openFileViewerByPath(\'' + esc(finding.file_path) + '\')">View</button>'
    + '</span>';

  var row = '<tr class="' + rowClass + '" data-file-path="' + _escHtml(finding.file_path) + '" style="border-bottom:1px solid #111;">'
    + '<td style="padding:3px 6px;text-align:center;"><input type="checkbox" class="scan-cb" data-file-path="' + _escHtml(finding.file_path) + '" onchange="scanUpdateSel()" onclick="event.stopPropagation()"></td>'
    + '<td style="padding:3px 8px;"><code style="color:#ccc;font-size:10px;">' + _escHtml(finding.file_name) + '</code></td>'
    + '<td style="padding:3px 8px;color:#555;font-size:9px;max-width:180px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;" title="' + _escHtml(finding.file_path) + '">' + _escHtml(finding.file_path) + '</td>'
    + '<td style="padding:3px 8px;color:#888;font-size:10px;">' + _escHtml(finding.engine || '') + '</td>'
    + '<td style="padding:3px 8px;font-size:10px;">' + (finding.features || []).map(function(f) { return '<span class="badge badge-blue">' + _escHtml(f) + '</span>'; }).join(' ') + '</td>'
    + '<td style="padding:3px 8px;text-align:center;">' + qStatusHtml + '</td>'
    + '<td style="padding:3px 8px;text-align:right;white-space:nowrap;">' + actions + '</td>'
    + '</tr>';

  var tbody = document.getElementById('results-tbody');
  if (tbody) tbody.insertAdjacentHTML('beforeend', row);
  applyTabFilter();
}

function switchResultsTab(tab) {
  _scanResultsTab = tab;
  ['tab-new','tab-known','tab-all'].forEach(function(id) {
    var el = document.getElementById(id);
    if (el) { el.style.color = '#888'; el.style.borderBottomColor = 'transparent'; }
  });
  var active = document.getElementById('tab-' + tab);
  if (active) { active.style.color = '#00ff41'; active.style.borderBottom = '2px solid #00ff41'; }
  applyTabFilter();
}

function applyTabFilter() {
  var rows = document.querySelectorAll('#results-tbody tr');
  rows.forEach(function(row) {
    if (_scanResultsTab === 'all') { row.style.display = ''; return; }
    if (_scanResultsTab === 'new' && row.classList.contains('result-new')) row.style.display = '';
    else if (_scanResultsTab === 'known' && row.classList.contains('result-known')) row.style.display = '';
    else row.style.display = 'none';
  });
}

function updateResultCounts() {
  var newCount = _scanFindings.filter(function(f) { return f.classification === 'new'; }).length;
  var knownCount = _scanFindings.filter(function(f) { return f.classification === 'known'; }).length;
  var nc = document.getElementById('tab-new-count'); if (nc) nc.textContent = newCount;
  var kc = document.getElementById('tab-known-count'); if (kc) kc.textContent = knownCount;
  var ac = document.getElementById('tab-all-count'); if (ac) ac.textContent = _scanFindings.length;
}

function quarantineScanFile(filePath, btn) {
  if (!confirm('Quarantine ' + filePath.split(/[\\/]/).pop() + '?')) return;
  var csrf = document.querySelector('meta[name="csrf-token"]');
  var token = csrf ? csrf.content : '';
  fetch('/admin/scanner/quarantine', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'X-CSRFToken': token },
    body: 'file_path=' + encodeURIComponent(filePath)
  })
  .then(function(r) {
    if (!r.ok) {
      return r.json().then(function(d) { throw new Error(d.error || 'HTTP ' + r.status); })
        .catch(function() { throw new Error('Server error: HTTP ' + r.status); });
    }
    return r.json();
  })
  .then(function(d) {
    if (d.success) {
      btn.outerHTML = '<span class="badge badge-success" style="font-size:9px;">Quarantined</span>';
    } else {
      alert('Quarantine failed: ' + (d.error || 'unknown'));
    }
  })
  .catch(function(e) {
    alert('Quarantine failed: ' + e.message);
  });
}

function stopScan() {
  if (_scanSSE) { _scanSSE.close(); _scanSSE = null; }
  var csrf = document.querySelector('meta[name="csrf-token"]');
  var token = csrf ? csrf.content : '';
  fetch('/admin/scanner/cancel', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'X-CSRFToken': token },
    body: _scanJobId ? 'scan_id=' + encodeURIComponent(_scanJobId) : ''
  });
  var pt = document.getElementById('scan-progress-text');
  if (pt) pt.textContent = 'Stopped';
}

function generateReport() {
  if (_scanLastId) window.open('/admin/scanner/report?scan_id=' + _scanLastId, '_blank');
}

function loadScanHistory() {
  var el = document.getElementById('scan-history-list');
  if (!el) return;
  el.innerHTML = '<div class="empty-state"><div class="spinner"></div><p>Loading history...</p></div>';
  fetch('/admin/scanner/history')
    .then(function(r) { return r.json(); })
    .then(function(d) {
      if (!d.scans || d.scans.length === 0) {
        el.innerHTML = '<p style="color:#555;text-align:center;padding:12px;">No scan history yet.</p>';
        return;
      }
      var html = '';
      d.scans.forEach(function(s) {
        var statusColor = s.status === 'completed' ? '#00ff41' : s.status === 'error' ? '#ff4444' : '#ffaa00';
        var dateStr = s.start_time ? new Date(s.start_time * 1000).toLocaleString() : 'N/A';
        html += '<div style="display:flex;align-items:center;justify-content:space-between;padding:6px 10px;border-bottom:1px solid #111;font-size:10px;">'
          + '<div style="display:flex;align-items:center;gap:10px;flex:1;min-width:0;">'
          + '<span style="color:' + statusColor + ';">●</span>'
          + '<code style="color:#00ff41;font-size:9px;">' + s.scan_id.substring(0, 8) + '</code>'
          + '<span style="color:#888;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;max-width:200px;" title="' + _escHtml(s.target_dir) + '">' + _escHtml(s.target_dir) + '</span>'
          + '<span style="color:#ccc;">' + s.scanned_files + '/' + s.total_files + ' files</span>'
          + '<span style="color:#ff4444;font-size:9px;">' + s.new_findings + ' new</span>'
          + '<span style="color:#ffaa00;font-size:9px;">' + s.known_findings + ' known</span>'
          + '<span style="color:#555;">' + dateStr + '</span>'
          + '<span style="color:#888;">' + (s.duration || '?') + 's</span>'
          + '</div>'
          + '<div style="display:flex;gap:4px;flex-shrink:0;">'
          + '<button class="btn btn-ghost btn-sm" style="font-size:9px;padding:1px 5px;" onclick="viewScanResults(\'' + s.scan_id + '\')">View</button>'
          + '<button class="btn btn-ghost btn-sm" style="font-size:9px;padding:1px 5px;" onclick="window.open(\'/admin/scanner/report?scan_id=' + s.scan_id + '\',\'_blank\')">Report</button>'
          + '</div>'
          + '</div>';
      });
      el.innerHTML = html;
    })
    .catch(function() {
      el.innerHTML = '<p style="color:#ff4444;text-align:center;padding:12px;">Failed to load history.</p>';
    });
}

function viewScanResults(scanId) {
  // Load full scan results from disk and render in the results card
  var tbody = document.getElementById('results-tbody');
  var card = document.getElementById('scan-results-card');
  if (!tbody || !card) return;
  tbody.innerHTML = '<tr><td colspan="7" style="padding:12px;text-align:center;"><div class="spinner"></div><p>Loading results...</p></td></tr>';
  card.style.display = 'flex';
  _scanFindings = [];
  _scanSelected.clear();
  _scanQuarantined.clear();
  fetch('/admin/scanner/results?scan_id=' + encodeURIComponent(scanId))
    .then(function(r) { return r.json(); })
    .then(function(d) {
      if (d.error) { tbody.innerHTML = '<tr><td colspan="7" style="color:#ff4444;padding:12px;">Error: ' + d.error + '</td></tr>'; return; }
      tbody.innerHTML = '';
      _scanFindings = d.findings || [];
      _scanFindings.forEach(function(f) { addResultRow(f); });
      updateResultCounts();
      scanUpdateSel();
      _scanLastId = d.scan_id;
      document.getElementById('scan-report-btn').style.display = '';
      document.getElementById('scan-progress-card').style.display = 'none';
    })
    .catch(function() { tbody.innerHTML = '<tr><td colspan="7" style="color:#ff4444;padding:12px;">Failed to load.</td></tr>'; });
}

// v2.0: Scan results — cross-result selection + batch quarantine
function scanUpdateSel() {
  _scanSelected.clear();
  document.querySelectorAll('.scan-cb:checked').forEach(function(cb) {
    _scanSelected.add(cb.dataset.filePath);
  });
  var count = _scanSelected.size;
  var countEl = document.getElementById('scan-selected-count');
  var btn = document.getElementById('scan-quarantine-sel-btn');
  if (countEl) { countEl.style.display = count > 0 ? '' : 'none'; countEl.textContent = count + ' selected'; }
  if (btn) btn.disabled = count === 0;
}

function scanToggleAll(masterCb) {
  document.querySelectorAll('.scan-cb').forEach(function(cb) {
    cb.checked = masterCb.checked;
  });
  scanUpdateSel();
}

function scanSelectAll() {
  document.querySelectorAll('.scan-cb').forEach(function(cb) { cb.checked = true; });
  document.getElementById('scan-select-all-cb').checked = true;
  scanUpdateSel();
}

function scanClearSel() {
  document.querySelectorAll('.scan-cb').forEach(function(cb) { cb.checked = false; });
  document.getElementById('scan-select-all-cb').checked = false;
  scanUpdateSel();
}

function scanQuarantineSelected() {
  var paths = Array.from(_scanSelected);
  if (!paths.length) return;
  if (!confirm('Quarantine ' + paths.length + ' selected files?')) return;
  var csrf = document.querySelector('meta[name="csrf-token"]');
  var token = csrf ? csrf.content : '';
  var done = 0;
  var failed = 0;
  var total = paths.length;

  function processNext() {
    if (paths.length === 0) {
      alert('Done: ' + done + ' quarantined, ' + failed + ' failed');
      _scanSelected.clear();
      scanUpdateSel();
      return;
    }
    var fp = paths.shift();
    fetch('/admin/scanner/quarantine', {
      method: 'POST',
      headers: {'Content-Type':'application/x-www-form-urlencoded','X-CSRFToken':token},
      body: 'file_path=' + encodeURIComponent(fp)
    })
    .then(function(r) { return r.json(); })
    .then(function(d) {
      if (d.success) {
        done++;
        _scanQuarantined.add(fp);
        // Update row status
        var row = document.querySelector('tr[data-file-path="' + fp.replace(/\\/g, '\\\\').replace(/'/g, "\\'") + '"]');
        if (row) {
          var td = row.querySelector('td:nth-child(6)');
          if (td) td.innerHTML = '<span class="badge badge-success" style="font-size:9px;">Quarantined</span>';
        }
      } else { failed++; }
      processNext();
    })
    .catch(function() { failed++; processNext(); });
  }
  processNext();
}
