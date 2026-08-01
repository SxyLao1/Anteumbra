/* Active scanner workflow. */
(function () {
  'use strict';

  var app = window.Anteumbra;
  var state = {
    stream: null, findings: [], tab: 'new', startedAt: 0, complete: false,
    scanId: '', jobId: '', selected: new Set(), quarantined: new Set(), historyRequest: 0
  };

  function node(id) { return document.getElementById(id); }

  function ownsScanner(root) {
    return Boolean(root && (
      root.id === 'scan-target-dir' ||
      (root.querySelector && root.querySelector('#scan-target-dir'))
    ));
  }

  function setState(status, progressText) {
    var labels = { starting: 'Starting', running: 'Running', stopping: 'Stopping', completed: 'Completed', stopped: 'Stopped', failed: 'Failed' };
    var colors = { starting: '#ffaa00', running: '#00ff41', stopping: '#ffaa00', completed: '#00ff41', stopped: '#ffaa00', failed: '#ff4444' };
    var active = ['starting', 'running', 'stopping'].indexOf(status) >= 0;
    var statusNode = node('scan-status');
    if (statusNode) { statusNode.textContent = labels[status] || status; statusNode.dataset.state = status; statusNode.style.color = colors[status] || '#888'; }
    var progress = node('scan-progress-text');
    if (progress && progressText != null) progress.textContent = progressText;
    var stop = node('scan-stop-btn');
    if (stop) { stop.disabled = status !== 'running'; stop.style.display = status === 'running' ? '' : 'none'; }
    var start = node('scan-start-btn');
    if (start) start.disabled = active;
    var config = node('scan-config-card');
    if (config) { config.hidden = active; config.style.display = active ? 'none' : 'flex'; }
  }

  function setResultsMessage(message, error) {
    var table = node('results-tbody');
    if (!table) return;
    table.innerHTML = '<tr><td colspan="7" class="scan-result-message"></td></tr>';
    table.querySelector('.scan-result-message').textContent = message;
    table.querySelector('.scan-result-message').style.color = error ? 'var(--color-danger)' : '';
  }

  function start() {
    var target = node('scan-target-dir');
    if (!target || !target.value.trim()) { app.ui.toast('Please enter a target directory.', 'warning'); return; }
    state.findings = [];
    state.complete = false;
    state.jobId = '';
    state.startedAt = Date.now();
    state.selected.clear();
    state.quarantined.clear();
    if (state.stream) state.stream.close();
    var table = node('results-tbody');
    if (table) table.replaceChildren();
    ['scan-config-card', 'scan-progress-card', 'scan-results-card'].forEach(function (id) {
      var card = node(id);
      if (card) {
        var visible = id === 'scan-progress-card';
        card.hidden = !visible;
        card.style.display = visible ? 'flex' : 'none';
      }
    });
    ['stat-new', 'stat-known', 'stat-clean', 'stat-errors', 'tab-new-count', 'tab-known-count', 'tab-all-count'].forEach(function (id) { var value = node(id); if (value) value.textContent = '0'; });
    var progressBar = node('scan-progress-bar');
    if (progressBar) progressBar.style.width = '0%';
    setState('starting', '0 / ? files');
    var body = new URLSearchParams({
      target_dir: target.value.trim(),
      recursive: node('scan-recursive').checked ? '1' : '0',
      extensions: node('scan-extensions').value.trim()
    });
    app.http.json('/admin/scanner/run', { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body: body.toString() })
      .then(function (result) {
        if (!result.success) throw new Error(result.error || 'Scanner did not start');
        state.jobId = result.scan_id;
        setState('running', '0 / ? files');
        state.stream = new EventSource(result.stream_url, { withCredentials: true });
        state.stream.onmessage = function (event) { try { handleEvent(JSON.parse(event.data)); } catch (error) { console.error('Scanner SSE parse error', error); } };
        state.stream.onerror = function () {
          if (!state.complete) { state.complete = true; setState('failed', 'Connection lost'); setResultsMessage('SSE connection lost.', true); }
          if (state.stream) { state.stream.close(); state.stream = null; }
        };
      })
      .catch(function (error) { state.complete = true; setState('failed', 'Start failed: ' + error.message); setResultsMessage('Start failed: ' + error.message, true); });
  }

  function handleEvent(event) {
    if (event.event === 'init') { setState('running', '0 / ' + (event.total_files || '?') + ' files'); return; }
    if (event.event === 'progress') {
      var total = event.total || 0;
      var progress = node('scan-progress-bar');
      if (progress) progress.style.width = (total ? Math.round(event.scanned / total * 100) : 0) + '%';
      var text = node('scan-progress-text'); if (text) text.textContent = event.scanned + ' / ' + total + ' files';
      var elapsed = node('scan-elapsed'); if (elapsed) elapsed.textContent = Math.round((Date.now() - state.startedAt) / 1000) + 's';
      [['stat-new', event.new_findings], ['stat-known', event.known_findings], ['stat-clean', event.clean], ['stat-errors', event.errors]].forEach(function (entry) { var stat = node(entry[0]); if (stat) stat.textContent = entry[1] || 0; });
      return;
    }
    if (event.event === 'finding') { state.findings.push(event); addRow(event); updateCounts(); return; }
    if (event.event === 'complete' || event.event === 'error') {
      state.complete = true;
      state.scanId = event.scan_id || state.scanId;
      state.jobId = '';
      var failed = event.event === 'error' || event.status === 'error';
      var stopped = event.status === 'cancelled';
      var terminalStatus = failed ? 'failed' : stopped ? 'stopped' : 'completed';
      // Successful scans retain their final scanned/total count for operator review.
      var terminalText = failed ? 'Failed - ' + (event.message || event.error_message || 'Unknown error') : (stopped ? 'Stopped' : null);
      setState(terminalStatus, terminalText);
      if (state.stream) { state.stream.close(); state.stream = null; }
      if (state.findings.length) node('scan-report-btn').style.display = '';
      window.setTimeout(loadHistory, 50);
    }
  }

  function addRow(finding) {
    var card = node('scan-results-card');
    if (card) { card.hidden = false; card.style.display = 'flex'; }
    var tbody = node('results-tbody');
    if (!tbody) return;
    var row = document.createElement('tr');
    row.className = finding.classification === 'new' ? 'result-new' : 'result-known';
    row.dataset.filePath = finding.file_path;
    var select = document.createElement('input');
    select.type = 'checkbox'; select.className = 'scan-cb'; select.dataset.filePath = finding.file_path; select.dataset.action = 'scanner.selection-change';
    var cells = [document.createElement('td'), document.createElement('td'), document.createElement('td'), document.createElement('td'), document.createElement('td'), document.createElement('td'), document.createElement('td')];
    cells[0].appendChild(select);
    cells[1].textContent = finding.file_name;
    cells[2].textContent = finding.file_path;
    cells[3].textContent = finding.engine || '';
    cells[4].textContent = (finding.features || []).join(', ');
    cells[5].textContent = finding.quarantine_id ? 'Quarantined' : 'Active';
    var view = document.createElement('button');
    view.className = 'btn btn-ghost btn-sm'; view.textContent = 'View'; view.dataset.action = 'records.view-path'; view.dataset.filePath = finding.file_path;
    cells[6].appendChild(view);
    cells.forEach(function (cell) { row.appendChild(cell); });
    tbody.appendChild(row);
    filterTab();
  }

  function updateCounts() {
    var fresh = state.findings.filter(function (item) { return item.classification === 'new'; }).length;
    var known = state.findings.filter(function (item) { return item.classification === 'known'; }).length;
    [['tab-new-count', fresh], ['tab-known-count', known], ['tab-all-count', state.findings.length]].forEach(function (entry) { var value = node(entry[0]); if (value) value.textContent = entry[1]; });
  }

  function switchTab(tab) {
    state.tab = tab;
    ['new', 'known', 'all'].forEach(function (name) { var control = node('tab-' + name); if (control) control.classList.toggle('active', name === tab); });
    filterTab();
  }

  function filterTab() {
    document.querySelectorAll('#results-tbody tr').forEach(function (row) {
      row.style.display = state.tab === 'all' || row.classList.contains('result-' + state.tab) ? '' : 'none';
    });
  }

  function stop() {
    if (!state.jobId || state.complete) return;
    setState('stopping', 'Stopping...');
    app.http.json('/admin/scanner/cancel', { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body: 'scan_id=' + encodeURIComponent(state.jobId) })
      .catch(function (error) { setState('running', 'Cancel failed: ' + error.message); });
  }

  function updateSelection() {
    state.selected.clear();
    document.querySelectorAll('.scan-cb:checked').forEach(function (checkbox) { state.selected.add(checkbox.dataset.filePath); });
    var count = node('scan-selected-count');
    var button = node('scan-quarantine-sel-btn');
    if (count) { count.textContent = state.selected.size + ' selected'; count.style.display = state.selected.size ? '' : 'none'; }
    if (button) button.disabled = state.selected.size === 0;
  }

  function quarantineSelection() {
    var paths = Array.from(state.selected);
    if (!paths.length || !app.confirm('Quarantine ' + paths.length + ' selected files?')) return;
    var completed = 0;
    function next() {
      var path = paths.shift();
      if (!path) { window.alert('Done: ' + completed + ' quarantined'); state.selected.clear(); updateSelection(); return; }
      app.http.json('/admin/scanner/quarantine', { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body: 'file_path=' + encodeURIComponent(path) })
        .then(function (result) { if (result.success) completed += 1; next(); }).catch(next);
    }
    next();
  }

  function loadHistory() {
    var target = node('scan-history-list');
    if (!target) return;
    var requestId = ++state.historyRequest;
    target.textContent = 'Loading history...';
    app.http.json('/admin/scanner/history').then(function (result) {
      if (requestId !== state.historyRequest || !target.isConnected) return;
      target.replaceChildren();
      (result.scans || []).forEach(function (scan) {
        var line = document.createElement('div');
        line.className = 'scan-history-row';
        line.textContent = scan.scan_id.slice(0, 8) + ' ' + scan.target_dir + ' ' + scan.scanned_files + '/' + scan.total_files;
        var view = document.createElement('button');
        view.className = 'btn btn-ghost btn-sm'; view.textContent = 'View'; view.dataset.action = 'scanner.view-results'; view.dataset.scanId = scan.scan_id;
        var report = document.createElement('button');
        report.className = 'btn btn-ghost btn-sm'; report.textContent = 'Report'; report.dataset.action = 'core.open-window'; report.dataset.url = '/admin/scanner/report?scan_id=' + encodeURIComponent(scan.scan_id);
        line.append(' ', view, ' ', report);
        target.appendChild(line);
      });
      if (!target.childElementCount) target.textContent = 'No scan history yet.';
    }).catch(function () { if (requestId === state.historyRequest) target.textContent = 'Failed to load history.'; });
  }

  function viewResults(scanId) {
    state.findings = []; state.selected.clear(); state.quarantined.clear();
    setResultsMessage('Loading results...');
    app.http.json('/admin/scanner/results?scan_id=' + encodeURIComponent(scanId)).then(function (result) {
      var tbody = node('results-tbody');
      if (tbody) tbody.replaceChildren();
      (result.findings || []).forEach(function (finding) { state.findings.push(finding); addRow(finding); });
      updateCounts(); updateSelection(); state.scanId = result.scan_id;
      var results = node('scan-results-card');
      if (results) { results.hidden = false; results.style.display = 'flex'; }
      node('scan-report-btn').style.display = '';
    }).catch(function (error) { setResultsMessage(error.message, true); });
  }

  app.register('scanner', {
    actions: {
      'scanner.start': { handler: start },
      'scanner.stop': { handler: stop },
      'scanner.tab': { handler: function (context) { switchTab(context.element.dataset.scanTab); } },
      'scanner.selection-change': { handler: updateSelection, events: ['change'], preventDefault: false },
      'scanner.select-all': { handler: function () { document.querySelectorAll('.scan-cb').forEach(function (box) { box.checked = true; }); var master = node('scan-select-all-cb'); if (master) master.checked = true; updateSelection(); } },
      'scanner.clear-selection': { handler: function () { document.querySelectorAll('.scan-cb').forEach(function (box) { box.checked = false; }); var master = node('scan-select-all-cb'); if (master) master.checked = false; updateSelection(); } },
      'scanner.toggle-all': { handler: function (context) { document.querySelectorAll('.scan-cb').forEach(function (box) { box.checked = context.element.checked; }); updateSelection(); }, events: ['change'], preventDefault: false },
      'scanner.quarantine-selection': { handler: quarantineSelection },
      'scanner.report': { handler: function () { if (state.scanId) window.open('/admin/scanner/report?scan_id=' + encodeURIComponent(state.scanId), '_blank'); } },
      'scanner.history-refresh': { handler: loadHistory },
      'scanner.view-results': { handler: function (context) { viewResults(context.element.dataset.scanId); } }
    },
    mount: function (root) { if (root && (root.id === 'scan-history-list' || root.querySelector && root.querySelector('#scan-history-list'))) loadHistory(); },
    unmount: function (root) {
      if (!ownsScanner(root)) return;
      state.historyRequest += 1;
      if (state.stream) { state.stream.close(); state.stream = null; }
    },
    loadHistory: loadHistory
  });
}());
