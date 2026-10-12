/* Block ledger and device broadcast workflows. */
(function () {
  'use strict';

  var app = window.Anteumbra;
  var state = {
    filter: 'all', page: 1, query: '', timer: null, devices: {}, selectedDevices: {},
    selectedRows: new Map(), ledgerRequestId: 0, mountId: 0, scope: null, mounted: false, busy: false
  };
  function scopeUrl(url) {
    var site = window.AnteumbraSite && window.AnteumbraSite.current();
    return site ? url + (url.indexOf('?') >= 0 ? '&' : '?') + 'site_id=' + encodeURIComponent(site) : url;
  }
  function label(zh, en) { return document.documentElement.lang.indexOf('zh') === 0 ? zh : en; }

  function setText(id, value) { var node = document.getElementById(id); if (node) node.textContent = value; }

  function pageScope() { return (window.AnteumbraSite && window.AnteumbraSite.current()) || ''; }
  function rowKey(siteId, ip) { return String(siteId || 'legacy') + '\u0000' + String(ip || ''); }
  function resetSelection() {
    state.selectedRows.clear();
    updateSelectionUi();
  }
  function selectedRows() { return Array.from(state.selectedRows.values()); }
  function setBusy(value) {
    state.busy = value;
    updateSelectionUi();
    document.querySelectorAll('.ledger-checkbox, [data-action="blocklist.select-page"], [data-action="blocklist.clear-selection"]').forEach(function (node) { node.disabled = value; });
    document.querySelectorAll('[data-action="blocklist.device-toggle"]').forEach(function (node) { node.disabled = value || node.dataset.available === 'false'; });
  }
  function updateSelectionUi() {
    var count = state.selectedRows.size;
    setText('ledger-selected-count', app.t('%(count)s selected', { count: count }));
    document.querySelectorAll('[data-action="blocklist.batch-block"], [data-action="blocklist.batch-unblock"], [data-action="blocklist.clear-selection"]').forEach(function (node) { node.disabled = state.busy || count === 0; });
    document.querySelectorAll('.ledger-checkbox').forEach(function (node) { node.checked = state.selectedRows.has(rowKey(node.dataset.siteId, node.dataset.ip)); node.disabled = state.busy; });
  }

  function loadLedger(filter) {
    state.filter = filter || state.filter;
    state.page = 1;
    document.querySelectorAll('.ledger-filter').forEach(function (button) {
      button.classList.toggle('active', button.dataset.ledgerFilter === state.filter);
    });
    fetchLedger();
  }

  function search(value) {
    state.query = value;
    state.page = 1;
    window.clearTimeout(state.timer);
    state.timer = window.setTimeout(fetchLedger, 250);
  }

  function fetchLedger() {
    var target = document.getElementById('ledger-tbody');
    if (!target) return;
    var requestId = ++state.ledgerRequestId;
    var mountId = state.mountId;
    target.textContent = 'Loading...';
    app.http.json(scopeUrl('/admin/blocklist/data?source=' + encodeURIComponent(state.filter) + '&page=' + state.page + '&q=' + encodeURIComponent(state.query)))
      .then(function (data) {
        if (requestId !== state.ledgerRequestId || mountId !== state.mountId || !target.isConnected) return;
        renderLedger(data);
      })
      .catch(function (error) {
        if (requestId === state.ledgerRequestId && mountId === state.mountId && target.isConnected) target.textContent = 'Failed to load: ' + error.message;
      });
  }

  function tableCell(text) {
    var cell = document.createElement('td');
    cell.textContent = text == null ? '' : String(text);
    return cell;
  }

  function renderLedger(data) {
    var stats = data.stats || {};
    setText('ledger-stat-total', stats.total || 0);
    setText('ledger-stat-auto', stats.auto || 0);
    setText('ledger-stat-manual', stats.manual || 0);
    setText('ledger-stat-today', stats.today || 0);
    var target = document.getElementById('ledger-tbody');
    if (!target) return;
    target.replaceChildren();
    (data.entries || []).forEach(function (entry) {
      var row = document.createElement('tr');
      var siteId = entry.site_id || 'legacy';
      row.dataset.siteName = entry.site_name || siteId;
      var checkCell = document.createElement('td');
      var checkbox = document.createElement('input');
      checkbox.type = 'checkbox'; checkbox.className = 'ledger-checkbox';
      checkbox.dataset.action = 'blocklist.ledger-selection';
      checkbox.dataset.siteId = siteId; checkbox.dataset.ip = entry.ip || '';
      checkbox.setAttribute('aria-label', label('选择 ' + (entry.ip || ''), 'Select ' + (entry.ip || '')));
      checkCell.appendChild(checkbox); row.appendChild(checkCell);
      row.appendChild(tableCell(entry.ip));
      row.appendChild(tableCell(entry.site_name || entry.site_id || label('未归属', 'Unassigned')));
      row.appendChild(tableCell(entry.source));
      row.appendChild(tableCell(entry.reason || ''));
      var notes = tableCell(entry.notes || '[add note]');
      notes.className = 'notes-cell';
      notes.dataset.action = 'blocklist.notes-edit';
      notes.dataset.ip = entry.ip;
      notes.dataset.siteId = entry.site_id || 'legacy';
      row.appendChild(notes);
      row.appendChild(tableCell((entry.blocked_at || '').slice(0, 16)));
      row.appendChild(tableCell(entry.status || 'unknown'));
      row.appendChild(tableCell(entry.broadcast_status || 'unknown'));
      target.appendChild(row);
    });
    if (!target.childElementCount) {
      var empty = document.createElement('tr');
      var cell = tableCell(app.t('No block records found.'));
      cell.colSpan = 9;
      empty.appendChild(cell);
      target.appendChild(empty);
    }
    updateSelectionUi();
    renderPagination(data);
  }

  function renderPagination(data) {
    var target = document.getElementById('ledger-pagination');
    if (!target) return;
    target.replaceChildren();
    function pageButton(label, page) {
      var button = document.createElement('button');
      button.className = 'btn btn-ghost btn-sm';
      button.textContent = label;
      button.dataset.action = 'blocklist.page';
      button.dataset.ledgerPage = page;
      return button;
    }
    if (data.page > 1) target.appendChild(pageButton(app.t('Prev'), data.page - 1));
    target.appendChild(document.createTextNode(app.t('Page %(page)s / %(total_pages)s (%(total)s total)', {
      page: data.page || 1, total_pages: data.total_pages || 1, total: data.total || 0
    })));
    if (data.page < data.total_pages) target.appendChild(pageButton(app.t('Next'), data.page + 1));
  }

  function editNotes(cell) {
    if (cell.querySelector('input')) return;
    var existing = cell.textContent === '[add note]' ? '' : cell.textContent;
    var input = document.createElement('input');
    input.value = existing;
    input.className = 'ledger-note-input';
    input.addEventListener('blur', function () { saveNotes(cell, input.value); });
    input.addEventListener('keydown', function (event) {
      if (event.key === 'Enter') input.blur();
      if (event.key === 'Escape') { cell.textContent = existing || '[add note]'; }
    });
    cell.replaceChildren(input);
    input.focus();
  }

  function saveNotes(cell, value) {
    app.http.json('/admin/blocklist/notes', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ip: cell.dataset.ip, site_id: cell.dataset.siteId, notes: value })
    }).then(function () { cell.textContent = value || '[add note]'; })
      .catch(function (error) { cell.textContent = 'Save failed: ' + error.message; });
  }

  function appendResult(message) {
    var target = document.getElementById('bl-result');
    if (!target) return;
    target.hidden = false;
    target.style.display = 'block';
    target.textContent = '[' + new Date().toLocaleTimeString() + '] ' + message + '\n' + target.textContent;
  }

  function appendBatchResult(item) {
    var target = document.getElementById('ledger-batch-results');
    if (!target) return;
    target.hidden = false;
    var row = document.createElement('div');
    row.dataset.outcome = item.success ? 'success' : 'failed';
    row.textContent = (item.success ? 'OK ' : 'FAIL ') + item.siteName + ' / ' + item.ip + ' / ' + item.device + (item.message ? ' - ' + item.message : '');
    target.appendChild(row);
  }

  function updateBatchSummary(done, failed) {
    var summary = document.getElementById('ledger-batch-summary');
    if (summary) summary.textContent = app.t('%(done)s succeeded, %(failed)s failed', { done: done, failed: failed });
  }

  function selectedDevices() {
    return Object.keys(state.selectedDevices).filter(function (name) { return state.selectedDevices[name]; });
  }

  function loadDevices() {
    app.http.json('/admin/blocklist/devices').then(function (result) {
      var target = document.getElementById('bl-device-toggles');
      if (!target) return;
      state.devices = {};
      state.selectedDevices = {};
      target.replaceChildren();
      (result.devices || []).forEach(function (device) {
        state.devices[device.name] = device;
        state.selectedDevices[device.name] = false;
        var button = document.createElement('button');
        button.className = 'btn btn-ghost btn-sm bl-dev-btn';
        button.textContent = device.name;
        button.disabled = !device.available;
        button.dataset.available = device.available ? 'true' : 'false';
        button.dataset.action = 'blocklist.device-toggle';
        button.dataset.deviceName = device.name;
        target.appendChild(button);
      });
    });
  }

  function toggleDevice(button) {
    if (state.busy) return;
    var name = button.dataset.deviceName;
    state.selectedDevices[name] = !state.selectedDevices[name];
    button.classList.toggle('active', state.selectedDevices[name]);
  }

  function selectedPage() {
    document.querySelectorAll('.ledger-checkbox').forEach(function (checkbox) {
      var key = rowKey(checkbox.dataset.siteId, checkbox.dataset.ip);
      state.selectedRows.set(key, { siteId: checkbox.dataset.siteId || 'legacy', ip: checkbox.dataset.ip || '', siteName: checkbox.closest('tr').dataset.siteName || checkbox.dataset.siteId || 'legacy' });
    });
    updateSelectionUi();
  }

  function toggleRow(checkbox) {
    if (state.busy) { checkbox.checked = state.selectedRows.has(rowKey(checkbox.dataset.siteId, checkbox.dataset.ip)); return; }
    var key = rowKey(checkbox.dataset.siteId, checkbox.dataset.ip);
    if (checkbox.checked) {
      var row = checkbox.closest('tr');
      state.selectedRows.set(key, { siteId: checkbox.dataset.siteId || 'legacy', ip: checkbox.dataset.ip || '', siteName: row && row.dataset.siteName ? row.dataset.siteName : (checkbox.dataset.siteId || 'legacy') });
    } else state.selectedRows.delete(key);
    updateSelectionUi();
  }

  function batchConfirmation(mode, rows, devices) {
    var grouped = {};
    var siteNames = {};
    rows.forEach(function (item) { (grouped[item.siteId] || (grouped[item.siteId] = [])).push(item.ip); siteNames[item.siteId] = item.siteName || item.siteId; });
    var lines = Object.keys(grouped).map(function (siteId) { return siteNames[siteId] + ' (' + siteId + '): ' + grouped[siteId].join(', '); });
    var action = mode === 'block' ? label('封禁', 'Block') : label('解封', 'Unblock');
    return action + ' ' + rows.length + ' ' + label('条台账记录？', 'ledger record(s)?') + '\n' + lines.join('\n') + '\n' + label('设备：', 'Devices: ') + devices.join(', ') + '\n' + label('设备按 IP 执行，使用这些设备的其他站点也可能受影响。', 'Devices act on IPs; other sites using these devices may be affected.');
  }

  function batchAction(mode) {
    if (state.busy) return;
    var rows = selectedRows();
    var devices = selectedDevices();
    if (!rows.length) return;
    if (!devices.length) { appendBatchResult({ success: false, siteName: label('批量操作', 'Batch operation'), ip: '', device: '', message: label('请明确选择执行设备。', 'Select the devices to execute this operation.') }); return; }
    var snapshot = rows.map(function (item) { return { siteId: item.siteId, ip: item.ip, siteName: item.siteName }; });
    var deviceSnapshot = devices.slice();
    var actionMountId = state.mountId;
    if (!app.confirm(batchConfirmation(mode, snapshot, deviceSnapshot))) return;
    var target = document.getElementById('ledger-batch-results');
    if (target) {
      target.querySelectorAll('[data-outcome]').forEach(function (item) { item.remove(); });
      target.hidden = false;
    }
    setBusy(true); updateBatchSummary(0, 0);
    var groups = {};
    snapshot.forEach(function (item) { (groups[item.siteId] || (groups[item.siteId] = { siteId: item.siteId, siteName: item.siteName, ips: [] })).ips.push(item.ip); });
    var done = 0; var failed = 0;
    var siteIds = Object.keys(groups);
    function submitGroup(index) {
      if (actionMountId !== state.mountId || !state.mounted) return;
      if (index >= siteIds.length) { setBusy(false); updateSelectionUi(); fetchLedger(); return; }
      var group = groups[siteIds[index]];
      var payload = { ips: group.ips.slice(), site_id: group.siteId, devices: deviceSnapshot.slice() };
      if (mode === 'block') payload.reason = (document.getElementById('bl-reason-input') || {}).value || 'Batch block from Blocklist';
      app.http.json('/admin/blocklist/' + mode, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload) }).then(function (response) {
        if (actionMountId !== state.mountId || !state.mounted) return;
        group.ips.forEach(function (ip) {
          var errors = (response.ledger_errors || []).filter(function (entry) { return entry.ip === ip; });
          var allSuccess = deviceSnapshot.every(function (device) {
            var receipt = (response.results || []).find(function (entry) { return entry.ip === ip && entry.device === device; });
            var success = !!receipt && receipt.success === true && errors.length === 0;
            appendBatchResult({ success: success, siteName: group.siteName, ip: ip, device: device, message: success ? '' : ((receipt && receipt.message) || (errors[0] && errors[0].error) || label('缺少成功回执', 'Missing successful receipt')) });
            if (success) done++; else failed++;
            return success;
          });
          if (allSuccess) state.selectedRows.delete(rowKey(group.siteId, ip));
          updateBatchSummary(done, failed);
        });
        submitGroup(index + 1);
      }).catch(function (error) {
        if (actionMountId !== state.mountId || !state.mounted) return;
        group.ips.forEach(function (ip) { deviceSnapshot.forEach(function (device) { failed++; appendBatchResult({ success: false, siteName: group.siteName, ip: ip, device: device, message: error.message }); }); updateBatchSummary(done, failed); });
        submitGroup(index + 1);
      });
    }
    submitGroup(0);
  }

  function showTargetSiteLedger(siteId) {
    var current = window.AnteumbraSite && window.AnteumbraSite.current();
    if (!current || current === siteId) { loadLedger('all'); return; }
    var result = document.getElementById('bl-result');
    var link = document.createElement('a');
    var url = new window.URL('/admin/blocklist', window.location.origin);
    url.searchParams.set('site', siteId);
    var lang = new window.URLSearchParams(window.location.search).get('lang');
    if (lang) url.searchParams.set('lang', lang);
    link.href = url.pathname + url.search;
    link.textContent = label('查看目标站点台账', 'View target site ledger');
    link.className = 'site-link';
    if (result) { result.appendChild(document.createElement('br')); result.appendChild(link); }
  }

  function submitManual(mode) {
    var input = document.getElementById('bl-ip-input');
    var ips = (input ? input.value : '').split(/[\n,;]+/).map(function (item) { return item.trim(); }).filter(Boolean);
    if (!ips.length) { appendResult(app.t('Enter IP addresses')); return; }
    var site = document.getElementById('bl-target-site');
    if (!site || !site.value) { appendResult(label('请先选择具体目标站点。', 'Choose a target site first.')); return; }
    if (!selectedDevices().length) { appendResult(label('请明确选择执行设备。', 'Select the devices to execute this operation.')); return; }
    var action = mode === 'block' ? label('封禁', 'Block') : label('解封', 'Unblock');
    if (!app.confirm(action + ': ' + ips.join(', ') + '\n' + site.options[site.selectedIndex].text + '\n' + selectedDevices().join(', '))) return;
    var payload = { ips: ips, devices: selectedDevices(), site_id: site.value };
    var profileId = new window.URLSearchParams(window.location.search).get('profile_id');
    if (profileId) payload.profile_id = profileId;
    if (mode === 'block') payload.reason = (document.getElementById('bl-reason-input') || {}).value || 'Manual block from Blocklist';
    appendResult(mode === 'block'
      ? app.t('Blocking %(count)s IPs...', { count: ips.length })
      : app.t('Unblocking %(count)s IPs...', { count: ips.length }));
    app.http.json('/admin/blocklist/' + mode, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload) })
      .then(function (result) {
        (result.results || []).forEach(function (item) { appendResult((item.success ? app.t('OK ') : app.t('FAIL ')) + item.device + ': ' + item.ip + ' - ' + (item.message || '')); });
        appendResult((result.success ? app.t('DONE: ') : app.t('FAIL: ')) + (result.message || ''));
        // Keep the full device receipt visible; changing sites is an explicit
        // navigation so the shell, ledger and exports remain consistent.
        showTargetSiteLedger(payload.site_id);
      }).catch(function (error) {
        ((error.payload && error.payload.results) || []).forEach(function (item) {
          appendResult((item.success ? app.t('OK ') : app.t('FAIL ')) + item.device + ': ' + item.ip + ' - ' + (item.message || ''));
        });
        appendResult(app.t('Error: ') + error.message);
        showTargetSiteLedger(payload.site_id);
      });
  }

  app.register('blocklist', {
    actions: {
      'blocklist.manual-block': { handler: function () { submitManual('block'); } },
      'blocklist.manual-unblock': { handler: function () { submitManual('unblock'); } },
      'blocklist.filter': { handler: function (context) { loadLedger(context.element.dataset.ledgerFilter); } },
      'blocklist.search': { handler: function (context) { search(context.element.value); }, events: ['input'], preventDefault: false },
      'blocklist.refresh': { handler: function () { fetchLedger(); } },
      'blocklist.export': { handler: function (context) { window.open(scopeUrl('/admin/blocklist/export?format=' + encodeURIComponent(context.element.dataset.format)), '_blank'); } },
      'blocklist.page': { handler: function (context) { state.page = Number(context.element.dataset.ledgerPage); fetchLedger(); } },
      'blocklist.notes-edit': { handler: function (context) { editNotes(context.element); } },
      'blocklist.device-toggle': { handler: function (context) { toggleDevice(context.element); } },
      'blocklist.ledger-selection': { handler: function (context) { toggleRow(context.element); }, events: ['change'], preventDefault: false },
      'blocklist.select-page': { handler: function () { selectedPage(); } },
      'blocklist.clear-selection': { handler: function () { if (!state.busy) resetSelection(); } },
      'blocklist.batch-block': { handler: function () { batchAction('block'); } },
      'blocklist.batch-unblock': { handler: function () { batchAction('unblock'); } }
    },
    mount: function (root) {
      var page = root && (root.id === 'ledger-tbody' || root.querySelector && root.querySelector('#ledger-tbody'));
      if (page) {
        var scope = pageScope();
        if (!state.mounted || state.scope !== scope) { state.scope = scope; state.mounted = true; state.mountId++; state.ledgerRequestId = 0; resetSelection(); loadDevices(); }
        updateSelectionUi();
        if (!state.ledgerRequestId) loadLedger('all');
      }
    },
    unmount: function (root) {
      var page = root && (root.classList && root.classList.contains('blocklist-view') || root.querySelector && root.querySelector('.blocklist-view'));
      if (!page) return;
      state.mountId++; state.mounted = false; state.scope = null; state.ledgerRequestId++; state.busy = false;
      resetSelection();
      if (state.timer !== null) { window.clearTimeout(state.timer); state.timer = null; }
    },
    loadLedger: loadLedger
  });
}());
