/* Block ledger and device broadcast workflows. */
(function () {
  'use strict';

  var app = window.Anteumbra;
  var state = { filter: 'all', page: 1, query: '', timer: null, devices: {}, selectedDevices: {} };

  function setText(id, value) { var node = document.getElementById(id); if (node) node.textContent = value; }

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
    target.textContent = 'Loading...';
    app.http.json('/admin/blocklist/data?source=' + encodeURIComponent(state.filter) + '&page=' + state.page + '&q=' + encodeURIComponent(state.query))
      .then(renderLedger)
      .catch(function (error) { target.textContent = 'Failed to load: ' + error.message; });
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
      row.appendChild(tableCell(entry.ip));
      row.appendChild(tableCell(entry.source));
      row.appendChild(tableCell(entry.reason || ''));
      var notes = tableCell(entry.notes || '[add note]');
      notes.className = 'notes-cell';
      notes.dataset.action = 'blocklist.notes-edit';
      notes.dataset.ip = entry.ip;
      notes.dataset.siteId = entry.site_id || 'legacy';
      row.appendChild(notes);
      row.appendChild(tableCell((entry.blocked_at || '').slice(0, 16)));
      row.appendChild(tableCell(entry.broadcast_status || 'unknown'));
      target.appendChild(row);
    });
    if (!target.childElementCount) {
      var empty = document.createElement('tr');
      var cell = tableCell('No block records found.');
      cell.colSpan = 6;
      empty.appendChild(cell);
      target.appendChild(empty);
    }
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
    if (data.page > 1) target.appendChild(pageButton('Prev', data.page - 1));
    target.appendChild(document.createTextNode('Page ' + (data.page || 1) + ' / ' + (data.total_pages || 1) + ' (' + (data.total || 0) + ' total)'));
    if (data.page < data.total_pages) target.appendChild(pageButton('Next', data.page + 1));
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
        button.dataset.action = 'blocklist.device-toggle';
        button.dataset.deviceName = device.name;
        target.appendChild(button);
      });
    });
  }

  function toggleDevice(button) {
    var name = button.dataset.deviceName;
    state.selectedDevices[name] = !state.selectedDevices[name];
    button.classList.toggle('active', state.selectedDevices[name]);
  }

  function submitManual(mode) {
    var input = document.getElementById('bl-ip-input');
    var ips = (input ? input.value : '').split(/[\n,;]+/).map(function (item) { return item.trim(); }).filter(Boolean);
    if (!ips.length) { appendResult('Enter IP addresses'); return; }
    var payload = { ips: ips, devices: selectedDevices() };
    if (mode === 'block') payload.reason = (document.getElementById('bl-reason-input') || {}).value || 'Manual block from Blocklist';
    appendResult((mode === 'block' ? 'Blocking ' : 'Unblocking ') + ips.length + ' IPs...');
    app.http.json('/admin/blocklist/' + mode, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload) })
      .then(function (result) {
        (result.results || []).forEach(function (item) { appendResult((item.success ? 'OK ' : 'FAIL ') + item.device + ': ' + item.ip + ' - ' + (item.message || '')); });
        appendResult((result.success ? 'DONE: ' : 'FAIL: ') + (result.message || ''));
        window.setTimeout(function () { loadLedger('all'); }, 300);
      }).catch(function (error) { appendResult('Error: ' + error.message); });
  }

  app.register('blocklist', {
    actions: {
      'blocklist.manual-block': { handler: function () { submitManual('block'); } },
      'blocklist.manual-unblock': { handler: function () { submitManual('unblock'); } },
      'blocklist.filter': { handler: function (context) { loadLedger(context.element.dataset.ledgerFilter); } },
      'blocklist.search': { handler: function (context) { search(context.element.value); }, events: ['input'], preventDefault: false },
      'blocklist.refresh': { handler: function () { fetchLedger(); } },
      'blocklist.export': { handler: function (context) { window.open('/admin/blocklist/export?format=' + encodeURIComponent(context.element.dataset.format), '_blank'); } },
      'blocklist.page': { handler: function (context) { state.page = Number(context.element.dataset.ledgerPage); fetchLedger(); } },
      'blocklist.notes-edit': { handler: function (context) { editNotes(context.element); } },
      'blocklist.device-toggle': { handler: function (context) { toggleDevice(context.element); } }
    },
    mount: function (root) {
      var page = root && (root.id === 'ledger-tbody' || root.querySelector && root.querySelector('#ledger-tbody'));
      if (page) { loadDevices(); loadLedger('all'); }
    },
    unmount: function (root) {
      var page = root && (root.id === 'ledger-tbody' || root.querySelector && root.querySelector('#ledger-tbody'));
      if (!page || state.timer === null) return;
      window.clearTimeout(state.timer);
      state.timer = null;
    },
    loadLedger: loadLedger
  });
}());
