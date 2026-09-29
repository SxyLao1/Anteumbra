/* Block ledger and device broadcast workflows. */
(function () {
  'use strict';

  var app = window.Anteumbra;
  var state = { filter: 'all', page: 1, query: '', timer: null, devices: {}, selectedDevices: {} };
  function scopeUrl(url) {
    var site = window.AnteumbraSite && window.AnteumbraSite.current();
    return site ? url + (url.indexOf('?') >= 0 ? '&' : '?') + 'site_id=' + encodeURIComponent(site) : url;
  }
  function label(zh, en) { return document.documentElement.lang.indexOf('zh') === 0 ? zh : en; }

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
    app.http.json(scopeUrl('/admin/blocklist/data?source=' + encodeURIComponent(state.filter) + '&page=' + state.page + '&q=' + encodeURIComponent(state.query)))
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
      row.appendChild(tableCell(entry.broadcast_status || 'unknown'));
      target.appendChild(row);
    });
    if (!target.childElementCount) {
      var empty = document.createElement('tr');
      var cell = tableCell(app.t('No block records found.'));
      cell.colSpan = 7;
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
