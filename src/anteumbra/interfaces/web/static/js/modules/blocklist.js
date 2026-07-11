/* Anteumbra blocklist module */
// All functions intentionally global — HTML onclick handlers depend on them
/* ============================================================
   v1.9.0: Block Ledger (台账)
   ============================================================ */
window._ledgerFilter = 'all';
window._ledgerPage = 1;
window._ledgerSearch = '';
var _ledgerSearchTimer = null;

function loadLedger(source) {
  window._ledgerFilter = source || 'all';
  window._ledgerPage = 1;
  document.querySelectorAll('.ledger-filter').forEach(function(b) {
    b.style.color = '#888'; b.style.borderBottomColor = 'transparent'; b.classList.remove('active');
  });
  var fb = document.getElementById('filter-' + window._ledgerFilter);
  if (fb) { fb.style.color = '#00ff41'; fb.style.borderBottom = '2px solid #00ff41'; fb.classList.add('active'); }
  _fetchLedger();
}
function ledgerSearch(val) {
  window._ledgerSearch = val; window._ledgerPage = 1;
  clearTimeout(_ledgerSearchTimer);
  _ledgerSearchTimer = setTimeout(_fetchLedger, 300);
}
function _fetchLedger() {
  var tbody = document.getElementById('ledger-tbody');
  if (!tbody) return;
  tbody.innerHTML = '<tr><td colspan="6" style="padding:24px;text-align:center;"><div class="spinner"></div></td></tr>';
  fetch('/admin/blocklist/data?source=' + window._ledgerFilter + '&page=' + window._ledgerPage + '&q=' + encodeURIComponent(window._ledgerSearch))
    .then(function(r) { return r.json(); })
    .then(renderLedger);
}
function renderLedger(data) {
  var s = data.stats || {};
  document.getElementById('ledger-stat-total').textContent = s.total || 0;
  document.getElementById('ledger-stat-auto').textContent = s.auto || 0;
  document.getElementById('ledger-stat-manual').textContent = s.manual || 0;
  document.getElementById('ledger-stat-today').textContent = s.today || 0;
  var tbody = document.getElementById('ledger-tbody');
  if (!data.entries || !data.entries.length) {
    tbody.innerHTML = '<tr><td colspan="6" style="padding:24px;text-align:center;color:#555;">No block records found.</td></tr>';
    document.getElementById('ledger-pagination').innerHTML = '0 records';
    return;
  }
  tbody.innerHTML = '';
  data.entries.forEach(function(e) {
    var sc = e.source === 'auto' ? '#ffaa00' : '#888';
    var st = e.broadcast_status === 'success' ? '#00ff41' : e.broadcast_status === 'partial' ? '#ffaa00' : '#ff4444';
    var stIcon = e.broadcast_status === 'success' ? 'V' : e.broadcast_status === 'partial' ? '~' : 'X';
    var notes = _escHtml(e.notes || '');
    var reason = _escHtml((e.reason || '').substring(0, 80));
    tbody.insertAdjacentHTML('beforeend',
      '<tr style="border-bottom:1px solid #111;">'
      + '<td style="padding:4px 10px;"><code style="color:#ccc;font-size:10px;">' + _escHtml(e.ip) + '</code></td>'
      + '<td style="padding:4px 10px;text-align:center;"><span style="color:' + sc + ';font-size:9px;">' + e.source + '</span></td>'
      + '<td style="padding:4px 10px;color:#888;font-size:10px;max-width:250px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;" title="' + _escHtml(e.reason||'') + '">' + reason + '</td>'
      + '<td style="padding:4px 10px;" class="notes-cell" data-ip="' + _escHtml(e.ip) + '" onclick="startEditNotes(this)">'
      + '<span style="color:' + (notes?'#ccc':'#555') + ';font-size:10px;cursor:pointer;">' + (notes || '[add note]') + '</span></td>'
      + '<td style="padding:4px 10px;color:#555;font-size:9px;">' + (e.blocked_at||'').substring(0,16) + '</td>'
      + '<td style="padding:4px 10px;text-align:center;"><span style="color:' + st + ';font-size:9px;" title="' + _escHtml((e.broadcast_devices||[]).join(', ')) + '">' + stIcon + '</span></td>'
      + '</tr>');
  });
  var pg = document.getElementById('ledger-pagination');
  if (data.total_pages > 1) {
    pg.innerHTML = (data.page > 1 ? '<button class="btn btn-ghost btn-sm" style="font-size:10px;" onclick="window._ledgerPage=' + (data.page-1) + ';_fetchLedger()">Prev</button> ' : '')
      + '<span>Page ' + data.page + ' / ' + data.total_pages + ' (' + data.total + ' total)</span>'
      + (data.page < data.total_pages ? ' <button class="btn btn-ghost btn-sm" style="font-size:10px;" onclick="window._ledgerPage=' + (data.page+1) + ';_fetchLedger()">Next</button>' : '');
  } else {
    pg.innerHTML = '<span>' + (data.total||0) + ' records</span>';
  }
}
function startEditNotes(cell) {
  if (cell.querySelector('input')) return;
  var ip = cell.dataset.ip;
  var curText = (cell.textContent || '').trim();
  if (curText === '[add note]') curText = '';
  var input = document.createElement('input');
  input.type = 'text'; input.value = curText;
  input.style.cssText = 'background:#111;color:#ccc;border:1px solid #00ff41;padding:2px 6px;font-size:10px;width:100%;font-family:var(--font-mono);';
  input.addEventListener('blur', function() { saveNotes(ip, input.value, cell); });
  input.addEventListener('keydown', function(ev) {
    if (ev.key==='Enter') input.blur();
    if (ev.key==='Escape') { cell.innerHTML = '<span style="color:'+(curText?'#ccc':'#555')+';font-size:10px;cursor:pointer;">'+(curText||'[add note]')+'</span>'; }
  });
  cell.innerHTML = ''; cell.appendChild(input); input.focus();
}
function saveNotes(ip, notes, cell) {
  fetch('/admin/blocklist/notes', {
    method: 'POST', headers: {'Content-Type':'application/json'},
    body: JSON.stringify({ip:ip, notes:notes})
  }).then(function(r) { return r.json(); }).then(function() {
    cell.innerHTML = '<span style="color:'+(notes?'#ccc':'#555')+';font-size:10px;cursor:pointer;">'+(notes||'[add note]')+'</span>';
  });
}
function exportLedger(fmt) {
  window.open('/admin/blocklist/export?format=' + fmt, '_blank');
}

// ── Manual Block/Unblock Panel ──
window._blDevices = window._blDevices || {};
window._blSelected = window._blSelected || {};

function loadBlocklistDevices() {
  fetch('/admin/blocklist/devices')
    .then(function(r) { return r.json(); })
    .then(function(d) {
      var container = document.getElementById('bl-device-toggles');
      if (!container) return;
      window._blDevices = {};
      window._blSelected = {};
      container.innerHTML = '';
      (d.devices || []).forEach(function(dev, i) {
        window._blDevices[dev.name] = dev;
        window._blSelected[dev.name] = false;
        var btn = document.createElement('button');
        btn.className = 'btn btn-ghost btn-sm bl-dev-btn';
        btn.textContent = dev.name;
        btn.title = dev.available ? 'Click to toggle' : 'Device unavailable';
        btn.style.cssText = 'font-size:9px;padding:2px 8px;color:#555;border:1px solid #333;';
        if (!dev.available) { btn.style.opacity = '0.4'; btn.disabled = true; }
        btn.onclick = function() { toggleBlDevice(dev.name, btn); };
        container.appendChild(btn);
      });
    });
}
function toggleBlDevice(name, btn) {
  window._blSelected[name] = !window._blSelected[name];
  if (window._blSelected[name]) {
    btn.style.color = '#00ff41'; btn.style.borderColor = '#00ff41'; btn.style.background = '#0a1a0a';
  } else {
    btn.style.color = '#555'; btn.style.borderColor = '#333'; btn.style.background = '';
  }
}
function _getSelectedDevices() {
  return Object.keys(window._blSelected).filter(function(k) { return window._blSelected[k]; });
}
function _blAppendResult(msg) {
  var el = document.getElementById('bl-result');
  if (!el) return;
  el.style.display = 'block';
  var now = new Date().toLocaleTimeString();
  el.innerHTML = '[' + now + '] ' + msg + '\n' + el.innerHTML;
}
function manualBlock() {
  var ips = (document.getElementById('bl-ip-input')?.value || '').split(/[\n,;]+/).map(function(s){return s.trim()}).filter(Boolean);
  if (!ips.length) { _blAppendResult('Enter IP addresses'); return; }
  var reason = document.getElementById('bl-reason-input')?.value?.trim() || 'Manual block from Blocklist';
  var devices = _getSelectedDevices();
  _blAppendResult('Blocking ' + ips.length + ' IPs on ' + (devices.length || 'all') + ' device(s)...');
  var csrf = document.querySelector('meta[name="csrf-token"]');
  fetch('/admin/blocklist/block', {
    method: 'POST', headers: {'Content-Type':'application/json','X-CSRFToken':csrf?.content||''},
    body: JSON.stringify({ips:ips, reason:reason, devices:devices})
  }).then(function(r){return r.json()}).then(function(d){
    (d.results||[]).forEach(function(r){ _blAppendResult((r.success?'OK':'FAIL') + ' ' + r.device + ': ' + r.ip + ' — ' + (r.message||'')); });
    _blAppendResult((d.success?'DONE':'FAIL') + ': ' + d.message);
    setTimeout(function(){ if(typeof loadLedger==='function') loadLedger('all'); }, 500);
  }).catch(function(e){ _blAppendResult('Error: ' + e.message); });
}
function manualUnblock() {
  var ips = (document.getElementById('bl-ip-input')?.value || '').split(/[\n,;]+/).map(function(s){return s.trim()}).filter(Boolean);
  if (!ips.length) { _blAppendResult('Enter IP addresses'); return; }
  var devices = _getSelectedDevices();
  _blAppendResult('Unblocking ' + ips.length + ' IPs on ' + (devices.length || 'all') + ' device(s)...');
  var csrf = document.querySelector('meta[name="csrf-token"]');
  fetch('/admin/blocklist/unblock', {
    method: 'POST', headers: {'Content-Type':'application/json','X-CSRFToken':csrf?.content||''},
    body: JSON.stringify({ips:ips, devices:devices})
  }).then(function(r){return r.json()}).then(function(d){
    (d.results||[]).forEach(function(r){ _blAppendResult((r.success?'OK':'FAIL') + ' ' + r.device + ': ' + r.ip + ' — ' + (r.message||'')); });
    _blAppendResult((d.success?'DONE':'FAIL') + ': ' + d.message);
    setTimeout(function(){ if(typeof loadLedger==='function') loadLedger('all'); }, 500);
  }).catch(function(e){ _blAppendResult('Error: ' + e.message); });
}
