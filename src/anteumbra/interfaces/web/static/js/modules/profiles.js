/* Trident v1.9.1: profiles module */
// All functions intentionally global — HTML onclick handlers depend on them
// v1.8.1: IP cross-page selection (profile detail page)
window._ipSelected = window._ipSelected || new Set();
window._ipTotal = window._ipTotal || 0;

function _restoreIPCheckboxes() {
  document.querySelectorAll('.ip-checkbox').forEach(function(cb) {
    cb.checked = window._ipSelected.has(cb.value);
  });
  _updateIPUI();
}

function toggleIPRow(row) {
  var cb = row.querySelector('.ip-checkbox'); cb.checked = !cb.checked;
  if (cb.checked) window._ipSelected.add(cb.value); else window._ipSelected.delete(cb.value);
  _updateIPUI();
}

function toggleAllIPs(m) {
  document.querySelectorAll('.ip-checkbox').forEach(function(cb) {
    cb.checked = m.checked;
    if (m.checked) window._ipSelected.add(cb.value); else window._ipSelected.delete(cb.value);
  });
  _updateIPUI();
}

function selectAllIPs() {
  document.querySelectorAll('.ip-checkbox').forEach(function(cb) {
    cb.checked = true; window._ipSelected.add(cb.value);
  });
  _updateIPUI();
}

function selectAllIPsAll() {
  // Select all IPs across all pages — read full list from data attribute
  var section = document.getElementById('ip-table-section');
  if (section && section.dataset.allIps) {
    try {
      var allIps = JSON.parse(section.dataset.allIps);
      allIps.forEach(function(ip) { window._ipSelected.add(ip); });
    } catch(e) { console.error('Failed to parse all IPs:', e); }
  }
  // Also check visible checkboxes
  document.querySelectorAll('.ip-checkbox').forEach(function(cb) {
    cb.checked = true;
    window._ipSelected.add(cb.value);
  });
  _updateIPUI();
}

function clearIPSelection() {
  window._ipSelected.clear();
  document.querySelectorAll('.ip-checkbox').forEach(function(cb) { cb.checked = false; });
  _updateIPUI();
}

function toggleIPCheckbox(cb) {
  if (cb.checked) window._ipSelected.add(cb.value);
  else window._ipSelected.delete(cb.value);
  _updateIPUI();
}
function updateBlockBtn() { _updateIPUI(); }

/* ============================================================
   v1.9.0: Records batch selection + toolbar (class-based, no dup IDs)
   ============================================================ */
window._recSelected = window._recSelected || new Set();

function _recUpdateUI() {
  var c = window._recSelected.size;
  document.querySelectorAll('.rec-count').forEach(function(el) { el.textContent = c + ' selected'; });
  document.querySelectorAll('.rec-batch-btn').forEach(function(b) { b.disabled = c === 0; });
}
function _restoreRecCheckboxes() {
  document.querySelectorAll('.rec-checkbox').forEach(function(cb) {
    cb.checked = window._recSelected.has(cb.value);
  });
  _recUpdateUI();
}
function toggleRecCb(cb) {
  if (cb.checked) window._recSelected.add(cb.value);
  else window._recSelected.delete(cb.value);
  _recUpdateUI();
}
function selRecPage(btn) {
  var row = btn.closest('[id^="records-table-container"]');
  (row||document).querySelectorAll('.rec-checkbox').forEach(function(cb) {
    cb.checked = true; window._recSelected.add(cb.value);
  });
  _recUpdateUI();
}
function selRecAll(btn) {
  var row = btn.closest('[data-all-paths]');
  if (row && row.dataset.allPaths) {
    try { JSON.parse(row.dataset.allPaths).forEach(function(p) { window._recSelected.add(p); }); } catch(e) {}
  }
  (row||document).querySelectorAll('.rec-checkbox').forEach(function(cb) {
    cb.checked = true; window._recSelected.add(cb.value);
  });
  _recUpdateUI();
}
function clearRecSel(btn) {
  window._recSelected.clear();
  var row = btn.closest('[id^="records-table-container"]');
  (row||document).querySelectorAll('.rec-checkbox').forEach(function(cb) { cb.checked = false; });
  _recUpdateUI();
}
function _activeRecContainer(trigger) {
  if (trigger) {
    var scoped = trigger.closest('[id^="records-table-container"]');
    if (scoped) return scoped;
  }
  var containers = Array.from(document.querySelectorAll('[id^="records-table-container"]'));
  return containers.find(function(el) { return el.offsetParent !== null; }) || containers[0] || null;
}

function _triggerStatsRefresh() {
  document.dispatchEvent(new Event('anteumbra:statsRefresh'));
}

function batchRecAction(action, trigger) {
  var container = _activeRecContainer(trigger);
  var paths = Array.from(window._recSelected);
  if (!paths.length) return;
  var labels = {quarantine:'Quarantine', false_positive:'Mark as FP', delete:'Delete'};
  if (!confirm(labels[action] + ' ' + paths.length + ' records?')) return;
  var csrf = document.querySelector('meta[name="csrf-token"]');
  var token = csrf ? csrf.content : '';
  var body = 'action=' + action;
  paths.forEach(function(fp) { body += '&file_paths[]=' + encodeURIComponent(fp); });
  fetch('/admin/records/batch', {
    method: 'POST',
    headers: {'Content-Type':'application/x-www-form-urlencoded','X-CSRFToken':token},
    body: body
  })
  .then(function(r) {
    if (!r.ok && r.status === 400) {
      return r.json().then(function(d) {
        if (d.code === 'csrf_expired') { alert('Session expired. Please refresh the page.'); return null; }
        throw new Error(d.error || 'Bad request');
      });
    }
    return r.json();
  })
  .then(function(d) {
    if (!d) return;
    if (d.error) { alert('Batch failed: ' + d.error); return; }
    alert('Done: ' + (d.success||0) + ' success, ' + (d.skipped||0) + ' skipped, ' + (d.failed||0) + ' failed');
    window._recSelected.clear();
    _triggerStatsRefresh();
    if (container && window.htmx) {
      htmx.ajax('GET', '/admin/records?compact=1' + (container.dataset.auditMode === 'true'?'&audit=true':''), {target:'#'+container.id,swap:'outerHTML'});
    }
  })
  .catch(function(e) { alert('Batch failed: ' + e.message); });
}

/* ============================================================
   v1.9.0: Quarantine batch selection (class-based)
   ============================================================ */
window._qSelected = window._qSelected || new Set();

function _qUpdateUI() {
  var c = window._qSelected.size;
  document.querySelectorAll('.q-count').forEach(function(el) { el.textContent = c + ' selected'; });
  document.querySelectorAll('.q-batch-btn').forEach(function(b) { b.disabled = c === 0; });
}
function _restoreQCheckboxes() {
  document.querySelectorAll('.q-checkbox').forEach(function(cb) {
    cb.checked = window._qSelected.has(cb.value);
  });
  _qUpdateUI();
}
function toggleQCheckbox(cb) {
  if (cb.checked) window._qSelected.add(cb.value);
  else window._qSelected.delete(cb.value);
  _qUpdateUI();
}
function selQPage(btn) {
  var row = btn.closest('#quarantine-list-container');
  (row||document).querySelectorAll('.q-checkbox').forEach(function(cb) {
    cb.checked = true; window._qSelected.add(cb.value);
  });
  _qUpdateUI();
}
function selQAll(btn) {
  var row = btn.closest('[data-all-qids]');
  if (row && row.dataset.allQids) {
    try { JSON.parse(row.dataset.allQids).forEach(function(id) { window._qSelected.add(id); }); } catch(e) {}
  }
  (row||document).querySelectorAll('.q-checkbox').forEach(function(cb) {
    cb.checked = true; window._qSelected.add(cb.value);
  });
  _qUpdateUI();
}
function clearQSel(btn) {
  window._qSelected.clear();
  var row = btn.closest('#quarantine-list-container');
  (row||document).querySelectorAll('.q-checkbox').forEach(function(cb) { cb.checked = false; });
  _qUpdateUI();
}
function batchQAction(action, trigger) {
  var container = trigger ? trigger.closest('#quarantine-list-container') : document.getElementById('quarantine-list-container');
  var ids = Array.from(window._qSelected);
  if (!ids.length) return;
  var labels = {restore:'Restore', delete:'Delete'};
  if (!confirm(labels[action] + ' ' + ids.length + ' quarantine records?')) return;
  var csrf = document.querySelector('meta[name="csrf-token"]');
  var token = csrf ? csrf.content : '';
  var body = 'action=' + action;
  ids.forEach(function(id) { body += '&qids[]=' + encodeURIComponent(id); });
  fetch('/admin/quarantine/batch', {
    method: 'POST',
    headers: {'Content-Type':'application/x-www-form-urlencoded','X-CSRFToken':token},
    body: body
  })
  .then(function(r) {
    if (!r.ok && r.status === 400) {
      return r.json().then(function(d) {
        if (d.code === 'csrf_expired') { alert('Session expired. Please refresh the page.'); return null; }
        throw new Error(d.error || 'Bad request');
      });
    }
    return r.json();
  })
  .then(function(d) {
    if (!d) return;
    if (d.error) { alert('Batch failed: ' + d.error); return; }
    alert('Done: ' + (d.success||0) + ' success, ' + (d.failed||0) + ' failed');
    window._qSelected.clear();
    _triggerStatsRefresh();
    if (container && window.htmx) {
      var status = container.dataset.currentStatus || 'quarantined';
      htmx.ajax('GET', '/admin/quarantine?status=' + encodeURIComponent(status), {target:'#quarantine-list-container', swap:'outerHTML'});
    }
  })
  .catch(function(e) { alert('Batch failed: ' + e.message); });
}

function _updateIPUI() {
  var count = window._ipSelected.size;
  var countEl = document.getElementById('ip-selected-count');
  if (countEl) countEl.textContent = count + ' selected';
  var btn = document.getElementById('block-ips-btn');
  if (btn) { btn.disabled = count === 0; btn.textContent = 'Block ' + (count > 0 ? count : 'Selected') + ' IP' + (count !== 1 ? 's' : ''); }
}

function copyIP(ip) { navigator.clipboard.writeText(ip); }

function copySelectedIPs() {
  var ips = window._ipSelected.size > 0 ? Array.from(window._ipSelected) :
    Array.from(document.querySelectorAll('.ip-addr')).map(function(el) { return el.textContent.trim(); });
  navigator.clipboard.writeText(ips.join('\n'));
}

function copyAllIPs() {
  var ips = Array.from(document.querySelectorAll('.ip-addr')).map(function(el) { return el.textContent.trim(); });
  navigator.clipboard.writeText(ips.join('\n'));
}

function blockSelectedIPs() {
  var ips = Array.from(window._ipSelected);
  if (ips.length === 0) return;
  if (!confirm('Block ' + ips.length + ' IPs?\n\n' + ips.slice(0, 10).join('\n') + (ips.length > 10 ? '\n... and ' + (ips.length - 10) + ' more' : ''))) return;
  // Extract profile_id from page URL
  var profileId = '';
  var m = window.location.pathname.match(/profiles\/([a-f0-9]+)/);
  if (m) profileId = m[1];
  fetch('/admin/api/v1/blocklist/add', {
    method: 'POST', headers: {'Content-Type':'application/json','X-CSRFToken':document.querySelector('meta[name="csrf-token"]')?.content||''},
    body: JSON.stringify({ips:ips, profile_id:profileId})
  }).then(function(r){return r.json()}).then(function(d){
    alert((d.success ? 'OK' : 'FAIL') + ': ' + (d.message||'Blocked'));
    if (d.success && typeof loadBlockStatus === 'function') setTimeout(loadBlockStatus, 500);
  });
}

// v1.8.2: Block status panel (Profiles page)
function loadBlockStatus() {
  fetch('/admin/block/status')
    .then(function(r) { return r.json(); })
    .then(function(d) {
      var panel = document.getElementById('block-status-panel');
      if (!panel) return;
      document.getElementById('bs-auto').textContent = 'Auto: ' + (d.auto_block_enabled ? 'ON (>' + (d.auto_block_min_score*100) + '%)' : 'OFF');
      document.getElementById('bs-devices').textContent = 'Devices: ' + d.device_count;
      document.getElementById('bs-queue').textContent = 'Queue: ' + (d.retry_queue?.pending || 0);
      document.getElementById('bs-blocked').textContent = 'Blocked: ' + (d.blocklist?.length || 0);

      // Render queue detail
      var qlist = document.getElementById('block-queue-list');
      if (qlist && d.retry_queue?.items?.length > 0) {
        var html = '';
        d.retry_queue.items.forEach(function(item) {
          html += '<div style="padding:2px 0; border-bottom:1px solid #111;">' +
            '<code style="color:#ffaa00;">' + item.ip + '</code>' +
            ' retry ' + item.attempts + '/' + item.max_attempts +
            ' next: ' + item.next_retry_at +
            ' <span style="color:#666;">' + (item.last_error || '') + '</span></div>';
        });
        qlist.innerHTML = html;
      } else if (qlist) {
        qlist.innerHTML = '<span style="color:#666;">No pending retries</span>';
      }

      // History
      if (d.history?.length > 0) {
        var hlist = document.getElementById('block-queue-list');
        if (hlist && !d.retry_queue?.items?.length) {
          var hhtml = '<div style="color:#888;margin-top:4px;">Recent:</div>';
          d.history.slice(-10).reverse().forEach(function(h) {
            hhtml += '<div style="font-size:10px; color:' + (h.success ? '#888' : '#ff4444') + ';">' +
              h.device + ': ' + h.ip + ' — ' + h.message + '</div>';
          });
          hlist.innerHTML = hhtml;
        }
      }
    });
}

function toggleBlockDetail() {
  var d = document.getElementById('block-detail');
  if (d) d.style.display = d.style.display === 'none' ? '' : 'none';
}
