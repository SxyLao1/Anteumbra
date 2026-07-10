/* Trident v1.9.1: records module */
// All functions intentionally global — HTML onclick handlers depend on them
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
    if (!d) return;  // CSRF error already handled
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

// ═══════════════════════════════════════════════════════════════
// v1.8.4: 安全文件内容查看器
// ═══════════════════════════════════════════════════════════════

var _fvLineWrap = false;

// 危险关键词高亮规则
var _dangerPatterns = [
  {re: /(eval)\s*\(/gi, cls: 'kw-danger'},
  {re: /(assert)\s*\(/gi, cls: 'kw-danger'},
  {re: /(system)\s*\(/gi, cls: 'kw-danger'},
  {re: /(exec)\s*\(/gi, cls: 'kw-danger'},
  {re: /(passthru)\s*\(/gi, cls: 'kw-danger'},
  {re: /(shell_exec)\s*\(/gi, cls: 'kw-danger'},
  {re: /(popen)\s*\(/gi, cls: 'kw-danger'},
  {re: /(proc_open)\s*\(/gi, cls: 'kw-danger'},
  {re: /\b(base64_decode)\s*\(/gi, cls: 'kw-warn'},
  {re: /\b(gzinflate)\s*\(/gi, cls: 'kw-warn'},
  {re: /\b(str_rot13)\s*\(/gi, cls: 'kw-warn'},
  {re: /\b(gzuncompress)\s*\(/gi, cls: 'kw-warn'},
  {re: /\b(file_get_contents)\s*\(/gi, cls: 'kw-info'},
  {re: /\b(file_put_contents)\s*\(/gi, cls: 'kw-info'},
  {re: /\b(move_uploaded_file)\s*\(/gi, cls: 'kw-info'},
  {re: /\b(\$_GET)\b/gi, cls: 'kw-var'},
  {re: /\b(\$_POST)\b/gi, cls: 'kw-var'},
  {re: /\b(\$_REQUEST)\b/gi, cls: 'kw-var'},
  {re: /\b(\$_SERVER)\b/gi, cls: 'kw-var'},
  {re: /\b(\$_FILES)\b/gi, cls: 'kw-var'},
  {re: /\b(\$_COOKIE)\b/gi, cls: 'kw-var'},
];

function _highlightDangerKeywords(html) {
  // 只在非 HTML 标签的部分做高亮（保护已转义的内容）
  var result = html;
  _dangerPatterns.forEach(function(p) {
    result = result.replace(p.re, function(match) {
      return '<span class="' + p.cls + '">' + match + '</span>';
    });
  });
  return result;
}

function openFileViewerByPath(filePath) {
  if (!filePath) return;
  _showFileViewerLoading(filePath);
  fetch('/admin/file/content?path=' + encodeURIComponent(filePath), {
    headers: { 'HX-Request': 'true' }
  })
    .then(function(r) {
      if (!r.ok) return r.json().then(function(d) { throw new Error(d.error || 'HTTP ' + r.status); });
      return r.json();
    })
    .then(_renderFileViewer)
    .catch(function(e) {
      var content = document.getElementById('fv-content');
      if (content) content.innerHTML = '<span style="color:#ff4444;">Error: ' + e.message + '</span>';
      document.getElementById('fv-file-size').textContent = 'ERROR';
    });
}

function openFileViewerByQid(qid) {
  if (!qid) return;
  _showFileViewerLoading('Quarantine: ' + qid);
  fetch('/admin/file/content?qid=' + encodeURIComponent(qid), {
    headers: { 'HX-Request': 'true' }
  })
    .then(function(r) {
      if (!r.ok) return r.json().then(function(d) { throw new Error(d.error || 'HTTP ' + r.status); });
      return r.json();
    })
    .then(_renderFileViewer)
    .catch(function(e) {
      var content = document.getElementById('fv-content');
      if (content) content.innerHTML = '<span style="color:#ff4444;">Error: ' + e.message + '</span>';
      document.getElementById('fv-file-size').textContent = 'ERROR';
    });
}

function _showFileViewerLoading(label) {
  var m = document.getElementById('file-viewer-modal');
  if (!m) {
    // Modal template not yet in DOM — load it from server
    var container = document.body;
    var div = document.createElement('div');
    div.innerHTML = '<div id="file-viewer-modal" class="modal-overlay" style="display:flex; z-index:3000;"><div style="margin:auto; color:#00ff41;"><div class="spinner"></div><p>Loading viewer...</p></div></div>';
    // Replace the temp div with actual content
    document.body.appendChild(div.firstElementChild);
    m = document.getElementById('file-viewer-modal');
  }
  m.style.display = 'flex';
  m.style.visibility = 'visible';
  m.style.opacity = '1';
  m.classList.add('active');
  document.getElementById('fv-file-path').textContent = label;
  document.getElementById('fv-file-size').textContent = 'Loading...';
  document.getElementById('fv-content').innerHTML = '';
}

function _renderFileViewer(data) {
  document.getElementById('fv-file-path').textContent = data.path || '';
  var sizeStr = data.size > 1024 ? (data.size / 1024).toFixed(1) + ' KB' : data.size + ' B';
  if (data.truncated) sizeStr += ' [TRUNCATED >512KB]';
  document.getElementById('fv-file-size').textContent = sizeStr + ' | ' + data.lines + ' lines';

  var html = _highlightDangerKeywords(data.content);
  document.getElementById('fv-content').innerHTML = html;

  // Apply wrap if active
  if (_fvLineWrap) {
    document.getElementById('fv-content').style.whiteSpace = 'pre-wrap';
  } else {
    document.getElementById('fv-content').style.whiteSpace = 'pre';
  }
}

function closeFileViewer() {
  var m = document.getElementById('file-viewer-modal');
  if (!m) return;
  m.style.display = 'none';
  m.style.visibility = 'hidden';
  m.style.opacity = '0';
  m.classList.remove('active');
}

function copyFileContent() {
  var pre = document.getElementById('fv-content');
  if (!pre) return;
  // Get raw text (not innerHTML with highlight spans)
  var text = pre.textContent || pre.innerText || '';
  navigator.clipboard.writeText(text).then(function() {
    var btn = document.querySelector('#file-viewer-modal .btn-ghost');
    if (btn && btn.textContent === 'Copy') {
      var orig = btn.textContent;
      btn.textContent = 'Copied!';
      setTimeout(function() { btn.textContent = orig; }, 1500);
    }
  });
}

function toggleLineWrap() {
  _fvLineWrap = !_fvLineWrap;
  var pre = document.getElementById('fv-content');
  if (!pre) return;
  pre.style.whiteSpace = _fvLineWrap ? 'pre-wrap' : 'pre';
  var btn = document.querySelector('#file-viewer-modal .btn-ghost:nth-child(2)');
  if (btn) btn.textContent = _fvLineWrap ? 'Unwrap' : 'Wrap';
}

// Extend ESC key handler
document.addEventListener('keydown', function(e) {
  if (e.key === 'Escape') {
    var fv = document.getElementById('file-viewer-modal');
    if (fv && fv.style.display !== 'none') {
      closeFileViewer();
      e.stopPropagation();
    }
  }
});
