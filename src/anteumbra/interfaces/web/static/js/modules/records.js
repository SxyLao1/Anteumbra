/* Records, quarantine, and safe source-viewer workflows. */
(function () {
  'use strict';

  var app = window.Anteumbra;
  var selectionFactory = window.AnteumbraSelectionController;
  var state = {
    records: selectionFactory.create({
      checkboxSelector: '.rec-checkbox', countSelector: '.rec-count',
      buttonSelector: '.rec-batch-btn', datasetKey: 'allPaths',
      onInvalidMetadata: function () { app.ui.toast('Selection metadata is invalid.', 'error'); }
    }),
    quarantine: selectionFactory.create({
      checkboxSelector: '.q-checkbox', countSelector: '.q-count',
      buttonSelector: '.q-batch-btn', datasetKey: 'allQids',
      onInvalidMetadata: function () { app.ui.toast('Selection metadata is invalid.', 'error'); }
    }),
    lineWrap: false
  };
  var dangerousTokens = /(eval|assert|system|exec|passthru|shell_exec|popen|proc_open)\s*\(|\b(base64_decode|gzinflate|str_rot13|gzuncompress)\s*\(|\b(file_get_contents|file_put_contents|move_uploaded_file)\s*\(|\b\$_(?:GET|POST|REQUEST|SERVER|FILES|COOKIE)\b/gi;

  function containerFor(element, selector) {
    return element && element.closest(selector);
  }

  function visibleContainer(selector) {
    return Array.from(document.querySelectorAll(selector)).find(function (item) {
      return item.offsetParent !== null;
    }) || document.querySelector(selector);
  }

  function updateRecordControls() {
    var count = state.records.size;
    document.querySelectorAll('.rec-count').forEach(function (item) { item.textContent = count + ' selected'; });
    document.querySelectorAll('.rec-batch-btn').forEach(function (item) { item.disabled = count === 0; });
  }

  function updateQuarantineControls() {
    var count = state.quarantine.size;
    document.querySelectorAll('.q-count').forEach(function (item) { item.textContent = count + ' selected'; });
    document.querySelectorAll('.q-batch-btn').forEach(function (item) { item.disabled = count === 0; });
  }

  function restoreSelections(root) {
    var scope = root && root.querySelectorAll ? root : document;
    scope.querySelectorAll('.rec-checkbox').forEach(function (checkbox) { checkbox.checked = state.records.has(checkbox.value); });
    scope.querySelectorAll('.q-checkbox').forEach(function (checkbox) { checkbox.checked = state.quarantine.has(checkbox.value); });
    updateRecordControls();
    updateQuarantineControls();
  }

  function setVisibleCheckboxes(container, selector, selection, checked) {
    (container || document).querySelectorAll(selector).forEach(function (checkbox) {
      checkbox.checked = checked;
      if (checked) selection.add(checkbox.value); else selection.delete(checkbox.value);
    });
  }

  function selectAllFromDataset(container, key, selection) {
    if (!container || !container.dataset[key]) return;
    try {
      JSON.parse(container.dataset[key]).forEach(function (value) { selection.add(String(value)); });
    } catch (_) {
      app.ui.toast('Selection metadata is invalid.', 'error');
    }
  }

  function filterList(input, itemSelector, source) {
    var keyword = String(input.value || '').toLowerCase();
    var target = input.dataset.container ? document.getElementById(input.dataset.container) : input.closest('[data-record-list]');
    if (!target) target = document;
    target.querySelectorAll(itemSelector).forEach(function (item) {
      var text = source(item).toLowerCase();
      item.style.display = !keyword || text.indexOf(keyword) >= 0 ? '' : 'none';
    });
  }

  function refreshRecords(container) {
    if (!container || !window.htmx) return;
    var audit = container.dataset.auditMode === 'true' ? '&audit=true' : '';
    window.htmx.ajax('GET', '/admin/records?compact=1' + audit, { target: '#' + container.id, swap: 'outerHTML' });
  }

  function refreshQuarantine(container) {
    if (!container || !window.htmx) return;
    var status = encodeURIComponent(container.dataset.currentStatus || 'quarantined');
    window.htmx.ajax('GET', '/admin/quarantine?status=' + status, { target: '#' + container.id, swap: 'outerHTML' });
  }

  function batchRecords(action, trigger) {
    var records = Array.from(state.records);
    if (!records.length) return;
    var labels = { quarantine: 'Quarantine', false_positive: 'Mark as FP', delete: 'Delete' };
    if (!app.confirm(labels[action] + ' ' + records.length + ' records?')) return;
    var body = new URLSearchParams({ action: action });
    records.forEach(function (path) { body.append('file_paths[]', path); });
    app.http.json('/admin/records/batch', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: body.toString()
    }).then(function (result) {
      if (result.error) throw new Error(result.error);
      window.alert('Done: ' + (result.success || 0) + ' success, ' + (result.skipped || 0) + ' skipped, ' + (result.failed || 0) + ' failed');
      state.records.clear();
      updateRecordControls();
      document.dispatchEvent(new Event('anteumbra:stats-refresh'));
      refreshRecords(visibleContainer('[id^="records-table-container"]') || containerFor(trigger, '[id^="records-table-container"]'));
    }).catch(function (error) {
      window.alert('Batch failed: ' + error.message);
    });
  }

  function batchQuarantine(action, trigger) {
    var ids = Array.from(state.quarantine);
    if (!ids.length) return;
    var labels = { restore: 'Restore', delete: 'Delete' };
    if (!app.confirm(labels[action] + ' ' + ids.length + ' quarantine records?')) return;
    var body = new URLSearchParams({ action: action });
    ids.forEach(function (id) { body.append('qids[]', id); });
    app.http.json('/admin/quarantine/batch', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: body.toString()
    }).then(function (result) {
      if (result.error) throw new Error(result.error);
      window.alert('Done: ' + (result.success || 0) + ' success, ' + (result.failed || 0) + ' failed');
      state.quarantine.clear();
      updateQuarantineControls();
      document.dispatchEvent(new Event('anteumbra:stats-refresh'));
      refreshQuarantine(visibleContainer('#quarantine-list-container') || containerFor(trigger, '#quarantine-list-container'));
    }).catch(function (error) {
      window.alert('Batch failed: ' + error.message);
    });
  }

  function decodeEscapedContent(value) {
    var decoder = document.createElement('textarea');
    decoder.innerHTML = String(value || '');
    return decoder.value;
  }

  function highlightClass(token) {
    var value = token.toLowerCase();
    if (/^(eval|assert|system|exec|passthru|shell_exec|popen|proc_open)/.test(value)) return 'kw-danger';
    if (/^(base64_decode|gzinflate|str_rot13|gzuncompress)/.test(value)) return 'kw-warn';
    if (/^(file_get_contents|file_put_contents|move_uploaded_file)/.test(value)) return 'kw-info';
    return 'kw-var';
  }

  function renderSourceContent(target, escapedContent) {
    var content = decodeEscapedContent(escapedContent);
    target.replaceChildren();
    dangerousTokens.lastIndex = 0;
    var cursor = 0;
    var match;
    while ((match = dangerousTokens.exec(content)) !== null) {
      target.appendChild(document.createTextNode(content.slice(cursor, match.index)));
      var token = document.createElement('span');
      token.className = highlightClass(match[0]);
      token.textContent = match[0];
      target.appendChild(token);
      cursor = match.index + match[0].length;
    }
    target.appendChild(document.createTextNode(content.slice(cursor)));
  }

  function showSource(label, query) {
    var modal = app.ui.showModal('file-viewer-modal');
    if (!modal) return;
    var path = document.getElementById('fv-file-path');
    var size = document.getElementById('fv-file-size');
    var content = document.getElementById('fv-content');
    if (path) path.textContent = label;
    if (size) size.textContent = 'Loading...';
    if (content) content.replaceChildren();
    app.http.json('/admin/file/content?' + query, { headers: { 'HX-Request': 'true' } })
      .then(function (result) {
        if (path) path.textContent = result.path || label;
        if (size) {
          var displaySize = result.size > 1024 ? (result.size / 1024).toFixed(1) + ' KB' : result.size + ' B';
          size.textContent = displaySize + ' | ' + result.lines + ' lines';
        }
        if (content) {
          renderSourceContent(content, result.content);
          content.style.whiteSpace = state.lineWrap ? 'pre-wrap' : 'pre';
        }
      })
      .catch(function (error) {
        if (size) size.textContent = 'ERROR';
        if (content) content.textContent = 'Error: ' + error.message;
      });
  }

  function closeSource() { app.ui.hideModal('file-viewer-modal'); }

  function copySource() {
    var content = document.getElementById('fv-content');
    if (!content || !navigator.clipboard) return;
    navigator.clipboard.writeText(content.textContent || '').then(function () {
      app.ui.toast('Source copied.', 'success');
    });
  }

  function toggleWrap(trigger) {
    state.lineWrap = !state.lineWrap;
    var content = document.getElementById('fv-content');
    if (content) content.style.whiteSpace = state.lineWrap ? 'pre-wrap' : 'pre';
    if (trigger) trigger.textContent = state.lineWrap ? 'Unwrap' : 'Wrap';
  }

  function openQuarantineDetail(trigger) {
    var modal = document.getElementById('quarantine-detail-modal');
    if (modal) app.ui.showModal(modal);
  }

  function closeRecordDetail() { app.ui.hideModal('record-detail-modal-overlay'); }

  function openProfileFromRecord(trigger) {
    var dashboard = app.module('dashboard');
    if (!dashboard || typeof dashboard.navigate !== 'function') return;
    closeRecordDetail();
    dashboard.navigate('profiles/' + trigger.dataset.profileId, 'Profile ' + trigger.dataset.profileLabel);
  }

  function closeQuarantineDetail() { app.ui.hideModal('quarantine-detail-modal'); }

  app.register('records', {
    actions: {
      'records.selection-change': { handler: function (context) {
        var checkbox = context.element;
        if (checkbox.checked) state.records.add(checkbox.value); else state.records.delete(checkbox.value);
        updateRecordControls();
      }, events: ['change'], preventDefault: false },
      'records.select-page': { handler: function (context) {
        setVisibleCheckboxes(containerFor(context.element, '[id^="records-table-container"]'), '.rec-checkbox', state.records, true);
        updateRecordControls();
      } },
      'records.select-all': { handler: function (context) {
        var container = containerFor(context.element, '[id^="records-table-container"]');
        selectAllFromDataset(container, 'allPaths', state.records);
        setVisibleCheckboxes(container, '.rec-checkbox', state.records, true);
        updateRecordControls();
      } },
      'records.clear-selection': { handler: function (context) {
        state.records.clear();
        setVisibleCheckboxes(containerFor(context.element, '[id^="records-table-container"]'), '.rec-checkbox', state.records, false);
        updateRecordControls();
      } },
      'records.batch': { handler: function (context) { batchRecords(context.element.dataset.batchAction, context.element); } },
      'records.filter': { handler: function (context) {
        filterList(context.element, '.record-item', function (item) { return (item.dataset.path || '') + ' ' + (item.textContent || ''); });
      }, events: ['input'], preventDefault: false },
      'quarantine.selection-change': { handler: function (context) {
        var checkbox = context.element;
        if (checkbox.checked) state.quarantine.add(checkbox.value); else state.quarantine.delete(checkbox.value);
        updateQuarantineControls();
      }, events: ['change'], preventDefault: false },
      'quarantine.select-page': { handler: function (context) {
        setVisibleCheckboxes(containerFor(context.element, '#quarantine-list-container'), '.q-checkbox', state.quarantine, true);
        updateQuarantineControls();
      } },
      'quarantine.select-all': { handler: function (context) {
        var container = containerFor(context.element, '#quarantine-list-container');
        selectAllFromDataset(container, 'allQids', state.quarantine);
        setVisibleCheckboxes(container, '.q-checkbox', state.quarantine, true);
        updateQuarantineControls();
      } },
      'quarantine.clear-selection': { handler: function (context) {
        state.quarantine.clear();
        setVisibleCheckboxes(containerFor(context.element, '#quarantine-list-container'), '.q-checkbox', state.quarantine, false);
        updateQuarantineControls();
      } },
      'quarantine.batch': { handler: function (context) { batchQuarantine(context.element.dataset.batchAction, context.element); } },
      'quarantine.filter': { handler: function (context) {
        filterList(context.element, '.record-item', function (item) { return item.textContent || ''; });
      }, events: ['input'], preventDefault: false },
      'records.view-path': { handler: function (context) {
        var path = context.element.dataset.filePath || (context.element.closest('.record-item') || {}).dataset.path;
        if (path) showSource(path, 'path=' + encodeURIComponent(path));
      } },
      'records.view-quarantine': { handler: function (context) {
        var id = context.element.dataset.quarantineId;
        if (id) showSource('Quarantine: ' + id, 'qid=' + encodeURIComponent(id));
      } },
      'records.file-close': { handler: closeSource },
      'records.file-copy': { handler: copySource },
      'records.file-wrap': { handler: function (context) { toggleWrap(context.element); } },
      'quarantine.detail-open': { handler: function (context) { openQuarantineDetail(context.element); } },
      'quarantine.detail-close': { handler: closeQuarantineDetail },
      'records.detail-close': { handler: closeRecordDetail },
      'records.detail-profile': { handler: function (context) { openProfileFromRecord(context.element); } }
    },
    mount: function (root) {
      restoreSelections(root);
      var recordDetail = root && root.id === 'record-detail-modal' ? root : root && root.querySelector && root.querySelector('#record-detail-modal');
      if (recordDetail && recordDetail.childElementCount) app.ui.showModal('record-detail-modal-overlay');
    },
    selectedRecords: function () { return new Set(state.records); },
    selectedQuarantine: function () { return new Set(state.quarantine); }
  });
}());
