/* Records, quarantine, and safe source-viewer workflows. */
(function () {
  'use strict';

  var app = window.Anteumbra;
  var selectionFactory = window.AnteumbraSelectionController;
  var state = {
    records: selectionFactory.create({
      checkboxSelector: '.rec-checkbox', countSelector: '.rec-count',
      buttonSelector: '.rec-batch-btn', datasetKey: 'allPaths',
      onInvalidMetadata: function () { app.ui.toast(app.t('Selection metadata is invalid.'), 'error'); }
    }),
    quarantine: selectionFactory.create({
      checkboxSelector: '.q-checkbox', countSelector: '.q-count',
      buttonSelector: '.q-batch-btn', datasetKey: 'allQids',
      onInvalidMetadata: function () { app.ui.toast(app.t('Selection metadata is invalid.'), 'error'); }
    }),
    lineWrap: false
  };
  var dangerousTokens = /(eval|assert|system|exec|passthru|shell_exec|popen|proc_open)\s*\(|\b(base64_decode|gzinflate|str_rot13|gzuncompress)\s*\(|\b(file_get_contents|file_put_contents|move_uploaded_file)\s*\(|\b\$_(?:GET|POST|REQUEST|SERVER|FILES|COOKIE)\b/gi;

  function siteApi() { return window.AnteumbraSite; }

  // The active scope is server state (URL + remembered choice), so every URL a
  // module builds has to carry it or the request would silently answer with
  // every site's data.
  function siteUrl(url) {
    var site = siteApi();
    return site && site.withSite ? site.withSite(url) : url;
  }

  // A row belongs to its own site: acting on it from the aggregate list must
  // stay inside that site instead of resolving an ambiguous path.
  function scopedUrl(url, trigger) {
    var site = siteApi();
    if (!site) return url;
    var siteId = (trigger && site.rowSite(trigger)) || site.current();
    if (!siteId) return url;
    var separator = url.indexOf('?') >= 0 ? '&' : '?';
    return url + separator + 'site_id=' + encodeURIComponent(siteId);
  }

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
    document.querySelectorAll('.rec-count').forEach(function (item) { item.textContent = app.t('%(count)s selected', { count: count }); });
    document.querySelectorAll('.rec-batch-btn').forEach(function (item) { item.disabled = count === 0; });
  }

  function updateQuarantineControls() {
    var count = state.quarantine.size;
    document.querySelectorAll('.q-count').forEach(function (item) { item.textContent = app.t('%(count)s selected', { count: count }); });
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
      app.ui.toast(app.t('Selection metadata is invalid.'), 'error');
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
    window.htmx.ajax('GET', siteUrl('/admin/records?compact=1' + audit), { target: '#' + container.id, swap: 'outerHTML' });
  }

  function refreshQuarantine(container) {
    if (!container || !window.htmx) return;
    var status = encodeURIComponent(container.dataset.currentStatus || 'quarantined');
    window.htmx.ajax('GET', siteUrl('/admin/quarantine?status=' + status), { target: '#' + container.id, swap: 'outerHTML' });
  }

  function batchRecords(action, trigger) {
    var records = Array.from(state.records);
    if (!records.length) return;
    var labels = { quarantine: app.t('Quarantine'), false_positive: app.t('Mark as FP'), delete: app.t('Delete') };
    if (!app.confirm(app.t('%(action)s %(count)s records?', { action: labels[action], count: records.length }))) return;
    var body = new URLSearchParams({ action: action });
    var scope = siteApi() ? siteApi().current() : '';
    if (scope) body.set('site_id', scope);
    records.forEach(function (path) { body.append('file_paths[]', path); });
    app.http.json('/admin/records/batch', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: body.toString()
    }).then(function (result) {
      if (result.error) throw new Error(result.error);
      window.alert(app.t('Done: %(success)s success, %(skipped)s skipped, %(failed)s failed', {
        success: result.success || 0, skipped: result.skipped || 0, failed: result.failed || 0
      }));
      state.records.clear();
      updateRecordControls();
      document.dispatchEvent(new Event('anteumbra:stats-refresh'));
      refreshRecords(visibleContainer('[id^="records-table-container"]') || containerFor(trigger, '[id^="records-table-container"]'));
    }).catch(function (error) {
      window.alert(app.t('Batch failed: %(message)s', { message: error.message }));
    });
  }

  function batchQuarantine(action, trigger) {
    var ids = Array.from(state.quarantine);
    if (!ids.length) return;
    var labels = { restore: app.t('Restore'), delete: app.t('Delete') };
    if (!app.confirm(app.t('%(action)s %(count)s quarantine records?', { action: labels[action], count: ids.length }))) return;
    var body = new URLSearchParams({ action: action });
    var scope = siteApi() ? siteApi().current() : '';
    if (scope) body.set('site_id', scope);
    ids.forEach(function (id) { body.append('qids[]', id); });
    app.http.json('/admin/quarantine/batch', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: body.toString()
    }).then(function (result) {
      if (result.error) throw new Error(result.error);
      window.alert(app.t('Done: %(success)s success, %(failed)s failed', {
        success: result.success || 0, failed: result.failed || 0
      }));
      state.quarantine.clear();
      updateQuarantineControls();
      document.dispatchEvent(new Event('anteumbra:stats-refresh'));
      refreshQuarantine(visibleContainer('#quarantine-list-container') || containerFor(trigger, '#quarantine-list-container'));
    }).catch(function (error) {
      window.alert(app.t('Batch failed: %(message)s', { message: error.message }));
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
    if (size) size.textContent = app.t('Loading...');
    if (content) content.replaceChildren();
    app.http.json('/admin/file/content?' + query, { headers: { 'HX-Request': 'true' } })
      .then(function (result) {
        if (path) path.textContent = result.path || label;
        if (size) {
          var displaySize = result.size > 1024 ? (result.size / 1024).toFixed(1) + ' KB' : result.size + ' B';
          var meta = app.t('%(size)s | %(lines)s lines', { size: displaySize, lines: result.lines });
          // The encoding only matters when the file is not plain UTF-8; showing
          // it explains why the glyphs look the way they do.
          if (result.encoding && result.encoding !== 'utf-8') {
            meta += ' | ' + result.encoding;
          }
          size.textContent = meta;
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
      app.ui.toast(app.t('Source copied.'), 'success');
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

  // One way to open a detection's detail, used by the ledger, the overview
  // quadrant, the scanner results and the cluster list alike.
  function openRecordDetail(trigger) {
    var path = trigger && trigger.dataset ? trigger.dataset.filePath : '';
    if (!path) return;
    var box = document.getElementById('record-detail-modal');
    var overlay = document.getElementById('record-detail-modal-overlay');
    if (!box || !overlay) return;
    box.innerHTML = '<div class="logs-placeholder">Loading detail...</div>';
    app.ui.showModal(overlay);
    app.http.text(scopedUrl('/admin/records/detail?file_path=' + encodeURIComponent(path), trigger), {
      headers: { 'HX-Request': 'true' }
    }).then(function (html) {
      box.innerHTML = html;
      app.processHtmx(box);
    }).catch(function (error) {
      box.textContent = 'Detail failed: ' + error.message;
    });
  }

  function reviewStatus() {
    var panel = document.querySelector('.records-panel[data-status]');
    return panel ? panel.dataset.status : 'all';
  }

  function reloadLedger() {
    var panel = document.querySelector('.records-panel[data-status]');
    if (!panel) return;
    app.http.text(siteUrl('/admin/records?compact=1&status=' + encodeURIComponent(reviewStatus())), {
      headers: { 'HX-Request': 'true' }
    }).then(function (html) {
      app.swapHtml(panel, html, 'outerHTML');
    }).catch(function (error) { app.ui.toast(app.t('Reload failed: %(message)s', { message: error.message }), 'error'); });
  }

  function reviewRecord(path, mark, trigger) {
    if (!path) return;
    var action = mark ? 'mark_false_positive' : 'unmark_false_positive';
    app.http.text(scopedUrl('/admin/' + action + '/' + encodeURIComponent(path) + '?status=' + encodeURIComponent(reviewStatus()), trigger), {
      method: 'POST', headers: { 'HX-Request': 'true' }
    }).then(function () {
      app.ui.toast(app.t(mark ? 'Marked as false positive.' : 'False positive cleared.'), 'success');
      reloadLedger();
    }).catch(function (error) {
      app.ui.toast(app.t('Review failed: %(message)s', { message: error.message }), 'error');
    });
  }

  function rearmRecordAlert(trigger) {
    var path = trigger && trigger.dataset ? trigger.dataset.filePath : '';
    if (!path) return;
    app.http.text(scopedUrl('/admin/records/rearm_alert/' + encodeURIComponent(path), trigger), {
      method: 'POST', headers: { 'HX-Request': 'true' }
    }).then(function () {
      app.ui.toast(app.t('Alert re-armed.'), 'success');
      openRecordDetail(trigger);
      reloadLedger();
    }).catch(function (error) {
      app.ui.toast(app.t('Re-arm failed: %(message)s', { message: error.message }), 'error');
    });
  }

  function switchStatus(status) {
    var panel = document.querySelector('.records-panel[data-status]');
    if (!panel || !status) return;
    app.http.text(siteUrl('/admin/records?compact=1&status=' + encodeURIComponent(status)), {
      headers: { 'HX-Request': 'true' }
    }).then(function (html) {
      app.swapHtml(panel, html, 'outerHTML');
    }).catch(function (error) { app.ui.toast(app.t('Filter failed: %(message)s', { message: error.message }), 'error'); });
  }

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
      'records.detail-open': { handler: function (context) { openRecordDetail(context.element); } },
      'records.mark-fp': { handler: function (context) { reviewRecord(context.element.dataset.filePath, true, context.element); } },
      'records.unmark-fp': { handler: function (context) { reviewRecord(context.element.dataset.filePath, false, context.element); } },
      'records.status': { handler: function (context) { switchStatus(context.element.dataset.status); } },
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
      'records.detail-rearm': { handler: function (context) { rearmRecordAlert(context.element); } },
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
