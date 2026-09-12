/* Profile and IP reputation workflows. */
(function () {
  'use strict';

  var app = window.Anteumbra;
  var selected = new Set();

  function selectedCheckboxes(scope) {
    return (scope || document).querySelectorAll('.ip-checkbox');
  }

  function updateControls() {
    var count = selected.size;
    var countNode = document.getElementById('ip-selected-count');
    var button = document.getElementById('block-ips-btn');
    if (countNode) countNode.textContent = app.t('%(count)s selected', { count: count });
    if (button) {
      button.disabled = count === 0;
      button.textContent = count
        ? app.t('Block %(count)s IP(s)', { count: count })
        : app.t('Block Selected IPs');
    }
  }

  function restore(root) {
    var scope = root && root.querySelectorAll ? root : document;
    selectedCheckboxes(scope).forEach(function (checkbox) {
      checkbox.checked = selected.has(checkbox.value);
    });
    updateControls();
  }

  function copy(text) {
    if (!navigator.clipboard) {
      app.ui.toast(app.t('Clipboard access is unavailable.'), 'warning');
      return;
    }
    navigator.clipboard.writeText(text).then(function () {
      app.ui.toast(app.t('Copied.'), 'success');
    }).catch(function () {
      app.ui.toast(app.t('Copy failed.'), 'error');
    });
  }

  function selectedOrVisible() {
    return selected.size ? Array.from(selected) : Array.from(document.querySelectorAll('.ip-addr')).map(function (node) {
      return node.textContent.trim();
    });
  }

  function blockSelected(trigger) {
    var ips = Array.from(selected);
    if (!ips.length) return;
    var listing = ips.slice(0, 10).join('\n') +
      (ips.length > 10 ? '\n' + app.t('... and %(count)s more', { count: ips.length - 10 }) : '');
    if (!app.confirm(app.t('Block %(count)s IPs?', { count: ips.length }) + '\n\n' + listing)) return;
    var page = trigger.closest('[data-profile-id]');
    var profileId = page ? page.dataset.profileId : '';
    app.http.json('/admin/api/v1/blocklist/add', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ips: ips, profile_id: profileId })
    }).then(function (result) {
      app.ui.toast((result.success ? app.t('OK: ') : app.t('FAIL: ')) + (result.message || app.t('Blocked')), result.success ? 'success' : 'error');
      if (result.success) window.setTimeout(loadBlockStatus, 350);
    }).catch(function (error) {
      app.ui.toast(app.t('Block failed: %(message)s', { message: error.message }), 'error');
    });
  }

  function appendLine(parent, content, className) {
    var node = document.createElement('div');
    if (className) node.className = className;
    node.textContent = content;
    parent.appendChild(node);
  }

  function loadBlockStatus() {
    var panel = document.getElementById('block-status-panel');
    if (!panel || panel.dataset.frontendLoaded) return;
    panel.dataset.frontendLoaded = 'true';
    app.http.json('/admin/block/status').then(function (result) {
      var values = {
        'bs-auto': result.auto_block_enabled
          ? app.t('Auto: ON (>%(score)s%%)', { score: result.auto_block_min_score * 100 })
          : app.t('Auto: OFF'),
        'bs-devices': app.t('Devices: %(count)s', { count: result.device_count }),
        'bs-queue': app.t('Queue: %(count)s', { count: (result.retry_queue && result.retry_queue.pending) || 0 }),
        'bs-blocked': app.t('Blocked: %(count)s', { count: (result.blocklist && result.blocklist.length) || 0 })
      };
      Object.keys(values).forEach(function (id) {
        var node = document.getElementById(id);
        if (node) node.textContent = values[id];
      });
      var list = document.getElementById('block-queue-list');
      if (!list) return;
      list.replaceChildren();
      var queued = result.retry_queue && result.retry_queue.items || [];
      if (queued.length) {
        queued.forEach(function (item) {
          appendLine(list, item.ip + ' retry ' + item.attempts + '/' + item.max_attempts + ' next: ' + item.next_retry_at + ' ' + (item.last_error || ''));
        });
      } else if (result.history && result.history.length) {
        appendLine(list, 'Recent:');
        result.history.slice(-10).reverse().forEach(function (item) {
          appendLine(list, item.device + ': ' + item.ip + ' - ' + item.message);
        });
      } else {
        appendLine(list, 'No pending retries');
      }
    }).catch(function (error) {
      panel.removeAttribute('data-frontend-loaded');
      app.ui.toast(app.t('Block status unavailable: %(message)s', { message: error.message }), 'warning');
    });
  }

  function toggleBlockDetail() {
    var detail = document.getElementById('block-detail');
    if (!detail) return;
    detail.hidden = !detail.hidden;
  }

  app.register('profiles', {
    actions: {
      'profiles.ip-toggle': { handler: function (context) {
        var checkbox = context.element;
        if (checkbox.checked) selected.add(checkbox.value); else selected.delete(checkbox.value);
        updateControls();
      }, events: ['change'], preventDefault: false },
      'profiles.ip-row-toggle': { handler: function (context) {
        var checkbox = context.element.querySelector('.ip-checkbox');
        if (!checkbox) return;
        checkbox.checked = !checkbox.checked;
        if (checkbox.checked) selected.add(checkbox.value); else selected.delete(checkbox.value);
        updateControls();
      } },
      'profiles.ip-toggle-all': { handler: function (context) {
        var scope = context.element.closest('#ip-table-section') || document;
        selectedCheckboxes(scope).forEach(function (checkbox) {
          checkbox.checked = context.element.checked;
          if (checkbox.checked) selected.add(checkbox.value); else selected.delete(checkbox.value);
        });
        updateControls();
      }, events: ['change'], preventDefault: false },
      'profiles.ip-select-page': { handler: function (context) {
        var scope = context.element.closest('#ip-table-section') || document;
        selectedCheckboxes(scope).forEach(function (checkbox) { checkbox.checked = true; selected.add(checkbox.value); });
        updateControls();
      } },
      'profiles.ip-select-all': { handler: function (context) {
        var section = context.element.closest('[data-all-ips]') || document.getElementById('ip-table-section');
        try { JSON.parse(section.dataset.allIps || '[]').forEach(function (ip) { selected.add(String(ip)); }); } catch (_) { app.ui.toast(app.t('IP selection metadata is invalid.'), 'error'); }
        selectedCheckboxes(section).forEach(function (checkbox) { checkbox.checked = true; selected.add(checkbox.value); });
        updateControls();
      } },
      'profiles.ip-clear': { handler: function (context) {
        selected.clear();
        selectedCheckboxes(context.element.closest('#ip-table-section') || document).forEach(function (checkbox) { checkbox.checked = false; });
        updateControls();
      } },
      'profiles.ip-copy': { handler: function (context) { copy(context.element.dataset.ip || ''); } },
      'profiles.ip-copy-selected': { handler: function () { copy(selectedOrVisible().join('\n')); } },
      'profiles.ip-copy-all': { handler: function () { copy(Array.from(document.querySelectorAll('.ip-addr')).map(function (node) { return node.textContent.trim(); }).join('\n')); } },
      'profiles.ip-block': { handler: function (context) { blockSelected(context.element); } },
      'profiles.block-detail': { handler: toggleBlockDetail }
    },
    mount: function (root) {
      restore(root);
      if (root && (root.id === 'block-status-panel' || root.querySelector && root.querySelector('#block-status-panel'))) loadBlockStatus();
    },
    selectedIps: function () { return new Set(selected); },
    loadBlockStatus: loadBlockStatus
  });
}());
