/* Runtime settings and local configuration editor workflows. */
(function () {
  'use strict';

  var app = window.Anteumbra;
  var systemPanels = {
    registry: { title: 'Registry Status', url: '/admin/system/registry_panel', action: '/admin/system/registry/compact', label: 'Compact', confirm: { en: 'Compact Registry?', zh: '压缩注册表？' } },
    wal: { title: 'WAL Management', url: '/admin/system/wal_panel', action: '/admin/system/wal/replay', label: 'Replay', confirm: { en: 'Replay WAL?', zh: '重放 WAL？' } },
    session: { title: 'Session Management', url: '/admin/system/session_panel?per_page=6', action: '/admin/system/session/cleanup', label: 'Cleanup', confirm: { en: 'Cleanup expired sessions?', zh: '清理已过期会话？' } },
    config: { title: 'Config Reload', url: '/admin/system/config_panel', action: '/admin/system/config/reload', label: 'Reload', confirm: { en: 'Reload config?', zh: '重新加载配置？' } }
  };
  var systemRequestId = 0;

  function systemModalIsCurrent(requestId, body) {
    var modal = document.getElementById('system-modal');
    return requestId === systemRequestId && body && body.isConnected && modal && modal.getAttribute('aria-hidden') === 'false';
  }

  function systemConfirmation(panel) {
    return document.documentElement.lang.indexOf('zh') === 0 ? panel.confirm.zh : panel.confirm.en;
  }

  function invalidateSystemRequests() {
    systemRequestId += 1;
  }

  function installSystemModalGuard() {
    if (document.documentElement.dataset.systemModalGuard) return;
    document.documentElement.dataset.systemModalGuard = 'true';
    document.addEventListener('click', function (event) {
      var close = event.target.closest('[data-action="core.modal-hide"][data-modal="system-modal"]');
      var backdrop = event.target.closest('#system-modal[data-action="core.backdrop-close"]');
      if (close || (backdrop && event.target === backdrop)) invalidateSystemRequests();
    });
    document.addEventListener('keydown', function (event) {
      var modal = document.getElementById('system-modal');
      if (event.key === 'Escape' && modal) invalidateSystemRequests();
    });
  }

  function resultNode(id, text, failed) {
    var node = document.getElementById(id);
    if (!node) return;
    node.hidden = false;
    node.style.display = '';
    node.style.color = failed ? 'var(--color-danger)' : 'var(--color-safe)';
    node.textContent = text;
  }

  function markDirty() {
    var status = document.getElementById('config-saved');
    if (status) status.style.display = 'none';
  }

  function saveConfig() {
    var changes = {};
    document.querySelectorAll('#config-tree input:not([disabled])').forEach(function (input) {
      var key = input.dataset.key;
      if (!key) return;
      if (input.type === 'checkbox') changes[key] = input.checked;
      else if (input.type === 'number') changes[key] = Number(input.value);
      else changes[key] = input.value;
    });
    app.http.json('/admin/settings/config/save', {
      method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ changes: changes })
    }).then(function (result) {
      resultNode('config-saved', result.success ? 'Saved' : 'Error: ' + (result.error || 'unknown'), !result.success);
    }).catch(function (error) { resultNode('config-saved', 'Error: ' + error.message, true); });
  }

  function generatePasswordHash() {
    var password = document.getElementById('env-pwd-input');
    if (!password || !password.value) { app.ui.toast(app.t('Enter a password first.'), 'warning'); return; }
    app.http.json('/admin/settings/env/hash', {
      method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ password: password.value })
    }).then(function (result) {
      if (!result.hash) throw new Error(result.error || 'Hash generation failed');
      password.value = '';
      var display = document.getElementById('env-pwd-display');
      if (display) { display.textContent = result.hash.slice(0, 60) + '...'; display.dataset.hash = result.hash; }
    }).catch(function (error) { app.ui.toast(error.message, 'error'); });
  }

  function saveEnvironment() {
    var vars = {};
    document.querySelectorAll('[data-env-key]').forEach(function (input) { vars[input.dataset.envKey] = input.value; });
    var hash = document.getElementById('env-pwd-display');
    if (hash && hash.dataset.hash) vars.ANTEUMBRA_PASSWORD_HASH = hash.dataset.hash;
    app.http.json('/admin/settings/env/save', {
      method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ vars: vars })
    }).then(function (result) {
      resultNode('env-saved', result.success ? 'Saved' : 'Error: ' + (result.error || 'unknown'), !result.success);
    }).catch(function (error) { resultNode('env-saved', 'Error: ' + error.message, true); });
  }

  function toggleSection(element) {
    var section = element.closest('.cfg-section, .config-section');
    if (section) section.classList.toggle('collapsed');
  }

  function searchConfig(input) {
    var query = String(input.value || '').toLowerCase();
    document.querySelectorAll('.cfg-section').forEach(function (section) {
      // Collapsed fields are not in innerText. Search stable keys even while hidden.
      var keys = Array.from(section.querySelectorAll('.cfg-field')).map(function (field) {
        return field.dataset.field || '';
      }).join(' ');
      var matched = !query || ((section.dataset.section || '') + ' ' + keys + ' ' + section.textContent).toLowerCase().indexOf(query) >= 0;
      section.classList.toggle('collapsed', !matched || !query);
      section.querySelectorAll('.cfg-field').forEach(function (field) {
        field.classList.toggle('cfg-highlight', Boolean(query && (field.dataset.field || '').toLowerCase().indexOf(query) >= 0));
      });
    });
  }

  function showSystemPanel(type) {
    var panel = systemPanels[type];
    if (!panel) return;
    var modal = app.ui.showModal('system-modal');
    if (!modal) return;
    var title = document.getElementById('system-modal-title');
    var body = document.getElementById('system-modal-body');
    var actions = document.getElementById('system-modal-actions');
    var requestId = ++systemRequestId;
    if (title) title.textContent = panel.title;
    if (body) body.innerHTML = '<div class="empty-state"><div class="spinner"></div><p>Loading...</p></div>';
    if (actions) {
      actions.replaceChildren();
      var button = document.createElement('button');
      button.className = 'btn btn-ghost btn-sm';
      button.textContent = panel.label;
      button.dataset.action = 'settings.system-run';
      button.dataset.systemType = type;
      actions.appendChild(button);
    }
    app.http.text(panel.url, { headers: { 'HX-Request': 'true' } }).then(function (html) {
      if (!systemModalIsCurrent(requestId, body)) return;
      body.innerHTML = html;
      app.processHtmx(body);
      app.mount(body);
    }).catch(function (error) {
      if (systemModalIsCurrent(requestId, body)) body.textContent = error.message;
    });
  }

  function runSystemAction(type) {
    var panel = systemPanels[type];
    var body = document.getElementById('system-modal-body');
    if (!panel || !body || !app.confirm(systemConfirmation(panel))) return;
    var requestId = ++systemRequestId;
    app.http.text(panel.action, { method: 'POST', headers: { 'HX-Request': 'true' } }).then(function (html) {
      if (!systemModalIsCurrent(requestId, body)) return;
      body.innerHTML = html;
      app.processHtmx(body);
      app.mount(body);
    }).catch(function (error) {
      if (systemModalIsCurrent(requestId, body)) body.textContent = error.message;
    });
  }

  function installTooltip() {
    if (document.getElementById('cfg-tooltip')) return;
    var tooltip = document.createElement('div');
    tooltip.id = 'cfg-tooltip';
    document.body.appendChild(tooltip);
    document.addEventListener('mouseover', function (event) {
      var source = event.target.closest('.cfg-info');
      if (!source || !source.dataset.tooltip) return;
      tooltip.textContent = source.dataset.tooltip;
      tooltip.style.display = 'block';
    });
    document.addEventListener('mousemove', function (event) {
      if (tooltip.style.display === 'block') {
        tooltip.style.left = event.clientX + 12 + 'px';
        tooltip.style.top = event.clientY - 30 + 'px';
      }
    });
    document.addEventListener('mouseout', function (event) {
      if (event.target.closest('.cfg-info')) tooltip.style.display = 'none';
    });
  }

  function exportSiem(format) {
    // Snapshot downloads never change the live streaming format or re-emit
    // historical detections to the external collector.
    window.location.assign('/admin/siem/export?download=1&format=' + encodeURIComponent(format || 'json_lines'));
  }

  function updateSessionHeader(root) {
    var panel = root && (root.matches && root.matches('[data-session-stats]') ? root : root.querySelector && root.querySelector('[data-session-stats]'));
    if (!panel) return;
    var target = document.getElementById('session-header-stats');
    if (!target) return;
    target.textContent = app.t('%(total)s total / %(active)s active', {
      total: panel.dataset.sessionCount, active: panel.dataset.activeCount
    });
  }

  app.register('settings', {
    actions: {
      'settings.system-open': { handler: function (context) { showSystemPanel(context.element.dataset.systemType); } },
      'settings.system-run': { handler: function (context) { runSystemAction(context.element.dataset.systemType); } },
      'settings.config-search': { handler: function (context) { searchConfig(context.element); }, events: ['input'], preventDefault: false },
      'settings.section-toggle': { handler: function (context) { toggleSection(context.element); } },
      'settings.mark-dirty': { handler: markDirty, events: ['change', 'input'], preventDefault: false },
      'settings.config-save': { handler: saveConfig },
      'settings.password-hash': { handler: generatePasswordHash },
      'settings.environment-save': { handler: saveEnvironment },
      'settings.config-reload-button': { handler: function () { runSystemAction('config'); } },
      'settings.siem-export': { handler: function (context) { exportSiem(context.element.dataset.siemFormat); } }
    },
    mount: function (root) { installTooltip(); installSystemModalGuard(); updateSessionHeader(root); }
  });
}());
