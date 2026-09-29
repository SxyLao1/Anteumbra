/* Console shell navigation, theme preference and business-form leave warning. */
(function (window, document) {
  'use strict';
  var app = window.Anteumbra;
  var storageKey = 'anteumbra-console-theme';
  var snapshots = new WeakMap();
  var locale = document.body.dataset.consoleLocale === 'zh' ? 'zh' : 'en';
  var workspaces = {
    duty: { zh: '值守台', en: 'Duty desk', route: '/admin/overview', items: [['概览','Overview','/admin/overview']] },
    investigate: { zh: '检测与调查', en: 'Detection & investigation', route: '/admin/threats', items: [['检测记录','Detection records','/admin/threats'],['日志分析','Log analyzer','/admin/logs/analyzer'],['主动扫描','Active scan','/admin/scanner'],['关联画像','Profiles','/admin/profiles'],['文件簇','File clusters','/admin/file-clusters']] },
    respond: { zh: '处置与复核', en: 'Response & review', route: '/admin/quarantine', items: [['隔离区','Quarantine','/admin/quarantine'],['封禁台账','Blocklist','/admin/blocklist']] },
    protect: { zh: '站点与防护', en: 'Sites & protection', route: '/admin/sites', items: [['站点清单','Sites','/admin/sites'],['规则库','Rules','/admin/yara/rules'],['内存马检测','Memory shell','/admin/memory-shell'],['内存马取证','Forensics','/admin/memory-shell/forensics']] },
    settings: { zh: '设置', en: 'Settings', route: '/admin/settings?open=notifications,plugins', items: [['通知','Notifications','/admin/settings?open=notifications'],['插件','Plugins','/admin/settings?open=plugins'],['账户与密钥','Account & secrets','/admin/settings?open=environment,advanced,account'],['完整配置','Config editor','/admin/config']] },
    system: { zh: '系统维护', en: 'System maintenance', route: '/admin/system', items: [['运行状态','Runtime health','/admin/system'],['WAL','WAL','/admin/system#system-wal-panel'],['注册表','Registry','/admin/system#system-registry-panel'],['会话','Sessions','/admin/system#system-session-panel'],['配置运行状态','Config runtime','/admin/system#system-config-panel']] }
  };
  var currentWorkspace = 'duty';

  function applyTheme(theme) { document.body.dataset.consoleTheme = theme; try { window.localStorage.setItem(storageKey, theme); } catch (error) {} }
  function toggleTheme() { applyTheme(document.body.dataset.consoleTheme === 'light' ? 'dark' : 'light'); }
  function businessForms(root) { return (root || document).querySelectorAll('form[method="post"], form[hx-post], form[data-console-draft]'); }
  function formValue(form) { return Array.prototype.map.call(form.elements || [], function (field) { if (!field.name || field.disabled || field.type === 'hidden') return ''; if (field.type === 'checkbox' || field.type === 'radio') return field.name + '=' + (field.checked ? '1' : '0'); return field.name + '=' + field.value; }).join('&'); }
  function snapshot(root) { businessForms(root).forEach(function (form) { snapshots.set(form, formValue(form)); }); }
  function isDirty() { var dirty = false; businessForms(document).forEach(function (form) { if (snapshots.has(form) && snapshots.get(form) !== formValue(form)) dirty = true; }); return dirty; }
  function confirmNavigation() { return !isDirty() || window.confirm(locale === 'zh' ? '存在未保存的业务表单修改，确定离开当前工作区？' : 'There are unsaved business-form changes. Leave this workspace?'); }
  function title(item) { return item[locale === 'zh' ? 0 : 1]; }
  function renderContext(workspace) { var nav = document.getElementById('console-context-nav'), data = workspaces[workspace]; if (!nav || !data) return; nav.innerHTML = data.items.map(function (item) { return '<a href="' + item[2] + '" data-action="console.route" data-route="' + item[2] + '">' + title(item) + '</a>'; }).join(''); document.querySelectorAll('[data-workspace]').forEach(function (link) { link.classList.toggle('active', link.dataset.workspace === workspace); }); }
  function navigate(route, label) { var dashboard = app && app.module && app.module('dashboard'); if (dashboard && dashboard.navigate) dashboard.navigate(route, label || route); }
  function workspace(element) { var key = workspaces[element.dataset.workspace] ? element.dataset.workspace : 'duty'; navigate(workspaces[key].route, workspaces[key][locale]); }
  function localeSwitch(element) { var url = new window.URL(window.location.href); url.searchParams.set('lang', element.dataset.locale); window.location.assign(url.toString()); }
  function inferWorkspace(path) {
    var currentPath = path.split('?')[0];
    var key = Object.keys(workspaces).find(function (name) {
      return workspaces[name].items.some(function (item) {
        var base = item[2].split(/[?#]/)[0];
        return currentPath === base || currentPath.indexOf(base + '/') === 0;
      });
    });
    currentWorkspace = key || 'duty';
    renderContext(currentWorkspace);
    var scopeNote = document.getElementById('console-scope-note');
    if (scopeNote) {
      var shared = /^\/admin\/(settings|config|system|yara)(\/|$)/.test(currentPath);
      var logs = currentPath.indexOf('/admin/logs') === 0;
      scopeNote.hidden = !shared && !logs;
      scopeNote.textContent = logs
        ? (locale === 'zh' ? '全站范围：运行日志与访问日志分析汇总服务器上的站点。' : 'Server scope: runtime logs and access-log analysis cover all sites.')
        : (locale === 'zh' ? '服务器共享：此处配置、规则及维护操作影响整台服务器，不受站点筛选限制。' : 'Shared across this server: configuration, rules and maintenance are independent of the site filter.');
    }
    document.querySelectorAll('#console-context-nav a').forEach(function (link) {
      var route = new window.URL(link.href);
      var current = new window.URL(window.location.href);
      var matchesQuery = true;
      route.searchParams.forEach(function (value, name) {
        if (current.searchParams.get(name) !== value) matchesQuery = false;
      });
      var active = route.pathname === currentPath && matchesQuery && route.hash === current.hash;
      if (active) link.setAttribute('aria-current', 'page');
    });
  }

  try { applyTheme(window.localStorage.getItem(storageKey) === 'light' ? 'light' : 'dark'); } catch (error) { applyTheme('dark'); }
  snapshot(document);
  window.addEventListener('beforeunload', function (event) { if (!isDirty()) return; event.preventDefault(); event.returnValue = ''; });
  if (app && app.register) app.register('console-shell', { actions: {
    'console.theme-toggle': { handler: toggleTheme },
    'console.workspace': { handler: function (context) { workspace(context.element); } },
    'console.route': { handler: function (context) { navigate(context.element.dataset.route, context.element.textContent); } },
    'console.locale': { handler: function (context) { localeSwitch(context.element); } }
  }, mount: function (root) { snapshot(root); inferWorkspace(window.location.pathname); } });
  window.AnteumbraConsoleShell = { confirmNavigation: confirmNavigation, snapshot: snapshot, inferWorkspace: inferWorkspace };
}(window, document));
