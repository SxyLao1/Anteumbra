/* Dashboard navigation and fragment lifecycle. */
(function () {
  'use strict';

  var app = window.Anteumbra;
  var state = { path: 'overview', title: 'Overview', requestId: 0, started: false, logObserver: null, logStream: null };
  var threatUrls = {
    active: '/admin/records?compact=1',
    quarantine: '/admin/quarantine?status=quarantined',
    audit: '/admin/records?audit=true&compact=1',
    clusters: '/admin/file-clusters'
  };

  function elementIn(root, selector) {
    if (!root) return null;
    if (root.matches && root.matches(selector)) return root;
    return root.querySelector ? root.querySelector(selector) : null;
  }

  function mainContent() { return document.getElementById('main-content'); }

  function setTitle(title) {
    var value = title || 'Overview';
    var brand = document.querySelector('.brand-sub');
    var page = document.getElementById('page-title');
    if (brand) brand.textContent = value;
    if (page) page.textContent = value;
  }

  function setLoading(target, text) {
    target.replaceChildren();
    var stateNode = document.createElement('div');
    stateNode.className = 'empty-state';
    var spinner = document.createElement('div');
    spinner.className = 'spinner';
    var label = document.createElement('p');
    label.textContent = text || 'Loading...';
    stateNode.append(spinner, label);
    target.appendChild(stateNode);
  }

  function setError(target, error) {
    target.replaceChildren();
    var stateNode = document.createElement('div');
    stateNode.className = 'empty-state';
    var label = document.createElement('p');
    label.textContent = 'Failed to load: ' + String(error && error.message ? error.message : error);
    stateNode.appendChild(label);
    target.appendChild(stateNode);
  }

  function highlightNavigation(path) {
    document.querySelectorAll('.nav-link[data-path]').forEach(function (link) {
      link.classList.toggle('active', link.dataset.path === path);
    });
  }

  function closeSidebar() {
    var sidebar = document.querySelector('.app-sidebar');
    var overlay = document.getElementById('sidebar-overlay');
    var toggle = document.getElementById('sidebar-toggle');
    if (sidebar) sidebar.classList.remove('open');
    if (overlay) overlay.classList.remove('active');
    if (toggle) toggle.classList.remove('active');
  }

  function toggleSidebar() {
    var sidebar = document.querySelector('.app-sidebar');
    var overlay = document.getElementById('sidebar-overlay');
    var toggle = document.getElementById('sidebar-toggle');
    if (sidebar) sidebar.classList.toggle('open');
    if (overlay) overlay.classList.toggle('active');
    if (toggle) toggle.classList.toggle('active');
  }

  function applyFragment(target, html) {
    if (html.indexOf('app-header') >= 0 || html.indexOf('app-shell') >= 0) {
      throw new Error('Server returned a full document instead of an admin fragment');
    }
    app.unmount(target);
    target.innerHTML = html;
    app.processHtmx(target);
    app.mount(target);
  }

  function load(path, title) {
    var target = mainContent();
    if (!target) return Promise.resolve();
    state.path = path;
    state.title = title || path;
    setTitle(state.title);
    highlightNavigation(path.replace('_content', ''));
    closeSidebar();
    var requestId = ++state.requestId;
    app.unmount(target);
    setLoading(target, 'Loading ' + state.title + '...');
    return app.http.text('/admin/' + path, { headers: { 'HX-Request': 'true' } })
      .then(function (html) {
        if (requestId !== state.requestId) return;
        applyFragment(target, html);
      })
      .catch(function (error) {
        if (requestId === state.requestId) setError(target, error);
      });
  }

  function refresh() { return load(state.path, state.title); }

  function htmxReplace(target, url) {
    return app.http.text(url, { headers: { 'HX-Request': 'true' } }).then(function (html) {
      return app.swapHtml(target, html, 'outerHTML');
    });
  }

  function loadOverviewPanels(root) {
    var metrics = elementIn(root, '#metrics-panel');
    if (metrics && !metrics.dataset.frontendLoaded) {
      metrics.dataset.frontendLoaded = 'true';
      app.http.text('/admin/metrics/data', { headers: { 'HX-Request': 'true' } })
        .then(function (html) { metrics.innerHTML = html; app.processHtmx(metrics); app.mount(metrics); })
        .catch(function () { metrics.removeAttribute('data-frontend-loaded'); });
    }

    var yara = elementIn(root, '#yara-rules-container');
    if (yara && !yara.dataset.frontendLoaded) {
      yara.dataset.frontendLoaded = 'true';
      htmxReplace(yara, '/admin/yara/rules?compact=1').catch(function () { yara.removeAttribute('data-frontend-loaded'); });
    }

    var records = elementIn(root, '#records-table-container');
    if (records && !records.dataset.frontendLoaded) {
      records.dataset.frontendLoaded = 'true';
      htmxReplace(records, '/admin/records?compact=1').catch(function () { records.removeAttribute('data-frontend-loaded'); });
    }

    anchorLogStream(root);
  }

  function anchorLogStream(root) {
    var stream = elementIn(root, '#live-log-stream');
    if (!stream || stream.dataset.frontendAnchored) return;
    stream.dataset.frontendAnchored = 'true';
    if (state.logObserver) state.logObserver.disconnect();
    var scroll = function () { stream.scrollTop = stream.scrollHeight; };
    window.requestAnimationFrame(scroll);
    window.setTimeout(scroll, 120);
    state.logObserver = new MutationObserver(scroll);
    state.logObserver.observe(stream, { childList: true });
    state.logStream = stream;
  }

  function unmount(root) {
    if (!state.logStream || !root) return;
    var containsStream = root === state.logStream || (
      root.contains && root.contains(state.logStream)
    );
    if (!containsStream) return;
    if (state.logObserver) state.logObserver.disconnect();
    state.logObserver = null;
    state.logStream = null;
  }

  function activateThreatTab(tab, trigger) {
    var page = trigger ? trigger.closest('[data-threats-tabs]') : document.querySelector('[data-threats-tabs]');
    if (!page) return;
    page.querySelectorAll('.threats-tab').forEach(function (button) {
      button.classList.toggle('active', button.dataset.tab === tab);
    });
    page.querySelectorAll('.threats-tab-content').forEach(function (panel) {
      var active = panel.id === 'threats-tab-' + tab;
      panel.hidden = !active;
      panel.style.display = active ? 'flex' : 'none';
    });
    var panel = page.querySelector('#threats-tab-' + tab + ' [data-threat-target]');
    if (panel && !panel.dataset.loaded && threatUrls[tab]) {
      panel.dataset.loaded = 'true';
      app.htmxGet(threatUrls[tab], '#' + panel.id, 'innerHTML');
    }
  }

  function toggleAudit(trigger) {
    var container = trigger && trigger.closest('[id^="records-table-container"]');
    container = container || document.getElementById('records-table-container');
    if (!container) return;
    var audit = container.dataset.auditMode === 'true';
    var url = audit ? '/admin/records?compact=1' : '/admin/records?audit=true&compact=1';
    htmxReplace(container, url).then(function () {
      trigger.textContent = audit ? 'Audit' : '<- Normal';
    });
  }

  function openLogAnalyzer() {
    var modal = document.getElementById('log-analyzer-modal');
    if (!modal) return;
    app.ui.showModal(modal);
    var source = document.getElementById('live-log-stream');
    var target = document.getElementById('analyzer-log-content');
    if (source && target) target.innerHTML = source.innerHTML;
    ['analyzer-filter-input', 'analyzer-level-filter', 'analyzer-module-filter', 'analyzer-time-filter'].forEach(function (id) {
      var field = document.getElementById(id);
      if (field) field.value = field.tagName === 'SELECT' ? 'all' : '';
    });
    setAnalyzerTimeVisibility();
    filterLogAnalyzer();
    if (window.AnteumbraSSEManager) window.AnteumbraSSEManager.reconnectWithAllLevels();
  }

  function closeLogAnalyzer() {
    app.ui.hideModal('log-analyzer-modal');
    if (window.AnteumbraSSEManager) window.AnteumbraSSEManager.reconnectNormal();
  }

  function filterLogAnalyzer() {
    var keyword = (document.getElementById('analyzer-filter-input') || {}).value || '';
    keyword = keyword.toLowerCase();
    var level = (document.getElementById('analyzer-level-filter') || {}).value || 'all';
    var moduleName = (document.getElementById('analyzer-module-filter') || {}).value || 'all';
    var range = (document.getElementById('analyzer-time-filter') || {}).value || 'all';
    var stream = document.getElementById('analyzer-log-content');
    if (!stream) return;
    var now = Date.now();
    var ranges = { '1h': 3600000, '6h': 21600000, '24h': 86400000, '7d': 604800000, '30d': 2592000000 };
    var minimum = ranges[range] ? now - ranges[range] : 0;
    var maximum = 0;
    if (range === 'custom') {
      var fromDate = (document.getElementById('analyzer-time-from-date') || {}).value;
      var fromTime = (document.getElementById('analyzer-time-from-time') || {}).value || '00:00';
      var toDate = (document.getElementById('analyzer-time-to-date') || {}).value;
      var toTime = (document.getElementById('analyzer-time-to-time') || {}).value || '23:59';
      if (fromDate) minimum = new Date(fromDate + 'T' + fromTime).getTime();
      if (toDate) maximum = new Date(toDate + 'T' + toTime).getTime();
    }
    var visible = 0;
    stream.querySelectorAll('.log-line').forEach(function (line) {
      var text = line.textContent || '';
      var show = !keyword || text.toLowerCase().indexOf(keyword) >= 0;
      var upper = text.toUpperCase();
      if (show && level !== 'all' && upper.indexOf(' ' + level + ' ') < 0 && upper.indexOf('[' + level + ']') < 0 && upper.indexOf(level + ' -') < 0) show = false;
      if (show && moduleName !== 'all' && text.indexOf('[' + moduleName + ']') < 0) show = false;
      var match = text.match(/\[(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})/);
      if (show && match && (minimum || maximum)) {
        var timestamp = new Date(match[1].replace(' ', 'T')).getTime();
        if ((minimum && timestamp < minimum) || (maximum && timestamp > maximum)) show = false;
      }
      line.style.display = show ? '' : 'none';
      if (show) visible += 1;
    });
    var count = document.getElementById('analyzer-count');
    if (count) count.textContent = visible + ' lines';
  }

  function setAnalyzerTimeVisibility() {
    var selector = document.getElementById('analyzer-time-filter');
    var custom = document.getElementById('analyzer-custom-time');
    if (custom) custom.style.display = selector && selector.value === 'custom' ? '' : 'none';
    filterLogAnalyzer();
  }

  function filterLogStream(input) {
    var keyword = String(input.value || '').toLowerCase();
    document.querySelectorAll('#live-log-stream .log-line, #log-stream .log-line').forEach(function (line) {
      line.style.display = !keyword || line.textContent.toLowerCase().indexOf(keyword) >= 0 ? '' : 'none';
    });
  }

  function loadAccessLogAnalysis() {
    var target = document.getElementById('analyzer-log-content');
    if (!target) return;
    setLoading(target, 'Loading access log analysis...');
    app.http.text('/admin/logs/access-analysis').then(function (html) {
      target.innerHTML = html;
      filterLogAnalyzer();
    }).catch(function (error) {
      setError(target, error);
    });
  }

  function refreshStatistics() {
    var stats = document.getElementById('overview-stats');
    if (stats && window.htmx) app.htmxGet('/admin/dashboard_content', '#overview-stats', 'innerHTML');
    var threats = document.getElementById('overview-active-threats');
    if (threats && window.htmx) app.htmxGet('/admin/records?compact=1', '#overview-active-threats', 'innerHTML');
  }

  app.register('dashboard', {
    actions: {
      'dashboard.navigate': { handler: function (context) { load(context.element.dataset.path, context.element.dataset.title); } },
      'dashboard.refresh': { handler: refresh },
      'dashboard.sidebar-toggle': { handler: toggleSidebar },
      'dashboard.sidebar-close': { handler: closeSidebar },
      'dashboard.logout': { handler: function () {
        if (!app.confirm('Confirm logout?')) return;
        if (window.AnteumbraSSEManager) window.AnteumbraSSEManager.disconnect();
        window.location.assign('/admin/logout');
      } },
      'dashboard.threat-tab': { handler: function (context) { activateThreatTab(context.element.dataset.tab, context.element); } },
      'dashboard.audit-toggle': { handler: function (context) { toggleAudit(context.element); } },
      'dashboard.log-open': { handler: openLogAnalyzer },
      'dashboard.log-close': { handler: closeLogAnalyzer },
      'dashboard.log-backdrop': { handler: function (context) {
        if (context.event.target === context.element) closeLogAnalyzer();
      } },
      'dashboard.log-filter': { handler: function () { filterLogAnalyzer(); }, events: ['input', 'change'], preventDefault: false },
      'dashboard.log-time': { handler: setAnalyzerTimeVisibility, events: ['change'], preventDefault: false },
      'dashboard.log-stream-filter': { handler: function (context) { filterLogStream(context.element); }, events: ['input'], preventDefault: false },
      'dashboard.log-access-analysis': { handler: loadAccessLogAnalysis }
    },
    navigate: load,
    mount: function (root) {
      if (!state.started && elementIn(root, '#main-content')) {
        state.started = true;
        setTitle(state.title);
        window.setTimeout(function () {
          if (window.AnteumbraSSEManager) window.AnteumbraSSEManager.getConnection();
          load('overview', 'Overview');
        }, 0);
        document.addEventListener('anteumbra:stats-refresh', refreshStatistics);
        document.addEventListener('keydown', function (event) {
          if (event.key !== 'Escape') return;
          closeLogAnalyzer();
          closeSidebar();
        });
      }
      if (elementIn(root, '#overview-stats') || elementIn(root, '#live-log-stream')) loadOverviewPanels(root);
      var threats = elementIn(root, '[data-threats-tabs]');
      if (threats && !threats.dataset.frontendMounted) {
        threats.dataset.frontendMounted = 'true';
        activateThreatTab('active', threats.querySelector('[data-tab="active"]'));
      }
    },
    load: load,
    refresh: refresh,
    unmount: unmount
  });
}());
