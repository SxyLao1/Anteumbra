/* Anteumbra v1.9.1 — Core dashboard logic (page modules in js/modules/) */
/* Anteumbra 仪表盘主逻辑 */

/* ============================================================
   Dashboard 全局函数（必须在 dashboard.js 中预定义，因为
   dashboard_content.html 通过 innerHTML 插入时其中的 <script> 不会执行）
   ============================================================ */

function toggleDashboardAudit() {
  var btn = document.getElementById('dash-audit-btn');
  var container = document.getElementById('records-table-container');
  if (!container || !btn) return;
  // 判断当前状态：按钮文本包含 "Normal" 说明当前是 Audit 模式
  var isAuditMode = btn.textContent.indexOf('Normal') !== -1;
  var url = isAuditMode ? '/admin/records?compact=1' : '/admin/records?audit=true&compact=1';
  var nextLabel = isAuditMode ? 'Audit' : '← Normal';
  var nextAuditParam = isAuditMode ? 'false' : 'true';
  fetch(url, { headers: { 'HX-Request': 'true' } })
    .then(function(r){ return r.text(); })
    .then(function(html){
      // 使用 outerHTML 替换容器，避免 records_table.html 最外层 div 嵌套
      var temp = document.createElement('div');
      temp.innerHTML = html;
      var newContainer = temp.firstElementChild;
      if (newContainer) {
        container.replaceWith(newContainer);
        container = document.getElementById('records-table-container');
        if (window.htmx) htmx.process(container);
      }
      btn.textContent = nextLabel;
      // 同步更新 Filter 的 hx-get audit 参数
      var filterInput = document.querySelector('#records-table-container').closest('.card').querySelector('input[name="q"]');
      if (filterInput) {
        filterInput.setAttribute('hx-get', '/admin/search?compact=1&audit=' + nextAuditParam);
      }
    })
    .catch(function(e){
      console.error('Audit toggle failed:', e);
    });
}

/* 当前页面状态（用于Refresh按钮） */
var _currentPath = 'dashboard_content';
var _currentTitle = 'Dashboard';

/* Loading占位HTML */
var _loadingHtml = '<div class="empty-state"><div class="spinner"></div><p>Initializing dashboard...</p></div>';

document.addEventListener('DOMContentLoaded', function() {
  AnteumbraUtils.setupHtmxCsrf();

  // 初始加载dashboard
  setTimeout(function() {
    loadDashboard();
  }, 300);

  // SSE连接
  if (window.AnteumbraSSEManager) {
    AnteumbraSSEManager.getConnection();
  }

  // 导航点击事件
  document.querySelectorAll('.nav-link[data-path]').forEach(function(link) {
    link.addEventListener('click', function(e) {
      e.preventDefault();
      var path = this.dataset.path;
      var title = this.dataset.title || path;
      loadContent(path, title);
      AnteumbraUtils.highlightNav(path.replace('_content', ''));
    });
  });

  // 登出
  var logoutBtn = document.getElementById('logout-btn');
  if (logoutBtn) {
    logoutBtn.addEventListener('click', function(e) {
      e.preventDefault();
      AnteumbraUtils.confirm('Confirm logout?', function() {
        if (window.AnteumbraSSEManager) AnteumbraSSEManager.disconnect();
        window.location.href = '/admin/logout';
      });
    });
  }

  // 模态框关闭
  document.addEventListener('click', function(e) {
    if (e.target.classList.contains('modal-overlay')) {
      e.target.classList.remove('active');
    }
    if (e.target.classList.contains('modal-close')) {
      var overlay = e.target.closest('.modal-overlay');
      if (overlay) overlay.classList.remove('active');
    }
  });

  // 移动端侧边栏
  var sidebarToggle = document.getElementById('sidebar-toggle');
  if (sidebarToggle) {
    sidebarToggle.addEventListener('click', function() {
      var sidebar = document.querySelector('.app-sidebar');
      var overlay = document.getElementById('sidebar-overlay');
      sidebar.classList.toggle('open');
      overlay.classList.toggle('active');
      this.classList.toggle('active');
    });
  }

  // 移动端导航点击关闭侧边栏
  document.querySelectorAll('.nav-link[data-path]').forEach(function(link) {
    link.addEventListener('click', function() {
      if (window.innerWidth <= 768) {
        closeSidebar();
      }
    });
  });
});

function closeSidebar() {
  var sidebar = document.querySelector('.app-sidebar');
  var overlay = document.getElementById('sidebar-overlay');
  var toggle = document.getElementById('sidebar-toggle');
  if (sidebar) sidebar.classList.remove('open');
  if (overlay) overlay.classList.remove('active');
  if (toggle) toggle.classList.remove('active');
}

/* ============================================================
   Dashboard加载
   ============================================================ */
function loadDashboard() {
  // v1.7.9: 仅在Dashboard页面自动加载，避免覆盖quarantine/audit等其他页面内容
  // v1.8.0: Overview 是默认首页
  if (window.location.pathname !== '/admin/' && window.location.pathname !== '/admin' && window.location.pathname !== '/admin/overview') {
    return;
  }
  var contentArea = document.getElementById('main-content');
  if (!contentArea) return;

  // 清空 toolbar
  var headerCenter = document.getElementById('header-center');
  if (headerCenter) headerCenter.innerHTML = '';
  var brandSub = document.querySelector('.brand-sub');
  if (brandSub) brandSub.textContent = 'Dashboard';

  // 先显示loading
  contentArea.innerHTML = _loadingHtml;

  fetch('/admin/overview', { headers: { 'HX-Request': 'true' } })
    .then(function(r) {
      if (!r.ok) throw new Error('HTTP ' + r.status);
      return r.text();
    })
    .then(function(html) {
      // 嵌套防护
      if (html.indexOf('app-header') !== -1 || html.indexOf('app-shell') !== -1) {
        console.error('[Dashboard] Nested page detected, redirecting...');
        window.location.href = '/admin/dashboard';
        return;
      }
      contentArea.innerHTML = html;
      if (window.htmx) {
        htmx.process(contentArea);
        contentArea.querySelectorAll('[hx-trigger*="load"]').forEach(function(el) {
          htmx.trigger(el, 'load');
        });
      }
      setTimeout(loadDashboardPanels, 50);

      // v2.0: Auto-scroll live log stream to bottom — robust multi-stage approach
      function _anchorLogStream() {
        var logStream = document.getElementById('live-log-stream');
        if (!logStream) return;
        // Use requestAnimationFrame to ensure layout is complete
        requestAnimationFrame(function() {
          logStream.scrollTop = logStream.scrollHeight;
        });
      }
      // Stage 1: immediate scroll after innerHTML is set
      _anchorLogStream();
      // Stage 2: delayed scroll after any async-rendered content
      setTimeout(_anchorLogStream, 100);
      setTimeout(_anchorLogStream, 300);
      // Stage 3: MutationObserver for ongoing SSE updates
      if (window._logStreamObserver) { window._logStreamObserver.disconnect(); }
      window._logStreamObserver = new MutationObserver(function() {
        var ls = document.getElementById('live-log-stream');
        if (ls) { ls.scrollTop = ls.scrollHeight; }
      });
      setTimeout(function() {
        var ls = document.getElementById('live-log-stream');
        if (ls && window._logStreamObserver) {
          window._logStreamObserver.observe(ls, { childList: true, subtree: false });
        }
      }, 50);

    })
    .catch(function(err) {
      console.error('[Dashboard] Load failed:', err);
      contentArea.innerHTML = '<div class="empty-state"><div style="font-size:32px;margin-bottom:12px;">⚠</div><p>Failed to load dashboard: ' + err.message + '</p></div>';
    });
}

/* ============================================================
   通用内容加载
   ============================================================ */
function loadContent(path, title) {
  var contentArea = document.getElementById('main-content');
  if (!contentArea) return;

  // 更新状态
  _currentPath = path;
  _currentTitle = title || path;

  // 更新 header 中的页面标题显示
  var brandSub = document.querySelector('.brand-sub');
  if (brandSub) brandSub.textContent = _currentTitle;
  // 同步更新 page-title（大标题）
  var pageTitle = document.getElementById('page-title');
  if (pageTitle) pageTitle.textContent = _currentTitle;

  // v1.8.0: header-center 留给未来多站点选择器，页面工具栏留在各自内容区
  var headerCenter = document.getElementById('header-center');
  if (headerCenter) headerCenter.innerHTML = '';

  // 先显示loading
  contentArea.innerHTML = _loadingHtml;

  // 使用fetch加载
  fetch('/admin/' + path, { headers: { 'HX-Request': 'true' } })
    .then(function(r) {
      if (!r.ok) throw new Error('HTTP ' + r.status);
      return r.text();
    })
    .then(function(html) {
      // 嵌套防护
      if (html.indexOf('app-header') !== -1 || html.indexOf('app-shell') !== -1) {
        console.error('[Dashboard] Nested page detected, redirecting...');
        window.location.href = '/admin/dashboard';
        return;
      }

      contentArea.innerHTML = html;
      // 手动处理HTMX属性
      if (window.htmx) {
        htmx.process(contentArea);
        contentArea.querySelectorAll('[hx-trigger*="load"]').forEach(function(el) {
          htmx.trigger(el, 'load');
        });
      }
      // v1.8.2: Load block status if Profiles page
      if (path === 'profiles') {
        setTimeout(function() { if (typeof loadBlockStatus === 'function') loadBlockStatus(); }, 300);
      }
      if (path === 'scanner') {
        setTimeout(function() { if (typeof loadScanHistory === 'function') loadScanHistory(); }, 200);
      }
      if (path === 'blocklist') {
        setTimeout(function() {
          if (typeof loadBlocklistDevices === 'function') loadBlocklistDevices();
          if (typeof loadLedger === 'function') loadLedger('all');
        }, 100);
      }
    })
    .catch(function(err) {
      console.error('[Content] Load failed:', err);
      contentArea.innerHTML = '<div class="empty-state"><div style="font-size:32px;margin-bottom:12px;">⚠</div><p>' + err.message + '</p></div>';
    });
}

/* ============================================================
   v1.8.0: Shared functions (Threats tabs + Log Analyzer)
   Defined here because HTMX innerHTML does not execute <script> tags
   ============================================================ */

var _threatsTabsLoaded = {active: true, quarantine: false, audit: false, clusters: false};

// Auto-load hidden tabs when Threats page loads
document.addEventListener('htmx:afterSettle', function(evt) {
  if (evt.target && evt.target.id === 'main-content') {
    // Check if Threats page just loaded
    if (document.querySelector('.threats-tab')) {
      setTimeout(function() {
        ['quarantine', 'audit', 'clusters'].forEach(function(tab) {
          if (!_threatsTabsLoaded[tab]) {
            _threatsTabsLoaded[tab] = true;
            var urls = { quarantine: '/admin/quarantine?status=quarantined', audit: '/admin/records?audit=true&compact=1', clusters: '/admin/file-clusters' };
            var targets = { quarantine: '#threats-quarantine-container', audit: '#threats-audit-container', clusters: '#threats-clusters-container' };
            if (urls[tab] && window.htmx) htmx.ajax('GET', urls[tab], {target: targets[tab], swap: 'innerHTML'});
          }
        });
      }, 200);
    }
  }
});

function switchThreatsTab(tab) {
  document.querySelectorAll('.threats-tab').forEach(function(t) {
    t.style.color = '#666'; t.style.borderBottomColor = 'transparent'; t.classList.remove('active');
  });
  var at = document.querySelector('.threats-tab[data-tab="' + tab + '"]');
  if (at) { at.style.color = '#00ff41'; at.style.borderBottomColor = '#00ff41'; at.classList.add('active'); }
  document.querySelectorAll('.threats-tab-content').forEach(function(c) { c.style.display = 'none'; });
  var ct = document.getElementById('threats-tab-' + tab);
  if (ct) {
    ct.style.display = 'flex';
    if (!_threatsTabsLoaded[tab]) {
      _threatsTabsLoaded[tab] = true;
      var urls = { quarantine: '/admin/quarantine?status=quarantined', audit: '/admin/records?audit=true&compact=1', clusters: '/admin/file-clusters' };
      var targets = { quarantine: '#threats-quarantine-container', audit: '#threats-audit-container', clusters: '#threats-clusters-container' };
      if (urls[tab] && window.htmx) htmx.ajax('GET', urls[tab], {target: targets[tab], swap: 'innerHTML'});
    }
  }
}

function openLogAnalyzer() {
  var m = document.getElementById('log-analyzer-modal'); if (!m) return;
  m.style.display = 'flex';
  m.style.visibility = 'visible';
  m.style.opacity = '1';
  m.classList.add('active');
  // Copy current content as starting point, then reconnect SSE with all levels
  var s = document.getElementById('live-log-stream'), t = document.getElementById('analyzer-log-content');
  if (s && t) { t.innerHTML = s.innerHTML; t.scrollTop = t.scrollHeight; }
  // v2.0: Reconnect SSE with ?levels=all for full log visibility
  if (window.AnteumbraSSEManager) {
    AnteumbraSSEManager.reconnectWithAllLevels();
  }
  // Reset filter controls to defaults
  var kw = document.getElementById('analyzer-filter-input');
  var lv = document.getElementById('analyzer-level-filter');
  var md = document.getElementById('analyzer-module-filter');
  var tr = document.getElementById('analyzer-time-filter');
  if (kw) kw.value = '';
  if (lv) lv.value = 'all';
  if (md) md.value = 'all';
  if (tr) tr.value = 'all';
  analyzerTimePreset();
}

function closeLogAnalyzer() {
  var m = document.getElementById('log-analyzer-modal'); if (!m) return;
  m.style.display = 'none'; m.style.visibility = 'hidden'; m.style.opacity = '0';
  m.classList.remove('active');
  // v2.0: Reconnect SSE with normal (filtered) levels
  if (window.AnteumbraSSEManager) {
    AnteumbraSSEManager.reconnectNormal();
  }
}

function loadAccessLogAnalysis() {
  var c = document.getElementById('analyzer-log-content'); if (!c) return;
  c.innerHTML = '<div class="empty-state"><p>Loading access log analysis...</p></div>';
  fetch('/admin/logs/access-analysis')
    .then(function(r) {
      if (!r.ok) throw new Error('HTTP ' + r.status);
      return r.text();
    })
    .then(function(html) {
      c.innerHTML = html || '<div class="log-line info">[ACCESS_ANALYSIS] No analysis output</div>';
      filterLogAnalyzer();
    })
    .catch(function(e) {
      c.innerHTML = '<div class="log-line error">[ACCESS_ANALYSIS][ERROR] ' + String(e).replace(/[<>]/g, '') + '</div>';
      filterLogAnalyzer();
    });
}

function analyzerTimePreset() {
  var tr = document.getElementById('analyzer-time-filter')?.value || 'all';
  var custom = document.getElementById('analyzer-custom-time');
  if (custom) custom.style.display = (tr === 'custom') ? '' : 'none';
  filterLogAnalyzer();
}

function filterLogAnalyzer() {
  var kw = (document.getElementById('analyzer-filter-input')?.value || '').toLowerCase();
  var lv = document.getElementById('analyzer-level-filter')?.value || 'all';
  var md = document.getElementById('analyzer-module-filter')?.value || 'all';
  var tr = document.getElementById('analyzer-time-filter')?.value || 'all';
  var c = document.getElementById('analyzer-log-content'); if (!c) return;

  // Time range: relative presets
  var now = Date.now(), minTime = 0, maxTime = 0;
  if (tr === '1h') minTime = now - 3600000;
  else if (tr === '6h') minTime = now - 21600000;
  else if (tr === '24h') minTime = now - 86400000;
  else if (tr === '7d') minTime = now - 604800000;
  else if (tr === '30d') minTime = now - 2592000000;
  else if (tr === 'custom') {
    // Custom absolute range: date + time inputs
    var fd = document.getElementById('analyzer-time-from-date');
    var ft = document.getElementById('analyzer-time-from-time');
    var td = document.getElementById('analyzer-time-to-date');
    var tt = document.getElementById('analyzer-time-to-time');
    if (fd && fd.value) { var fv = fd.value; if (ft && ft.value) fv += 'T' + ft.value; else fv += 'T00:00'; minTime = new Date(fv).getTime(); }
    if (td && td.value) { var tv = td.value; if (tt && tt.value) tv += 'T' + tt.value; else tv += 'T23:59'; maxTime = new Date(tv).getTime(); }
  }

  var v = 0;
  c.querySelectorAll('.log-line').forEach(function(el) {
    var tx = el.textContent; var s = true;
    if (kw && tx.toLowerCase().indexOf(kw) < 0) s = false;
    // Level: match ' CRITICAL ', '[CRITICAL]', or 'CRITICAL -'
    if (lv !== 'all') {
      var up = tx.toUpperCase();
      if (up.indexOf(' ' + lv + ' ') < 0 && up.indexOf('[' + lv + ']') < 0 && up.indexOf(lv + ' -') < 0) s = false;
    }
    if (md !== 'all' && tx.indexOf('[' + md + ']') < 0) s = false;
    // Time range
    if (minTime > 0 || maxTime > 0) {
      var m = tx.match(/\[(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})/);
      if (m) {
        var ts = new Date(m[1].replace(' ', 'T')).getTime();
        if (minTime > 0 && ts < minTime) s = false;
        if (maxTime > 0 && ts > maxTime) s = false;
      }
    }
    el.style.display = s ? '' : 'none'; if (s) v++;
  });
  var ce = document.getElementById('analyzer-count'); if (ce) ce.textContent = v + ' lines';
}

function filterLogStream() {
  var kw = (document.getElementById('log-filter-input')?.value || '').toLowerCase();
  var c = document.getElementById('live-log-stream'); if (!c) return;
  c.querySelectorAll('.log-line').forEach(function(el) {
    el.style.display = (kw && el.textContent.toLowerCase().indexOf(kw) < 0) ? 'none' : '';
  });
}

// v2.0: Client-side record table filtering (fixes search focus loss)
function filterRecordsTable(input) {
  var kw = (input.value || '').toLowerCase();
  var containerId = input.dataset.container;
  var container = document.getElementById(containerId);
  if (!container) return;
  container.querySelectorAll('.record-item').forEach(function(el) {
    var text = (el.dataset.path || '') + ' ' + (el.textContent || '');
    el.style.display = (kw && text.toLowerCase().indexOf(kw) < 0) ? 'none' : '';
  });
}

// v2.0: Client-side YARA rule filtering (fixes toolbar disappearing on search)
function yaraClientFilter(input) {
  var kw = (input.value || '').toLowerCase();
  var container = document.getElementById('yara-rules-container');
  if (!container) return;
  container.querySelectorAll('.record-item').forEach(function(el) {
    var text = (el.dataset.filename || '') + ' ' + (el.textContent || '');
    el.style.display = (kw && text.toLowerCase().indexOf(kw) < 0) ? 'none' : '';
  });
}

// v2.0: Client-side quarantine filtering (fixes search focus loss)
function filterQuarantineTable(input) {
  var kw = (input.value || '').toLowerCase();
  var container = document.getElementById('quarantine-list-container');
  if (!container) return;
  container.querySelectorAll('.record-item').forEach(function(el) {
    var text = (el.textContent || '');
    el.style.display = (kw && text.toLowerCase().indexOf(kw) < 0) ? 'none' : '';
  });
}

// v1.8.0: Moved from dashboard.html for consistency
function closeRecordDetail() {
  var overlay = document.getElementById('record-detail-modal-overlay');
  var modal = document.getElementById('record-detail-modal');
  if (overlay) { overlay.style.display = 'none'; overlay.classList.remove('active'); }
  if (modal) { modal.style.display = 'none'; modal.classList.remove('active'); modal.innerHTML = ''; }
}

// v1.8.0: Auto-show record detail modal when content is swapped in
document.addEventListener('htmx:afterSwap', function(evt) {
  if (evt.detail.target.id === 'record-detail-modal') {
    showRecordDetail();
  }
});

// v1.8.0: System modal (Settings page)
var _systemUrls = {
  registry: '/admin/system/registry_panel',
  wal: '/admin/system/wal_panel',
  session: '/admin/system/session_panel?per_page=6',
  config: '/admin/system/config_panel'
};
var _systemTitles = {
  registry: 'Registry Status', wal: 'WAL Management',
  session: 'Session Management', config: 'Config Reload'
};
var _systemActions = {
  registry: '<button class=\"btn btn-ghost btn-sm\" hx-post=\"/admin/system/registry/compact\" hx-target=\"#system-modal-body\" hx-swap=\"innerHTML\">Compact</button>',
  wal: '<button class=\"btn btn-ghost btn-sm\" hx-post=\"/admin/system/wal/replay\" hx-target=\"#system-modal-body\" hx-swap=\"innerHTML\">Replay</button>',
  session: '<button class=\"btn btn-ghost btn-sm\" hx-post=\"/admin/system/session/cleanup\" hx-target=\"#system-modal-body\" hx-swap=\"innerHTML\">Cleanup</button>',
  config: '<button class=\"btn btn-ghost btn-sm\" hx-post=\"/admin/system/config/reload\" hx-confirm=\"Reload config?\" hx-target=\"#system-modal-body\" hx-swap=\"innerHTML\">Reload</button>'
};
function openSystemModal(type) {
  var m = document.getElementById('system-modal');
  var t = document.getElementById('system-modal-title');
  var b = document.getElementById('system-modal-body');
  var a = document.getElementById('system-modal-actions');
  if (!m || !b) return;
  m.style.display = 'flex'; m.style.visibility = 'visible'; m.style.opacity = '1';
  m.classList.add('active');
  if (t) t.textContent = _systemTitles[type] || type;
  if (a) a.innerHTML = _systemActions[type] || '';
  b.innerHTML = '<div class=\"empty-state\"><div class=\"spinner\"></div><p>Loading...</p></div>';
  if (_systemUrls[type]) htmx.ajax('GET', _systemUrls[type], {target: '#system-modal-body', swap: 'innerHTML'});
}
function closeSystemModal() {
  var m = document.getElementById('system-modal'); if (!m) return;
  m.style.display = 'none'; m.style.visibility = 'hidden'; m.style.opacity = '0';
  m.classList.remove('active');
}


// Load block status when Profiles page loads
document.addEventListener('htmx:afterSettle', function(evt) {
  _restoreIPCheckboxes();
  _restoreRecCheckboxes();
  _restoreQCheckboxes();
  if (document.getElementById('block-status-panel')) loadBlockStatus();
});

// v2.0 fix: Stats refresh triggered by batch quarantine/FP/delete operations
document.addEventListener('anteumbra:statsRefresh', function() {
  // Refresh Security Report panel on Overview page
  var statsPanel = document.getElementById('overview-stats');
  if (statsPanel && window.htmx) {
    htmx.ajax('GET', '/admin/dashboard_content', {target: '#overview-stats', swap: 'innerHTML'});
  }
  // Also refresh Active Threats panel
  var threatsPanel = document.getElementById('overview-active-threats');
  if (threatsPanel && window.htmx) {
    htmx.ajax('GET', '/admin/records?compact=1', {target: '#overview-active-threats', swap: 'innerHTML'});
  }
});


function _escHtml(str) {
  if (!str) return '';
  return String(str).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}
function _escJs(str) {
  if (!str) return '';
  return String(str).replace(/\\/g, '\\\\').replace(/'/g, "\\'").replace(/"/g, '\\"').replace(/\n/g, '\\n');
}

// ESC key closes modals
document.addEventListener('keydown', function(e) {
  if (e.key === 'Escape') {
    closeRecordDetail();
    closeLogAnalyzer();
    closeSystemModal();
  }
});

/* ============================================================
   刷新当前页面（Refresh按钮调用）
   ============================================================ */
function refreshCurrent() {
  if (_currentPath === 'dashboard_content') {
    loadDashboard();
  } else {
    loadContent(_currentPath, _currentTitle);
  }
}

/* ============================================================
   手动加载Dashboard各面板数据
   ============================================================ */
function loadDashboardPanels() {
  // Metrics面板
  var metricsPanel = document.getElementById('metrics-panel');
  if (metricsPanel) {
    fetch('/admin/metrics/data', { headers: { 'HX-Request': 'true' } })
      .then(function(r) { return r.text(); })
      .then(function(html) {
        metricsPanel.innerHTML = html;
        if (window.htmx) htmx.process(metricsPanel);
      })
      .catch(function(e) { console.error('Metrics load failed:', e); });
  }

  // YARA规则面板（compact模式，使用outerHTML避免嵌套）
  var yaraContainer = document.getElementById('yara-rules-container');
  if (yaraContainer) {
    fetch('/admin/yara/rules?compact=1', { headers: { 'HX-Request': 'true' } })
      .then(function(r) { return r.text(); })
      .then(function(html) {
        var temp = document.createElement('div');
        temp.innerHTML = html;
        var newContainer = temp.firstElementChild;
        if (newContainer) {
          yaraContainer.replaceWith(newContainer);
          if (window.htmx) htmx.process(newContainer);
        }
      })
      .catch(function(e) { console.error('YARA load failed:', e); });
  }

  // Records面板（compact模式，使用outerHTML避免嵌套）
  var recordsContainer = document.getElementById('records-table-container');
  if (recordsContainer) {
    fetch('/admin/records?compact=1', { headers: { 'HX-Request': 'true' } })
      .then(function(r) { return r.text(); })
      .then(function(html) {
        var temp = document.createElement('div');
        temp.innerHTML = html;
        var newContainer = temp.firstElementChild;
        if (newContainer) {
          recordsContainer.replaceWith(newContainer);
          if (window.htmx) htmx.process(newContainer);
        }
      })
      .catch(function(e) { console.error('Records load failed:', e); });
  }
}

function showYaraEditModal(filename) {
  AnteumbraUtils.modal.show('yara-edit-modal');
}

function confirmDelete(filename) {
  AnteumbraUtils.confirm('Delete rule file: ' + filename + ' ?', function() {
    var btn = document.querySelector('[data-delete-file="' + filename + '"]');
    if (btn) btn.click();
  });
}


// v1.7.9-Patch: 修复 Record Detail Modal 显示
function showRecordDetail() {
    const modal = document.getElementById('record-detail-modal');
    const overlay = document.getElementById('record-detail-modal-overlay');
    if (modal) {
        modal.style.display = 'flex';
        modal.classList.add('active');
    }
    if (overlay) {
        overlay.style.display = 'block';
        overlay.classList.add('active');
    }
}



// v1.9.5: Config Editor — moved from config_editor.html (HTMX innerHTML doesn't exec script)
function saveConfig() {
  var changes = {};
  document.querySelectorAll('#config-tree input:not([disabled])').forEach(function(inp) {
    var key = inp.dataset.key; if (!key) return;
    var val;
    if (inp.type === 'checkbox') val = inp.checked;
    else if (inp.type === 'number') val = parseFloat(inp.value) || 0;
    else val = inp.value;
    changes[key] = val;
  });
  fetch('/admin/settings/config/save', {
    method: 'POST',
    headers: {'Content-Type': 'application/json', 'X-CSRFToken': document.querySelector('meta[name="csrf-token"]')?.content || ''},
    body: JSON.stringify({changes: changes})
  }).then(function(r) { return r.json(); }).then(function(data) {
    var el = document.getElementById('config-saved');
    if (data.success) { if (el) { el.style.display = ''; el.textContent = 'Saved'; } }
    else { if (el) { el.style.display = ''; el.textContent = 'Error: ' + (data.error || 'unknown'); el.style.color = '#ff4444'; } }
  });
}
function saveEnvVars() {
  var vars = {};
  var hashVal = document.getElementById('env-pwd-display')?.dataset?.hash;
  if (hashVal) vars['ANTEUMBRA_PASSWORD_HASH'] = hashVal;
  ['ANTEUMBRA_WECHAT_API_KEY','ANTEUMBRA_EMAIL_USERNAME','ANTEUMBRA_EMAIL_PASSWORD','ANTEUMBRA_EMAIL_FROM','ANTEUMBRA_EMAIL_TO','ANTEUMBRA_WEBHOOK_SECRET'].forEach(function(k) {
    var el = document.getElementById('env-' + k);
    if (el) vars[k] = el.value;
  });
  fetch('/admin/settings/env/save', {
    method: 'POST',
    headers: {'Content-Type': 'application/json', 'X-CSRFToken': document.querySelector('meta[name="csrf-token"]')?.content || ''},
    body: JSON.stringify({vars: vars})
  }).then(function(r) { return r.json(); }).then(function(data) {
    var el = document.getElementById('env-saved');
    if (data.success) { if (el) { el.style.display = ''; el.textContent = 'Saved'; } }
    else { if (el) { el.style.display = ''; el.textContent = 'Error: ' + (data.error || 'unknown'); el.style.color = '#ff4444'; } }
  });
}
function generatePwdHash() {
  var pwd = document.getElementById('env-pwd-input').value;
  if (!pwd) { alert('Enter a password first'); return; }
  fetch('/admin/settings/env/hash', {
    method: 'POST',
    headers: {'Content-Type': 'application/json', 'X-CSRFToken': document.querySelector('meta[name="csrf-token"]')?.content || ''},
    body: JSON.stringify({password: pwd})
  }).then(function(r) { return r.json(); }).then(function(data) {
    if (data.hash) {
      document.getElementById('env-pwd-input').value = '';
      document.getElementById('env-pwd-display').textContent = data.hash.substring(0, 60) + '...';
      document.getElementById('env-pwd-display').dataset.hash = data.hash;
    }
  });
}
function markDirty() {
  var el = document.getElementById('config-saved');
  if (el) el.style.display = 'none';
}
