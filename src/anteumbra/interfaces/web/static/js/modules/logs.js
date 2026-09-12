/* Log analyzer page: server-filtered history, live tail, aggregates, export.
 *
 * The page owns its own filter state; every change re-queries
 * /admin/logs/analyzer/data so the aggregates and the table never disagree.
 * Live tail subscribes to the same SSE stream the overview uses and pushes
 * parsed lines through the same client-side filter set.
 */
(function () {
  'use strict';

  var app = window.Anteumbra;
  var LEVELS = ['CRITICAL', 'ERROR', 'WARNING', 'INFO', 'DEBUG'];
  var MAX_LIVE_ROWS = 400;

  var state = {
    range: '24h', level: 'all', module: 'all', keyword: '', hitsOnly: false, limit: 500,
    from: '', to: '',
    live: false, stream: null, rows: [], modulesSeeded: false, requestId: 0
  };

  function node(id) { return document.getElementById(id); }
  function setText(id, value) { var el = node(id); if (el) el.textContent = value; }

  // ── client-side parser (mirrors application/log_analyzer_service.py) ──────
  var TAG_RE = /\[([A-Za-z0-9_.:-]{2,24})\]/g;
  var MODULES = ['MONITOR', 'MANUAL_SCANNER', 'SCANNER', 'SCAN', 'QUARANTINE', 'REGISTRY',
    'NOTIFIER', 'SECURITY', 'ALERT', 'YARA', 'PROFILE', 'WAL', 'PLUGIN', 'SIEM', 'CONFIG',
    'API', 'WEB', 'STDOUT'];
  var MARKERS = ['MATCH', 'HIT', 'SUCCESS', 'FAILED', 'FAIL', 'START', 'STOP', 'SKIP', 'SAFE'];
  var LEVEL_WORDS = ['CRITICAL', 'ERROR', 'WARNING', 'WARN', 'INFO', 'DEBUG'];

  function tags(text) {
    var out = []; var m; TAG_RE.lastIndex = 0;
    while ((m = TAG_RE.exec(text)) !== null) out.push(m[1].toUpperCase());
    return out;
  }

  function parseLine(text) {
    var found = tags(text);
    var level = 'INFO';
    var assigned = /level=(CRITICAL|ERROR|WARNING|WARN|INFO|DEBUG)/i.exec(text);
    if (assigned) {
      level = assigned[1].toUpperCase();
    } else {
      for (var i = 0; i < found.length; i++) {
        if (LEVEL_WORDS.indexOf(found[i]) !== -1) { level = found[i]; break; }
      }
      if (level === 'INFO') {
        var bare = /\b(CRITICAL|ERROR|WARNING|DEBUG)\b/.exec(text);
        if (bare) level = bare[1];
      }
    }
    if (level === 'WARN') level = 'WARNING';
    var module = 'SYSTEM';
    for (var j = 0; j < found.length; j++) {
      if (MODULES.indexOf(found[j]) !== -1) { module = found[j]; break; }
    }
    var marker = null;
    for (var k = 0; k < found.length; k++) {
      if (MARKERS.indexOf(found[k]) !== -1 && LEVEL_WORDS.indexOf(found[k]) === -1) { marker = found[k]; break; }
    }
    var stamp = /^\[(\d{4}-\d{2}-\d{2})[ T](\d{2}:\d{2}:\d{2})/.exec(text);
    return {
      time: stamp ? stamp[1] + ' ' + stamp[2] : '',
      level: level, module: module, marker: marker,
      hit: marker === 'MATCH' || marker === 'HIT', text: text
    };
  }

  function levelRank(level) {
    var index = LEVELS.indexOf(level);
    return index === -1 ? LEVELS.length : index;
  }

  function matches(row) {
    if (state.level !== 'all' && row.level !== state.level) return false;
    if (state.module !== 'all' && row.module !== state.module) return false;
    if (state.hitsOnly && !row.hit) return false;
    if (state.keyword) {
      var hay = row.text.toLowerCase();
      var terms = state.keyword.toLowerCase().split(/\s+/).filter(Boolean);
      for (var i = 0; i < terms.length; i++) if (hay.indexOf(terms[i]) === -1) return false;
    }
    return true;
  }

  // ── rendering ────────────────────────────────────────────────────────────
  function highlight(text) {
    var fragment = document.createDocumentFragment();
    var terms = state.keyword ? state.keyword.split(/\s+/).filter(Boolean) : [];
    if (!terms.length) { fragment.appendChild(document.createTextNode(text)); return fragment; }
    var lower = text.toLowerCase();
    var spans = [];
    terms.forEach(function (term) {
      var needle = term.toLowerCase(); var from = 0; var at;
      while ((at = lower.indexOf(needle, from)) !== -1) {
        spans.push([at, at + needle.length]); from = at + needle.length;
      }
    });
    spans.sort(function (a, b) { return a[0] - b[0]; });
    var cursor = 0;
    spans.forEach(function (span) {
      if (span[0] < cursor) return;
      fragment.appendChild(document.createTextNode(text.slice(cursor, span[0])));
      var mark = document.createElement('mark');
      mark.textContent = text.slice(span[0], span[1]);
      fragment.appendChild(mark);
      cursor = span[1];
    });
    fragment.appendChild(document.createTextNode(text.slice(cursor)));
    return fragment;
  }

  function renderRows(rows) {
    var tbody = node('log-rows');
    if (!tbody) return;
    tbody.replaceChildren();
    if (!rows.length) {
      var empty = document.createElement('tr');
      var cell = document.createElement('td');
      cell.colSpan = 5; cell.className = 'logs-placeholder';
      cell.textContent = 'No log lines match the current filters.';
      empty.appendChild(cell); tbody.appendChild(empty);
      return;
    }
    rows.forEach(function (row) { tbody.appendChild(buildRow(row)); });
  }

  function buildRow(row) {
    var tr = document.createElement('tr');
    tr.className = 'logs-row logs-row--' + row.level.toLowerCase() + (row.hit ? ' logs-row--hit' : '');
    var time = document.createElement('td');
    time.className = 'logs-col-time';
    time.textContent = row.time ? row.time.slice(11) : '—';
    if (row.time) time.title = row.time;
    var level = document.createElement('td');
    level.className = 'logs-col-level';
    var badge = document.createElement('span');
    badge.className = 'logs-level logs-level--' + row.level.toLowerCase();
    badge.textContent = row.level;
    level.appendChild(badge);
    var module = document.createElement('td');
    module.className = 'logs-col-module';
    var chip = document.createElement('span');
    chip.className = 'logs-module';
    chip.textContent = row.module;
    module.appendChild(chip);
    var message = document.createElement('td');
    message.className = 'logs-message';
    message.appendChild(highlight(row.text));
    var actions = document.createElement('td');
    actions.className = 'logs-col-actions';
    var copy = document.createElement('button');
    copy.className = 'btn btn-ghost btn-xs'; copy.type = 'button';
    copy.textContent = 'Copy';
    copy.dataset.action = 'logs.copy';
    actions.appendChild(copy);
    [time, level, module, message, actions].forEach(function (cell) { tr.appendChild(cell); });
    return tr;
  }

  function renderTimeline(series) {
    var host = node('log-timeline');
    if (!host) return;
    host.replaceChildren();
    if (!series || !series.length) {
      host.innerHTML = '<div class="logs-placeholder">No time-bucketed data.</div>';
      setText('log-timeline-hint', '');
      return;
    }
    var peak = Math.max.apply(null, series.map(function (point) { return point.total; }).concat([1]));
    series.forEach(function (point) {
      var bar = document.createElement('div');
      bar.className = 'logs-bar';
      bar.style.height = Math.max(2, Math.round((point.total / peak) * 100)) + '%';
      bar.dataset.total = point.total;
      bar.dataset.errors = point.errors;
      if (point.errors) bar.classList.add('logs-bar--errors');
      bar.title = point.label + ' — ' + point.total + ' lines' + (point.errors ? ', ' + point.errors + ' errors' : '');
      host.appendChild(bar);
    });
    setText('log-timeline-hint', series[0].label + ' → ' + series[series.length - 1].label + '  |  peak ' + peak);
  }

  function renderBreakdown(levels, modules) {
    var levelHost = node('log-levels');
    var moduleHost = node('log-modules');
    if (!levelHost || !moduleHost) return;
    var levelTotal = LEVELS.reduce(function (sum, name) { return sum + (levels[name] || 0); }, 0) || 1;
    levelHost.replaceChildren();
    LEVELS.forEach(function (name) {
      var value = levels[name] || 0;
      levelHost.appendChild(breakdownRow(name, value, Math.round((value / levelTotal) * 100), 'logs-level--' + name.toLowerCase()));
    });
    var moduleNames = Object.keys(modules || {});
    var modulePeak = moduleNames.reduce(function (max, key) { return Math.max(max, modules[key]); }, 1);
    moduleHost.replaceChildren();
    moduleNames.forEach(function (name) {
      moduleHost.appendChild(breakdownRow(name, modules[name], Math.round((modules[name] / modulePeak) * 100), 'logs-module'));
    });
    seedModules(moduleNames);
  }

  function breakdownRow(label, value, percent, cls) {
    var row = document.createElement('div');
    row.className = 'logs-breakdown-row';
    var name = document.createElement('span');
    name.className = 'logs-breakdown-label ' + cls;
    name.textContent = label;
    var track = document.createElement('span');
    track.className = 'logs-breakdown-track';
    var fill = document.createElement('span');
    fill.className = 'logs-breakdown-fill';
    fill.style.width = Math.max(2, percent) + '%';
    track.appendChild(fill);
    var count = document.createElement('span');
    count.className = 'logs-breakdown-value';
    count.textContent = value;
    row.append(name, track, count);
    return row;
  }

  function seedModules(names) {
    var select = node('log-module');
    if (!select || state.modulesSeeded) return;
    names.forEach(function (name) {
      var option = document.createElement('option');
      option.value = name; option.textContent = name;
      select.appendChild(option);
    });
    state.modulesSeeded = true;
    if (state.module !== 'all') select.value = state.module;
  }

  // ── data ─────────────────────────────────────────────────────────────────
  function query() {
    var params = new URLSearchParams({
      range: state.range, level: state.level, module: state.module,
      q: state.keyword, limit: String(state.limit)
    });
    if (state.hitsOnly) params.set('hits', '1');
    if (state.range === 'custom') {
      if (state.from) params.set('from', String(new Date(state.from).getTime() / 1000));
      if (state.to) params.set('to', String(new Date(state.to).getTime() / 1000));
    }
    return '/admin/logs/analyzer/data?' + params.toString();
  }

  function setState(text) { setText('log-state', text); }

  function refresh() {
    var requestId = ++state.requestId;
    setState('Loading...');
    return app.http.json(query()).then(function (data) {
      if (requestId !== state.requestId) return data;
      state.rows = data.rows || [];
      setText('log-kpi-scanned', data.scanned || 0);
      setText('log-kpi-matched', data.matched || 0);
      setText('log-kpi-errors', data.errors || 0);
      setText('log-kpi-hits', data.hits || 0);
      setText('log-count-badge', state.rows.length);
      setText('log-truncated-hint', data.truncated
        ? 'showing the newest ' + state.rows.length + ' of ' + data.matched + ' matches'
        : (data.undated ? data.undated + ' undated lines hidden by the time filter' : ''));
      renderRows(state.rows.slice().reverse());
      renderTimeline(data.timeline);
      renderBreakdown(data.levels || {}, data.modules || {});
      setState('Updated ' + new Date().toLocaleTimeString());
      return data;
    }).catch(function (error) {
      setState('Failed: ' + error.message);
      return null;
    });
  }

  // ── live tail ────────────────────────────────────────────────────────────
  function startLive() {
    if (state.live) return;
    var meta = document.querySelector('meta[name="sse-token"]');
    var token = meta ? meta.content : '';
    if (!token) { setState('SSE token missing'); return; }
    state.live = true;
    var button = node('log-live-btn');
    if (button) button.classList.add('active');
    setState('Live tail connected');
    state.stream = new EventSource('/admin/stream_logs?token=' + encodeURIComponent(token) + '&levels=all',
      { withCredentials: true });
    state.stream.onmessage = function (event) {
      var row = parseLine(String(event.data || ''));
      if (!matches(row)) return;
      state.rows.push(row);
      if (state.rows.length > MAX_LIVE_ROWS) state.rows.shift();
      setText('log-count-badge', state.rows.length);
      var tbody = node('log-rows');
      if (!tbody) return;
      if (tbody.firstChild && tbody.firstChild.className === 'logs-row') {
        tbody.insertBefore(buildRow(row), tbody.firstChild);
      } else {
        renderRows(state.rows.slice().reverse());
      }
      while (tbody.children.length > MAX_LIVE_ROWS) tbody.removeChild(tbody.lastChild);
    };
    state.stream.onerror = function () {
      setState('Live tail reconnecting...');
    };
  }

  function stopLive() {
    state.live = false;
    if (state.stream) { state.stream.close(); state.stream = null; }
    var button = node('log-live-btn');
    if (button) button.classList.remove('active');
    setState('Live tail stopped');
  }

  function toggleLive() { if (state.live) { stopLive(); } else { startLive(); } }

  // ── export ───────────────────────────────────────────────────────────────
  function exportRows(format) {
    var rows = state.rows.slice().reverse();
    var payload = format === 'csv' ? toCsv(rows) : JSON.stringify(rows, null, 2);
    var blob = new Blob([payload], { type: format === 'csv' ? 'text/csv' : 'application/json' });
    var url = URL.createObjectURL(blob);
    var link = document.createElement('a');
    link.href = url;
    link.download = 'anteumbra-logs-' + new Date().toISOString().replace(/[:.]/g, '-') + '.' + format;
    document.body.appendChild(link);
    link.click();
    link.remove();
    URL.revokeObjectURL(url);
    setState('Exported ' + rows.length + ' lines as ' + format.toUpperCase());
  }

  function toCsv(rows) {
    var escape = function (value) {
      var text = String(value == null ? '' : value);
      return /[",\n]/.test(text) ? '"' + text.replace(/"/g, '""') + '"' : text;
    };
    var lines = ['time,level,module,marker,message'];
    rows.forEach(function (row) {
      lines.push([row.time, row.level, row.module, row.marker || '', row.text].map(escape).join(','));
    });
    return lines.join('\n');
  }

  function applyControlValues() {
    var level = node('log-level'); if (level) state.level = level.value;
    var module = node('log-module'); if (module) state.module = module.value;
    var keyword = node('log-keyword'); if (keyword) state.keyword = keyword.value.trim();
    var hits = node('log-hits-only'); if (hits) state.hitsOnly = hits.checked;
    var limit = node('log-limit'); if (limit) state.limit = Number(limit.value) || 500;
    var from = node('log-from'); if (from) state.from = from.value;
    var to = node('log-to'); if (to) state.to = to.value;
  }

  // Typing must filter without waiting for blur; 300ms keeps the API calm on a
  // 5000-line history.
  var searchTimer = null;
  function search() {
    window.clearTimeout(searchTimer);
    searchTimer = window.setTimeout(function () {
      applyControlValues();
      state.modulesSeeded = true;
      refresh();
    }, 300);
  }

  function selectRange(range) {
    state.range = range;
    document.querySelectorAll('.logs-range-btn').forEach(function (button) {
      button.classList.toggle('active', button.dataset.range === range);
    });
    var custom = node('log-custom-range');
    if (custom) custom.hidden = range !== 'custom';
    refresh();
  }

  function resetFilters() {
    state.level = 'all'; state.module = 'all'; state.keyword = ''; state.hitsOnly = false; state.limit = 500;
    state.from = ''; state.to = '';
    ['log-level', 'log-module', 'log-limit'].forEach(function (id) {
      var el = node(id); if (el) el.value = id === 'log-limit' ? '500' : 'all';
    });
    ['log-keyword', 'log-from', 'log-to'].forEach(function (id) { var el = node(id); if (el) el.value = ''; });
    var hits = node('log-hits-only'); if (hits) hits.checked = false;
    selectRange('all');
  }

  function copyRow(context) {
    var row = context.element.closest('tr');
    var text = row ? row.querySelector('.logs-message').textContent : '';
    if (!text) return;
    if (navigator.clipboard) navigator.clipboard.writeText(text);
    app.ui.toast('Line copied');
  }

  function loadAccessAnalysis() {
    var panel = node('log-access-panel');
    var content = node('log-access-content');
    if (!panel || !content) return;
    panel.hidden = false;
    content.innerHTML = '<div class="logs-placeholder">Analyzing configured access logs...</div>';
    app.http.text('/admin/logs/access-analysis', { headers: { 'HX-Request': 'true' } })
      .then(function (html) { content.innerHTML = html; app.processHtmx(content); })
      .catch(function (error) { content.textContent = 'Analysis failed: ' + error.message; });
  }

  app.register('logs', {
    actions: {
      'logs.range': { handler: function (context) { applyControlValues(); selectRange(context.element.dataset.range); } },
      'logs.filter': { handler: function () { applyControlValues(); state.modulesSeeded = true; refresh(); },
                       events: ['change'], preventDefault: false },
      'logs.search': { handler: search, events: ['input'], preventDefault: false },
      'logs.refresh': { handler: function () { applyControlValues(); refresh(); } },
      'logs.live-toggle': { handler: toggleLive },
      'logs.clear': { handler: resetFilters },
      'logs.export': { handler: function (context) { exportRows(context.element.dataset.format); } },
      'logs.copy': { handler: copyRow },
      'logs.access-analysis': { handler: loadAccessAnalysis },
      'logs.access-close': { handler: function () { var panel = node('log-access-panel'); if (panel) panel.hidden = true; } }
    },
    mount: function (root) {
      var page = root && (root.id === 'log-rows' || (root.querySelector && root.querySelector('#log-rows')));
      if (page) refresh();
    },
    unmount: function (root) {
      var page = root && (root.querySelector && root.querySelector('#log-rows'));
      if (page && state.live) stopLive();
    },
    refresh: refresh
  });
}());
