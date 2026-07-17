/* Anteumbra SSE connection manager */
window.AnteumbraSSEManager = {
  eventSource: null,
  isConnected: false,
  lastActivity: 0,
  HEALTH_CHECK_INTERVAL: 30000,
  reconnectTimer: null,
  reconnectAttempts: 0,
  MAX_RECONNECT_DELAY: 30000,
  healthCheckTimer: null,
  MAX_LOG_LINES: 500,
  historyLoaded: false,
  historyLoading: null,
  _analyzerOpen: false,
  _allLevels: false,

  getConnection() {
    if (this.eventSource && this.eventSource.readyState === EventSource.OPEN) {
      return this.eventSource;
    }
    // Load history before opening the live stream.
    if (!this.historyLoaded) {
      if (!this.historyLoading) {
        this.historyLoading = this.loadHistory().finally(() => {
          this.historyLoading = null;
          this.createConnection();
        });
      }
      return null;
    }
    return this.createConnection();
  },

  loadHistory() {
    var self = this;
    var logStream = document.getElementById('live-log-stream');
    if (!logStream) {
      // Keep historyLoaded=false so the next DOM-ready call can retry.
      return Promise.resolve(false);
    }
    return fetch('/admin/logs/history')
      .then(function(r) {
        if (!r.ok) throw new Error('HTTP ' + r.status);
        return r.text();
      })
      .then(function(html) {
        if (html && html.trim()) {
          logStream.innerHTML = html;
        }
        self.historyLoaded = true;
      })
      .catch(function(e) {
        console.error('[SSE-MGR] History load failed:', e);
        self.historyLoaded = true;
      });
  },

  createConnection() {
    if (this.eventSource) { this.eventSource.close(); }

    const tokenMeta = document.querySelector('meta[name="sse-token"]');
    const token = tokenMeta ? tokenMeta.content : '';
    if (!token) { console.error('[SSE-MGR] Token missing'); return null; }

    this.updateStatus('connecting');
    var sseUrl = '/admin/stream_logs?token=' + encodeURIComponent(token);
    if (this._allLevels) { sseUrl += '&levels=all'; }
    this.eventSource = new EventSource(sseUrl, { withCredentials: true });

    this.eventSource.onopen = () => {
      this.isConnected = true;
      this.lastActivity = Date.now();
      this.reconnectAttempts = 0;
      this.updateStatus('connected');
      this.startHealthCheck();
    };

    this.eventSource.onerror = (e) => {
      this.isConnected = false;
      this.updateStatus('disconnected');
      this.stopHealthCheck();

      if (this.reconnectTimer) clearTimeout(this.reconnectTimer);

      const baseDelay = Math.min(5000 * Math.pow(2, this.reconnectAttempts), this.MAX_RECONNECT_DELAY);
      const jitter = Math.random() * 2000;
      const delay = baseDelay + jitter;
      this.reconnectAttempts++;

      this.reconnectTimer = setTimeout(() => this.getConnection(), delay);
    };

    this.eventSource.onmessage = (e) => {
      this.lastActivity = Date.now();
      this.appendLogLine(e.data);
    };

    return this.eventSource;
  },

  _appendToStream(container, rawData) {
    if (!container) return;

    let logClass = 'info';
    const upper = rawData.toUpperCase();
    if (upper.indexOf('[CRITICAL]') !== -1 || upper.indexOf('CRITICAL') !== -1) {
      logClass = 'critical';
    } else if (upper.indexOf('[ERROR]') !== -1 || upper.indexOf('ERROR') !== -1) {
      logClass = 'error';
    } else if (upper.indexOf('[WARNING]') !== -1 || upper.indexOf('WARN') !== -1) {
      logClass = 'warn';
    } else if (upper.indexOf('[DEBUG]') !== -1 || upper.indexOf('DEBUG') !== -1) {
      logClass = 'debug';
    }

    const line = document.createElement('div');
    line.className = 'log-line ' + logClass;
    line.textContent = rawData;

    container.appendChild(line);

    while (container.children.length > this.MAX_LOG_LINES) {
      container.removeChild(container.firstChild);
    }

    requestAnimationFrame(function() {
      container.scrollTop = container.scrollHeight;
    });
  },

  appendLogLine(rawData) {
    if (rawData.indexOf('[SSE]') === 0) {
      return;
    }

    const filterInput = document.getElementById('log-search-input');
    const term = filterInput ? filterInput.value.toLowerCase() : '';
    const matches = !term || rawData.toLowerCase().includes(term);

    const logStream = document.getElementById('log-stream');
    if (logStream) {
      this._appendToStream(logStream, rawData);
      if (!matches && logStream.lastChild) {
        logStream.lastChild.style.display = 'none';
      }
    }

    const liveStream = document.getElementById('live-log-stream');
    if (liveStream) {
      const placeholder = liveStream.querySelector('.empty-state');
      if (placeholder) placeholder.remove();
      this._appendToStream(liveStream, rawData);
      if (!matches && liveStream.lastChild) {
        liveStream.lastChild.style.display = 'none';
      }
    }

    if (this._analyzerOpen) {
      const analyzerContent = document.getElementById('analyzer-log-content');
      if (analyzerContent) {
        const analyzerPlaceholder = analyzerContent.querySelector('.empty-state');
        if (analyzerPlaceholder) analyzerPlaceholder.remove();
        this._appendToStream(analyzerContent, rawData);
        if (!matches && analyzerContent.lastChild) {
          analyzerContent.lastChild.style.display = 'none';
        }
      }
    }
  },

  reconnectWithAllLevels() {
    this.disconnect();
    this.historyLoaded = true;
    this._allLevels = true;
    this._analyzerOpen = true;
    return this.createConnection();
  },

  reconnectNormal() {
    this.disconnect();
    this.historyLoaded = true;
    this._allLevels = false;
    this._analyzerOpen = false;
    return this.createConnection();
  },

  disconnect() {
    this.stopHealthCheck();
    if (this.eventSource) {
      this.eventSource.close();
      this.eventSource = null;
      this.isConnected = false;
      this.reconnectAttempts = 0;
      this.historyLoaded = false;
      this.updateStatus('disconnected');
    }
    if (this.reconnectTimer) { clearTimeout(this.reconnectTimer); this.reconnectTimer = null; }
  },

  startHealthCheck() {
    this.stopHealthCheck();
    this.healthCheckTimer = setInterval(() => {
      const elapsed = Date.now() - this.lastActivity;
      if (elapsed > this.HEALTH_CHECK_INTERVAL * 2) {
        console.warn('[SSE-MGR] Health check failed - no activity for ' + elapsed + 'ms');
        if (this.eventSource) {
          this.eventSource.close();
          this.isConnected = false;
          this.updateStatus('disconnected');
          this.getConnection();
        }
      }
    }, this.HEALTH_CHECK_INTERVAL);
  },

  stopHealthCheck() {
    if (this.healthCheckTimer) {
      clearInterval(this.healthCheckTimer);
      this.healthCheckTimer = null;
    }
  },

  updateStatus(state) {
    const el = document.getElementById('sse-status-indicator');
    if (!el) return;
    el.className = 'sse-status ' + state;
    const label = el.querySelector('.status-label');
    if (label) {
      label.textContent = state === 'connected' ? 'LIVE' : state === 'connecting' ? '...' : 'OFF';
    }
  }
};
window.TridentSSEManager = window.AnteumbraSSEManager;
