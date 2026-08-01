/* Anteumbra frontend application shell.
 *
 * Flask renders fragments through HTMX, so page-specific listeners attached to
 * replaced nodes are unreliable.  This file owns one delegated event boundary
 * and a small module registry; feature modules register semantic actions rather
 * than leaking functions and mutable state onto window.
 */
(function (window, document) {
  'use strict';

  var modules = new Map();
  var actions = new Map();
  var started = false;

  function csrfToken() {
    var meta = document.querySelector('meta[name="csrf-token"]');
    return meta ? meta.content : '';
  }

  function escapeHtml(value) {
    return String(value == null ? '' : value)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#39;');
  }

  function parseHtml(html) {
    var wrapper = document.createElement('template');
    wrapper.innerHTML = String(html || '').trim();
    return wrapper.content.firstElementChild;
  }

  function mount(root) {
    var scope = root || document;
    modules.forEach(function (module) {
      if (typeof module.mount === 'function') module.mount(scope);
    });
  }

  function unmount(root) {
    var scope = root || document;
    modules.forEach(function (module) {
      if (typeof module.unmount === 'function') module.unmount(scope);
    });
  }

  function processHtmx(root) {
    if (window.htmx && root) window.htmx.process(root);
  }

  function swapHtml(target, html, swap) {
    if (!target) return null;
    unmount(target);
    if (swap === 'outerHTML') {
      var next = parseHtml(html);
      if (!next) return target;
      target.replaceWith(next);
      processHtmx(next);
      mount(next);
      return next;
    }
    target.innerHTML = html;
    processHtmx(target);
    mount(target);
    return target;
  }

  function responseError(response) {
    return response.text().then(function (body) {
      var message = 'HTTP ' + response.status;
      try {
        var parsed = JSON.parse(body);
        message = parsed.error || parsed.message || message;
      } catch (_) {
        if (body) message = body;
      }
      throw new Error(message);
    });
  }

  function request(url, options) {
    var requestOptions = Object.assign({}, options || {});
    requestOptions.headers = Object.assign({}, requestOptions.headers || {});
    var token = csrfToken();
    if (token && !requestOptions.headers['X-CSRFToken']) {
      requestOptions.headers['X-CSRFToken'] = token;
    }
    return window.fetch(url, requestOptions);
  }

  function requestJson(url, options) {
    return request(url, options).then(function (response) {
      if (!response.ok) return responseError(response);
      return response.json();
    });
  }

  function requestText(url, options) {
    return request(url, options).then(function (response) {
      if (!response.ok) return responseError(response);
      return response.text();
    });
  }

  function showModal(id) {
    var modal = typeof id === 'string' ? document.getElementById(id) : id;
    if (!modal) return null;
    modal.hidden = false;
    modal.style.display = 'flex';
    modal.classList.add('active');
    modal.setAttribute('aria-hidden', 'false');
    return modal;
  }

  function hideModal(id) {
    var modal = typeof id === 'string' ? document.getElementById(id) : id;
    if (!modal) return;
    modal.classList.remove('active');
    modal.hidden = true;
    modal.style.display = 'none';
    modal.setAttribute('aria-hidden', 'true');
  }

  function toast(message, level, duration) {
    var container = document.querySelector('.toast-container');
    if (!container) {
      container = document.createElement('div');
      container.className = 'toast-container';
      container.setAttribute('aria-live', 'polite');
      document.body.appendChild(container);
    }
    var notice = document.createElement('div');
    notice.className = 'toast toast-' + (level || 'info');
    notice.textContent = String(message || '');
    container.appendChild(notice);
    window.setTimeout(function () { notice.remove(); }, duration || 3500);
  }

  function resolveTarget(selector, fallback) {
    return selector ? document.querySelector(selector) : fallback;
  }

  function dispatchAction(event) {
    var element = event.target.closest('[data-action]');
    if (!element) return;
    var binding = actions.get(element.dataset.action);
    if (!binding) {
      console.error('Unknown Anteumbra action: ' + element.dataset.action);
      return;
    }
    if (binding.events.indexOf(event.type) === -1) return;

    if (binding.preventDefault !== false && ['click', 'submit', 'dragover', 'drop'].indexOf(event.type) >= 0) {
      event.preventDefault();
    }
    binding.handler({ app: app, event: event, element: element });
  }

  function registerAction(name, handler, events, preventDefault) {
    actions.set(name, {
      handler: handler,
      events: events || ['click'],
      preventDefault: preventDefault !== false
    });
  }

  var app = {
    register: function (name, module) {
      modules.set(name, module);
      Object.keys(module.actions || {}).forEach(function (actionName) {
        var binding = module.actions[actionName];
        registerAction(actionName, binding.handler, binding.events, binding.preventDefault);
      });
      return module;
    },
    module: function (name) { return modules.get(name); },
    action: registerAction,
    mount: mount,
    unmount: unmount,
    actionNames: function () { return Array.from(actions.keys()); },
    processHtmx: processHtmx,
    swapHtml: swapHtml,
    htmxGet: function (url, target, swap) {
      if (!window.htmx) return Promise.reject(new Error('HTMX is unavailable'));
      window.htmx.ajax('GET', url, { target: target, swap: swap || 'innerHTML' });
      return Promise.resolve();
    },
    http: { request: request, json: requestJson, text: requestText, csrfToken: csrfToken },
    escape: { html: escapeHtml },
    ui: { showModal: showModal, hideModal: hideModal, toast: toast },
    confirm: function (message) { return window.confirm(message); },
    resolveTarget: resolveTarget,
    start: function () {
      if (started) return;
      started = true;
      ['click', 'change', 'input', 'keydown', 'dragover', 'dragleave', 'drop'].forEach(function (eventName) {
        document.addEventListener(eventName, dispatchAction);
      });
      document.addEventListener('htmx:configRequest', function (event) {
        var token = csrfToken();
        if (token) event.detail.headers['X-CSRFToken'] = token;
      });
      document.addEventListener('htmx:beforeSwap', function (event) {
        unmount(event.detail.target);
      });
      document.addEventListener('htmx:afterSwap', function (event) {
        mount(event.detail.target);
      });
      mount(document);
    }
  };

  registerAction('core.modal-hide', function (context) {
    hideModal(context.element.dataset.modal || context.element.closest('.modal-overlay'));
  });
  registerAction('core.backdrop-close', function (context) {
    if (context.event.target === context.element) hideModal(context.element);
  });
  registerAction('core.page-jump', function (context) {
    if (context.event.key !== 'Enter') return;
    var page = context.element.value;
    var url = context.element.dataset.pageUrl;
    if (!url || !page) return;
    app.htmxGet(url.replace('__PAGE__', encodeURIComponent(page)), context.element.dataset.target, context.element.dataset.swap || 'outerHTML');
  }, ['keydown'], false);
  registerAction('core.open-window', function (context) {
    if (context.element.dataset.url) window.open(context.element.dataset.url, context.element.dataset.windowTarget || '_blank');
  });
  registerAction('core.print', function () { window.print(); });
  registerAction('core.close-window', function () { window.close(); });
  registerAction('core.navigate-location', function (context) {
    if (context.element.dataset.url) window.location.assign(context.element.dataset.url);
  });

  window.Anteumbra = app;
  document.addEventListener('DOMContentLoaded', function () { app.start(); });
}(window, document));
