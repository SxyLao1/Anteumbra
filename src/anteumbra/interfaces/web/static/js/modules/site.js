/* Site scope for a deployment that watches more than one site.
 *
 * The active site is server state: it lives in the URL (?site=) and behind it
 * in the shell's data-site attribute.  Every URL a module builds on the fly has
 * to carry it, otherwise a fragment silently widens the operator's question
 * back to "all sites" right after they narrowed it.
 */
(function (window, document) {
  'use strict';

  var app = window.Anteumbra;

  function shell() {
    return document.getElementById('main-content') || document.body;
  }

  function current() {
    var node = shell();
    return (node && node.dataset ? node.dataset.site : '') || '';
  }

  function withSite(url) {
    var site = current();
    if (!url || !site) return url;
    var separator = url.indexOf('?') >= 0 ? '&' : '?';
    return url + separator + 'site=' + encodeURIComponent(site);
  }

  function selectSite(value) {
    var target = new window.URL(window.location.href);
    // An empty value is the aggregate view; it stays in the URL so the choice
    // is visible and shareable rather than remembered only on the server.
    target.searchParams.set('site', value || '');
    window.location.assign(target.toString());
  }

  function rowSite(element) {
    var row = element && element.closest ? element.closest('[data-site-id]') : null;
    return (row && row.dataset.siteId) || '';
  }

  app.register('site', {
    actions: {
      'site.select': {
        handler: function (context) { selectSite(context.element.value); },
        events: ['change'],
        preventDefault: false
      }
    }
  });

  window.AnteumbraSite = {
    current: current,
    withSite: withSite,
    rowSite: rowSite,
    select: selectSite
  };
}(window, document));
