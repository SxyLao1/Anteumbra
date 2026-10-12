/* A queue refresh retains the operator's current group and page. */
(function () {
  'use strict';
  var app = window.Anteumbra;
  function refresh() {
    var host = document.getElementById('duty-queue');
    if (!host || !window.htmx) return;
    var view = host.querySelector('[data-duty-view]');
    var url = '/admin/duty-queue?view=' + encodeURIComponent(view ? view.dataset.dutyView : 'active') +
      '&page=' + encodeURIComponent(view ? view.dataset.dutyPage : '1');
    if (window.AnteumbraSite) url = window.AnteumbraSite.withSite(url);
    window.htmx.ajax('GET', url, { source: host, target: host, swap: 'innerHTML' });
  }
  app.register('duty', {
    actions: {
      'duty.refresh': { handler: refresh }
    }
  });
  // No timer replaces the list while an operator is reading or selecting it.
  // Mutations update the snapshot; newly ingested events appear on explicit refresh.
  document.addEventListener('anteumbra:stats-refresh', refresh);
}());
