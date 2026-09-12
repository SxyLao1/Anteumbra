/* File cluster list: collapsed by default, expandable, with a local filter.
 *
 * Members are rendered server-side; this module only toggles visibility and
 * filters rows so a large cluster list stays scannable without extra requests.
 */
(function () {
  'use strict';

  var app = window.Anteumbra;
  var state = { query: '' };

  function node(id) { return document.getElementById(id); }

  function cards() {
    return Array.prototype.slice.call(document.querySelectorAll('.cluster-card'));
  }

  function setExpanded(card, expanded) {
    var body = card.querySelector('.cluster-files');
    var toggle = card.querySelector('.cluster-toggle');
    if (body) body.hidden = !expanded;
    card.classList.toggle('is-expanded', expanded);
    if (toggle) {
      toggle.setAttribute('aria-expanded', expanded ? 'true' : 'false');
      var arrow = toggle.querySelector('.cluster-arrow');
      if (arrow) arrow.textContent = expanded ? '▼' : '▶';
    }
  }

  function toggleCard(trigger) {
    var card = trigger.closest('.cluster-card');
    if (!card) return;
    setExpanded(card, !card.classList.contains('is-expanded'));
  }

  function applyFilter() {
    var query = state.query.toLowerCase();
    var terms = query.split(/\s+/).filter(Boolean);
    var visible = 0;
    cards().forEach(function (card) {
      var haystack = (card.dataset.search || card.textContent || '').toLowerCase();
      var match = terms.every(function (term) { return haystack.indexOf(term) !== -1; });
      card.hidden = !match;
      if (match) visible += 1;
      // a filtered view is more useful expanded than collapsed
      if (match && terms.length) setExpanded(card, true);
    });
    var empty = node('clusters-empty');
    if (empty) empty.hidden = visible !== 0;
    var count = node('clusters-visible');
    if (count) count.textContent = visible + ' / ' + cards().length;
  }

  function search(trigger) {
    state.query = (trigger.value || '').trim();
    applyFilter();
  }

  function setAll(expanded) {
    cards().forEach(function (card) {
      if (!card.hidden) setExpanded(card, expanded);
    });
  }

  app.register('clusters', {
    actions: {
      'clusters.toggle': { handler: function (context) { toggleCard(context.element); } },
      'clusters.search': { handler: function (context) { search(context.element); },
                           events: ['input'], preventDefault: false },
      'clusters.expand-all': { handler: function () { setAll(true); } },
      'clusters.collapse-all': { handler: function () { setAll(false); } }
    },
    mount: function (root) {
      var page = root && (root.id === 'clusters-list' || (root.querySelector && root.querySelector('#clusters-list')));
      if (!page) return;
      cards().forEach(function (card) { setExpanded(card, false); });
      applyFilter();
    },
    expandAll: function () { setAll(true); },
    collapseAll: function () { setAll(false); },
    filter: function (value) { state.query = value || ''; applyFilter(); }
  });
}());
