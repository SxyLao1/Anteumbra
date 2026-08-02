/* Shared selection state for paginated HTMX lists. */
(function () {
  'use strict';

  function create(options) {
    var selected = new Set();

    function scope(root) { return root && root.querySelectorAll ? root : document; }
    function update() {
      var count = selected.size;
      document.querySelectorAll(options.countSelector).forEach(function (node) {
        node.textContent = count + ' selected';
      });
      document.querySelectorAll(options.buttonSelector).forEach(function (node) {
        node.disabled = count === 0;
      });
    }
    function restore(root) {
      scope(root).querySelectorAll(options.checkboxSelector).forEach(function (checkbox) {
        checkbox.checked = selected.has(checkbox.value);
      });
      update();
    }
    function setVisible(container, checked) {
      scope(container).querySelectorAll(options.checkboxSelector).forEach(function (checkbox) {
        checkbox.checked = checked;
        if (checked) selected.add(checkbox.value); else selected.delete(checkbox.value);
      });
      update();
    }
    function selectAll(container) {
      var serialized = container && container.dataset[options.datasetKey];
      if (serialized) {
        try {
          JSON.parse(serialized).forEach(function (value) { selected.add(String(value)); });
        } catch (_) {
          options.onInvalidMetadata();
        }
      }
      setVisible(container, true);
    }
    var api = {
      change: function (checkbox) {
        if (checkbox.checked) selected.add(checkbox.value); else selected.delete(checkbox.value);
        update();
      },
      selectPage: function (container) { setVisible(container, true); },
      selectAll: selectAll,
      clear: function (container) { selected.clear(); setVisible(container, false); },
      restore: restore,
      update: update,
      values: function () { return Array.from(selected); },
      snapshot: function () { return new Set(selected); },
      reset: function () { selected.clear(); update(); },
      add: function (value) { selected.add(value); return api; },
      delete: function (value) { return selected.delete(value); },
      has: function (value) { return selected.has(value); }
    };
    api[Symbol.iterator] = function () { return selected[Symbol.iterator](); };
    Object.defineProperty(api, 'size', { get: function () { return selected.size; } });
    return api;
  }

  window.AnteumbraSelectionController = { create: create };
}());
