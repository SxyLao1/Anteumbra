/* YARA rule selection, editor, and upload workflows. */
(function () {
  'use strict';

  var app = window.Anteumbra;
  var selected = new Set();
  var uploadFile = null;

  function refreshSelection(root) {
    var scope = root && root.querySelectorAll ? root : document;
    scope.querySelectorAll('.yara-checkbox').forEach(function (checkbox) {
      checkbox.checked = selected.has(checkbox.dataset.filename);
    });
    var count = selected.size;
    document.querySelectorAll('#yara-selected-count').forEach(function (node) {
      node.textContent = count + ' selected';
      node.style.display = count ? '' : 'none';
    });
    document.querySelectorAll('#yara-batch-delete-btn, #yara-deselect-btn').forEach(function (node) { node.style.display = count ? '' : 'none'; });
    document.querySelectorAll('#yara-select-all-btn').forEach(function (node) { node.style.display = count ? 'none' : ''; });
  }

  function refreshRules(container) {
    if (!container || !window.htmx) return;
    var compact = container.dataset.compact === 'true' ? '?compact=1' : '';
    window.htmx.ajax('GET', '/admin/yara/rules' + compact, { target: '#' + container.id, swap: 'outerHTML' });
  }

  function setUploadFile(file) {
    if (!file) return;
    if (!/\.yar$/i.test(file.name)) {
      app.ui.toast('Only .yar files are allowed.', 'error');
      return;
    }
    uploadFile = file;
    var name = document.getElementById('yara-file-name');
    var size = document.getElementById('yara-file-size');
    var info = document.getElementById('yara-file-info');
    var preview = document.getElementById('yara-upload-preview');
    var submit = document.getElementById('yara-upload-btn');
    if (name) name.textContent = file.name;
    if (size) size.textContent = (file.size / 1024).toFixed(1) + ' KB';
    if (info) { info.hidden = false; info.style.display = 'flex'; }
    var reader = new FileReader();
    reader.onload = function (event) {
      if (preview) preview.value = event.target.result;
      if (submit) submit.disabled = false;
    };
    reader.readAsText(file);
  }

  function showUpload() {
    uploadFile = null;
    app.ui.showModal('yara-upload-modal');
    ['yara-file-input', 'yara-upload-preview', 'yara-upload-result'].forEach(function (id) {
      var field = document.getElementById(id);
      if (field) field.value = '';
      if (field && field.id === 'yara-upload-result') field.textContent = '';
    });
    var info = document.getElementById('yara-file-info');
    var submit = document.getElementById('yara-upload-btn');
    if (info) { info.hidden = true; info.style.display = 'none'; }
    if (submit) submit.disabled = true;
  }

  function submitUpload() {
    if (!uploadFile) return;
    var button = document.getElementById('yara-upload-btn');
    var result = document.getElementById('yara-upload-result');
    if (button) { button.disabled = true; button.textContent = 'Uploading...'; }
    if (result) result.textContent = 'Uploading...';
    var form = new FormData();
    form.append('file', uploadFile);
    form.append('csrf_token', app.http.csrfToken());
    app.http.json('/admin/yara/rules/upload', { method: 'POST', body: form })
      .then(function (response) {
        if (!response.success) throw new Error(response.error || 'Upload failed');
        if (result) result.textContent = response.message || 'Upload successful';
        app.ui.toast(response.message || 'Upload successful', 'success');
        window.setTimeout(function () {
          app.ui.hideModal('yara-upload-modal');
          var container = document.getElementById('yara-rules-container');
          if (container) refreshRules(container);
        }, 500);
      })
      .catch(function (error) {
        if (result) result.textContent = 'Upload failed: ' + error.message;
        if (button) { button.disabled = false; button.textContent = 'Upload'; }
      });
  }

  function batchDelete() {
    var rules = Array.from(selected);
    if (!rules.length || !app.confirm('Delete ' + rules.length + ' selected rule(s)?')) return;
    Promise.all(rules.map(function (filename) {
      return app.http.json('/admin/yara/rules/' + encodeURIComponent(filename), { method: 'DELETE' })
        .then(function (response) {
          if (!response.success) throw new Error(response.error || 'Rule deletion failed');
          return response;
        });
    })).then(function () {
      selected.clear();
      refreshSelection(document);
      var container = document.getElementById('yara-rules-container');
      if (container) refreshRules(container);
    }).catch(function (error) { app.ui.toast('Rule deletion failed: ' + error.message, 'error'); });
  }

  function filterRules(input) {
    var keyword = String(input.value || '').toLowerCase();
    var container = input.closest('#yara-rules-container') || document.getElementById('yara-rules-container');
    if (!container) return;
    container.querySelectorAll('.record-item').forEach(function (item) {
      var text = (item.dataset.filename || '') + ' ' + (item.textContent || '');
      item.style.display = !keyword || text.toLowerCase().indexOf(keyword) >= 0 ? '' : 'none';
    });
  }

  app.register('yara', {
    actions: {
      'yara.show-upload': { handler: showUpload },
      'yara.file-zone': { handler: function (context) {
        var event = context.event;
        if (event.type === 'dragover') context.element.classList.add('drag-over');
        if (event.type === 'dragleave') context.element.classList.remove('drag-over');
        if (event.type === 'drop') {
          context.element.classList.remove('drag-over');
          setUploadFile(event.dataTransfer.files[0]);
        }
        if (event.type === 'click' && event.target.id !== 'yara-file-input') document.getElementById('yara-file-input').click();
      }, events: ['click', 'dragover', 'dragleave', 'drop'] },
      'yara.file-select': { handler: function (context) { setUploadFile(context.element.files[0]); }, events: ['change'], preventDefault: false },
      'yara.submit-upload': { handler: submitUpload },
      'yara.selection-change': { handler: function (context) {
        var filename = context.element.dataset.filename;
        if (context.element.checked) selected.add(filename); else selected.delete(filename);
        refreshSelection(document);
      }, events: ['change'], preventDefault: false },
      'yara.select-all': { handler: function (context) {
        var root = context.element.closest('#yara-rules-container') || document;
        root.querySelectorAll('.yara-checkbox').forEach(function (checkbox) { checkbox.checked = true; selected.add(checkbox.dataset.filename); });
        refreshSelection(root);
      } },
      'yara.clear-selection': { handler: function (context) {
        selected.clear();
        refreshSelection(context.element.closest('#yara-rules-container') || document);
      } },
      'yara.batch-delete': { handler: batchDelete },
      'yara.filter': { handler: function (context) { filterRules(context.element); }, events: ['input'], preventDefault: false },
      'yara.edit-open': { handler: function (context) {
        var modal = document.getElementById('yara-edit-modal');
        if (modal) {
          var title = modal.querySelector('.modal-header span');
          if (title) title.textContent = 'Edit: ' + context.element.dataset.filename;
          app.ui.showModal(modal);
        }
      } }
    },
    mount: refreshSelection,
    selectedRules: function () { return new Set(selected); }
  });
}());
