/* Anteumbra 通用工具库 */
const AnteumbraUtils = {
  getCsrfToken() {
    const meta = document.querySelector('meta[name="csrf-token"]');
    return meta ? meta.content : '';
  },
  toast(msg, type='info', duration=3000) {
    let c = document.querySelector('.toast-container');
    if (!c) { c = document.createElement('div'); c.className='toast-container'; document.body.appendChild(c); }
    const el = document.createElement('div');
    el.className = 'toast toast-'+type+' animate-fade-in-up';
    const icon = {success:'✓',error:'✕',warning:'!',info:'ℹ'}[type]||'ℹ';
    el.innerHTML = '<span style="font-family:monospace;font-size:16px;">'+icon+'</span> '+msg;
    c.appendChild(el);
    setTimeout(()=>{ el.style.opacity='0'; el.style.transform='translateX(100%)'; setTimeout(()=>el.remove(),300); }, duration);
  },
  modal: {
    show(id){ const el=document.getElementById(id); if(el)el.classList.add('active'); },
    hide(id){ const el=document.getElementById(id); if(el)el.classList.remove('active'); },
    hideAll(){ document.querySelectorAll('.modal-overlay').forEach(m=>m.classList.remove('active')); }
  },
  confirm(msg, onConfirm, onCancel) {
    const o = document.createElement('div');
    o.className='modal-overlay active'; o.style.zIndex='3000';
    o.innerHTML = '<div class="modal-box" style="max-width:400px;"><div class="modal-header">确认操作</div><div class="modal-body">'+msg+'</div><div class="modal-footer"><button class="btn btn-ghost" id="btn-cancel">取消</button><button class="btn btn-danger" id="btn-confirm">确认</button></div></div>';
    document.body.appendChild(o);
    o.querySelector('#btn-confirm').onclick = ()=>{ o.remove(); if(onConfirm)onConfirm(); };
    o.querySelector('#btn-cancel').onclick = ()=>{ o.remove(); if(onCancel)onCancel(); };
    o.onclick = (e)=>{ if(e.target===o){ o.remove(); if(onCancel)onCancel(); } };
  },
  setupHtmxCsrf() {
    document.addEventListener('htmx:configRequest', (event)=>{
      const token=this.getCsrfToken();
      if(token) event.detail.headers['X-CSRFToken']=token;
    });
  },
  highlightNav(path) {
    document.querySelectorAll('.nav-link').forEach(link=>{
      link.classList.toggle('active', link.dataset.path===path);
    });
  }
};
window.AnteumbraUtils = AnteumbraUtils;
window.TridentUtils = AnteumbraUtils; // Deprecated: remove in 2.0 after legacy extensions migrate.
