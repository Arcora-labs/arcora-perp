"use strict";
const ARCORA = window.ARCORA = {
  icon: (name) => ({close:'×',check:'✓',arrow:'↗'}[name] || '·'),
  format: (value, digits=2) => new Intl.NumberFormat('en-US',{minimumFractionDigits:digits,maximumFractionDigits:digits}).format(value),
  toast(message){const t=document.getElementById('toast');if(!t)return;t.textContent=message;t.classList.add('visible');clearTimeout(this.toastTimer);this.toastTimer=setTimeout(()=>t.classList.remove('visible'),3500)},
  dialog(html,kicker='ARCORA / DESIGN PREVIEW'){const d=document.getElementById('app-dialog');document.getElementById('dialog-kicker').textContent=kicker;document.getElementById('dialog-content').innerHTML=html;if(!d.open)d.showModal();return d},
  close(){document.getElementById('app-dialog').close()}
};
document.querySelector('[data-close]')?.addEventListener('click',()=>ARCORA.close());
document.getElementById('app-dialog')?.addEventListener('click',e=>{if(e.target===e.currentTarget){const r=e.currentTarget.getBoundingClientRect();if(e.clientX<r.left||e.clientX>r.right||e.clientY<r.top||e.clientY>r.bottom)ARCORA.close()}});
document.getElementById('app-dialog')?.addEventListener('close',()=>document.querySelector('#app-dialog video')?.pause());
if(new URLSearchParams(window.__ARCORA_PREVIEW_SEARCH__ || location.search).get('still')==='1')document.body.dataset.still='true';
