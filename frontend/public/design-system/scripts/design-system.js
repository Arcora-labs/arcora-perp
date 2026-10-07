'use strict';
document.querySelectorAll('[data-copy]').forEach(b=>b.addEventListener('click',async()=>{try{await navigator.clipboard.writeText(b.dataset.copy);ARCORA.toast(b.dataset.copy+' copied.')}catch{ARCORA.toast('Color token: '+b.dataset.copy)}}));
document.querySelectorAll('[data-message]').forEach(b=>b.addEventListener('click',()=>ARCORA.toast(b.dataset.message)));
document.querySelectorAll('.specimen-sides button').forEach(b=>b.addEventListener('click',()=>document.querySelectorAll('.specimen-sides button').forEach(x=>x.setAttribute('aria-pressed',String(x===b)))));
document.getElementById('replay-motion').addEventListener('click',()=>{const d=document.querySelector('.motion-demo');d.classList.remove('is-playing');void d.offsetWidth;d.classList.add('is-playing')});
