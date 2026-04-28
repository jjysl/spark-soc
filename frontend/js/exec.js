// â”€â”€ AUTENTICACAO â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
// Carrega info do usuario logado e popula o topbar
(async function loadSession() {
  try {
    const resp = await fetch('/auth/me', { credentials: 'include' });
    if (resp.status === 401) { window.location.href = '/login'; return; }
    const user = await resp.json();
    document.getElementById('userAvatar').textContent = user.avatar || user.name?.slice(0,2).toUpperCase() || 'SC';
    document.getElementById('userName').textContent   = user.name || user.username;
    document.getElementById('userRole').textContent   = user.role + (user.provider !== 'local' ? ' Â· ' + user.provider : '');
  } catch(e) {
    window.location.href = '/login';
  }
})();

async function doLogout() {
  await fetch('/auth/logout', { method: 'POST', credentials: 'include' });
  window.location.href = '/login';
}

// CLOCK
function tick(){const s=new Date().toUTCString().split(' ')[4]+' UTC';document.getElementById('clock').textContent=s;document.getElementById('footerClock').textContent=s;}
tick();setInterval(tick,1000);

// TAB SWITCH
function switchTab(id,btn){
  document.querySelectorAll('.panel').forEach(p=>p.classList.remove('active'));
  document.querySelectorAll('.tbtn').forEach(b=>b.classList.remove('active'));
  document.getElementById('panel-'+id).classList.add('active');
  btn.classList.add('active');
}

// TIME SELECTOR
document.querySelectorAll('.tsel span').forEach(el=>{
  el.addEventListener('click',function(){this.closest('.tsel').querySelectorAll('span').forEach(s=>s.classList.remove('active'));this.classList.add('active');});
});

