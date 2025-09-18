let token = localStorage.getItem('token')||null;
let socket = null;
function $(id){return document.getElementById(id);}
function show(id){['view-login','view-register','view-dashboard','view-admin'].forEach(i=>document.getElementById(i).classList.add('hidden')); document.getElementById(id).classList.remove('hidden');}

async function api(path, opts={}){opts.headers = opts.headers || {}; opts.headers['Content-Type']='application/json'; if(token) opts.headers['Authorization']='Bearer '+token; const r = await fetch(path, opts); try{ return await r.json(); }catch(e){ return {}; } }

document.getElementById('to-register').addEventListener('click', ()=>show('view-register'));
document.getElementById('to-login').addEventListener('click', ()=>show('view-login'));

document.getElementById('reg-btn').addEventListener('click', async ()=>{
  const u = $('reg-username').value.trim(), p = $('reg-password').value;
  const r = await api('/api/register', { method:'POST', body: JSON.stringify({ username:u, password:p }) });
  if(r.token){ alert('Registered. Please login.'); show('view-login'); } else alert('Error: '+(r.error||'unknown'));
});

document.getElementById('login-btn').addEventListener('click', async ()=>{
  const u = $('login-username').value.trim(), p = $('login-password').value;
  const r = await api('/api/login', { method:'POST', body: JSON.stringify({ username:u, password:p }) });
  if(r.token){ token = r.token; localStorage.setItem('token', token); if(r.user && r.user.admin){ show('view-admin'); connectSocket(); } else { show('view-dashboard'); connectSocket(); } } else alert('Login failed: '+(r.error||'unknown'));
});

document.getElementById('btn-logout').addEventListener('click', ()=>{ token=null; localStorage.removeItem('token'); if(socket) socket.disconnect(); show('view-login'); });

function connectSocket(){ if(socket) socket.disconnect(); socket = io(); socket.on('connect', ()=>{ if(token) socket.emit('auth', { token }); }); socket.on('auth_ok', ({ user })=>{ $('welcome').innerText = 'Welcome '+user.username; renderWallet(user); }); socket.on('chat_history', msgs=>{ const el=$('chat-history'); el.innerHTML=''; (msgs||[]).forEach(m=>{ const d=document.createElement('div'); d.textContent = m.from+': '+m.text; el.appendChild(d); }); }); socket.on('chat_message', m=>{ const el=$('chat-history'); const d=document.createElement('div'); d.textContent = (m.from||m.user)+': '+m.text; el.appendChild(d); }); socket.on('prices', p=>{ window.latestPrices = p; }); socket.on('balance_updated', d=>{ if(d.username===getUser()) fetchMe(); }); socket.on('banned', ()=>{ alert('You were banned'); localStorage.removeItem('token'); token=null; if(socket) socket.disconnect(); show('view-login'); }); }

function getUser(){ try{ const payload = JSON.parse(atob(token.split('.')[1])); return payload.username; }catch(e){ return null; } }

async function fetchMe(){ const res = await api('/api/admin/users'); if(res && Array.isArray(res)){ const me = res.find(x=>x.username===getUser()); if(me){ renderWallet(me); } } }

function renderWallet(u){ const w=$('wallet'); w.innerHTML=''; const b = u.balances||{}; for(const k in b){ const d=document.createElement('div'); d.textContent = k+': '+b[k]; w.appendChild(d); } }

$('chat-send').addEventListener('click', ()=>{ const text = $('chat-input').value.trim(); if(!text) return; socket.emit('send_chat', { token, text }); $('chat-input').value=''; });

$('admin-chat-send').addEventListener('click', ()=>{ const text = $('admin-chat-input').value.trim(); const target = prompt('Reply to user: username'); if(!target||!text) return; socket.emit('admin_reply', { token, username: target, text }); });

// buy/sell
$('buy').addEventListener('click', ()=>{ const amt = Number($('manual-amount').value)||0; socket.emit('trade', { token, pair: $('pair-select').value, type:'buy', amountBase: amt }); });
$('sell').addEventListener('click', ()=>{ const amt = Number($('manual-amount').value)||0; socket.emit('trade', { token, pair: $('pair-select').value, type:'sell', amountBase: amt }); });

// auto reconnect if token present
if(localStorage.getItem('token')){ token = localStorage.getItem('token'); connectSocket(); show('view-dashboard'); }
