import express from 'express';
import http from 'http';
import { Server } from 'socket.io';
import pkg from 'pg';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import dotenv from 'dotenv';
import cors from 'cors';
import { stringify } from 'csv-stringify';
import path from 'path';
import { fileURLToPath } from 'url';

dotenv.config();

const { Pool } = pkg;
const app = express();
const server = http.createServer(app);
const io = new Server(server, { cors: { origin: true } });

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'devsecret';
const ADMIN_PASS = process.env.ADMIN_PASS || '12041998avril1999A';

const DATABASE_URL = process.env.DATABASE_URL;
if (!DATABASE_URL) {
  console.error('❌ No DATABASE_URL provided. Set it in environment variables.');
  process.exit(1);
}

const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false,
});

// Create tables if not exist
async function initDb() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      username TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      balances JSONB DEFAULT '{"EUR":0,"BTC":0,"ETH":0,"USDT":0,"XRP":0,"LTC":0}'::jsonb,
      banned BOOLEAN DEFAULT FALSE,
      created_at TIMESTAMP DEFAULT NOW()
    );
  `);
  await pool.query(`
    CREATE TABLE IF NOT EXISTS chats (
      id SERIAL PRIMARY KEY,
      username TEXT UNIQUE NOT NULL,
      messages JSONB DEFAULT '[]'::jsonb,
      updated_at TIMESTAMP DEFAULT NOW()
    );
  `);
  await pool.query(`
    CREATE TABLE IF NOT EXISTS transactions (
      id SERIAL PRIMARY KEY,
      username TEXT NOT NULL,
      type TEXT,
      pair TEXT,
      amount NUMERIC,
      currency TEXT,
      side TEXT,
      value_eur NUMERIC,
      timestamp TIMESTAMP DEFAULT NOW()
    );
  `);
  console.log('✅ DB initialized');
}

initDb().catch(err=>{ console.error('DB init error', err); process.exit(1); });

app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// Simple prices simulation (in-memory)
const PAIRS = {
  'BTC/EUR': { symbol:'BTC', price:25000, vol:0.03 },
  'ETH/EUR': { symbol:'ETH', price:1500, vol:0.04 },
  'USDT/EUR': { symbol:'USDT', price:1, vol:0.001 },
  'XRP/EUR': { symbol:'XRP', price:0.5, vol:0.06 },
  'LTC/EUR': { symbol:'LTC', price:80, vol:0.05 }
};
const priceSeries = {};
Object.keys(PAIRS).forEach(k=>priceSeries[k]=[PAIRS[k].price]);

function stepMarket(){
  Object.keys(PAIRS).forEach(pair=>{
    const meta = PAIRS[pair];
    const series = priceSeries[pair];
    const last = series.length ? series[series.length-1] : meta.price;
    const shock = (Math.random()-0.5)*2*meta.vol;
    const drift = (Math.random()-0.5)*0.001;
    const next = Math.max(0.0000001, last*(1+shock+drift));
    series.push(next);
    if(series.length>300) series.shift();
  });
  io.emit('prices', serverPriceSnapshot());
}
setInterval(stepMarket, 1000);
function serverPriceSnapshot(){ const out={}; Object.keys(priceSeries).forEach(p=>out[p]=priceSeries[p].slice(-1)[0]); return out; }

// Helpers
function sanitizeUserRow(row){
  if(!row) return null;
  return {
    username: row.username,
    balances: row.balances,
    banned: row.banned
  };
}

function authMiddleware(req,res,next){
  const h = req.headers.authorization;
  if(!h) return res.status(401).json({ error:'no auth' });
  const token = h.split(' ')[1];
  try{
    const payload = jwt.verify(token, JWT_SECRET);
    req.user = payload;
    next();
  }catch(e){ return res.status(401).json({ error:'invalid token' }); }
}

// Routes
app.get('/health', (req,res)=> res.json({status:'ok', uptime: process.uptime()}));

app.post('/api/register', async (req,res)=>{
  const { username, password } = req.body;
  if(!username || !password) return res.status(400).json({ error:'missing' });
  try{
    const hash = await bcrypt.hash(password, 10);
    await pool.query('INSERT INTO users(username, password_hash) VALUES($1,$2)', [username, hash]);
    // create chat row
    await pool.query('INSERT INTO chats(username, messages) VALUES($1, $2) ON CONFLICT (username) DO NOTHING', [username, JSON.stringify([])]);
    const token = jwt.sign({ username }, JWT_SECRET, { expiresIn:'7d' });
    res.json({ token, user: { username } });
  }catch(err){
    console.error('register err', err);
    return res.status(400).json({ error:'user exists or db error' });
  }
});

app.post('/api/login', async (req,res)=>{
  const { username, password } = req.body;
  if(!username || !password) return res.status(400).json({ error:'missing' });
  try{
    if(username==='admin'){
      if(password !== ADMIN_PASS) return res.status(401).json({ error:'invalid' });
      const token = jwt.sign({ username:'admin', admin:true }, JWT_SECRET, { expiresIn:'7d' });
      return res.json({ token, user:{ username:'admin', admin:true } });
    }
    const r = await pool.query('SELECT username, password_hash, banned, balances FROM users WHERE username = $1', [username]);
    if(r.rowCount===0) return res.status(401).json({ error:'invalid' });
    const row = r.rows[0];
    if(row.banned) return res.status(403).json({ error:'Your account has been banned by admin.' });
    const ok = await bcrypt.compare(password, row.password_hash);
    if(!ok) return res.status(401).json({ error:'invalid' });
    const token = jwt.sign({ username }, JWT_SECRET, { expiresIn:'7d' });
    res.json({ token, user: sanitizeUserRow(row) });
  }catch(e){ console.error('login err', e); res.status(500).json({ error:'server' }); }
});

app.get('/api/admin/users', authMiddleware, async (req,res)=>{
  if(!req.user || req.user.username!=='admin') return res.status(403).json({ error:'forbidden' });
  const r = await pool.query('SELECT username, balances, banned FROM users ORDER BY username');
  res.json(r.rows);
});

app.post('/api/admin/set-balance', authMiddleware, async (req,res)=>{
  if(!req.user || req.user.username!=='admin') return res.status(403).json({ error:'forbidden' });
  const { username, currency, amount } = req.body;
  if(!username || !currency || typeof amount !== 'number') return res.status(400).json({ error:'missing' });
  const r = await pool.query('SELECT balances FROM users WHERE username=$1', [username]);
  if(r.rowCount===0) return res.status(404).json({ error:'not found' });
  const balances = r.rows[0].balances || {EUR:0,BTC:0,ETH:0,USDT:0,XRP:0,LTC:0};
  balances[currency] = amount;
  await pool.query('UPDATE users SET balances = $1 WHERE username = $2', [balances, username]);
  await pool.query('INSERT INTO transactions(username, type, currency, amount) VALUES($1,$2,$3,$4)', [username,'admin-adjust',currency,amount]);
  // notify user via socket
  io.to(username).emit('balance_updated', { username, currency, amount, balances });
  // append chat message
  const chatRes = await pool.query('SELECT messages FROM chats WHERE username=$1', [username]);
  let msgs = [];
  if(chatRes.rowCount) msgs = chatRes.rows[0].messages || [];
  msgs.push({ from:'admin', text:`Your ${currency} balance set to ${amount}`, time: new Date() });
  await pool.query('UPDATE chats SET messages = $1, updated_at = NOW() WHERE username = $2', [msgs, username]);
  io.to(username).emit('chat_message', { user: username, from:'admin', text:`Your ${currency} balance set to ${amount}`, time: new Date() });
  res.json({ ok:true });
});

app.post('/api/admin/ban', authMiddleware, async (req,res)=>{
  if(!req.user || req.user.username!=='admin') return res.status(403).json({ error:'forbidden' });
  const { username, ban } = req.body;
  if(!username || typeof ban !== 'boolean') return res.status(400).json({ error:'missing' });
  await pool.query('UPDATE users SET banned = $1 WHERE username = $2', [ban, username]);
  io.to(username).emit('banned', { banned: ban, message: ban ? 'You have been banned by admin.' : 'You have been unbanned.' });
  res.json({ ok:true });
});

app.get('/api/admin/chat/:username', authMiddleware, async (req,res)=>{
  if(!req.user || req.user.username!=='admin') return res.status(403).json({ error:'forbidden' });
  const username = req.params.username;
  const r = await pool.query('SELECT messages FROM chats WHERE username=$1', [username]);
  res.json(r.rowCount ? r.rows[0].messages : []);
});

app.get('/api/transactions/export', authMiddleware, async (req,res)=>{
  const requester = req.user;
  const usernameQuery = req.query.username;
  let filter = '';
  const params = [];
  if(requester.username !== 'admin'){
    filter = 'WHERE username = $1';
    params.push(requester.username);
  } else if(usernameQuery){
    filter = 'WHERE username = $1';
    params.push(usernameQuery);
  }
  const q = `SELECT username, type, pair, amount, currency, side, value_eur, timestamp FROM transactions ${filter} ORDER BY timestamp DESC`;
  const r = await pool.query(q, params);
  const records = r.rows.map(t=>({ username: t.username, type: t.type, pair: t.pair, amount: t.amount, currency: t.currency, side: t.side, valueEUR: t.value_eur, timestamp: t.timestamp }));
  res.setHeader('Content-Disposition', `attachment; filename="transactions_${params.length?params[0]:'all'}.csv"`);
  res.setHeader('Content-Type','text/csv');
  stringify(records, { header:true }).pipe(res);
});

app.get('/api/prices', (req,res)=> res.json(serverPriceSnapshot()));

// Chat and trades via socket
io.on('connection', (socket)=>{
  console.log('socket connected', socket.id);
  socket.on('auth', async ({ token })=>{
    try{
      const payload = jwt.verify(token, JWT_SECRET);
      socket.user = payload;
      const username = payload.username;
      if(username === 'admin'){
        socket.join('admins');
        socket.emit('prices', serverPriceSnapshot());
      } else {
        // check banned
        const r = await pool.query('SELECT banned, balances FROM users WHERE username=$1', [username]);
        if(r.rowCount && r.rows[0].banned){
          socket.emit('banned', { banned:true, message:'Your account is banned.' });
          socket.disconnect(true);
          return;
        }
        socket.join(username);
        socket.emit('auth_ok', { user: { username, balances: r.rowCount ? r.rows[0].balances : {EUR:0} } });
        const cr = await pool.query('SELECT messages FROM chats WHERE username=$1', [username]);
        socket.emit('chat_history', cr.rowCount ? cr.rows[0].messages : []);
      }
    }catch(e){ socket.emit('auth_error', { msg:'invalid token' }); }
  });

  socket.on('send_chat', async ({ token, text })=>{
    try{
      const payload = jwt.verify(token, JWT_SECRET);
      const username = payload.username;
      const r = await pool.query('SELECT banned, messages FROM chats WHERE username=$1', [username]);
      if(r.rowCount && r.rows[0].banned) return socket.emit('banned', { banned:true });
      let msgs = (r.rowCount && r.rows[0].messages) ? r.rows[0].messages : [];
      msgs.push({ from: username, text, time: new Date() });
      await pool.query('INSERT INTO chats(username, messages) VALUES($1,$2) ON CONFLICT (username) DO UPDATE SET messages = $2, updated_at = NOW()', [username, msgs]);
      io.to('admins').emit('chat_message', { user: username, from: username, text, time: new Date() });
      io.to(username).emit('chat_message', { user: username, from: username, text, time: new Date() });
    }catch(e){ console.error('send_chat err', e); }
  });

  socket.on('admin_reply', async ({ token, username, text })=>{
    try{
      const payload = jwt.verify(token, JWT_SECRET);
      if(payload.username !== 'admin') return;
      const r = await pool.query('SELECT messages FROM chats WHERE username=$1', [username]);
      let msgs = r.rowCount && r.rows[0].messages ? r.rows[0].messages : [];
      msgs.push({ from:'admin', text, time: new Date() });
      await pool.query('INSERT INTO chats(username, messages) VALUES($1,$2) ON CONFLICT (username) DO UPDATE SET messages = $2, updated_at = NOW()', [username, msgs]);
      io.to(username).emit('chat_message', { user: username, from: 'admin', text, time: new Date() });
      io.to('admins').emit('chat_message', { user: username, from: 'admin', text, time: new Date() });
    }catch(e){ console.error('admin_reply err', e); }
  });

  socket.on('trade', async ({ token, pair, type, amountBase })=>{
    try{
      const payload = jwt.verify(token, JWT_SECRET);
      const username = payload.username;
      const r = await pool.query('SELECT balances, banned FROM users WHERE username=$1', [username]);
      if(!r.rowCount) return socket.emit('trade_result', { ok:false, reason:'user not found' });
      if(r.rows[0].banned) return socket.emit('trade_result', { ok:false, reason:'banned' });
      let balances = r.rows[0].balances || {EUR:0};
      const currentPrice = serverPriceSnapshot()[pair];
      if(type === 'buy'){
        const cost = Number(amountBase) * Number(currentPrice);
        if((balances.EUR||0) < cost) return socket.emit('trade_result', { ok:false, reason:'insufficient EUR' });
        balances.EUR = (balances.EUR||0) - cost;
        balances[PAIRS[pair].symbol] = (balances[PAIRS[pair].symbol]||0) + Number(amountBase);
        await pool.query('UPDATE users SET balances=$1 WHERE username=$2', [balances, username]);
        await pool.query('INSERT INTO transactions(username,type,pair,amount,currency,value_eur) VALUES($1,$2,$3,$4,$5,$6)', [username,'buy',pair,amountBase,PAIRS[pair].symbol,cost]);
      } else {
        if((balances[PAIRS[pair].symbol]||0) < Number(amountBase)) return socket.emit('trade_result', { ok:false, reason:'insufficient asset' });
        balances[PAIRS[pair].symbol] = (balances[PAIRS[pair].symbol]||0) - Number(amountBase);
        const proceeds = Number(amountBase) * Number(currentPrice);
        balances.EUR = (balances.EUR||0) + proceeds;
        await pool.query('UPDATE users SET balances=$1 WHERE username=$2', [balances, username]);
        await pool.query('INSERT INTO transactions(username,type,pair,amount,currency,value_eur) VALUES($1,$2,$3,$4,$5,$6)', [username,'sell',pair,amountBase,PAIRS[pair].symbol,proceeds]);
      }
      io.to('admins').emit('user_update', { username, balances });
      socket.emit('trade_result', { ok:true, balances });
    }catch(e){ console.error('trade err', e); socket.emit('trade_result', { ok:false, reason:'server' }); }
  });

  socket.on('disconnect', ()=>{});
});

// Serve static and SPA fallback
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

server.listen(PORT, ()=> console.log('Server started on', PORT));
