// server.js - full fix pkg compatible, login chắc chắn
const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const fs = require('fs');
const path = require('path');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const { v4: uuidv4 } = require('uuid');

const app = express();
app.use(cors());
app.use(bodyParser.json());
app.use(express.static('public'));

const PORT = process.env.PORT || 10000;
const DATA_FILE = path.join(__dirname, 'keys.json');
const CONFIG_FILE = path.join(__dirname, 'config.json');

const JWT_SECRET = process.env.JWT_SECRET || 'please-change-me-jwt';
const HMAC_SECRET = process.env.HMAC_SECRET || 'please-change-me-hmac';
const ADMIN_USER = process.env.ADMIN_USER || 'ZxsVN-ad';
const ADMIN_PASS = process.env.ADMIN_PASS || 'hentai';

// --- helper: PBKDF2 hash
function createPBKDF2Hash(password) {
  const salt = crypto.randomBytes(16).toString('hex');
  const iterations = 150000;
  const keylen = 64;
  const digest = 'sha512';
  const derived = crypto.pbkdf2Sync(password, salt, iterations, keylen, digest).toString('hex');
  return `$pbkdf2$${iterations}$${salt}$${derived}`;
}

function verifyPBKDF2Hash(stored, password) {
  try {
    const parts = stored.split('$');
    if (parts.length !== 5 || parts[1] !== 'pbkdf2') return false;
    const iterations = parseInt(parts[2], 10);
    const salt = parts[3];
    const derived = parts[4];
    const keylen = Buffer.from(derived, 'hex').length;
    const check = crypto.pbkdf2Sync(password, salt, iterations, keylen, 'sha512').toString('hex');
    return crypto.timingSafeEqual(Buffer.from(check, 'hex'), Buffer.from(derived, 'hex'));
  } catch (e) {
    return false;
  }
}

// --- helper files
if (!fs.existsSync(DATA_FILE)) fs.writeFileSync(DATA_FILE, '[]', 'utf8');
if (!fs.existsSync(CONFIG_FILE)) {
  const cfg = { admin: { username: ADMIN_USER, passwordHash: createPBKDF2Hash(ADMIN_PASS) } };
  fs.writeFileSync(CONFIG_FILE, JSON.stringify(cfg, null, 2), 'utf8');
}

function loadKeys() { try { return JSON.parse(fs.readFileSync(DATA_FILE,'utf8')); } catch(e){ return []; } }
function saveKeys(keys) { fs.writeFileSync(DATA_FILE, JSON.stringify(keys,null,2),'utf8'); }
function loadConfig() { return JSON.parse(fs.readFileSync(CONFIG_FILE,'utf8')); }
function saveConfig(cfg) { fs.writeFileSync(CONFIG_FILE, JSON.stringify(cfg,null,2),'utf8'); }
function signValue(val) { return crypto.createHmac('sha256', HMAC_SECRET).update(val).digest('hex'); }

// --- middleware admin
function requireAdmin(req,res,next){
  const auth = req.headers['authorization'];
  if(!auth) return res.status(401).json({error:'Missing token'});
  const parts = auth.split(' ');
  if(parts.length!==2||parts[0]!=='Bearer') return res.status(401).json({error:'Invalid token'});
  const token = parts[1];
  try{
    const payload = jwt.verify(token,JWT_SECRET);
    const cfg = loadConfig();
    if(payload && payload.username === cfg.admin.username){ req.admin = payload; return next(); }
    else return res.status(403).json({error:'Not admin'});
  }catch(e){ return res.status(401).json({error:'Token invalid'}); }
}

// --- ADMIN LOGIN
app.post('/api/admin-login',(req,res)=>{
  const { username,password } = req.body||{};
  const cfg = loadConfig();
  if(!username || !password) return res.status(400).json({success:false,message:'Missing username/password'});
  if(username!==cfg.admin.username) return res.status(401).json({success:false,message:'Invalid username'});
  if(!verifyPBKDF2Hash(cfg.admin.passwordHash,password)) return res.status(401).json({success:false,message:'Invalid password'});

  const token = jwt.sign({ username:cfg.admin.username, iat:Math.floor(Date.now()/1000) }, JWT_SECRET, { expiresIn:'6h' });
  return res.json({ success:true, token });
});

// --- ADMIN INFO (hiển thị username)
app.get('/api/admin-info',(req,res)=>{
  const cfg = loadConfig();
  return res.json({ username: cfg.admin.username });
});

// --- ADMIN: create key
app.post('/api/create-key',requireAdmin,(req,res)=>{
  const { days, devices } = req.body||{};
  if(!days || !devices) return res.status(400).json({success:false,message:'Missing params'});
  const keys = loadKeys();
  const keyCode = `ZXS-${Math.random().toString(36).substring(2,8).toUpperCase()}-${Math.random().toString(36).substring(2,6).toUpperCase()}`;
  const createdAt = new Date().toISOString();
  const expiresAt = new Date(Date.now() + days*24*60*60*1000).toISOString();
  const signature = signValue(keyCode);
  const record = { id: uuidv4(), key_code:keyCode, signature, created_at:createdAt, expires_at:expiresAt, allowed_devices:Number(devices), devices:[] };
  keys.push(record);
  saveKeys(keys);
  return res.json({ success:true, key:record });
});

// --- ADMIN: list keys
app.get('/api/list-keys',requireAdmin,(req,res)=>res.json(loadKeys()));

// --- ADMIN: extend / reset / delete keys
app.post('/api/extend-key',requireAdmin,(req,res)=>{
  const { key, days } = req.body||{}; if(!key||!days) return res.status(400).json({success:false});
  const keys = loadKeys(); const found = keys.find(k=>k.key_code===key); if(!found) return res.status(404).json({success:false});
  found.expires_at = new Date(new Date(found.expires_at).getTime() + days*86400000).toISOString(); saveKeys(keys); return res.json({success:true});
});
app.post('/api/reset-key',requireAdmin,(req,res)=>{
  const { key } = req.body||{}; const keys = loadKeys(); const found = keys.find(k=>k.key_code===key); if(!found) return res.status(404).json({success:false});
  found.devices=[]; saveKeys(keys); return res.json({success:true});
});
app.post('/api/delete-key',requireAdmin,(req,res)=>{
  const { key } = req.body||{}; let keys = loadKeys(); keys = keys.filter(k=>k.key_code!==key); saveKeys(keys); return res.json({success:true});
});

// --- VERIFY KEY
app.post('/api/verify-key',(req,res)=>{
  const { key, device_id } = req.body||{};
  if(!key || !device_id) return res.status(400).json({success:false,message:'Missing key/device_id'});
  const keys = loadKeys(); const found = keys.find(k=>k.key_code===key);
  if(!found) return res.status(404).json({success:false,message:'Key not found'});
  if(signValue(found.key_code)!==found.signature) return res.status(500).json({success:false,message:'Key signature mismatch'});
  if(new Date(found.expires_at)<new Date()) return res.json({success:false,message:'Expired'});
  if(!Array.isArray(found.devices)) found.devices=[];
  if(!found.devices.includes(device_id)){
    if(found.devices.length>=found.allowed_devices) return res.json({success:false,message:'Device limit reached'});
    found.devices.push(device_id); saveKeys(keys);
  }
  return res.json({success:true,message:'OK'});
});

// --- Serve UI
app.get('/',(req,res)=>{
  const cfg = loadConfig();
  const p = path.join(__dirname,'public','index.html');
  if(fs.existsSync(p)) return res.sendFile(p);
  return res.send(`<h2>License Server Running</h2><p>Admin username: ${cfg.admin.username}</p>`);
});

app.listen(PORT,()=>console.log('Server listening on',PORT));
