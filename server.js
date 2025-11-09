// server.js (CommonJS)
const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const fs = require('fs');
const path = require('path');
const bcrypt = require('bcrypt');
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

// --- CONFIG / SECRETS (set env vars in Render)
// JWT secret for admin tokens:
const JWT_SECRET = process.env.JWT_SECRET || 'please-change-me-jwt';
// HMAC secret for signing keys:
const HMAC_SECRET = process.env.HMAC_SECRET || 'please-change-me-hmac';

// --- helper to read/write files
if (!fs.existsSync(DATA_FILE)) fs.writeFileSync(DATA_FILE, '[]', 'utf8');
if (!fs.existsSync(CONFIG_FILE)) {
  // initial config with one admin user (password bcrypt-hashed)
  const adminPassword = '123321';
  const hash = bcrypt.hashSync(adminPassword, 10);
  const cfg = { admin: { username: 'ZxsVN-ad', passwordHash: hash } };
  fs.writeFileSync(CONFIG_FILE, JSON.stringify(cfg, null, 2), 'utf8');
}

function loadKeys() {
  try { return JSON.parse(fs.readFileSync(DATA_FILE, 'utf8')); }
  catch (e) { return []; }
}
function saveKeys(keys) {
  fs.writeFileSync(DATA_FILE, JSON.stringify(keys, null, 2), 'utf8');
}
function loadConfig() {
  return JSON.parse(fs.readFileSync(CONFIG_FILE, 'utf8'));
}
function saveConfig(cfg) {
  fs.writeFileSync(CONFIG_FILE, JSON.stringify(cfg, null, 2), 'utf8');
}

// --- helper: HMAC sign a value
function signValue(val) {
  return crypto.createHmac('sha256', HMAC_SECRET).update(val).digest('hex');
}

// --- middleware: protect admin endpoints with JWT
function requireAdmin(req, res, next) {
  const auth = req.headers['authorization'];
  if (!auth) return res.status(401).json({ error: 'Missing token' });
  const parts = auth.split(' ');
  if (parts.length !== 2 || parts[0] !== 'Bearer') return res.status(401).json({ error: 'Invalid token' });
  const token = parts[1];
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    if (payload && payload.username === loadConfig().admin.username) {
      req.admin = payload;
      return next();
    } else {
      return res.status(403).json({ error: 'Not admin' });
    }
  } catch (e) {
    return res.status(401).json({ error: 'Token invalid' });
  }
}

// --- ADMIN LOGIN -> return JWT
app.post('/api/admin-login', async (req, res) => {
  const { username, password } = req.body || {};
  const cfg = loadConfig();
  if (!username || !password) return res.status(400).json({ success: false, message: 'Missing' });
  if (username !== cfg.admin.username) return res.status(401).json({ success: false, message: 'Invalid' });
  const ok = await bcrypt.compare(password, cfg.admin.passwordHash);
  if (!ok) return res.status(401).json({ success: false, message: 'Invalid' });
  const token = jwt.sign({ username: cfg.admin.username, iat: Math.floor(Date.now() / 1000) }, JWT_SECRET, { expiresIn: '6h' });
  return res.json({ success: true, token });
});

// --- ADMIN: create key
app.post('/api/create-key', requireAdmin, (req, res) => {
  const { days, devices } = req.body || {};
  if (!days || !devices) return res.status(400).json({ success: false, message: 'Missing params' });

  const keys = loadKeys();
  const keyCode = `ZXS-${Math.random().toString(36).substring(2,8).toUpperCase()}-${Math.random().toString(36).substring(2,6).toUpperCase()}`;
  const createdAt = new Date().toISOString();
  const expiresAt = new Date(Date.now() + (days * 24 * 60 * 60 * 1000)).toISOString();

  const signature = signValue(keyCode); // HMAC signature
  const record = {
    id: uuidv4(),
    key_code: keyCode,
    signature,
    created_at: createdAt,
    expires_at: expiresAt,
    allowed_devices: Number(devices),
    devices: []
  };
  keys.push(record);
  saveKeys(keys);
  return res.json({ success: true, key: record });
});

// --- ADMIN: list keys
app.get('/api/list-keys', requireAdmin, (req, res) => {
  const keys = loadKeys();
  return res.json(keys);
});

// --- ADMIN: extend / reset / delete
app.post('/api/extend-key', requireAdmin, (req, res) => {
  const { key, days } = req.body || {};
  if (!key || !days) return res.status(400).json({ success: false });
  const keys = loadKeys();
  const found = keys.find(k => k.key_code === key);
  if (!found) return res.status(404).json({ success: false });
  found.expires_at = new Date(new Date(found.expires_at).getTime() + days * 86400000).toISOString();
  saveKeys(keys);
  return res.json({ success: true });
});

app.post('/api/reset-key', requireAdmin, (req, res) => {
  const { key } = req.body || {};
  const keys = loadKeys();
  const found = keys.find(k => k.key_code === key);
  if (!found) return res.status(404).json({ success: false });
  found.devices = [];
  saveKeys(keys);
  return res.json({ success: true });
});

app.post('/api/delete-key', requireAdmin, (req, res) => {
  const { key } = req.body || {};
  let keys = loadKeys();
  keys = keys.filter(k => k.key_code !== key);
  saveKeys(keys);
  return res.json({ success: true });
});

// --- VERIFY KEY (WinForm calls this) ---
// Note: this endpoint is intentionally public (no JWT) because WinForm cannot hold admin JWT.
// But it checks signature & device binding. Use HTTPS in production.
app.post('/api/verify-key', (req, res) => {
  const { key, device_id } = req.body || {};
  if (!key || !device_id) return res.status(400).json({ success: false, message: 'Missing' });

  const keys = loadKeys();
  const found = keys.find(k => k.key_code === key);
  if (!found) return res.status(404).json({ success: false, message: 'Key not found' });

  // verify signature server-side (defense against tampered key entries)
  const expectedSig = signValue(found.key_code);
  if (expectedSig !== found.signature) {
    return res.status(500).json({ success: false, message: 'Key signature mismatch' });
  }

  // expiry
  if (new Date(found.expires_at) < new Date()) {
    return res.json({ success: false, message: 'Expired' });
  }

  // device binding
  if (!Array.isArray(found.devices)) found.devices = [];
  if (!found.devices.includes(device_id)) {
    if (found.devices.length >= found.allowed_devices) {
      return res.json({ success: false, message: 'Device limit reached' });
    }
    found.devices.push(device_id);
    saveKeys(keys);
  }

  // respond success
  return res.json({ success: true, message: 'OK' });
});

// --- Serve UI if present
app.get('/', (req, res) => {
  const p = path.join(__dirname, 'public', 'index.html');
  if (fs.existsSync(p)) return res.sendFile(p);
  return res.send('License server running');
});

app.listen(PORT, () => console.log('Server listening on', PORT));
