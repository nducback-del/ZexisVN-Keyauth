// server.js (bcrypt-free, uses crypto PBKDF2)
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

// --- CONFIG / SECRETS
const JWT_SECRET = process.env.JWT_SECRET || 'please-change-me-jwt';
const HMAC_SECRET = process.env.HMAC_SECRET || 'please-change-me-hmac';
// optional initial admin provided via env (only used to create config if missing)
const ADMIN_USER = process.env.ADMIN_USER;
const ADMIN_PASS = process.env.ADMIN_PASS;

// --- helper to read/write files
if (!fs.existsSync(DATA_FILE)) fs.writeFileSync(DATA_FILE, '[]', 'utf8');

// If no config and env provided, create config using PBKDF2
if (!fs.existsSync(CONFIG_FILE) && ADMIN_USER && ADMIN_PASS) {
  const cfg = {
    admin: {
      username: ADMIN_USER,
      passwordHash: createPBKDF2Hash(ADMIN_PASS) // see function below
    }
  };
  fs.writeFileSync(CONFIG_FILE, JSON.stringify(cfg, null, 2), 'utf8');
  console.log('Created config.json from env ADMIN_USER/ADMIN_PASS');
}

function loadKeys() {
  try { return JSON.parse(fs.readFileSync(DATA_FILE, 'utf8')); }
  catch (e) { return []; }
}
function saveKeys(keys) {
  fs.writeFileSync(DATA_FILE, JSON.stringify(keys, null, 2), 'utf8');
}
function loadConfig() {
  try { return JSON.parse(fs.readFileSync(CONFIG_FILE, 'utf8')); }
  catch (e) { return null; }
}
function saveConfig(cfg) {
  fs.writeFileSync(CONFIG_FILE, JSON.stringify(cfg, null, 2), 'utf8');
}

// --- helper: HMAC sign a value
function signValue(val) {
  return crypto.createHmac('sha256', HMAC_SECRET).update(val).digest('hex');
}

// --- PBKDF2 password utils (no external deps)
function createPBKDF2Hash(password) {
  const salt = crypto.randomBytes(16).toString('hex');
  const iterations = 150000; // sufficiently large
  const keylen = 64;
  const digest = 'sha512';
  const derived = crypto.pbkdf2Sync(password, salt, iterations, keylen, digest).toString('hex');
  // store format: $pbkdf2$iterations$salt$derived
  return `$pbkdf2$${iterations}$${salt}$${derived}`;
}

function verifyPBKDF2Hash(stored, password) {
  try {
    // stored: $pbkdf2$iterations$salt$derived
    const parts = stored.split('$');
    // ['', 'pbkdf2', iterations, salt, derived]
    if (parts.length !== 5 || parts[1] !== 'pbkdf2') return false;
    const iterations = parseInt(parts[2], 10);
    const salt = parts[3];
    const derived = parts[4];
    const keylen = Buffer.from(derived, 'hex').length;
    const check = crypto.pbkdf2Sync(password, salt, iterations, keylen, 'sha512').toString('hex');

    // timing-safe compare
    return crypto.timingSafeEqual(Buffer.from(check, 'hex'), Buffer.from(derived, 'hex'));
  } catch (e) {
    return false;
  }
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
    const cfg = loadConfig();
    if (!cfg) return res.status(500).json({ error: 'Server config missing' });
    if (payload && payload.username === cfg.admin.username) {
      req.admin = payload;
      return next();
    } else {
      return res.status(403).json({ error: 'Not admin' });
    }
  } catch (e) {
    return res.status(401).json({ error: 'Token invalid' });
  }
}

// --- ADMIN LOGIN
app.post('/api/admin-login', async (req, res) => {
  try {
    const { username, password } = req.body || {};
    const cfg = loadConfig();
    if (!cfg) return res.status(500).json({ success: false, message: 'Config missing; set ADMIN_USER/ADMIN_PASS env or create config.json' });

    if (!username || !password) return res.status(400).json({ success: false, message: 'Missing username or password' });
    if (username !== cfg.admin.username) return res.status(401).json({ success: false, message: 'Invalid username' });

    const storedHash = cfg.admin.passwordHash || '';
    let ok = false;

    // 1) If PBKDF2 format we created, verify with our function
    if (storedHash.startsWith('$pbkdf2$')) {
      ok = verifyPBKDF2Hash(storedHash, password);
    } else if (storedHash.startsWith('$2')) {
      // 2) legacy bcrypt hash detected (created earlier). Try to verify with bcryptjs IF it's available at runtime.
      try {
        const bcrypt = require('bcryptjs'); // try dynamic require (if present)
        ok = await bcrypt.compare(password, storedHash);
        if (ok) {
          // migrate hash to PBKDF2 to avoid bcrypt dependency in future
          cfg.admin.passwordHash = createPBKDF2Hash(password);
          saveConfig(cfg);
          console.log('Migrated bcrypt admin hash to PBKDF2 format.');
        }
      } catch (e) {
        // bcryptjs not available in runtime (likely reason for original error)
        console.warn('bcrypt-style admin hash found but bcryptjs not installed. To login, either set ADMIN_PASS env and remove config.json so it will be recreated, or install bcryptjs.');
        return res.status(500).json({ success: false, message: 'Server missing bcrypt runtime to verify legacy password. Delete config.json or set ADMIN_PASS env to recreate admin.' });
      }
    } else {
      // unknown format -> reject and instruct
      return res.status(500).json({ success: false, message: 'Unknown password hash format in config.json. Recreate config.json from env or remove it.' });
    }

    if (!ok) return res.status(401).json({ success: false, message: 'Invalid password' });

    const token = jwt.sign(
      { username: cfg.admin.username, iat: Math.floor(Date.now() / 1000) },
      JWT_SECRET,
      { expiresIn: '6h' }
    );
    return res.json({ success: true, token });
  } catch (e) {
    console.error('Login error:', e);
    return res.status(500).json({ success: false, message: 'Server error' });
  }
});

// --- ADMIN: create key
app.post('/api/create-key', requireAdmin, (req, res) => {
  const { days, devices } = req.body || {};
  if (!days || !devices) return res.status(400).json({ success: false, message: 'Missing params' });

  const keys = loadKeys();
  const keyCode = `ZXS-${Math.random().toString(36).substring(2,8).toUpperCase()}-${Math.random().toString(36).substring(2,6).toUpperCase()}`;
  const createdAt = new Date().toISOString();
  const expiresAt = new Date(Date.now() + (days * 24 * 60 * 60 * 1000)).toISOString();

  const signature = signValue(keyCode);
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

// --- VERIFY KEY (public)
app.post('/api/verify-key', (req, res) => {
  const { key, device_id } = req.body || {};
  if (!key || !device_id) return res.status(400).json({ success: false, message: 'Missing key or device_id' });

  const keys = loadKeys();
  const found = keys.find(k => k.key_code === key);
  if (!found) return res.status(404).json({ success: false, message: 'Key not found' });

  const expectedSig = signValue(found.key_code);
  if (expectedSig !== found.signature) return res.status(500).json({ success: false, message: 'Key signature mismatch' });

  if (new Date(found.expires_at) < new Date()) return res.json({ success: false, message: 'Expired' });

  if (!Array.isArray(found.devices)) found.devices = [];
  if (!found.devices.includes(device_id)) {
    if (found.devices.length >= found.allowed_devices) return res.json({ success: false, message: 'Device limit reached' });
    found.devices.push(device_id);
    saveKeys(keys);
  }

  return res.json({ success: true, message: 'OK' });
});

// --- Serve UI
app.get('/', (req, res) => {
  const p = path.join(__dirname, 'public', 'index.html');
  if (fs.existsSync(p)) return res.sendFile(p);
  return res.send('License server running');
});

app.listen(PORT, () => console.log('Server listening on', PORT));
