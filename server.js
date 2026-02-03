// server.js - Enhanced Auth API with User Management
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
const USERS_FILE = path.join(__dirname, 'users.json');
const CONFIG_FILE = path.join(__dirname, 'config.json');

const JWT_SECRET = process.env.JWT_SECRET || 'please-change-jwt';
const HMAC_SECRET = process.env.HMAC_SECRET || 'please-change-hmac';

const FREE_KEY_LIMIT = 50;

/* ================= INIT FILES ================= */
if (!fs.existsSync(DATA_FILE)) fs.writeFileSync(DATA_FILE, '[]', 'utf8');

if (!fs.existsSync(USERS_FILE)) {
  fs.writeFileSync(USERS_FILE, '[]', 'utf8');
}

if (!fs.existsSync(CONFIG_FILE)) {
  const adminPassword = '1';
  const hash = bcrypt.hashSync(adminPassword, 10);
  const cfg = { 
    admin: { 
      username: 'admin', 
      passwordHash: hash 
    } 
  };
  fs.writeFileSync(CONFIG_FILE, JSON.stringify(cfg, null, 2), 'utf8');
}

/* ================= HELPERS ================= */
function loadKeys() {
  try { return JSON.parse(fs.readFileSync(DATA_FILE, 'utf8')); }
  catch { return []; }
}

function saveKeys(keys) {
  fs.writeFileSync(DATA_FILE, JSON.stringify(keys, null, 2), 'utf8');
}

function loadUsers() {
  try { return JSON.parse(fs.readFileSync(USERS_FILE, 'utf8')); }
  catch { return []; }
}

function saveUsers(users) {
  fs.writeFileSync(USERS_FILE, JSON.stringify(users, null, 2), 'utf8');
}

function loadConfig() {
  return JSON.parse(fs.readFileSync(CONFIG_FILE, 'utf8'));
}

function signValue(val) {
  return crypto.createHmac('sha256', HMAC_SECRET).update(val).digest('hex');
}

function randomChunk(len) {
  return Math.random().toString(36).substring(2, 2 + len).toUpperCase();
}

function generateKey(type = "KEY") {
  const prefix = type === "USER" ? "USER" : "KEY";
  return `${prefix}-${randomChunk(6)}-${randomChunk(4)}`;
}

/* ================= AUTH MIDDLEWARE ================= */
function requireAdmin(req, res, next) {
  const auth = req.headers['authorization'];
  if (!auth) return res.status(401).json({ error: 'Missing token' });

  const parts = auth.split(' ');
  if (parts[0] !== 'Bearer') return res.status(401).json({ error: 'Invalid token' });

  try {
    const payload = jwt.verify(parts[1], JWT_SECRET);
    if (payload.role === 'admin') {
      req.user = payload;
      return next();
    }
    return res.status(403).json({ error: 'Admin access required' });
  } catch {
    return res.status(401).json({ error: 'Token invalid' });
  }
}

function requireAuth(req, res, next) {
  const auth = req.headers['authorization'];
  if (!auth) return res.status(401).json({ error: 'Missing token' });

  const parts = auth.split(' ');
  if (parts[0] !== 'Bearer') return res.status(401).json({ error: 'Invalid token' });

  try {
    const payload = jwt.verify(parts[1], JWT_SECRET);
    req.user = payload;
    return next();
  } catch {
    return res.status(401).json({ error: 'Token invalid' });
  }
}

/* ================= ADMIN LOGIN ================= */
app.post('/api/admin-login', async (req, res) => {
  const { username, password } = req.body || {};
  const cfg = loadConfig();

  if (username !== cfg.admin.username)
    return res.status(401).json({ success: false, message: 'Invalid credentials' });

  const ok = await bcrypt.compare(password, cfg.admin.passwordHash);
  if (!ok) return res.status(401).json({ success: false, message: 'Invalid credentials' });

  const token = jwt.sign(
    { username: cfg.admin.username, role: 'admin', iat: Date.now() },
    JWT_SECRET,
    { expiresIn: '6h' }
  );

  res.json({ success: true, token, role: 'admin' });
});

/* ================= USER REGISTRATION ================= */
app.post('/api/register', async (req, res) => {
  const { username, password, email } = req.body || {};
  
  if (!username || !password || !email) {
    return res.status(400).json({ success: false, message: 'All fields required' });
  }

  if (username.length < 3 || password.length < 6) {
    return res.status(400).json({ success: false, message: 'Username min 3 chars, password min 6 chars' });
  }

  const users = loadUsers();
  
  // Check if username or email already exists
  if (users.find(u => u.username === username)) {
    return res.status(400).json({ success: false, message: 'Username already exists' });
  }
  
  if (users.find(u => u.email === email)) {
    return res.status(400).json({ success: false, message: 'Email already exists' });
  }

  const hashedPassword = await bcrypt.hash(password, 10);
  
  const newUser = {
    id: uuidv4(),
    username,
    email,
    passwordHash: hashedPassword,
    role: 'user',
    isPremium: false,
    isActive: true,
    isBanned: false,
    createdAt: new Date().toISOString(),
    keyCount: 0,
    lastLogin: null
  };

  users.push(newUser);
  saveUsers(users);

  res.json({ success: true, message: 'Registration successful' });
});

/* ================= USER LOGIN ================= */
app.post('/api/login', async (req, res) => {
  const { username, password } = req.body || {};
  
  if (!username || !password) {
    return res.status(400).json({ success: false, message: 'Username and password required' });
  }

  const users = loadUsers();
  const user = users.find(u => u.username === username);

  if (!user) {
    return res.status(401).json({ success: false, message: 'Invalid credentials' });
  }

  if (user.isBanned) {
    return res.status(403).json({ success: false, message: 'Account is banned' });
  }

  if (!user.isActive) {
    return res.status(403).json({ success: false, message: 'Account is locked' });
  }

  const ok = await bcrypt.compare(password, user.passwordHash);
  if (!ok) {
    return res.status(401).json({ success: false, message: 'Invalid credentials' });
  }

  // Update last login
  user.lastLogin = new Date().toISOString();
  saveUsers(users);

  const token = jwt.sign(
    { 
      userId: user.id,
      username: user.username, 
      role: user.role,
      isPremium: user.isPremium,
      iat: Date.now() 
    },
    JWT_SECRET,
    { expiresIn: '6h' }
  );

  res.json({ 
    success: true, 
    token,
    user: {
      username: user.username,
      email: user.email,
      isPremium: user.isPremium,
      keyCount: user.keyCount
    }
  });
});

/* ================= CREATE KEY (USER) ================= */
app.post('/api/create-key', requireAuth, (req, res) => {
  const { days, devices, type } = req.body || {};
  
  if (!days || !devices) {
    return res.status(400).json({ success: false, message: 'Days and devices required' });
  }

  const users = loadUsers();
  const user = users.find(u => u.id === req.user.userId);

  if (!user) {
    return res.status(404).json({ success: false, message: 'User not found' });
  }

  if (user.isBanned) {
    return res.status(403).json({ success: false, message: 'Account is banned' });
  }

  if (!user.isActive) {
    return res.status(403).json({ success: false, message: 'Account is locked' });
  }

  // Check key limit for non-premium users
  if (!user.isPremium && user.keyCount >= FREE_KEY_LIMIT) {
    return res.status(403).json({ 
      success: false, 
      message: `Free users can only create ${FREE_KEY_LIMIT} keys. Upgrade to Premium for unlimited keys.` 
    });
  }

  const keys = loadKeys();
  const keyCode = generateKey(type);
  const createdAt = new Date().toISOString();
  const expiresAt = new Date(Date.now() + days * 86400000).toISOString();
  const signature = signValue(keyCode);

  const record = {
    id: uuidv4(),
    key_code: keyCode,
    type: type === "USER" ? "USER" : "KEY",
    signature,
    created_at: createdAt,
    expires_at: expiresAt,
    allowed_devices: Number(devices),
    devices: [],
    owner_id: user.id,
    owner_username: user.username
  };

  keys.push(record);
  saveKeys(keys);

  // Update user key count
  user.keyCount++;
  saveUsers(users);

  res.json({ success: true, key: record });
});

/* ================= LIST USER KEYS ================= */
app.get('/api/my-keys', requireAuth, (req, res) => {
  const keys = loadKeys();
  const userKeys = keys.filter(k => k.owner_id === req.user.userId);
  res.json(userKeys);
});

/* ================= LIST ALL KEYS (ADMIN) ================= */
app.get('/api/list-keys', requireAdmin, (req, res) => {
  res.json(loadKeys());
});

/* ================= USER STATS ================= */
app.get('/api/my-stats', requireAuth, (req, res) => {
  const users = loadUsers();
  const user = users.find(u => u.id === req.user.userId);
  
  if (!user) {
    return res.status(404).json({ success: false, message: 'User not found' });
  }

  const keys = loadKeys();
  const userKeys = keys.filter(k => k.owner_id === user.id);
  const now = new Date();

  const stats = {
    totalKeys: userKeys.length,
    activeKeys: userKeys.filter(k => new Date(k.expires_at) > now).length,
    expiredKeys: userKeys.filter(k => new Date(k.expires_at) <= now).length,
    isPremium: user.isPremium,
    keyLimit: user.isPremium ? 'Unlimited' : FREE_KEY_LIMIT,
    keysRemaining: user.isPremium ? 'Unlimited' : Math.max(0, FREE_KEY_LIMIT - user.keyCount)
  };

  res.json(stats);
});

/* ================= EXTEND KEY ================= */
app.post('/api/extend-key', requireAuth, (req, res) => {
  const { key, days } = req.body || {};
  const keys = loadKeys();
  const found = keys.find(k => k.key_code === key);
  
  if (!found) {
    return res.status(404).json({ success: false, message: 'Key not found' });
  }

  // Check ownership (admins can extend any key)
  if (req.user.role !== 'admin' && found.owner_id !== req.user.userId) {
    return res.status(403).json({ success: false, message: 'Not authorized' });
  }

  found.expires_at = new Date(
    new Date(found.expires_at).getTime() + days * 86400000
  ).toISOString();

  saveKeys(keys);
  res.json({ success: true });
});

/* ================= RESET KEY ================= */
app.post('/api/reset-key', requireAuth, (req, res) => {
  const { key } = req.body || {};
  const keys = loadKeys();
  const found = keys.find(k => k.key_code === key);
  
  if (!found) {
    return res.status(404).json({ success: false, message: 'Key not found' });
  }

  // Check ownership
  if (req.user.role !== 'admin' && found.owner_id !== req.user.userId) {
    return res.status(403).json({ success: false, message: 'Not authorized' });
  }

  found.devices = [];
  saveKeys(keys);
  res.json({ success: true });
});

/* ================= DELETE KEY ================= */
app.post('/api/delete-key', requireAuth, (req, res) => {
  const { key } = req.body || {};
  let keys = loadKeys();
  const found = keys.find(k => k.key_code === key);
  
  if (!found) {
    return res.status(404).json({ success: false, message: 'Key not found' });
  }

  // Check ownership
  if (req.user.role !== 'admin' && found.owner_id !== req.user.userId) {
    return res.status(403).json({ success: false, message: 'Not authorized' });
  }

  keys = keys.filter(k => k.key_code !== key);
  saveKeys(keys);

  // Update user key count
  if (found.owner_id) {
    const users = loadUsers();
    const user = users.find(u => u.id === found.owner_id);
    if (user && user.keyCount > 0) {
      user.keyCount--;
      saveUsers(users);
    }
  }

  res.json({ success: true });
});

/* ================= VERIFY KEY (PUBLIC - FOR WINFORM) ================= */
app.post('/api/verify-key', (req, res) => {
  const { key, device_id } = req.body || {};
  
  if (!key || !device_id) {
    return res.status(400).json({ success: false, message: 'Key and device_id required' });
  }

  const keys = loadKeys();
  const found = keys.find(k => k.key_code === key);
  
  if (!found) {
    return res.status(404).json({ success: false, message: 'Key not found' });
  }

  const expectedSig = signValue(found.key_code);
  if (expectedSig !== found.signature) {
    return res.status(500).json({ success: false, message: 'Signature mismatch' });
  }

  if (new Date(found.expires_at) < new Date()) {
    return res.json({ success: false, message: 'Expired' });
  }

  if (!found.devices.includes(device_id)) {
    if (found.devices.length >= found.allowed_devices) {
      return res.json({ success: false, message: 'Device limit reached' });
    }

    found.devices.push(device_id);
    saveKeys(keys);
  }

  res.json({ success: true, message: 'OK', type: found.type });
});

/* ================= ADMIN: USER MANAGEMENT ================= */

// Get all users
app.get('/api/admin/users', requireAdmin, (req, res) => {
  const users = loadUsers().map(u => ({
    id: u.id,
    username: u.username,
    email: u.email,
    role: u.role,
    isPremium: u.isPremium,
    isActive: u.isActive,
    isBanned: u.isBanned,
    keyCount: u.keyCount,
    createdAt: u.createdAt,
    lastLogin: u.lastLogin
  }));
  res.json(users);
});

// Grant premium
app.post('/api/admin/grant-premium', requireAdmin, (req, res) => {
  const { userId } = req.body || {};
  
  const users = loadUsers();
  const user = users.find(u => u.id === userId);
  
  if (!user) {
    return res.status(404).json({ success: false, message: 'User not found' });
  }

  user.isPremium = true;
  saveUsers(users);
  
  res.json({ success: true, message: 'Premium granted' });
});

// Revoke premium
app.post('/api/admin/revoke-premium', requireAdmin, (req, res) => {
  const { userId } = req.body || {};
  
  const users = loadUsers();
  const user = users.find(u => u.id === userId);
  
  if (!user) {
    return res.status(404).json({ success: false, message: 'User not found' });
  }

  user.isPremium = false;
  saveUsers(users);
  
  res.json({ success: true, message: 'Premium revoked' });
});

// Ban user
app.post('/api/admin/ban-user', requireAdmin, (req, res) => {
  const { userId } = req.body || {};
  
  const users = loadUsers();
  const user = users.find(u => u.id === userId);
  
  if (!user) {
    return res.status(404).json({ success: false, message: 'User not found' });
  }

  user.isBanned = true;
  saveUsers(users);
  
  res.json({ success: true, message: 'User banned' });
});

// Unban user
app.post('/api/admin/unban-user', requireAdmin, (req, res) => {
  const { userId } = req.body || {};
  
  const users = loadUsers();
  const user = users.find(u => u.id === userId);
  
  if (!user) {
    return res.status(404).json({ success: false, message: 'User not found' });
  }

  user.isBanned = false;
  saveUsers(users);
  
  res.json({ success: true, message: 'User unbanned' });
});

// Lock/Unlock user
app.post('/api/admin/toggle-active', requireAdmin, (req, res) => {
  const { userId } = req.body || {};
  
  const users = loadUsers();
  const user = users.find(u => u.id === userId);
  
  if (!user) {
    return res.status(404).json({ success: false, message: 'User not found' });
  }

  user.isActive = !user.isActive;
  saveUsers(users);
  
  res.json({ success: true, message: user.isActive ? 'User activated' : 'User locked' });
});

// Delete user
app.post('/api/admin/delete-user', requireAdmin, (req, res) => {
  const { userId } = req.body || {};
  
  let users = loadUsers();
  const user = users.find(u => u.id === userId);
  
  if (!user) {
    return res.status(404).json({ success: false, message: 'User not found' });
  }

  // Delete all user's keys
  let keys = loadKeys();
  keys = keys.filter(k => k.owner_id !== userId);
  saveKeys(keys);

  // Delete user
  users = users.filter(u => u.id !== userId);
  saveUsers(users);
  
  res.json({ success: true, message: 'User and all their keys deleted' });
});

// Admin stats
app.get('/api/admin/stats', requireAdmin, (req, res) => {
  const users = loadUsers();
  const keys = loadKeys();
  const now = new Date();

  const stats = {
    totalUsers: users.length,
    activeUsers: users.filter(u => u.isActive && !u.isBanned).length,
    premiumUsers: users.filter(u => u.isPremium).length,
    bannedUsers: users.filter(u => u.isBanned).length,
    totalKeys: keys.length,
    activeKeys: keys.filter(k => new Date(k.expires_at) > now).length
  };

  res.json(stats);
});

/* ================= ROOT ================= */
app.get('/', (req, res) => {
  res.send("AUTH API - Multi-User License Server v2.0");
});

app.listen(PORT, () => console.log('✅ Server running on port', PORT));
