// server.js - Enhanced Auth API v3.0 with Advanced Features
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
const DEVICES_FILE = path.join(__dirname, 'devices.json');

const JWT_SECRET = process.env.JWT_SECRET || 'please-change-jwt-secret-2025';
const HMAC_SECRET = process.env.HMAC_SECRET || 'please-change-hmac-secret-2025';

const FREE_KEY_LIMIT = 10; // Giới hạn 10 key cho tài khoản free
const MAX_ACCOUNTS_PER_DEVICE = 3; // Tối đa 3 tài khoản mỗi thiết bị

/* ================= INIT FILES ================= */
if (!fs.existsSync(DATA_FILE)) fs.writeFileSync(DATA_FILE, '[]', 'utf8');

if (!fs.existsSync(USERS_FILE)) {
  fs.writeFileSync(USERS_FILE, '[]', 'utf8');
}

if (!fs.existsSync(DEVICES_FILE)) {
  fs.writeFileSync(DEVICES_FILE, '[]', 'utf8');
}

if (!fs.existsSync(CONFIG_FILE)) {
  const adminPassword = '1';
  const hash = bcrypt.hashSync(adminPassword, 10);
  const cfg = { 
    admin: { 
      username: 'admin', 
      passwordHash: hash 
    },
    contact: {
      admin_profile: 'https://facebook.com/admin', // Thay link của bạn
      telegram: '@admin_contact',
      email: 'admin@example.com'
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

function loadDevices() {
  try { return JSON.parse(fs.readFileSync(DEVICES_FILE, 'utf8')); }
  catch { return []; }
}

function saveDevices(devices) {
  fs.writeFileSync(DEVICES_FILE, JSON.stringify(devices, null, 2), 'utf8');
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
  const prefix = type;
  return `${prefix}-${randomChunk(6)}-${randomChunk(4)}`;
}

// Tạo API Code duy nhất cho mỗi user
function generateAPICode() {
  return `API-${crypto.randomBytes(16).toString('hex').toUpperCase()}`;
}

// Tạo Device ID từ thông tin máy
function generateDeviceId(req) {
  const userAgent = req.headers['user-agent'] || '';
  const ip = req.ip || req.connection.remoteAddress || '';
  const combined = `${userAgent}-${ip}`;
  return crypto.createHash('sha256').update(combined).digest('hex');
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
    { expiresIn: '12h' }
  );

  res.json({ success: true, token, role: 'admin' });
});

/* ================= USER REGISTRATION ================= */
app.post('/api/register', async (req, res) => {
  const { username, password, email } = req.body || {};
  
  if (!username || !password || !email) {
    return res.status(400).json({ success: false, message: 'Vui lòng điền đầy đủ thông tin' });
  }

  if (username.length < 3 || password.length < 6) {
    return res.status(400).json({ 
      success: false, 
      message: 'Username tối thiểu 3 ký tự, mật khẩu tối thiểu 6 ký tự' 
    });
  }

  // Kiểm tra giới hạn thiết bị
  const deviceId = generateDeviceId(req);
  const devices = loadDevices();
  const deviceRecord = devices.find(d => d.device_id === deviceId);
  
  if (deviceRecord && deviceRecord.accounts.length >= MAX_ACCOUNTS_PER_DEVICE) {
    return res.status(403).json({ 
      success: false, 
      message: `Thiết bị này đã đăng ký tối đa ${MAX_ACCOUNTS_PER_DEVICE} tài khoản. Vui lòng liên hệ admin để được hỗ trợ.` 
    });
  }

  const users = loadUsers();
  
  // Check if username or email already exists
  if (users.find(u => u.username === username)) {
    return res.status(400).json({ success: false, message: 'Tên đăng nhập đã tồn tại' });
  }
  
  if (users.find(u => u.email === email)) {
    return res.status(400).json({ success: false, message: 'Email đã được sử dụng' });
  }

  const hashedPassword = await bcrypt.hash(password, 10);
  const apiCode = generateAPICode();
  
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
    lastLogin: null,
    apiCode: apiCode, // Mã API riêng cho mỗi user
    deviceId: deviceId // Lưu device đăng ký
  };

  users.push(newUser);
  saveUsers(users);

  // Lưu device tracking
  if (deviceRecord) {
    deviceRecord.accounts.push(newUser.id);
  } else {
    devices.push({
      device_id: deviceId,
      accounts: [newUser.id],
      created_at: new Date().toISOString()
    });
  }
  saveDevices(devices);

  res.json({ 
    success: true, 
    message: 'Đăng ký thành công! Vui lòng đăng nhập.',
    apiCode: apiCode // Trả về API code để user lưu lại
  });
});

/* ================= USER LOGIN ================= */
app.post('/api/login', async (req, res) => {
  const { username, password } = req.body || {};
  
  if (!username || !password) {
    return res.status(400).json({ success: false, message: 'Vui lòng nhập đầy đủ thông tin' });
  }

  const users = loadUsers();
  const user = users.find(u => u.username === username);

  if (!user) {
    return res.status(401).json({ success: false, message: 'Tên đăng nhập hoặc mật khẩu không đúng' });
  }

  if (user.isBanned) {
    return res.status(403).json({ 
      success: false, 
      message: 'Tài khoản đã bị khóa. Vui lòng liên hệ admin.' 
    });
  }

  if (!user.isActive) {
    return res.status(403).json({ 
      success: false, 
      message: 'Tài khoản đã bị tạm khóa. Vui lòng liên hệ admin.' 
    });
  }

  const ok = await bcrypt.compare(password, user.passwordHash);
  if (!ok) {
    return res.status(401).json({ success: false, message: 'Tên đăng nhập hoặc mật khẩu không đúng' });
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
    { expiresIn: '12h' }
  );

  res.json({ 
    success: true, 
    token,
    user: {
      username: user.username,
      email: user.email,
      isPremium: user.isPremium,
      keyCount: user.keyCount,
      apiCode: user.apiCode // Trả về API code
    }
  });
});

/* ================= CREATE KEY (USER & ADMIN) ================= */
app.post('/api/create-key', requireAuth, (req, res) => {
  const { days, devices, type } = req.body || {};
  
  if (!days || !devices) {
    return res.status(400).json({ success: false, message: 'Vui lòng nhập đầy đủ thông tin' });
  }

  const users = loadUsers();
  const user = users.find(u => u.id === req.user.userId);

  // Admin có thể tạo key không giới hạn
  if (req.user.role !== 'admin') {
    if (!user) {
      return res.status(404).json({ success: false, message: 'Không tìm thấy người dùng' });
    }

    if (user.isBanned) {
      return res.status(403).json({ success: false, message: 'Tài khoản đã bị khóa' });
    }

    if (!user.isActive) {
      return res.status(403).json({ success: false, message: 'Tài khoản đã bị tạm khóa' });
    }

    // Check key limit for non-premium users
    if (!user.isPremium && user.keyCount >= FREE_KEY_LIMIT) {
      return res.status(403).json({ 
        success: false, 
        message: `Tài khoản free chỉ tạo được ${FREE_KEY_LIMIT} key. Nâng cấp Premium để tạo không giới hạn!` 
      });
    }
  }

  const keys = loadKeys();
  const keyCode = generateKey(type || "KEY");
  const createdAt = new Date().toISOString();
  const expiresAt = new Date(Date.now() + days * 86400000).toISOString();
  const signature = signValue(keyCode);

  const record = {
    id: uuidv4(),
    key_code: keyCode,
    type: type || "KEY",
    signature,
    created_at: createdAt,
    expires_at: expiresAt,
    allowed_devices: Number(devices),
    devices: [],
    owner_id: req.user.role === 'admin' ? 'admin' : user.id,
    owner_username: req.user.role === 'admin' ? 'admin' : user.username
  };

  keys.push(record);
  saveKeys(keys);

  // Update user key count (nếu không phải admin)
  if (req.user.role !== 'admin' && user) {
    user.keyCount++;
    saveUsers(users);
  }

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
    keyLimit: user.isPremium ? 'Không giới hạn' : FREE_KEY_LIMIT,
    keysRemaining: user.isPremium ? 'Không giới hạn' : Math.max(0, FREE_KEY_LIMIT - user.keyCount),
    apiCode: user.apiCode
  };

  res.json(stats);
});

/* ================= GET API CODE ================= */
app.get('/api/my-api-code', requireAuth, (req, res) => {
  const users = loadUsers();
  const user = users.find(u => u.id === req.user.userId);
  
  if (!user) {
    return res.status(404).json({ success: false, message: 'User not found' });
  }

  res.json({ 
    success: true, 
    apiCode: user.apiCode,
    username: user.username 
  });
});

/* ================= EXTEND KEY ================= */
app.post('/api/extend-key', requireAuth, (req, res) => {
  const { key, days } = req.body || {};
  const keys = loadKeys();
  const found = keys.find(k => k.key_code === key);
  
  if (!found) {
    return res.status(404).json({ success: false, message: 'Không tìm thấy key' });
  }

  // Check ownership (admins can extend any key)
  if (req.user.role !== 'admin' && found.owner_id !== req.user.userId) {
    return res.status(403).json({ success: false, message: 'Bạn không có quyền' });
  }

  found.expires_at = new Date(
    new Date(found.expires_at).getTime() + days * 86400000
  ).toISOString();

  saveKeys(keys);
  res.json({ success: true, message: 'Gia hạn key thành công' });
});

/* ================= RESET KEY ================= */
app.post('/api/reset-key', requireAuth, (req, res) => {
  const { key } = req.body || {};
  const keys = loadKeys();
  const found = keys.find(k => k.key_code === key);
  
  if (!found) {
    return res.status(404).json({ success: false, message: 'Không tìm thấy key' });
  }

  // Check ownership
  if (req.user.role !== 'admin' && found.owner_id !== req.user.userId) {
    return res.status(403).json({ success: false, message: 'Bạn không có quyền' });
  }

  found.devices = [];
  saveKeys(keys);
  res.json({ success: true, message: 'Reset thiết bị thành công' });
});

/* ================= DELETE KEY ================= */
app.post('/api/delete-key', requireAuth, (req, res) => {
  const { key } = req.body || {};
  let keys = loadKeys();
  const found = keys.find(k => k.key_code === key);
  
  if (!found) {
    return res.status(404).json({ success: false, message: 'Không tìm thấy key' });
  }

  // Check ownership
  if (req.user.role !== 'admin' && found.owner_id !== req.user.userId) {
    return res.status(403).json({ success: false, message: 'Bạn không có quyền' });
  }

  keys = keys.filter(k => k.key_code !== key);
  saveKeys(keys);

  // Update user key count
  if (found.owner_id && found.owner_id !== 'admin') {
    const users = loadUsers();
    const user = users.find(u => u.id === found.owner_id);
    if (user && user.keyCount > 0) {
      user.keyCount--;
      saveUsers(users);
    }
  }

  res.json({ success: true, message: 'Xóa key thành công' });
});

/* ================= VERIFY KEY (PUBLIC - FOR WINFORM/CLIENT) ================= */
app.post('/api/verify-key', (req, res) => {
  const { key, device_id, api_code } = req.body || {};
  
  if (!key || !device_id) {
    return res.status(400).json({ success: false, message: 'Thiếu key hoặc device_id' });
  }

  // Kiểm tra API code nếu có
  if (api_code) {
    const users = loadUsers();
    const user = users.find(u => u.apiCode === api_code);
    if (!user) {
      return res.status(401).json({ success: false, message: 'API Code không hợp lệ' });
    }
  }

  const keys = loadKeys();
  const found = keys.find(k => k.key_code === key);
  
  if (!found) {
    return res.status(404).json({ success: false, message: 'Key không tồn tại' });
  }

  const expectedSig = signValue(found.key_code);
  if (expectedSig !== found.signature) {
    return res.status(500).json({ success: false, message: 'Chữ ký không khớp' });
  }

  if (new Date(found.expires_at) < new Date()) {
    return res.json({ success: false, message: 'Key đã hết hạn' });
  }

  if (!found.devices.includes(device_id)) {
    if (found.devices.length >= found.allowed_devices) {
      return res.json({ 
        success: false, 
        message: 'Đã đạt giới hạn thiết bị',
        devices_used: found.devices.length,
        devices_allowed: found.allowed_devices
      });
    }

    found.devices.push(device_id);
    saveKeys(keys);
  }

  res.json({ 
    success: true, 
    message: 'Xác thực thành công', 
    type: found.type,
    expires_at: found.expires_at,
    devices_remaining: found.allowed_devices - found.devices.length
  });
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
    lastLogin: u.lastLogin,
    apiCode: u.apiCode,
    deviceId: u.deviceId
  }));
  res.json(users);
});

// Grant premium
app.post('/api/admin/grant-premium', requireAdmin, (req, res) => {
  const { userId } = req.body || {};
  
  const users = loadUsers();
  const user = users.find(u => u.id === userId);
  
  if (!user) {
    return res.status(404).json({ success: false, message: 'Không tìm thấy user' });
  }

  user.isPremium = true;
  saveUsers(users);
  
  res.json({ success: true, message: 'Đã cấp Premium' });
});

// Revoke premium
app.post('/api/admin/revoke-premium', requireAdmin, (req, res) => {
  const { userId } = req.body || {};
  
  const users = loadUsers();
  const user = users.find(u => u.id === userId);
  
  if (!user) {
    return res.status(404).json({ success: false, message: 'Không tìm thấy user' });
  }

  user.isPremium = false;
  saveUsers(users);
  
  res.json({ success: true, message: 'Đã thu hồi Premium' });
});

// Ban user
app.post('/api/admin/ban-user', requireAdmin, (req, res) => {
  const { userId } = req.body || {};
  
  const users = loadUsers();
  const user = users.find(u => u.id === userId);
  
  if (!user) {
    return res.status(404).json({ success: false, message: 'Không tìm thấy user' });
  }

  user.isBanned = true;
  saveUsers(users);
  
  res.json({ success: true, message: 'Đã ban user' });
});

// Unban user
app.post('/api/admin/unban-user', requireAdmin, (req, res) => {
  const { userId } = req.body || {};
  
  const users = loadUsers();
  const user = users.find(u => u.id === userId);
  
  if (!user) {
    return res.status(404).json({ success: false, message: 'Không tìm thấy user' });
  }

  user.isBanned = false;
  saveUsers(users);
  
  res.json({ success: true, message: 'Đã unban user' });
});

// Lock/Unlock user
app.post('/api/admin/toggle-active', requireAdmin, (req, res) => {
  const { userId } = req.body || {};
  
  const users = loadUsers();
  const user = users.find(u => u.id === userId);
  
  if (!user) {
    return res.status(404).json({ success: false, message: 'Không tìm thấy user' });
  }

  user.isActive = !user.isActive;
  saveUsers(users);
  
  res.json({ success: true, message: user.isActive ? 'Đã kích hoạt user' : 'Đã khóa user' });
});

// Delete user
app.post('/api/admin/delete-user', requireAdmin, (req, res) => {
  const { userId } = req.body || {};
  
  let users = loadUsers();
  const user = users.find(u => u.id === userId);
  
  if (!user) {
    return res.status(404).json({ success: false, message: 'Không tìm thấy user' });
  }

  // Delete all user's keys
  let keys = loadKeys();
  keys = keys.filter(k => k.owner_id !== userId);
  saveKeys(keys);

  // Delete user
  users = users.filter(u => u.id !== userId);
  saveUsers(users);
  
  res.json({ success: true, message: 'Đã xóa user và tất cả key của họ' });
});

// Admin stats
app.get('/api/admin/stats', requireAdmin, (req, res) => {
  const users = loadUsers();
  const keys = loadKeys();
  const devices = loadDevices();
  const now = new Date();

  const stats = {
    totalUsers: users.length,
    activeUsers: users.filter(u => u.isActive && !u.isBanned).length,
    premiumUsers: users.filter(u => u.isPremium).length,
    bannedUsers: users.filter(u => u.isBanned).length,
    totalKeys: keys.length,
    activeKeys: keys.filter(k => new Date(k.expires_at) > now).length,
    totalDevices: devices.length
  };

  res.json(stats);
});

// Get contact info
app.get('/api/contact', (req, res) => {
  const cfg = loadConfig();
  res.json(cfg.contact || {});
});

/* ================= ROOT ================= */
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.get('/api', (req, res) => {
  res.json({
    name: "AuthAPI v3.0 - Enhanced Multi-User License System",
    version: "3.0.0",
    features: [
      "Multi-user authentication",
      "10 keys limit for free users",
      "3 accounts per device limit",
      "Unique API code per account",
      "Support for C#, Python, C++, CMD, HTML injection",
      "IPA menu & Internal menu support",
      "Admin can create unlimited keys"
    ]
  });
});

app.listen(PORT, () => {
  console.log('✅ AuthAPI v3.0 Server running on port', PORT);
  console.log('📝 Free users: 10 keys limit');
  console.log('💻 Device limit: 3 accounts per device');
  console.log('🔑 Each user gets unique API code');
});
