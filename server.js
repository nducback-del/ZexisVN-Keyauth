// server.js (CommonJS)
const express = require("express");
const bodyParser = require("body-parser");
const cors = require("cors");
const fs = require("fs");
const path = require("path");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const crypto = require("crypto");
const { v4: uuidv4 } = require("uuid");

const app = express();
app.use(cors());
app.use(bodyParser.json());
app.use(express.static("public"));

const PORT = process.env.PORT || 10000;
const DATA_FILE = path.join(__dirname, "keys.json");
const CONFIG_FILE = path.join(__dirname, "config.json");

// --- Secrets (đặt env trong Render nếu muốn bảo mật)
const JWT_SECRET = process.env.JWT_SECRET || "change-this-secret";
const HMAC_SECRET = process.env.HMAC_SECRET || "change-this-hmac";

// --- Init file
if (!fs.existsSync(DATA_FILE)) fs.writeFileSync(DATA_FILE, "[]", "utf8");
if (!fs.existsSync(CONFIG_FILE)) {
  const adminPassword = "123321";
  const hash = bcrypt.hashSync(adminPassword, 10);
  const cfg = { admin: { username: "ZxsVN-ad", passwordHash: hash } };
  fs.writeFileSync(CONFIG_FILE, JSON.stringify(cfg, null, 2), "utf8");
}

// --- File helpers
function loadKeys() {
  try {
    return JSON.parse(fs.readFileSync(DATA_FILE, "utf8"));
  } catch {
    return [];
  }
}
function saveKeys(keys) {
  fs.writeFileSync(DATA_FILE, JSON.stringify(keys, null, 2), "utf8");
}
function loadConfig() {
  return JSON.parse(fs.readFileSync(CONFIG_FILE, "utf8"));
}
function saveConfig(cfg) {
  fs.writeFileSync(CONFIG_FILE, JSON.stringify(cfg, null, 2), "utf8");
}

// --- Helper: HMAC sign
function signValue(val) {
  return crypto.createHmac("sha256", HMAC_SECRET).update(val).digest("hex");
}

// --- Middleware: require admin JWT
function requireAdmin(req, res, next) {
  const auth = req.headers["authorization"];
  if (!auth) return res.status(401).json({ error: "Missing token" });
  const parts = auth.split(" ");
  if (parts.length !== 2 || parts[0] !== "Bearer")
    return res.status(401).json({ error: "Invalid token" });
  const token = parts[1];
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    if (payload.username === loadConfig().admin.username) {
      req.admin = payload;
      next();
    } else {
      res.status(403).json({ error: "Not admin" });
    }
  } catch {
    res.status(401).json({ error: "Token invalid" });
  }
}

// --- ADMIN LOGIN
app.post("/api/admin-login", async (req, res) => {
  const { username, password } = req.body || {};
  const cfg = loadConfig();

  if (!username || !password)
    return res.status(400).json({ success: false, message: "Missing fields" });

  if (username !== cfg.admin.username)
    return res.status(401).json({ success: false, message: "Invalid login" });

  const ok = await bcrypt.compare(password, cfg.admin.passwordHash);
  if (!ok)
    return res.status(401).json({ success: false, message: "Invalid login" });

  const token = jwt.sign(
    { username: cfg.admin.username },
    JWT_SECRET,
    { expiresIn: "6h" }
  );
  res.json({ success: true, token });
});

// --- ADMIN: create key
app.post("/api/create-key", requireAdmin, (req, res) => {
  const { days, devices } = req.body || {};
  if (!days || !devices)
    return res.status(400).json({ success: false, message: "Missing params" });

  const keys = loadKeys();
  const keyCode = `ZXS-${Math.random().toString(36).substring(2,8).toUpperCase()}-${Math.random().toString(36).substring(2,6).toUpperCase()}`;
  const createdAt = new Date().toISOString();
  const expiresAt = new Date(Date.now() + days * 86400000).toISOString();

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
  res.json({ success: true, key: record });
});

// --- ADMIN: list keys
app.get("/api/list-keys", requireAdmin, (req, res) => {
  res.json(loadKeys());
});

// --- ADMIN: extend key
app.post("/api/extend-key", requireAdmin, (req, res) => {
  const { key, days } = req.body || {};
  const keys = loadKeys();
  const found = keys.find(k => k.key_code === key);
  if (!found) return res.status(404).json({ success: false });
  found.expires_at = new Date(new Date(found.expires_at).getTime() + days * 86400000).toISOString();
  saveKeys(keys);
  res.json({ success: true });
});

// --- ADMIN: reset key devices
app.post("/api/reset-key", requireAdmin, (req, res) => {
  const { key } = req.body || {};
  const keys = loadKeys();
  const found = keys.find(k => k.key_code === key);
  if (!found) return res.status(404).json({ success: false });
  found.devices = [];
  saveKeys(keys);
  res.json({ success: true });
});

// --- ADMIN: delete key
app.post("/api/delete-key", requireAdmin, (req, res) => {
  const { key } = req.body || {};
  let keys = loadKeys();
  keys = keys.filter(k => k.key_code !== key);
  saveKeys(keys);
  res.json({ success: true });
});

// --- VERIFY KEY (public endpoint)
app.post("/api/verify-key", (req, res) => {
  const { key, device_id } = req.body || {};
  if (!key || !device_id)
    return res.status(400).json({ success: false, message: "Missing" });

  const keys = loadKeys();
  const found = keys.find(k => k.key_code === key);
  if (!found)
    return res.status(404).json({ success: false, message: "Key not found" });

  const expectedSig = signValue(found.key_code);
  if (expectedSig !== found.signature)
    return res.status(500).json({ success: false, message: "Invalid signature" });

  if (new Date(found.expires_at) < new Date())
    return res.json({ success: false, message: "Expired" });

  if (!Array.isArray(found.devices)) found.devices = [];
  if (!found.devices.includes(device_id)) {
    if (found.devices.length >= found.allowed_devices)
      return res.json({ success: false, message: "Device limit reached" });
    found.devices.push(device_id);
    saveKeys(keys);
  }

  res.json({ success: true, message: "OK" });
});

// --- UI fallback
app.get("/", (req, res) => {
  const index = path.join(__dirname, "public", "index.html");
  if (fs.existsSync(index)) res.sendFile(index);
  else res.send("License server running ✅");
});

app.listen(PORT, () => console.log(`✅ Server running on port ${PORT}`));
