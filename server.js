// ===== server.js =====
import express from "express";
import bodyParser from "body-parser";
import cors from "cors";

const app = express();
const PORT = process.env.PORT || 10000;

// ===== middleware =====
app.use(cors());
app.use(bodyParser.json());
app.use(express.static("public")); // chứa file index.html

// ===== dữ liệu tạm (lưu trong RAM) =====
let ADMIN = { username: "admin", password: "123456" };
let KEYS = [];

// ===== Login =====
app.post("/login", (req, res) => {
  const { username, password } = req.body;
  if (username === ADMIN.username && password === ADMIN.password) {
    return res.json({ success: true });
  } else {
    return res.status(401).json({ success: false, message: "Sai tài khoản hoặc mật khẩu" });
  }
});

// ===== Verify Key (cho app C#) =====
app.post("/api/verify-key", (req, res) => {
  const { key } = req.body;
  const found = KEYS.find(k => k.key_code === key);
  if (!found) return res.json({ success: false, message: "Key không tồn tại" });

  const now = new Date();
  const expired = new Date(found.expires_at);
  if (expired < now) return res.json({ success: false, message: "Key hết hạn" });

  res.json({ success: true, message: "Key hợp lệ", key: found });
});

// ===== Create Key =====
app.post("/api/create-key", (req, res) => {
  const { days, devices } = req.body;
  const key = `KEY-${Math.random().toString(36).substring(2, 8).toUpperCase()}-${Math.random()
    .toString(36)
    .substring(2, 6)
    .toUpperCase()}`;
  const created_at = new Date();
  const expires_at = new Date();
  expires_at.setDate(created_at.getDate() + days);
  const keyData = {
    key_code: key,
    created_at,
    expires_at,
    allowed_devices: devices,
    is_active: true,
  };
  KEYS.push(keyData);
  res.json({ success: true, key: keyData });
});

// ===== List Keys =====
app.get("/api/list-keys", (req, res) => {
  res.json(KEYS);
});

// ===== Extend Key =====
app.post("/api/extend-key", (req, res) => {
  const { key, days } = req.body;
  const found = KEYS.find(k => k.key_code === key);
  if (!found) return res.json({ success: false });
  const expires = new Date(found.expires_at);
  expires.setDate(expires.getDate() + days);
  found.expires_at = expires;
  res.json({ success: true });
});

// ===== Reset Key =====
app.post("/api/reset-key", (req, res) => {
  const { key } = req.body;
  const found = KEYS.find(k => k.key_code === key);
  if (!found) return res.json({ success: false });
  found.is_active = true;
  res.json({ success: true });
});

// ===== Delete Key =====
app.post("/api/delete-key", (req, res) => {
  const { key } = req.body;
  KEYS = KEYS.filter(k => k.key_code !== key);
  res.json({ success: true });
});

// ===== Home route =====
app.get("/", (req, res) => {
  res.sendFile(process.cwd() + "/public/index.html");
});

app.listen(PORT, () => console.log(`✅ Server running on port ${PORT}`));
