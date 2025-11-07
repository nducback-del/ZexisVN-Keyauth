// server.js
const express = require("express");
const fs = require("fs");
const path = require("path");
const cors = require("cors");

const app = express();
const PORT = process.env.PORT || 10000;
const DATA_FILE = path.join(__dirname, "keys.json");

app.use(cors());
app.use(express.json());

// Đọc dữ liệu key
let keys = [];
if (fs.existsSync(DATA_FILE)) {
  try {
    keys = JSON.parse(fs.readFileSync(DATA_FILE, "utf8"));
  } catch (err) {
    console.error("Lỗi đọc keys.json:", err);
    keys = [];
  }
}

// Lưu file keys.json
function saveKeys() {
  fs.writeFileSync(DATA_FILE, JSON.stringify(keys, null, 2), "utf8");
}

// 🔐 Login admin
app.post("/api/admin-login", (req, res) => {
  const { username, password } = req.body;
  if (username === "admin" && password === "123456") {
    res.json({ success: true });
  } else {
    res.json({ success: false, message: "Sai tài khoản hoặc mật khẩu" });
  }
});

// 🪄 Tạo key
app.post("/api/create-key", (req, res) => {
  try {
    const { days, devices } = req.body;
    if (!days || !devices) {
      return res.json({ success: false, message: "Thiếu thông tin" });
    }

    const prefix = "ZXS";
    const rand = Math.random().toString(36).substring(2, 8).toUpperCase();
    const rand2 = Math.random().toString(36).substring(2, 6).toUpperCase();
    const key_code = `${prefix}-${rand}-${rand2}`;
    const created_at = new Date();
    const expires_at = new Date(created_at.getTime() + days * 86400000);

    const key = {
      key_code,
      created_at,
      expires_at,
      allowed_devices: devices,
      used_devices: [],
      is_active: true,
    };

    keys.push(key);
    saveKeys();

    res.json({ success: true, key });
  } catch (err) {
    console.error("Lỗi tạo key:", err);
    res.status(500).json({ success: false });
  }
});

// 📋 Danh sách key
app.get("/api/list-keys", (req, res) => {
  res.json(keys);
});

// ♻️ Gia hạn key
app.post("/api/extend-key", (req, res) => {
  const { key, days } = req.body;
  const found = keys.find(k => k.key_code === key);
  if (!found) return res.json({ success: false });

  found.expires_at = new Date(
    new Date(found.expires_at).getTime() + days * 86400000
  );
  saveKeys();
  res.json({ success: true });
});

// 🔄 Reset key
app.post("/api/reset-key", (req, res) => {
  const { key } = req.body;
  const found = keys.find(k => k.key_code === key);
  if (!found) return res.json({ success: false });

  found.used_devices = [];
  saveKeys();
  res.json({ success: true });
});

// ❌ Xoá key
app.post("/api/delete-key", (req, res) => {
  const { key } = req.body;
  keys = keys.filter(k => k.key_code !== key);
  saveKeys();
  res.json({ success: true });
});

// 🧩 Trang chủ test
app.get("/", (req, res) => {
  res.send("✅ License Server đang chạy...");
});

app.listen(PORT, () =>
  console.log(`✅ Server đang chạy tại cổng ${PORT}`)
);
