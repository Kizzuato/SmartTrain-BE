const express = require("express");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const { sequelize, User } = require("./models");
const cors = require("cors");
const axios = require("axios");
const { PassThrough } = require("stream");
require("dotenv").config();

const authMiddleware = require("./middlewares/authmiddleware");
const autoResync = require("./middlewares/errmiddleware");

const app = express();
const clients = [];

app.use(cors());
app.use(express.json());

// Routes
app.get("/", (req, res) => {
  res.status(201).json({ message: "Halo dari API Smart-Train" });
});

// Register
app.post("/auth/register", async (req, res, next) => {
  const { email, username, password } = req.body;
  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    await User.create({ email, username, password: hashedPassword });
    res.status(201).json({ message: "User registered successfully" });
  } catch (error) {
    next(error);
  }
});

// Login
app.post("/auth/login", async (req, res, next) => {
  const { email, password } = req.body;
  try {
    const user = await User.findOne({ where: { email } });
    if (!user || !(await bcrypt.compare(password, user.password))) {
      return res.status(401).json({ message: "Invalid username or password" });
    }
    const token = jwt.sign({ userId: user.id }, process.env.JWT_SECRET, {
      expiresIn: "1h",
    });
    res.json({ token });
  } catch (error) {
    next(error);
  }
});

// Me
app.get("/auth/user", authMiddleware, async (req, res, next) => {
  try {
    const user = await User.findByPk(req.userId);
    if (!user) return res.status(404).json({ message: "User not found" });
    res.json({ user });
  } catch (error) {
    next(error);
  }
});

// List Users (hanya yang login bisa akses)
app.get("/users", authMiddleware, async (req, res, next) => {
  try {
    const users = await User.findAll();
    res.json({ users });
  } catch (error) {
    next(error);
  }
});

// 🚀 Live Streaming Proxy (multi client)
app.get("/stream", (req, res) => {
  res.writeHead(200, {
    "Content-Type": cameraContentType, // pakai content-type dari kamera
    "Cache-Control": "no-cache",
    "Connection": "keep-alive",
    "Pragma": "no-cache",
  });

  clients.push(res);

  req.on("close", () => {
    const idx = clients.indexOf(res);
    if (idx !== -1) clients.splice(idx, 1);
  });
});

let cameraContentType = "multipart/x-mixed-replace; boundary=frame"; // default
let cameraStream;

// Relay 1 koneksi dari kamera
async function startRelay() {
  const camUrl = "http://192.168.18.16:4747/video"; // MJPEG stream

  try {
    const response = await axios.get(camUrl, { responseType: "stream" });

    // simpan Content-Type dari kamera (supaya boundary cocok)
    if (response.headers["content-type"]) {
      cameraContentType = response.headers["content-type"];
    }

    cameraStream = response.data;

    // broadcast chunk ke semua client
    cameraStream.on("data", (chunk) => {
      clients.forEach((res) => res.write(chunk));
    });

    cameraStream.on("end", () => {
      console.log("Camera stream ended, reconnecting in 3s...");
      setTimeout(startRelay, 3000);
    });

    cameraStream.on("error", (err) => {
      console.error("Camera stream error:", err.message);
      setTimeout(startRelay, 3000);
    });

  } catch (err) {
    console.error("Failed to connect camera:", err.message);
    setTimeout(startRelay, 3000);
  }
}

startRelay();

// Error handler untuk auto-resync
app.use(autoResync);

// Start server
sequelize.sync().then(() => {
  app.listen(5000, () => console.log("Server running on port 5000"));
});
