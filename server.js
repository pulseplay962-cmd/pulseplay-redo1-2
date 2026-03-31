import express from "express";
import dotenv from "dotenv";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import cookieParser from "cookie-parser";
import crypto from "crypto";
import { createClient } from "@supabase/supabase-js";

dotenv.config();

const app = express();
const PORT = process.env.PORT || 3000;

// ---------- MIDDLEWARE ----------
app.use(express.json());
app.use(cookieParser());

// ---------- SUPABASE ----------
const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_ROLE_KEY
);

// ---------- IN-MEMORY REFRESH STORE (upgrade later to Redis) ----------
const refreshTokens = new Set();

console.log("OPENAI KEY EXISTS:", !!process.env.OPENAI_API_KEY);

// ---------- JWT HELPERS ----------
function createAccessToken(user) {
  return jwt.sign(
    { id: user.id, email: user.email },
    process.env.JWT_SECRET,
    { expiresIn: "15m" }
  );
}

function createRefreshToken(user) {
  return jwt.sign(
    { id: user.id },
    process.env.JWT_SECRET,
    { expiresIn: "7d" }
  );
}

// ---------- SET AUTH COOKIES ----------
function setAuthCookies(res, user) {
  const accessToken = createAccessToken(user);
  const refreshToken = createRefreshToken(user);

  refreshTokens.add(refreshToken);

  res.cookie("accessToken", accessToken, {
    httpOnly: true,
    secure: false, // ⚠️ set TRUE in production HTTPS
    sameSite: "strict",
    maxAge: 15 * 60 * 1000
  });

  res.cookie("refreshToken", refreshToken, {
    httpOnly: true,
    secure: false, // ⚠️ set TRUE in production HTTPS
    sameSite: "strict",
    maxAge: 7 * 24 * 60 * 60 * 1000
  });
}

// ---------- AUTH MIDDLEWARE ----------
function auth(req, res, next) {
  try {
    const token = req.cookies.accessToken;

    if (!token) {
      return res.status(401).json({ error: "Not authenticated" });
    }

    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded;

    next();
  } catch (err) {
    return res.status(401).json({ error: "Invalid or expired token" });
  }
}

// ---------- SIGNUP ----------
app.post("/signup", async (req, res) => {
  try {
    const { email, password } = req.body;

    const hashedPassword = await bcrypt.hash(password, 12);

    const { data, error } = await supabase
      .from("users")
      .insert([{ email, password: hashedPassword }])
      .select()
      .single();

    if (error) throw error;

    setAuthCookies(res, data);

    res.json({
      user: { id: data.id, email: data.email }
    });
  } catch (err) {
    res.status(500).json({ error: "Signup failed" });
  }
});

// ---------- LOGIN ----------
app.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    const { data } = await supabase
      .from("users")
      .select("*")
      .eq("email", email)
      .single();

    if (!data) {
      return res.status(401).json({ error: "Invalid credentials" });
    }

    const isValid = await bcrypt.compare(password, data.password);

    if (!isValid) {
      return res.status(401).json({ error: "Invalid credentials" });
    }

    setAuthCookies(res, data);

    res.json({
      user: { id: data.id, email: data.email }
    });
  } catch (err) {
    res.status(500).json({ error: "Login failed" });
  }
});

// ---------- REFRESH TOKEN ----------
app.post("/refresh", (req, res) => {
  try {
    const token = req.cookies.refreshToken;

    if (!token || !refreshTokens.has(token)) {
      return res.status(401).json({ error: "Invalid refresh token" });
    }

    const decoded = jwt.verify(token, process.env.JWT_SECRET);

    const newAccessToken = createAccessToken(decoded);

    res.cookie("accessToken", newAccessToken, {
      httpOnly: true,
      secure: false,
      sameSite: "strict",
      maxAge: 15 * 60 * 1000
    });

    res.json({ success: true });
  } catch (err) {
    res.status(401).json({ error: "Refresh failed" });
  }
});

// ---------- LOGOUT ----------
app.post("/logout", (req, res) => {
  const refreshToken = req.cookies.refreshToken;

  refreshTokens.delete(refreshToken);

  res.clearCookie("accessToken");
  res.clearCookie("refreshToken");

  res.json({ success: true });
});

// ---------- PROTECTED ROUTE ----------
app.get("/dashboard", auth, (req, res) => {
  res.json({
    message: "Welcome to your secure dashboard 🚀",
    user: req.user
  });
});

// ---------- HEALTH CHECK ----------
app.get("/", (req, res) => {
  res.json({ status: "PulsePlay API running 🚀" });
});

// ---------- START SERVER ----------
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
