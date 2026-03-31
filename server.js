import express from "express";
import dotenv from "dotenv";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import cookieParser from "cookie-parser";
import crypto from "crypto";
import { createClient } from "@supabase/supabase-js";
import OpenAI from "openai";

dotenv.config();

const app = express();
const PORT = process.env.PORT || 3000;

// ---------- DEBUG ----------
console.log("OPENAI KEY:", process.env.OPENAI_API_KEY ? "LOADED" : "MISSING");
console.log("SUPABASE URL:", process.env.SUPABASE_URL ? "LOADED" : "MISSING");
console.log("SUPABASE KEY:", process.env.SUPABASE_SERVICE_ROLE_KEY ? "LOADED" : "MISSING");

// ---------- MIDDLEWARE ----------
app.use(express.json());
app.use(cookieParser());

// ---------- SUPABASE (SAFE INIT) ----------
let supabase = null;

function getSupabase() {
  if (supabase) return supabase;

  const url = process.env.SUPABASE_URL;
  const key = process.env.SUPABASE_SERVICE_ROLE_KEY;

  if (!url || !key) {
    console.error("❌ Supabase env vars missing");
    return null;
  }

  supabase = createClient(url, key);
  console.log("✅ Supabase initialized");

  return supabase;
}

// ---------- OPENAI (SAFE INIT) ----------
let openai = null;

function getOpenAI() {
  if (openai) return openai;

  if (!process.env.OPENAI_API_KEY) {
    console.error("❌ OPENAI_API_KEY missing");
    return null;
  }

  openai = new OpenAI({
    apiKey: process.env.OPENAI_API_KEY
  });

  console.log("✅ OpenAI initialized");
  return openai;
}

// ---------- AUTH STORAGE ----------
const refreshTokens = new Set();

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

// ---------- COOKIE SETTER ----------
function setAuthCookies(res, user) {
  const accessToken = createAccessToken(user);
  const refreshToken = createRefreshToken(user);

  refreshTokens.add(refreshToken);

  res.cookie("accessToken", accessToken, {
    httpOnly: true,
    secure: false,
    sameSite: "strict",
    maxAge: 15 * 60 * 1000
  });

  res.cookie("refreshToken", refreshToken, {
    httpOnly: true,
    secure: false,
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
    return res.status(401).json({ error: "Invalid token" });
  }
}

// ---------- SIGNUP ----------
app.post("/signup", async (req, res) => {
  try {
    const supabase = getSupabase();
    if (!supabase) return res.status(500).json({ error: "DB not configured" });

    const { email, password } = req.body;

    const hashedPassword = await bcrypt.hash(password, 12);

    const { data, error } = await supabase
      .from("users")
      .insert([{ email, password: hashedPassword }])
      .select()
      .single();

    if (error) throw error;

    setAuthCookies(res, data);

    res.json({ user: { id: data.id, email: data.email } });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Signup failed" });
  }
});

// ---------- LOGIN ----------
app.post("/login", async (req, res) => {
  try {
    const supabase = getSupabase();
    if (!supabase) return res.status(500).json({ error: "DB not configured" });

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

    res.json({ user: { id: data.id, email: data.email } });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Login failed" });
  }
});

// ---------- REFRESH ----------
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
  const token = req.cookies.refreshToken;
  refreshTokens.delete(token);

  res.clearCookie("accessToken");
  res.clearCookie("refreshToken");

  res.json({ success: true });
});

// ---------- DASHBOARD ----------
app.get("/dashboard", auth, (req, res) => {
  res.json({
    message: "Welcome 🚀",
    user: req.user
  });
});

// ---------- OPENAI TEST ----------
app.get("/ai-test", async (req, res) => {
  const client = getOpenAI();

  if (!client) {
    return res.status(500).json({ error: "OpenAI not configured" });
  }

  try {
    const response = await client.responses.create({
      model: "gpt-4.1-mini",
      input: "Say hello from PulsePlay API"
    });

    res.json({
      output: response.output[0].content[0].text
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "OpenAI failed" });
  }
});

// ---------- HEALTH ----------
app.get("/", (req, res) => {
  res.json({ status: "PulsePlay API running 🚀" });
});

// ---------- START ----------
app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
});
