'use strict';
/**
 * Kisan Saha — backend
 * Express + Blynk proxy + MongoDB Atlas history + OpenWeatherMap predictive lock + email-OTP sessions
 */
require('dotenv').config();
const express = require('express');
const cors = require('cors');
const axios = require('axios');
const nodemailer = require('nodemailer');
const crypto = require('crypto');
const { MongoClient } = require('mongodb');

const env = process.env;

/* ───────────────────────── Configuration ───────────────────────── */
const CFG = {
  port: Number(env.PORT) || 3000,
  origin: env.ALLOWED_ORIGIN || '*', // e.g. https://<user>.github.io  (no trailing slash, no path)
  blynkToken: env.BLYNK_TOKEN,
  mongoUri: env.MONGO_URI,
  dbName: env.MONGO_DB || 'kisan_saha',
  owmKey: env.OWM_API_KEY,
  lat: env.FARM_LAT,
  lon: env.FARM_LON,
  secret: env.SESSION_SECRET,
  otpLen: Number(env.OTP_LENGTH) || 4,
  otpTtlMs: 5 * 60 * 1000,
  otpCooldownMs: 45 * 1000,
  otpMaxAttempts: 5,
  sessionTtlMs: 12 * 60 * 60 * 1000,
  pollMs: 10 * 60 * 1000,
  weatherMs: 6 * 60 * 60 * 1000,
  retentionDays: Number(env.RETENTION_DAYS) || 30,
  // "Heavy rain" definition over the next 12h (3-hour OWM slots)
  rain: {
    totalMm: Number(env.RAIN_TOTAL_MM) || 10, // cumulative mm in 12h
    peakMm: Number(env.RAIN_PEAK_MM) || 8, // single 3h slot mm
    minPop: Number(env.RAIN_MIN_POP) || 0.6, // probability of precipitation floor
  },
};

// Blynk datastream mapping — adjust to match your template
// Matches the NodeMCU firmware / original prototype
const PINS = {
  moisture: 'v0',
  temperature: 'v1',
  humidity: 'v2',
  auto: 'v3', // 1 = Auto (smart) mode, 0 = Manual   (write)
  pumpCmd: 'v4', // 1 = run, 0 = stop, honoured in Manual (write)
  pumpState: 'v5', // relay feedback: 1 or 255 = running (read)
  diag: 'v6', // diagnostics text from firmware (read)
  ota: 'v10', // used in the OTA phase
};
// Optional: virtual pins the firmware reads the crop min/max thresholds from.
// Leave unset until the firmware supports them; the UI then shows targets as display-only.
const TARGET_PINS = {
  min: env.PIN_TARGET_MIN ? env.PIN_TARGET_MIN.toLowerCase() : null,
  max: env.PIN_TARGET_MAX ? env.PIN_TARGET_MAX.toLowerCase() : null,
};
const TARGET_SYNC = Boolean(TARGET_PINS.min && TARGET_PINS.max);
const READ_MAP = {
  moisture: PINS.moisture,
  temperature: PINS.temperature,
  humidity: PINS.humidity,
  pumpState: PINS.pumpState,
  auto: PINS.auto,
  ...(TARGET_SYNC ? { min: TARGET_PINS.min, max: TARGET_PINS.max } : {}),
};

const REQUIRED = ['BLYNK_TOKEN', 'MONGO_URI', 'SESSION_SECRET', 'SMTP_USER', 'SMTP_PASS', 'OTP_EMAIL_TO'];
const missing = REQUIRED.filter((k) => !env[k]);
if (missing.length) {
  console.error('Missing required env vars:', missing.join(', '));
  process.exit(1);
}

/* ───────────────────────── Helpers ───────────────────────── */
const sha256 = (s) => crypto.createHash('sha256').update(s).digest('hex');
const hmac = (s) => crypto.createHmac('sha256', CFG.secret).update(s).digest('hex');
const safeEqual = (a, b) => {
  const A = Buffer.from(a), B = Buffer.from(b);
  return A.length === B.length && crypto.timingSafeEqual(A, B);
};
const round = (n, d = 1) => Math.round(n * 10 ** d) / 10 ** d;
const wrap = (fn) => (req, res) =>
  Promise.resolve(fn(req, res)).catch((err) => {
    console.error(`[${req.method} ${req.path}]`, err.message);
    res.status(502).json({ error: 'DEVICE_UNREACHABLE', message: 'Could not reach the controller. Try again shortly.' });
  });

/* ───────────────────────── Blynk ───────────────────────── */
const blynk = axios.create({ baseURL: 'https://blynk.cloud/external/api', timeout: 8000 });
const tk = encodeURIComponent(CFG.blynkToken);

async function blynkGetPin(pin) {
  const r = await blynk.get(`/get?token=${tk}&${pin}`);
  return Array.isArray(r.data) ? r.data[0] : r.data;
}
async function blynkConnected() {
  const r = await blynk.get(`/isHardwareConnected?token=${tk}`);
  return r.data === true || r.data === 'true';
}
async function blynkSet(pin, value) {
  await blynk.get(`/update?token=${tk}&${pin}=${encodeURIComponent(value)}`);
  cache.t = 0;
}

let cache = { t: 0, d: null };
async function readDevice(force = false) {
  if (!force && cache.d && Date.now() - cache.t < 4000) return cache.d;
  const keys = Object.keys(READ_MAP);
  const [conn, diag, ...vals] = await Promise.allSettled([
    blynkConnected(),
    blynkGetPin(PINS.diag),
    ...keys.map((k) => blynkGetPin(READ_MAP[k])),
  ]);
  const d = {
    online: conn.status === 'fulfilled' ? conn.value : null,
    diag: diag.status === 'fulfilled' && diag.value != null && diag.value !== '' ? String(diag.value).slice(0, 140) : null,
    min: null,
    max: null,
  };
  keys.forEach((k, i) => {
    const v = vals[i].status === 'fulfilled' ? vals[i].value : null;
    d[k] = v == null || v === '' || Number.isNaN(Number(v)) ? null : Number(v);
  });
  d.pump = d.pumpState == null ? null : d.pumpState > 0;
  delete d.pumpState;
  d.auto = d.auto == null ? null : d.auto > 0;
  cache = { t: Date.now(), d };
  return d;
}

/* ───────────────────────── MongoDB ───────────────────────── */
const mongo = new MongoClient(CFG.mongoUri, { serverSelectionTimeoutMS: 10000 });
let col = {};

async function initDb() {
  await mongo.connect();
  const db = mongo.db(CFG.dbName);
  col = {
    readings: db.collection('readings'),
    sessions: db.collection('sessions'),
    otps: db.collection('otps'),
    state: db.collection('state'),
  };
  await Promise.all([
    col.readings.createIndex({ ts: 1 }, { expireAfterSeconds: CFG.retentionDays * 86400 }),
    col.sessions.createIndex({ expiresAt: 1 }, { expireAfterSeconds: 0 }),
  ]);
}

/* ───────────────────────── Weather lock ───────────────────────── */
const weather = {
  lock: false,
  autoWasOn: null,
  since: null,
  checkedAt: null,
  error: null,
  forecast: null,
};

async function loadWeatherState() {
  const doc = await col.state.findOne({ _id: 'weather' });
  if (doc) {
    const { _id, ...rest } = doc;
    Object.assign(weather, rest);
  }
}
const saveWeather = () => col.state.updateOne({ _id: 'weather' }, { $set: { ...weather } }, { upsert: true });

async function engageLock() {
  let autoWasOn = false;
  try {
    const d = await readDevice(true);
    autoWasOn = d.auto === true;
  } catch (_) { /* keep default */ }
  weather.autoWasOn = autoWasOn;
  weather.lock = true;
  weather.since = new Date().toISOString();
  await saveWeather(); // persist first: the poller keeps enforcing even if the writes below fail
  try { await blynkSet(PINS.auto, 0); } catch (e) { console.error('lock: auto off failed', e.message); }
  try { await blynkSet(PINS.pumpCmd, 0); } catch (e) { console.error('lock: pump off failed', e.message); }
  console.log('[weather] LOCK engaged');
}

async function releaseLock() {
  if (weather.autoWasOn) {
    try { await blynkSet(PINS.auto, 1); } catch (e) { console.error('release: auto restore failed', e.message); return; }
  }
  weather.lock = false;
  weather.autoWasOn = null;
  weather.since = null;
  await saveWeather();
  console.log('[weather] LOCK released');
}

async function checkWeather() {
  if (!CFG.owmKey || !CFG.lat || !CFG.lon) return;
  try {
    const { data } = await axios.get('https://api.openweathermap.org/data/2.5/forecast', {
      params: { lat: CFG.lat, lon: CFG.lon, appid: CFG.owmKey, units: 'metric', cnt: 5 },
      timeout: 10000,
    });
    const horizon = Date.now() / 1000 + 12 * 3600;
    const slots = (data.list || []).filter((s) => s.dt <= horizon);
    const rainOf = (s) => (s.rain && s.rain['3h']) || 0;
    const totalMm = slots.reduce((a, s) => a + rainOf(s), 0);
    const peakMm = slots.reduce((a, s) => Math.max(a, rainOf(s)), 0);
    const maxPop = slots.reduce((a, s) => Math.max(a, s.pop || 0), 0);
    const firstRain = slots.find((s) => rainOf(s) > 0);

    const heavy = maxPop >= CFG.rain.minPop && (totalMm >= CFG.rain.totalMm || peakMm >= CFG.rain.peakMm);

    weather.forecast = {
      horizonH: 12,
      totalMm: round(totalMm),
      peakMm: round(peakMm),
      pop: round(maxPop, 2),
      firstRainAt: firstRain ? new Date(firstRain.dt * 1000).toISOString() : null,
      summary: slots[0]?.weather?.[0]?.description || null,
      tempC: slots[0]?.main?.temp != null ? round(slots[0].main.temp) : null,
    };
    weather.checkedAt = new Date().toISOString();
    weather.error = null;

    if (heavy && !weather.lock) await engageLock();
    else if (!heavy && weather.lock) await releaseLock();
    else await saveWeather();
  } catch (e) {
    weather.error = 'FORECAST_UNAVAILABLE';
    console.error('[weather] check failed:', e.message);
  }
}

const publicWeather = () => ({
  lock: weather.lock,
  since: weather.since,
  forecast: weather.forecast,
  checkedAt: weather.checkedAt,
  nextCheckAt: weather.checkedAt ? new Date(new Date(weather.checkedAt).getTime() + CFG.weatherMs).toISOString() : null,
  error: weather.error,
  enabled: Boolean(CFG.owmKey && CFG.lat && CFG.lon),
});

/* ───────────────────────── Polling (10 min) ───────────────────────── */
async function poll() {
  try {
    const d = await readDevice(true);
    await col.readings.insertOne({
      ts: new Date(),
      moisture: d.moisture,
      temperature: d.temperature,
      humidity: d.humidity,
      pump: d.pump,
      auto: d.auto,
      min: d.min,
      max: d.max,
      online: d.online,
    });
    // Enforcement: while locked, nothing may be running
    if (weather.lock && (d.pump || d.auto)) {
      console.log('[weather] enforcing lock on device');
      if (d.auto) await blynkSet(PINS.auto, 0);
      if (d.pump) await blynkSet(PINS.pumpCmd, 0);
    }
  } catch (e) {
    console.error('[poll] failed:', e.message);
  }
}

/* ───────────────────────── Mail / OTP ───────────────────────── */
const mailer = nodemailer.createTransport(
  env.SMTP_HOST
    ? { host: env.SMTP_HOST, port: Number(env.SMTP_PORT) || 587, secure: env.SMTP_SECURE === 'true', auth: { user: env.SMTP_USER, pass: env.SMTP_PASS } }
    : { service: 'gmail', auth: { user: env.SMTP_USER, pass: env.SMTP_PASS } }
);

const hits = new Map(); // ip -> {n, reset}
function limiter(max, windowMs) {
  return (req, res, next) => {
    const now = Date.now();
    const rec = hits.get(req.ip);
    if (!rec || rec.reset < now) hits.set(req.ip, { n: 1, reset: now + windowMs });
    else if (++rec.n > max) return res.status(429).json({ error: 'RATE_LIMITED', message: 'Too many attempts. Please wait.' });
    next();
  };
}
setInterval(() => { const n = Date.now(); for (const [k, v] of hits) if (v.reset < n) hits.delete(k); }, 60000).unref();

async function auth(req, res, next) {
  try {
    const token = req.get('x-auth-pin');
    if (!token) return res.status(401).json({ error: 'UNAUTHORIZED' });
    const s = await col.sessions.findOne({ _id: sha256(token), expiresAt: { $gt: new Date() } });
    if (!s) return res.status(401).json({ error: 'UNAUTHORIZED' });
    next();
  } catch (e) {
    res.status(500).json({ error: 'SERVER_ERROR' });
  }
}

/* ───────────────────────── App ───────────────────────── */
const app = express();
app.set('trust proxy', 1);
app.disable('x-powered-by');
app.use(cors({ origin: CFG.origin, allowedHeaders: ['Content-Type', 'x-auth-pin'], methods: ['GET', 'POST', 'OPTIONS'] }));
app.use(express.json({ limit: '10kb' }));
app.use((req, res, next) => {
  res.set({ 'X-Content-Type-Options': 'nosniff', 'Cache-Control': 'no-store', 'Referrer-Policy': 'no-referrer' });
  next();
});

app.get('/health', (_req, res) => res.json({ ok: true, uptime: Math.round(process.uptime()) }));

/* ── Auth ── */
app.post('/api/auth/send-otp', limiter(10, 10 * 60 * 1000), async (_req, res) => {
  try {
    const now = Date.now();
    const cur = await col.otps.findOne({ _id: 'current' });
    if (cur && now - cur.lastSentAt < CFG.otpCooldownMs) {
      const wait = Math.ceil((CFG.otpCooldownMs - (now - cur.lastSentAt)) / 1000);
      return res.status(429).json({ error: 'COOLDOWN', retryAfter: wait, message: `Wait ${wait}s before requesting another code.` });
    }
    const otp = String(crypto.randomInt(10 ** (CFG.otpLen - 1), 10 ** CFG.otpLen));
    await col.otps.updateOne(
      { _id: 'current' },
      { $set: { hash: hmac(otp), expiresAt: now + CFG.otpTtlMs, attempts: 0, lastSentAt: now } },
      { upsert: true }
    );
    await mailer.sendMail({
      from: `"Kisan Saha" <${env.SMTP_USER}>`,
      to: env.OTP_EMAIL_TO,
      subject: `Kisan Saha access code: ${otp}`,
      text: `Your one-time access code is ${otp}. It expires in 5 minutes. If you did not request it, ignore this email.`,
      html: `<div style="font-family:Arial,sans-serif;background:#090b10;padding:32px;color:#e7eaf0">
        <div style="max-width:380px;margin:auto;border:1px solid #1d2535;border-radius:12px;padding:28px;background:#0e131c">
        <div style="font-size:12px;letter-spacing:.14em;color:#7b8494;text-transform:uppercase">Kisan Saha</div>
        <div style="font-size:34px;letter-spacing:.35em;font-weight:700;margin:18px 0">${otp}</div>
        <div style="font-size:13px;color:#9aa3b2">One-time access code. Expires in 5 minutes.<br>If you did not request this, you can ignore this email.</div>
        </div></div>`,
    });
    res.json({ ok: true, length: CFG.otpLen, ttl: CFG.otpTtlMs / 1000, cooldown: CFG.otpCooldownMs / 1000 });
  } catch (e) {
    console.error('[otp] send failed:', e.message);
    res.status(502).json({ error: 'MAIL_FAILED', message: 'Could not send the code. Try again.' });
  }
});

app.post('/api/auth/verify', limiter(30, 10 * 60 * 1000), async (req, res) => {
  try {
    const otp = String(req.body?.otp ?? '');
    if (!new RegExp(`^\\d{${CFG.otpLen}}$`).test(otp)) return res.status(400).json({ error: 'BAD_CODE', message: 'Enter the full code.' });
    const cur = await col.otps.findOne({ _id: 'current' });
    if (!cur || cur.expiresAt < Date.now()) return res.status(401).json({ error: 'EXPIRED', message: 'Code expired. Request a new one.' });
    if (cur.attempts >= CFG.otpMaxAttempts) {
      await col.otps.deleteOne({ _id: 'current' });
      return res.status(401).json({ error: 'LOCKED_OUT', message: 'Too many wrong attempts. Request a new code.' });
    }
    if (!safeEqual(cur.hash, hmac(otp))) {
      await col.otps.updateOne({ _id: 'current' }, { $inc: { attempts: 1 } });
      return res.status(401).json({ error: 'WRONG_CODE', message: 'Incorrect code.' });
    }
    await col.otps.deleteOne({ _id: 'current' });
    const token = crypto.randomBytes(32).toString('hex');
    const expiresAt = new Date(Date.now() + CFG.sessionTtlMs);
    await col.sessions.insertOne({ _id: sha256(token), expiresAt, createdAt: new Date() });
    res.json({ ok: true, token, expiresAt: expiresAt.toISOString() });
  } catch (e) {
    console.error('[otp] verify failed:', e.message);
    res.status(500).json({ error: 'SERVER_ERROR', message: 'Verification failed.' });
  }
});

app.post('/api/auth/logout', auth, async (req, res) => {
  await col.sessions.deleteOne({ _id: sha256(req.get('x-auth-pin')) });
  res.json({ ok: true });
});

/* ── Telemetry / history / weather ── */
app.get('/api/telemetry', auth, wrap(async (_req, res) => {
  const device = await readDevice();
  res.json({ device, weather: publicWeather(), config: { targetSync: TARGET_SYNC }, serverTime: new Date().toISOString() });
}));

app.get('/api/history', auth, async (req, res) => {
  try {
    const hours = Math.min(Math.max(Number(req.query.hours) || 24, 1), 168);
    const since = new Date(Date.now() - hours * 3600e3);
    const rows = await col.readings.find({ ts: { $gte: since } }, { projection: { _id: 0 } }).sort({ ts: 1 }).toArray();
    const step = Math.max(1, Math.ceil(rows.length / 300));
    const points = rows
      .filter((_, i) => i % step === 0 || i === rows.length - 1)
      .map((r) => ({ t: r.ts.getTime(), m: r.moisture, tp: r.temperature, h: r.humidity, p: r.pump ? 1 : 0, mn: r.min ?? null, mx: r.max ?? null }));
    res.json({ hours, count: points.length, points });
  } catch (e) {
    console.error('[history]', e.message);
    res.status(500).json({ error: 'SERVER_ERROR' });
  }
});

app.get('/api/weather', auth, (_req, res) => res.json(publicWeather()));

/* ── Control ── */
const locked = (res) =>
  res.status(423).json({ error: 'WEATHER_LOCK', message: 'Heavy rain forecast. Irrigation is locked until conditions clear.' });

app.post('/api/control', auth, wrap(async (req, res) => {
  const on = req.body?.pump;
  if (typeof on !== 'boolean') return res.status(400).json({ error: 'BAD_REQUEST' });
  if (on && weather.lock) return locked(res);
  if (on) {
    const d = await readDevice();
    if (d.auto) return res.status(409).json({ error: 'AUTO_MODE_ACTIVE', message: 'Turn Auto mode off to run the pump manually.' });
  }
  await blynkSet(PINS.pumpCmd, on ? 1 : 0);
  res.json({ ok: true, pump: on });
}));

app.post('/api/auto', auth, wrap(async (req, res) => {
  const enabled = req.body?.enabled;
  if (typeof enabled !== 'boolean') return res.status(400).json({ error: 'BAD_REQUEST' });
  if (enabled && weather.lock) return locked(res);
  await blynkSet(PINS.auto, enabled ? 1 : 0);
  res.json({ ok: true, auto: enabled });
}));

app.post('/api/target', auth, wrap(async (req, res) => {
  if (!TARGET_SYNC) return res.status(501).json({ error: 'TARGET_PINS_NOT_SET', message: 'Threshold sync is not enabled on the server.' });
  const min = Number(req.body?.min), max = Number(req.body?.max);
  if (!Number.isFinite(min) || !Number.isFinite(max) || min < 5 || max > 95 || min >= max) {
    return res.status(400).json({ error: 'BAD_REQUEST', message: 'Thresholds must satisfy 5 <= min < max <= 95.' });
  }
  await blynkSet(TARGET_PINS.min, Math.round(min));
  await blynkSet(TARGET_PINS.max, Math.round(max));
  res.json({ ok: true, min: Math.round(min), max: Math.round(max) });
}));

app.use((_req, res) => res.status(404).json({ error: 'NOT_FOUND' }));

/* ───────────────────────── Boot ───────────────────────── */
(async () => {
  await initDb();
  await loadWeatherState();
  app.listen(CFG.port, () => console.log(`Kisan Saha API on :${CFG.port}`));
  await checkWeather();
  await poll();
  setInterval(checkWeather, CFG.weatherMs);
  setInterval(poll, CFG.pollMs);
})().catch((e) => {
  console.error('Fatal startup error:', e);
  process.exit(1);
});
