/* Taraz backend — secured version. Part 1a: config, CORS, token, rate limit */
const express = require('express');
const { Pool } = require('pg');
const cors = require('cors');
const webpush = require('web-push');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');

/* ============ CONFIG ============ */
const IS_PROD = !!process.env.VERCEL || process.env.NODE_ENV === 'production';
const AUTH_MODE = (process.env.AUTH_MODE || 'soft').toLowerCase() === 'strict' ? 'strict' : 'soft';
const TOKEN_TTL_MS = 30 * 24 * 60 * 60 * 1000;

let TOKEN_SECRET = process.env.JWT_SECRET || '';
if (TOKEN_SECRET && TOKEN_SECRET.length < 32) {
  console.error('JWT_SECRET too short (min 32 chars) - token signing disabled');
  TOKEN_SECRET = '';
}
if (!TOKEN_SECRET && !IS_PROD) {
  TOKEN_SECRET = crypto.randomBytes(32).toString('hex');
  console.warn('JWT_SECRET not set - using random dev secret');
}
if (!TOKEN_SECRET && IS_PROD) console.error('JWT_SECRET missing in production - login will return 500');

const ADMIN_PHONES = (process.env.ADMIN_PHONES || '').split(',').map(s => s.trim()).filter(Boolean);

const DEFAULT_ORIGINS = ['https://taraz-app.ir', 'https://www.taraz-app.ir'];
const DEV_ORIGINS = ['http://localhost:3000', 'http://localhost:5500', 'http://127.0.0.1:5500'];
const ALLOWED_ORIGINS = (process.env.ALLOWED_ORIGINS
  ? process.env.ALLOWED_ORIGINS.split(',').map(s => s.trim()).filter(Boolean)
  : DEFAULT_ORIGINS
).concat(IS_PROD ? [] : DEV_ORIGINS);

/* ============ VAPID ============ */
let PUSH_READY = false;
if (process.env.VAPID_PUBLIC_KEY && process.env.VAPID_PRIVATE_KEY && process.env.VAPID_SUBJECT) {
  try {
    webpush.setVapidDetails(process.env.VAPID_SUBJECT, process.env.VAPID_PUBLIC_KEY, process.env.VAPID_PRIVATE_KEY);
    PUSH_READY = true;
  } catch (e) { console.error('VAPID config invalid:', e.message); }
} else {
  console.warn('VAPID keys not set - push endpoints return 503');
}

/* ============ APP ============ */
const app = express();
app.disable('x-powered-by');
app.set('trust proxy', true);

app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'no-referrer');
  next();
});

app.use(cors({
  origin: (origin, cb) => cb(null, !origin || ALLOWED_ORIGINS.includes(origin)),
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  maxAge: 600
}));

app.use(express.json({ limit: '10mb' }));
app.use((err, req, res, next) => {
  if (err && err.type === 'entity.parse.failed') return res.status(400).json({ error: 'درخواست نامعتبر است' });
  if (err && err.type === 'entity.too.large') return res.status(413).json({ error: 'حجم درخواست زیاد است' });
  return next(err);
});

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

/* ============ HELPERS ============ */
const PHONE_RE = /^09\d{9}$/;
const GENERIC_ERROR = 'خطای سرور؛ کمی بعد دوباره امتحان کن';
const FORBIDDEN = { error: 'اجازهٔ این کار را نداری' };
const AUTH_EXPIRED = { error: 'نشست شما تمام شده؛ دوباره وارد شو', code: 'AUTH_REQUIRED' };

function fail(res, where, e) {
  console.error(where + ' error:', e && e.message ? e.message : e);
  if (!res.headersSent) res.status(500).json({ error: GENERIC_ERROR });
}
function str(v) { return typeof v === 'string' ? v.trim() : ''; }
function rawStr(v) { return typeof v === 'string' ? v : ''; }
function isPhone(v) { return typeof v === 'string' && PHONE_RE.test(v); }
function bodyOf(req) { return req.body && typeof req.body === 'object' && !Array.isArray(req.body) ? req.body : {}; }
const SAFE_ID = /^[A-Za-z0-9_-]{1,50}$/;
function newId(prefix) { return prefix + Date.now().toString(36) + crypto.randomBytes(4).toString('hex'); }

function clientIp(req) {
  const real = req.headers['x-real-ip'];
  if (typeof real === 'string' && real.trim()) return real.trim();
  const fwd = req.headers['x-forwarded-for'];
  if (typeof fwd === 'string' && fwd.trim()) return fwd.split(',')[0].trim();
  return (req.socket && req.socket.remoteAddress) || 'unknown';
}

function sanitizeUser(u) {
  if (!u) return null;
  const out = Object.assign({}, u);
  delete out.password_hash;
  delete out.security_answer_hash;
  return out;
}
function publicUser(u) {
  return u ? { phone: u.phone, name: u.name, role: u.role, avatar: u.avatar || null, joined_at: u.joined_at } : null;
}

/* ============ TOKEN (HMAC-SHA256) ============ */
function b64url(buf) {
  return Buffer.from(buf).toString('base64').replace(/=+$/, '').replace(/\+/g, '-').replace(/\//g, '_');
}
function b64urlDecode(s) {
  s = s.replace(/-/g, '+').replace(/_/g, '/');
  while (s.length % 4) s += '=';
  return Buffer.from(s, 'base64');
}
function signToken(user) {
  const now = Date.now();
  const payload = { p: user.phone, r: user.role || null, iat: now, exp: now + TOKEN_TTL_MS };
  const b = b64url(JSON.stringify(payload));
  const sig = b64url(crypto.createHmac('sha256', TOKEN_SECRET).update(b).digest());
  return { token: b + '.' + sig, expiresAt: payload.exp };
}
function verifyToken(token) {
  if (!TOKEN_SECRET || typeof token !== 'string' || token.length > 2000) return null;
  const parts = token.split('.');
  if (parts.length !== 2) return null;
  const expected = crypto.createHmac('sha256', TOKEN_SECRET).update(parts[0]).digest();
  let given;
  try { given = b64urlDecode(parts[1]); } catch (e) { return null; }
  if (given.length !== expected.length || !crypto.timingSafeEqual(given, expected)) return null;
  let p;
  try { p = JSON.parse(b64urlDecode(parts[0]).toString('utf8')); } catch (e) { return null; }
  if (!p || !isPhone(p.p) || typeof p.exp !== 'number' || p.exp < Date.now()) return null;
  return { phone: p.p, role: p.r, exp: p.exp, isAdmin: ADMIN_PHONES.includes(p.p) };
}

app.use((req, res, next) => {
  req.auth = null;
  req.authError = false;
  const h = req.headers.authorization;
  if (typeof h === 'string' && h.trim()) {
    const m = /^Bearer\s+(.+)$/i.exec(h.trim());
    const v = m ? verifyToken(m[1].trim()) : null;
    if (v) req.auth = v; else req.authError = true;
  }
  next();
});

function requireAuth(req, res, next) {
  if (req.authError || !req.auth) return res.status(401).json(AUTH_EXPIRED);
  next();
}
function softAuth(req, res, next) {
  if (req.authError) return res.status(401).json(AUTH_EXPIRED);
  if (!req.auth && AUTH_MODE === 'strict') return res.status(401).json(AUTH_EXPIRED);
  next();
}
function requireAdmin(req, res, next) {
  if (req.authError || !req.auth) return res.status(401).json(AUTH_EXPIRED);
  if (!req.auth.isAdmin) return res.status(403).json(FORBIDDEN);
  next();
}
// بدون توکن (فقط soft) مجاز؛ با توکن فقط خودش یا ادمین
function canActAs(req, phone) {
  if (!req.auth) return AUTH_MODE !== 'strict';
  return req.auth.phone === phone || req.auth.isAdmin;
}

/* ============ RATE LIMIT (جدول login_attempts) ============ */
const MIN = 60 * 1000;

function tooMany(res, sec) {
  const minutes = Math.max(1, Math.ceil(sec / 60));
  res.setHeader('Retry-After', String(Math.max(1, sec)));
  return res.status(429).json({ error: 'تلاش‌های زیادی انجام شد؛ ' + minutes + ' دقیقه دیگر دوباره امتحان کن' });
}
// فقط بررسی. خروجی: ثانیهٔ انتظار یا 0
async function rateCheck(key, max, windowMs) {
  try {
    const r = await pool.query('SELECT count, first_at FROM login_attempts WHERE key = $1', [key]);
    if (!r.rows.length) return 0;
    const now = Date.now(), first = Number(r.rows[0].first_at);
    if (first + windowMs <= now) return 0;
    return Number(r.rows[0].count) >= max ? Math.ceil((first + windowMs - now) / 1000) : 0;
  } catch (e) { console.error('rateCheck error:', e.message); return 0; }
}
// ثبت یک تلاش
async function rateHit(key, windowMs) {
  const now = Date.now();
  try {
    const r = await pool.query(
      `INSERT INTO login_attempts (key, count, first_at) VALUES ($1, 1, $2)
       ON CONFLICT (key) DO UPDATE SET
         count = CASE WHEN login_attempts.first_at <= $3 THEN 1 ELSE login_attempts.count + 1 END,
         first_at = CASE WHEN login_attempts.first_at <= $3 THEN $2 ELSE login_attempts.first_at END
       RETURNING count, first_at`, [key, now, now - windowMs]);
    if (Math.random() < 0.01) pool.query('DELETE FROM login_attempts WHERE first_at < $1', [now - 1440 * MIN]).catch(() => {});
    return { count: Number(r.rows[0].count), first: Number(r.rows[0].first_at) };
  } catch (e) { console.error('rateHit error:', e.message); return { count: 0, first: now }; }
}
// شمردن و بررسی در یک قدم
async function rateLimit(key, max, windowMs) {
  const r = await rateHit(key, windowMs);
  return r.count > max ? Math.ceil((r.first + windowMs - Date.now()) / 1000) : 0;
}
async function rateReset(key) {
  try { await pool.query('DELETE FROM login_attempts WHERE key = $1', [key]); }
  catch (e) { console.error('rateReset error:', e.message); }
}

let DUMMY_HASH = null;
async function dummyHash() {
  if (!DUMMY_HASH) DUMMY_HASH = await bcrypt.hash(crypto.randomBytes(16).toString('hex'), 10);
  return DUMMY_HASH;
}

/* ===== END PART 1a ===== */


async function initDB() {
  const queries = [
    `CREATE TABLE IF NOT EXISTS users (
      phone VARCHAR(20) PRIMARY KEY,
      name VARCHAR(100) NOT NULL,
      role VARCHAR(50),
      avatar TEXT,
      password_hash TEXT,
      security_question TEXT,
      security_answer_hash TEXT,
      joined_at BIGINT
    )`,
    `CREATE TABLE IF NOT EXISTS listings (
      id VARCHAR(50) PRIMARY KEY,
      seller_phone VARCHAR(20),
      seller_name VARCHAR(100),
      category_id VARCHAR(50),
      title VARCHAR(200),
      qty VARCHAR(50),
      qty_num INTEGER,
      price BIGINT,
      old_price BIGINT,
      region VARCHAR(100),
      description TEXT,
      urgent BOOLEAN DEFAULT FALSE,
      urgent_reason VARCHAR(50),
      product_key VARCHAR(100),
      photos JSONB DEFAULT '[]'::jsonb,
      location_lat NUMERIC,
      location_lng NUMERIC,
      created_at BIGINT
    )`,
    `CREATE TABLE IF NOT EXISTS capacities (
      id VARCHAR(50) PRIMARY KEY,
      owner_phone VARCHAR(20),
      owner_name VARCHAR(100),
      service_type VARCHAR(50),
      type_id VARCHAR(50),
      title VARCHAR(200),
      region VARCHAR(100),
      route_from VARCHAR(100),
      route_to VARCHAR(100),
      capacity_total INTEGER,
      capacity_used INTEGER DEFAULT 0,
      price BIGINT,
      unit VARCHAR(50),
      available_from BIGINT,
      available_to BIGINT,
      rating NUMERIC(3,1) DEFAULT 0,
      created_at BIGINT
    )`,
    `CREATE TABLE IF NOT EXISTS bookings (
      id VARCHAR(50) PRIMARY KEY,
      capacity_id VARCHAR(50),
      customer_phone VARCHAR(20),
      customer_name VARCHAR(100),
      qty INTEGER,
      total BIGINT,
      status VARCHAR(20) DEFAULT 'pending',
      created_at BIGINT
    )`,
    `CREATE TABLE IF NOT EXISTS conversations (
      id VARCHAR(50) PRIMARY KEY,
      listing_id VARCHAR(50),
      listing_title VARCHAR(200),
      buyer_phone VARCHAR(20),
      buyer_name VARCHAR(100),
      seller_phone VARCHAR(20),
      seller_name VARCHAR(100),
      created_at BIGINT,
      last_message_at BIGINT
    )`,
    `CREATE TABLE IF NOT EXISTS messages (
      id VARCHAR(50) PRIMARY KEY,
      conv_id VARCHAR(50),
      from_phone VARCHAR(20),
      text TEXT,
      read BOOLEAN DEFAULT FALSE,
      created_at BIGINT
    )`,
    `CREATE TABLE IF NOT EXISTS ratings (
      id VARCHAR(50) PRIMARY KEY,
      from_phone VARCHAR(20),
      from_name VARCHAR(100),
      to_phone VARCHAR(20),
      score INTEGER,
      comment TEXT,
      created_at BIGINT
    )`,
    `ALTER TABLE conversations ADD COLUMN IF NOT EXISTS buyer_deal_at BIGINT`,
    `ALTER TABLE conversations ADD COLUMN IF NOT EXISTS seller_deal_at BIGINT`,
    `ALTER TABLE conversations ADD COLUMN IF NOT EXISTS deal_remind_at BIGINT`,
    `ALTER TABLE ratings ADD COLUMN IF NOT EXISTS verified BOOLEAN DEFAULT FALSE`,
    `CREATE TABLE IF NOT EXISTS notifications (
      id VARCHAR(50) PRIMARY KEY,
      user_phone VARCHAR(20),
      type VARCHAR(50),
      icon VARCHAR(10),
      title VARCHAR(200),
      body TEXT,
      read BOOLEAN DEFAULT FALSE,
      created_at BIGINT
    )`,
    `CREATE TABLE IF NOT EXISTS missions (
      id VARCHAR(50) PRIMARY KEY,
      owner_phone VARCHAR(20),
      raw_text TEXT,
      steps JSONB,
      total BIGINT,
      status VARCHAR(20),
      created_at BIGINT
    )`,
    `CREATE TABLE IF NOT EXISTS favorites (
      id VARCHAR(50) PRIMARY KEY,
      user_phone VARCHAR(20),
      listing_id VARCHAR(50),
      created_at BIGINT
    )`,
    `CREATE TABLE IF NOT EXISTS push_subscriptions (
      id VARCHAR(50) PRIMARY KEY,
      user_phone VARCHAR(20),
      subscription JSONB,
      created_at BIGINT
    )`,
    `CREATE TABLE IF NOT EXISTS ready_profiles (
      phone VARCHAR(20) PRIMARY KEY,
      name VARCHAR(100),
      is_ready BOOLEAN DEFAULT FALSE,
      service_type VARCHAR(50),
      region VARCHAR(100),
      notes TEXT,
      updated_at BIGINT
    )`,
    `CREATE TABLE IF NOT EXISTS user_watches (
      id VARCHAR(50) PRIMARY KEY,
      user_phone VARCHAR(20),
      service_type VARCHAR(50),
      route_from VARCHAR(100),
      route_to VARCHAR(100),
      notes TEXT,
      created_at BIGINT
    )`,
    `CREATE TABLE IF NOT EXISTS escrows (
      id VARCHAR(50) PRIMARY KEY,
      mission_id VARCHAR(50),
      buyer_phone VARCHAR(20),
      seller_phone VARCHAR(20),
      amount BIGINT,
      status VARCHAR(20) DEFAULT 'pending',
      created_at BIGINT
    )`,
    `CREATE TABLE IF NOT EXISTS login_attempts (
      key VARCHAR(200) PRIMARY KEY,
      count INTEGER NOT NULL DEFAULT 0,
      first_at BIGINT NOT NULL
    )`
  ];
  for (const q of queries) {
    try { await pool.query(q); } catch (e) { console.error('DB init error:', e.message); }
  }
  const migrations = [
    'ALTER TABLE listings ADD COLUMN IF NOT EXISTS location_lat NUMERIC',
    'ALTER TABLE listings ADD COLUMN IF NOT EXISTS location_lng NUMERIC',
    'ALTER TABLE users ADD COLUMN IF NOT EXISTS password_hash TEXT',
    'ALTER TABLE users ADD COLUMN IF NOT EXISTS security_question TEXT',
    'ALTER TABLE users ADD COLUMN IF NOT EXISTS security_answer_hash TEXT',
    // هر کاربر فقط یک امتیاز به هر نفر دارد (امتیاز تکراری پاک می‌شود)
    'DELETE FROM ratings a USING ratings b WHERE a.from_phone = b.from_phone AND a.to_phone = b.to_phone AND (a.created_at < b.created_at OR (a.created_at = b.created_at AND a.ctid < b.ctid))',
    'CREATE UNIQUE INDEX IF NOT EXISTS ratings_from_to_uq ON ratings (from_phone, to_phone)'
  ];
  for (const q of migrations) {
    try { await pool.query(q); } catch (e) { console.warn('Migration skip:', e.message); }
  }
  console.log('DB ready');
}

// یک‌بار init، lazy، برای Vercel
let _dbReady = null;
function ensureDB() {
  if (!_dbReady) _dbReady = initDB().catch(e => { _dbReady = null; throw e; });
  return _dbReady;
}
app.use('/api', async (req, res, next) => {
  try { await ensureDB(); next(); } catch (e) { fail(res, 'ensureDB', e); }
});

/* ============ AUTH ============ */
const PW_MIN = 6, PW_MAX = 128;
function pwOk(p) { return typeof p === 'string' && p.length >= PW_MIN && p.length <= PW_MAX; }

function sendAuth(res, user, extra) {
  if (!TOKEN_SECRET) return res.status(500).json({ error: GENERIC_ERROR });
  const t = signToken(user);
  return res.json(Object.assign(
    { ok: true, user: publicUser(user), token: t.token, expiresAt: t.expiresAt },
    extra || {}
  ));
}

app.post('/api/auth/register', async (req, res) => {
  try {
    const b = bodyOf(req);
    const phone = str(b.phone), name = str(b.name);
    const role = str(b.role) || 'کاربر', password = rawStr(b.password);
    if (!isPhone(phone)) return res.status(400).json({ error: 'شماره معتبر وارد کن' });
    if (name.length < 3 || name.length > 100) return res.status(400).json({ error: 'نام معتبر وارد کن' });
    if (!pwOk(password)) return res.status(400).json({ error: 'پسورد باید بین ۶ تا ۱۲۸ کاراکتر باشد' });
    if (role.length > 50) return res.status(400).json({ error: 'نقش نامعتبر است' });
    if (!TOKEN_SECRET) return res.status(500).json({ error: GENERIC_ERROR });

    const wait = await rateLimit('reg:ip:' + clientIp(req), 10, 60 * MIN);
    if (wait) return tooMany(res, wait);

    const ex = await pool.query('SELECT phone, password_hash FROM users WHERE phone = $1', [phone]);
    const hash = await bcrypt.hash(password, 10);

    if (ex.rows.length) {
      if (ex.rows[0].password_hash) {
        return res.status(409).json({ error: 'این شماره قبلاً ثبت‌نام کرده؛ وارد شو' });
      }
      // حساب قدیمی بدون پسورد: فقط اگر داده‌ای ندارد قابل تصاحب است
      const used = await pool.query(
        `SELECT (
           (SELECT COUNT(*) FROM listings WHERE seller_phone=$1) +
           (SELECT COUNT(*) FROM missions WHERE owner_phone=$1) +
           (SELECT COUNT(*) FROM conversations WHERE buyer_phone=$1 OR seller_phone=$1) +
           (SELECT COUNT(*) FROM capacities WHERE owner_phone=$1)
         ) AS n`, [phone]);
      if (Number(used.rows[0].n) > 0) {
        return res.status(409).json({ error: 'این شماره قبلاً استفاده شده؛ با پشتیبانی تماس بگیر' });
      }
      await pool.query(
        'UPDATE users SET password_hash=$1, name=$2 WHERE phone=$3 AND password_hash IS NULL',
        [hash, name, phone]);
    } else {
      await pool.query(
        'INSERT INTO users (phone, name, role, password_hash, joined_at) VALUES ($1,$2,$3,$4,$5)',
        [phone, name, role, hash, Date.now()]);
    }
    const r = await pool.query('SELECT * FROM users WHERE phone = $1', [phone]);
    return sendAuth(res, r.rows[0], { message: 'ثبت‌نام موفق' });
  } catch (e) { fail(res, 'register', e); }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const b = bodyOf(req);
    const phone = str(b.phone), password = rawStr(b.password);
    if (!phone || !password) return res.status(400).json({ error: 'شماره و پسورد لازمه' });
    if (password.length > PW_MAX) return res.status(400).json({ error: 'شماره یا پسورد اشتباه است' });
    if (!isPhone(phone)) return res.status(401).json({ error: 'شماره یا پسورد اشتباه است' });
    if (!TOKEN_SECRET) return res.status(500).json({ error: GENERIC_ERROR });

    const pk = 'login:phone:' + phone, ik = 'login:ip:' + clientIp(req);
    const w1 = await rateCheck(pk, 5, 15 * MIN); if (w1) return tooMany(res, w1);
    const w2 = await rateCheck(ik, 20, 15 * MIN); if (w2) return tooMany(res, w2);

    const r = await pool.query('SELECT * FROM users WHERE phone = $1', [phone]);
    const user = r.rows[0] || null;

    if (user && !user.password_hash) {
      return res.status(400).json({ error: 'برای این شماره پسورد تنظیم نشده؛ ثبت‌نام کن' });
    }
    const valid = await bcrypt.compare(password, user ? user.password_hash : await dummyHash());
    if (!user || !valid) {
      await rateHit(pk, 15 * MIN);
      await rateHit(ik, 15 * MIN);
      return res.status(401).json({ error: 'شماره یا پسورد اشتباه است' });
    }
    await rateReset(pk);
    return sendAuth(res, user);
  } catch (e) { fail(res, 'login', e); }
});

app.post('/api/auth/change-password', softAuth, async (req, res) => {
  try {
    const b = bodyOf(req);
    const phone = str(b.phone), oldPw = rawStr(b.oldPassword), newPw = rawStr(b.newPassword);
    if (!isPhone(phone) || !oldPw || !newPw) return res.status(400).json({ error: 'همه فیلدها لازمه' });
    if (!pwOk(newPw)) return res.status(400).json({ error: 'پسورد جدید باید بین ۶ تا ۱۲۸ کاراکتر باشد' });
    if (!canActAs(req, phone)) return res.status(403).json(FORBIDDEN);

    const key = 'chpw:' + phone;
    const w = await rateLimit(key, 10, 15 * MIN); if (w) return tooMany(res, w);

    const r = await pool.query('SELECT password_hash FROM users WHERE phone = $1', [phone]);
    const h = r.rows[0] ? r.rows[0].password_hash : null;
    const valid = await bcrypt.compare(oldPw, h || await dummyHash());
    if (!h || !valid) return res.status(401).json({ error: 'پسورد فعلی اشتباه است' });

    const nh = await bcrypt.hash(newPw, 10);
    await pool.query('UPDATE users SET password_hash=$1 WHERE phone=$2', [nh, phone]);
    await rateReset(key);
    res.json({ ok: true, message: 'پسورد تغییر کرد' });
  } catch (e) { fail(res, 'change-password', e); }
});

app.post('/api/auth/set-security', requireAuth, async (req, res) => {
  try {
    const b = bodyOf(req);
    const phone = str(b.phone) || req.auth.phone;
    const question = str(b.question), answer = rawStr(b.answer);
    if (!question || !answer) return res.status(400).json({ error: 'همه فیلدها لازمه' });
    if (question.length > 200 || answer.trim().length < 2 || answer.length > 200) {
      return res.status(400).json({ error: 'سوال یا جواب نامعتبر است' });
    }
    if (!canActAs(req, phone)) return res.status(403).json(FORBIDDEN);
    const ah = await bcrypt.hash(answer.toLowerCase().trim(), 10);
    await pool.query(
      'UPDATE users SET security_question=$1, security_answer_hash=$2 WHERE phone=$3',
      [question, ah, phone]);
    res.json({ ok: true, message: 'سوال امنیتی ذخیره شد' });
  } catch (e) { fail(res, 'set-security', e); }
});

app.get('/api/auth/security-question/:phone', async (req, res) => {
  try {
    const w = await rateLimit('secq:ip:' + clientIp(req), 30, 10 * MIN);
    if (w) return tooMany(res, w);
    const phone = str(req.params.phone);
    if (!isPhone(phone)) return res.status(404).json({ error: 'سوال امنیتی برای این شماره تنظیم نشده' });
    const r = await pool.query('SELECT security_question FROM users WHERE phone=$1', [phone]);
    if (!r.rows.length || !r.rows[0].security_question) {
      return res.status(404).json({ error: 'سوال امنیتی برای این شماره تنظیم نشده' });
    }
    res.json({ question: r.rows[0].security_question });
  } catch (e) { fail(res, 'security-question', e); }
});

app.post('/api/auth/recover', async (req, res) => {
  try {
    const b = bodyOf(req);
    const phone = str(b.phone), answer = rawStr(b.answer), newPw = rawStr(b.newPassword);
    if (!isPhone(phone) || !answer || !newPw) return res.status(400).json({ error: 'همه فیلدها لازمه' });
    if (!pwOk(newPw) || answer.length > 200) {
      return res.status(400).json({ error: 'پسورد جدید باید بین ۶ تا ۱۲۸ کاراکتر باشد' });
    }
    const pk = 'rec:phone:' + phone, ik = 'rec:ip:' + clientIp(req);
    const w1 = await rateCheck(pk, 5, 60 * MIN); if (w1) return tooMany(res, w1);
    const w2 = await rateCheck(ik, 20, 60 * MIN); if (w2) return tooMany(res, w2);

    const r = await pool.query('SELECT security_answer_hash FROM users WHERE phone=$1', [phone]);
    const h = r.rows[0] ? r.rows[0].security_answer_hash : null;
    const valid = await bcrypt.compare(answer.toLowerCase().trim(), h || await dummyHash());
    if (!h || !valid) {
      await rateHit(pk, 60 * MIN);
      await rateHit(ik, 60 * MIN);
      return res.status(401).json({ error: 'پاسخ اشتباه است یا بازیابی ممکن نیست' });
    }
    const nh = await bcrypt.hash(newPw, 10);
    await pool.query('UPDATE users SET password_hash=$1 WHERE phone=$2', [nh, phone]);
    await rateReset(pk);
    await rateReset('login:phone:' + phone);
    res.json({ ok: true, message: 'پسورد بازیابی شد' });
  } catch (e) { fail(res, 'recover', e); }
});

// مسیر قدیمی بسته شد
app.post('/api/users/login', (req, res) => {
  res.status(410).json({ error: 'این روش ورود حذف شده؛ با شماره و پسورد وارد شو یا ثبت‌نام کن' });
});

/* ===== END PART 1b ===== */

/* ============ USER API ============ */
app.get('/api/users/:phone', async (req, res) => {
  try {
    const r = await pool.query('SELECT * FROM users WHERE phone = $1', [req.params.phone]);
    if (!r.rows.length) return res.status(404).json({ error: 'not found' });
    res.json({ user: publicUser(r.rows[0]) });
  } catch (e) { fail(res, 'get user', e); }
});

const MAX_AVATAR = 1500000; // کاراکتر
app.post('/api/users/:phone/avatar', softAuth, async (req, res) => {
  try {
    const phone = req.params.phone;
    if (!canActAs(req, phone)) return res.status(403).json(FORBIDDEN);
    const avatar = rawStr(bodyOf(req).avatar);
    if (!/^data:image\/(png|jpe?g|webp|gif);base64,[A-Za-z0-9+/=]+$/.test(avatar) || avatar.length > MAX_AVATAR) {
      return res.status(400).json({ error: 'تصویر نامعتبر یا بزرگ است' });
    }
    await pool.query('UPDATE users SET avatar = $1 WHERE phone = $2', [avatar, phone]);
    res.json({ ok: true });
  } catch (e) { fail(res, 'avatar', e); }
});

/* ============ LISTINGS API ============ */
app.get('/api/listings', async (req, res) => {
  try {
    res.setHeader('Cache-Control', 'no-store');
    const r = await pool.query('SELECT * FROM listings ORDER BY created_at DESC LIMIT 200');
    res.json({ listings: r.rows });
  } catch (e) { fail(res, 'get listings', e); }
});

function numOrNull(v) { const n = Number(v); return Number.isFinite(n) ? n : null; }

app.post('/api/listings', softAuth, async (req, res) => {
  try {
    const l = bodyOf(req);
    const sellerPhone = req.auth ? req.auth.phone : str(l.sellerPhone);
    if (!isPhone(sellerPhone)) return res.status(400).json({ error: 'شمارهٔ فروشنده نامعتبر است' });
    if (!canActAs(req, sellerPhone)) return res.status(403).json(FORBIDDEN);
    const title = str(l.title);
    if (!title || title.length > 200) return res.status(400).json({ error: 'عنوان آگهی نامعتبر است' });
    const price = numOrNull(l.price);
    if (price === null || price < 0) return res.status(400).json({ error: 'قیمت نامعتبر است' });
    const photos = Array.isArray(l.photos) ? l.photos.slice(0, 8) : [];
    const id = (typeof l.id === 'string' && SAFE_ID.test(l.id)) ? l.id : newId('L');
    const loc = l.location && typeof l.location === 'object' ? l.location : {};
    await pool.query(
      `INSERT INTO listings (id, seller_phone, seller_name, category_id, title, qty, qty_num, price, old_price, region, description, urgent, urgent_reason, product_key, photos, location_lat, location_lng, created_at)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18)`,
      [id, sellerPhone, str(l.sellerName).slice(0, 100), str(l.categoryId).slice(0, 50), title,
       str(String(l.qty == null ? '' : l.qty)).slice(0, 50), numOrNull(l.qtyNum), price, numOrNull(l.oldPrice),
       str(l.region).slice(0, 100), str(l.desc).slice(0, 3000) || null, l.urgent === true,
       str(l.urgentReason).slice(0, 50) || null, str(l.productKey).slice(0, 100) || null,
       JSON.stringify(photos), numOrNull(loc.lat), numOrNull(loc.lng), Date.now()]
    );
    res.json({ ok: true, id });
  } catch (e) { fail(res, 'post listing', e); }
});

app.delete('/api/listings/:id', requireAuth, async (req, res) => {
  try {
    const r = await pool.query('SELECT seller_phone FROM listings WHERE id = $1', [req.params.id]);
    if (!r.rows.length) return res.json({ ok: true });
    if (r.rows[0].seller_phone !== req.auth.phone && !req.auth.isAdmin) return res.status(403).json(FORBIDDEN);
    await pool.query('DELETE FROM listings WHERE id = $1', [req.params.id]);
    res.json({ ok: true });
  } catch (e) { fail(res, 'delete listing', e); }
});

/* ============ ADMIN STATS ============ */
app.get('/api/admin/stats', requireAdmin, async (req, res) => {
  try {
    const u = await pool.query('SELECT COUNT(*) FROM users');
    const l = await pool.query('SELECT COUNT(*) FROM listings');
    const c = await pool.query('SELECT COUNT(*) FROM conversations');
    res.json({
      users: parseInt(u.rows[0].count, 10),
      listings: parseInt(l.rows[0].count, 10),
      conversations: parseInt(c.rows[0].count, 10)
    });
  } catch (e) { fail(res, 'admin stats', e); }
});

/* ============ CAPACITIES API ============ */
app.get('/api/capacities', async (req, res) => {
  try {
    const r = await pool.query('SELECT * FROM capacities ORDER BY created_at DESC LIMIT 200');
    res.json({ capacities: r.rows });
  } catch (e) { fail(res, 'get capacities', e); }
});

app.post('/api/capacities', softAuth, async (req, res) => {
  try {
    const c = bodyOf(req);
    const owner = req.auth ? req.auth.phone : str(c.ownerPhone);
    if (!isPhone(owner)) return res.status(400).json({ error: 'شمارهٔ مالک نامعتبر است' });
    if (!canActAs(req, owner)) return res.status(403).json(FORBIDDEN);
    const total = numOrNull(c.capacityTotal), price = numOrNull(c.price);
    if (total === null || total <= 0 || price === null || price < 0) {
      return res.status(400).json({ error: 'ظرفیت یا قیمت نامعتبر است' });
    }
    const id = (typeof c.id === 'string' && SAFE_ID.test(c.id)) ? c.id : newId('C');
    await pool.query(
      `INSERT INTO capacities (id, owner_phone, owner_name, service_type, type_id, title, region, route_from, route_to, capacity_total, capacity_used, price, unit, available_from, available_to, rating, created_at)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17)`,
      [id, owner, str(c.ownerName).slice(0, 100), str(c.serviceType).slice(0, 50), str(c.typeId).slice(0, 50),
       str(c.title).slice(0, 200), str(c.region).slice(0, 100), str(c.routeFrom).slice(0, 100) || null,
       str(c.routeTo).slice(0, 100) || null, Math.floor(total), 0, price, str(c.unit).slice(0, 50),
       numOrNull(c.availableFrom), numOrNull(c.availableTo), 0, Date.now()]
    );
    res.json({ ok: true, id });
  } catch (e) { fail(res, 'post capacity', e); }
});

/* ============ CONVERSATIONS API ============ */
function isMember(conv, phone) { return conv.buyer_phone === phone || conv.seller_phone === phone; }
// بدون توکن (soft) فقط وقتی مجاز است که حالت strict نباشد
function canSeeConv(req, conv) {
  if (!req.auth) return AUTH_MODE !== 'strict';
  return req.auth.isAdmin || isMember(conv, req.auth.phone);
}

app.get('/api/conversations/:phone', softAuth, async (req, res) => {
  try {
    if (!canActAs(req, req.params.phone)) return res.status(403).json(FORBIDDEN);
    const r = await pool.query(
      'SELECT * FROM conversations WHERE buyer_phone = $1 OR seller_phone = $1 ORDER BY last_message_at DESC',
      [req.params.phone]);
    res.json({ conversations: r.rows });
  } catch (e) { fail(res, 'get conversations', e); }
});

app.post('/api/conversations', softAuth, async (req, res) => {
  try {
    const c = bodyOf(req);
    const buyer = str(c.buyerPhone), seller = str(c.sellerPhone), listingId = str(c.listingId);
    if (!isPhone(buyer) || !isPhone(seller) || buyer === seller || !listingId) {
      return res.status(400).json({ error: 'اطلاعات گفتگو نامعتبر است' });
    }
    if (!canActAs(req, buyer)) return res.status(403).json(FORBIDDEN);
    const ex = await pool.query(
      `SELECT * FROM conversations WHERE listing_id = $1
       AND ((buyer_phone = $2 AND seller_phone = $3) OR (buyer_phone = $3 AND seller_phone = $2))`,
      [listingId, buyer, seller]);
    if (ex.rows.length) return res.json({ conversation: ex.rows[0] });
    const id = (typeof c.id === 'string' && SAFE_ID.test(c.id)) ? c.id : newId('V');
    const now = Date.now();
    await pool.query(
      `INSERT INTO conversations (id, listing_id, listing_title, buyer_phone, buyer_name, seller_phone, seller_name, created_at, last_message_at)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
      [id, listingId.slice(0, 50), str(c.listingTitle).slice(0, 200), buyer, str(c.buyerName).slice(0, 100),
       seller, str(c.sellerName).slice(0, 100), now, now]);
    const r = await pool.query('SELECT * FROM conversations WHERE id = $1', [id]);
    res.json({ conversation: r.rows[0] });
  } catch (e) { fail(res, 'post conversation', e); }
});

/* ============ MESSAGES API ============ */
app.get('/api/messages/:convId', softAuth, async (req, res) => {
  try {
    const cr = await pool.query('SELECT * FROM conversations WHERE id = $1', [req.params.convId]);
    if (!cr.rows.length) return res.json({ messages: [] });
    if (!canSeeConv(req, cr.rows[0])) return res.status(403).json(FORBIDDEN);
    const r = await pool.query('SELECT * FROM messages WHERE conv_id = $1 ORDER BY created_at ASC LIMIT 1000',
      [req.params.convId]);
    res.json({ messages: r.rows });
  } catch (e) { fail(res, 'get messages', e); }
});

app.post('/api/messages', softAuth, async (req, res) => {
  try {
    const m = bodyOf(req);
    const text = rawStr(m.text);
    if (!text.trim() || text.length > 5000) return res.status(400).json({ error: 'متن پیام نامعتبر است' });
    const cr = await pool.query('SELECT * FROM conversations WHERE id = $1', [str(m.convId)]);
    if (!cr.rows.length) return res.status(404).json({ error: 'گفتگو پیدا نشد' });
    const from = req.auth ? req.auth.phone : str(m.fromPhone);
    if (!isMember(cr.rows[0], from)) return res.status(403).json(FORBIDDEN);
    if (!canActAs(req, from)) return res.status(403).json(FORBIDDEN);
    const id = (typeof m.id === 'string' && SAFE_ID.test(m.id)) ? m.id : newId('M');
    const now = Date.now();
    await pool.query(
      'INSERT INTO messages (id, conv_id, from_phone, text, read, created_at) VALUES ($1,$2,$3,$4,$5,$6)',
      [id, cr.rows[0].id, from, text, false, now]);
    await pool.query('UPDATE conversations SET last_message_at = $1 WHERE id = $2', [now, cr.rows[0].id]);
    try {
      const c = cr.rows[0];
      const toPhone = c.buyer_phone === from ? c.seller_phone : c.buyer_phone;
      const fromName = (c.buyer_phone === from ? c.buyer_name : c.seller_name) || 'کاربر';
      if (toPhone && toPhone !== from) {
        const nid = ('NM-' + c.id + '-' + toPhone).slice(0, 50);
        const preview = text.trim().slice(0, 80);
        await pool.query(
          `INSERT INTO notifications (id, user_phone, type, icon, title, body, read, created_at)
           VALUES ($1,$2,'message','💬',$3,$4,false,$5)
           ON CONFLICT (id) DO UPDATE SET title=EXCLUDED.title, body=EXCLUDED.body, read=false, created_at=EXCLUDED.created_at`,
          [nid, toPhone, 'پیام جدید از ' + fromName, preview, now]);
      }
    } catch (ne) { console.error('message notif failed', ne.message); }
    res.json({ ok: true, id });
  } catch (e) { fail(res, 'post message', e); }
});

/* ===== END PART 2a ===== */

/* ============ BOOKINGS API ============ */
app.get('/api/bookings/:phone', softAuth, async (req, res) => {
  try {
    if (!canActAs(req, req.params.phone)) return res.status(403).json(FORBIDDEN);
    const r = await pool.query('SELECT * FROM bookings WHERE customer_phone = $1 ORDER BY created_at DESC', [req.params.phone]);
    res.json({ bookings: r.rows });
  } catch (e) { fail(res, 'get bookings', e); }
});

app.post('/api/bookings', softAuth, async (req, res) => {
  const client = await pool.connect();
  try {
    const b = bodyOf(req);
    const customer = req.auth ? req.auth.phone : str(b.customerPhone);
    if (!isPhone(customer)) return res.status(400).json({ error: 'شماره نامعتبر است' });
    if (!canActAs(req, customer)) return res.status(403).json(FORBIDDEN);
    const qty = Number(b.qty), total = Number(b.total), capId = str(b.capacityId);
    if (!Number.isInteger(qty) || qty < 1 || qty > 100000 || !capId) return res.status(400).json({ error: 'تعداد یا ظرفیت نامعتبر است' });
    if (!Number.isFinite(total) || total < 0) return res.status(400).json({ error: 'مبلغ نامعتبر است' });
    const id = (typeof b.id === 'string' && SAFE_ID.test(b.id)) ? b.id : newId('B');
    await client.query('BEGIN');
    const up = await client.query(
      'UPDATE capacities SET capacity_used = COALESCE(capacity_used,0) + $1 WHERE id = $2 AND COALESCE(capacity_used,0) + $1 <= capacity_total RETURNING id',
      [qty, capId]);
    if (!up.rows.length) { await client.query('ROLLBACK'); return res.status(409).json({ error: 'ظرفیت کافی نیست' }); }
    await client.query(
      'INSERT INTO bookings (id, capacity_id, customer_phone, customer_name, qty, total, status, created_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)',
      [id, capId, customer, str(b.customerName).slice(0, 100), qty, Math.round(total), 'pending', Date.now()]);
    await client.query('COMMIT');
    res.json({ ok: true, id });
  } catch (e) {
    try { await client.query('ROLLBACK'); } catch (_) {}
    fail(res, 'post booking', e);
  } finally { client.release(); }
});

/* ============ RATINGS API ============ */
app.get('/api/ratings/:phone', async (req, res) => {
  try {
    const r = await pool.query('SELECT id, from_name, to_phone, score, comment, created_at FROM ratings WHERE to_phone = $1 ORDER BY created_at DESC LIMIT 500', [req.params.phone]);
    const rows = r.rows.map(x => ({ id: x.id, fromName: x.from_name, toPhone: x.to_phone, score: x.score, comment: x.comment, createdAt: Number(x.created_at) }));
    const avg = rows.length ? rows.reduce((a, x) => a + x.score, 0) / rows.length : 0;
    res.json({ ratings: rows, avg, count: rows.length });
  } catch (e) { fail(res, 'get ratings', e); }
});

app.post('/api/ratings', softAuth, async (req, res) => {
  try {
    const r = bodyOf(req);
    const from = req.auth ? req.auth.phone : str(r.fromPhone);
    const to = str(r.toPhone), score = Number(r.score);
    if (!isPhone(from) || !isPhone(to) || from === to) return res.status(400).json({ error: 'امتیاز نامعتبر است' });
    if (!canActAs(req, from)) return res.status(403).json(FORBIDDEN);
    if (!Number.isInteger(score) || score < 1 || score > 5) return res.status(400).json({ error: 'امتیاز باید بین ۱ تا ۵ باشد' });
    const w = await rateLimit('rate:' + from, 30, 60 * MIN);
    if (w) return tooMany(res, w);
    const id = (typeof r.id === 'string' && SAFE_ID.test(r.id)) ? r.id : newId('R');
    // «تأییدشده» یعنی هر دو طرف در یک گفتگو «معامله انجام شد» را زده‌اند
    const vc = await pool.query(
      `SELECT 1 FROM conversations WHERE buyer_deal_at IS NOT NULL AND seller_deal_at IS NOT NULL
       AND ((buyer_phone=$1 AND seller_phone=$2) OR (buyer_phone=$2 AND seller_phone=$1)) LIMIT 1`, [from, to]);
    const verified = vc.rows.length > 0;
    // اگر قبلاً به این نفر امتیاز داده، امتیاز قبلی به‌روز می‌شود (تکراری ساخته نمی‌شود)
    await pool.query(
      `INSERT INTO ratings (id, from_phone, from_name, to_phone, score, comment, created_at, verified) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
       ON CONFLICT (from_phone, to_phone) DO UPDATE SET score = EXCLUDED.score, comment = EXCLUDED.comment, from_name = EXCLUDED.from_name, created_at = EXCLUDED.created_at, verified = EXCLUDED.verified`,
      [id, from, str(r.fromName).slice(0, 100), to, score, str(r.comment).slice(0, 1000) || null, Date.now(), verified]);
    res.json({ ok: true, id, verified });
  } catch (e) { fail(res, 'post rating', e); }
});

/* ============ DEAL CONFIRMATION ============ */
// هر طرف گفتگو «معامله انجام شد» را می‌زند؛ وقتی هر دو زدند، امتیاز آن‌ها «تأییدشده» حساب می‌شود
app.post('/api/conversations/:id/deal', softAuth, async (req, res) => {
  try {
    if (!req.auth) return res.status(401).json({ error: 'ابتدا وارد شوید' });
    const me = req.auth.phone;
    const c = await pool.query('SELECT * FROM conversations WHERE id = $1', [req.params.id]);
    if (!c.rows.length) return res.status(404).json({ error: 'گفتگو پیدا نشد' });
    const conv = c.rows[0];
    if (!isMember(conv, me)) return res.status(403).json(FORBIDDEN);
    const col = conv.buyer_phone === me ? 'buyer_deal_at' : 'seller_deal_at';
    const r = await pool.query(`UPDATE conversations SET ${col} = COALESCE(${col}, $2) WHERE id = $1 RETURNING buyer_deal_at, seller_deal_at`, [conv.id, Date.now()]);
    const both = !!(r.rows[0].buyer_deal_at && r.rows[0].seller_deal_at);
    const other = conv.buyer_phone === me ? conv.seller_phone : conv.buyer_phone;
    try {
      await pool.query(`INSERT INTO notifications (id, user_phone, type, title, body, created_at) VALUES ($1,$2,'deal',$3,$4,$5)`,
        [newId('N'), other, both ? 'معامله تأیید شد' : 'تأیید معامله', both ? 'هر دو طرف تأیید کردید؛ می‌توانید امتیاز بدهید.' : 'طرف مقابل می‌گوید معامله انجام شد. شما هم تأیید کنید.', Date.now()]);
    } catch (e) {}
    res.json({ ok: true, both });
  } catch (e) { fail(res, 'deal', e); }
});

// گفتگوهایی که ≥۴۸ ساعت از اولین پیام گذشته و هنوز تأیید/یادآوری نشده‌اند → یادآوری به هر دو طرف
// (Vercel بدون پردازش پس‌زمینه است؛ این مسیر باید با cron بیرونی یا Vercel Cron صدا زده شود)
app.post('/api/cron/deal-reminders', async (req, res) => {
  if (!process.env.CRON_SECRET || req.get('x-cron-secret') !== process.env.CRON_SECRET) return res.status(403).json(FORBIDDEN);
  try {
    const cutoff = Date.now() - 48 * 3600 * 1000;
    const r = await pool.query(
      `SELECT id, listing_title, buyer_phone, seller_phone FROM conversations
       WHERE deal_remind_at IS NULL AND (buyer_deal_at IS NULL OR seller_deal_at IS NULL)
       AND EXISTS (SELECT 1 FROM messages m WHERE m.conv_id = conversations.id AND m.created_at < $1)
       LIMIT 200`, [cutoff]);
    for (const c of r.rows) {
      for (const p of [c.buyer_phone, c.seller_phone]) {
        await pool.query(`INSERT INTO notifications (id, user_phone, type, title, body, created_at) VALUES ($1,$2,'deal-remind',$3,$4,$5)`,
          [newId('N'), p, 'معامله انجام شد؟', 'درباره «' + String(c.listing_title || '').slice(0, 60) + '» چه شد؟ اگر معامله انجام شده، در گفتگو تأیید کنید.', Date.now()]);
      }
      await pool.query('UPDATE conversations SET deal_remind_at = $2 WHERE id = $1', [c.id, Date.now()]);
    }
    res.json({ ok: true, reminded: r.rows.length });
  } catch (e) { fail(res, 'deal-reminders', e); }
});

/* ============ NOTIFICATIONS API ============ */
app.get('/api/notifications/:phone', softAuth, async (req, res) => {
  try {
    if (!canActAs(req, req.params.phone)) return res.status(403).json(FORBIDDEN);
    const r = await pool.query('SELECT * FROM notifications WHERE user_phone = $1 ORDER BY created_at DESC LIMIT 50', [req.params.phone]);
    res.json({ notifications: r.rows });
  } catch (e) { fail(res, 'get notifications', e); }
});

app.post('/api/notifications', softAuth, async (req, res) => {
  try {
    const n = bodyOf(req);
    const to = str(n.userPhone);
    if (!isPhone(to)) return res.status(400).json({ error: 'شماره نامعتبر است' });
    const key = 'notif:' + (req.auth ? req.auth.phone : clientIp(req));
    const w = await rateLimit(key, 60, 10 * MIN); if (w) return tooMany(res, w);
    const title = str(n.title).slice(0, 200), body = rawStr(n.body).slice(0, 1000);
    if (!title) return res.status(400).json({ error: 'عنوان اعلان خالی است' });
    const id = (typeof n.id === 'string' && SAFE_ID.test(n.id)) ? n.id : newId('N');
    await pool.query(
      'INSERT INTO notifications (id, user_phone, type, icon, title, body, read, created_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)',
      [id, to, str(n.type).slice(0, 50), str(n.icon).slice(0, 10) || '🔔', title, body, false, Date.now()]);
    res.json({ ok: true, id });
  } catch (e) { fail(res, 'post notification', e); }
});

/* Mark the message notification of one conversation as read (for this user) */
app.post('/api/notifications/read-conv', softAuth, async (req, res) => {
  try {
    const b = bodyOf(req);
    const phone = str(b.phone), convId = str(b.convId);
    if (!isPhone(phone) || !SAFE_ID.test(convId)) return res.status(400).json({ error: 'ورودی نامعتبر است' });
    const prefix = 'NM-' + convId + '-';
    await pool.query(
      "UPDATE notifications SET read = true WHERE user_phone = $1 AND type = 'message' AND left(id, $2) = $3",
      [phone, prefix.length, prefix]);
    const rprefix = 'NR-' + convId + '-';
    await pool.query(
      "UPDATE notifications SET read = true WHERE user_phone = $1 AND type = 'request' AND left(id, $2) = $3",
      [phone, rprefix.length, rprefix]);
    res.json({ ok: true });
  } catch (e) { fail(res, 'read conv notifications', e); }
});

/* ============ MISSIONS API ============ */
app.get('/api/missions/:phone', softAuth, async (req, res) => {
  try {
    if (!canActAs(req, req.params.phone)) return res.status(403).json(FORBIDDEN);
    const r = await pool.query('SELECT * FROM missions WHERE owner_phone = $1 ORDER BY created_at DESC LIMIT 50', [req.params.phone]);
    res.json({ missions: r.rows });
  } catch (e) { fail(res, 'get missions', e); }
});

function missionStatus(v, dflt) {
  const s = str(v);
  return s && s.length <= 20 ? s : dflt;
}

app.post('/api/missions', softAuth, async (req, res) => {
  try {
    const m = bodyOf(req);
    const owner = req.auth ? req.auth.phone : str(m.ownerPhone);
    if (!isPhone(owner)) return res.status(400).json({ error: 'شماره نامعتبر است' });
    if (!canActAs(req, owner)) return res.status(403).json(FORBIDDEN);
    const total = Number(m.total);
    if (!Number.isFinite(total) || total < 0) return res.status(400).json({ error: 'مبلغ نامعتبر است' });
    const steps = Array.isArray(m.steps) ? m.steps.slice(0, 50) : [];
    const id = (typeof m.id === 'string' && SAFE_ID.test(m.id)) ? m.id : newId('MS');
    await pool.query(
      'INSERT INTO missions (id, owner_phone, raw_text, steps, total, status, created_at) VALUES ($1,$2,$3,$4,$5,$6,$7)',
      [id, owner, rawStr(m.rawText).slice(0, 3000), JSON.stringify(steps), Math.round(total), missionStatus(m.status, 'draft'), Date.now()]);
    res.json({ ok: true, id });
  } catch (e) { fail(res, 'post mission', e); }
});

app.put('/api/missions/:id', requireAuth, async (req, res) => {
  try {
    const m = bodyOf(req);
    const cur = await pool.query('SELECT owner_phone FROM missions WHERE id = $1', [req.params.id]);
    if (!cur.rows.length) return res.status(404).json({ error: 'مأموریت پیدا نشد' });
    if (cur.rows[0].owner_phone !== req.auth.phone && !req.auth.isAdmin) return res.status(403).json(FORBIDDEN);
    const total = Number(m.total);
    if (!Array.isArray(m.steps) || m.steps.length > 50 || !Number.isFinite(total) || total < 0) {
      return res.status(400).json({ error: 'اطلاعات مأموریت نامعتبر است' });
    }
    await pool.query(
      'UPDATE missions SET steps = $1, total = $2, status = COALESCE($3, status) WHERE id = $4',
      [JSON.stringify(m.steps), Math.round(total), missionStatus(m.status, null), req.params.id]);
    res.json({ ok: true });
  } catch (e) { fail(res, 'update mission', e); }
});

/* ============ ESCROW API ============ */
app.post('/api/escrow', requireAuth, async (req, res) => {
  try {
    const b = bodyOf(req);
    const buyer = req.auth.phone, seller = str(b.seller_phone), amount = Number(b.amount);
    const missionId = str(b.mission_id);
    if (str(b.buyer_phone) && str(b.buyer_phone) !== buyer && !req.auth.isAdmin) return res.status(403).json(FORBIDDEN);
    if (!isPhone(seller) || seller === buyer || !missionId) return res.status(400).json({ error: 'اطلاعات نامعتبر است' });
    if (!Number.isFinite(amount) || amount <= 0) return res.status(400).json({ error: 'مبلغ نامعتبر است' });
    const mr = await pool.query('SELECT owner_phone FROM missions WHERE id = $1', [missionId]);
    if (mr.rows.length && mr.rows[0].owner_phone !== buyer && !req.auth.isAdmin) return res.status(403).json(FORBIDDEN);
    const sr = await pool.query('SELECT 1 FROM users WHERE phone = $1', [seller]);
    if (!sr.rows.length) return res.status(400).json({ error: 'فروشنده پیدا نشد' });
    const id = newId('E');
    await pool.query(
      'INSERT INTO escrows (id, mission_id, buyer_phone, seller_phone, amount, status, created_at) VALUES ($1,$2,$3,$4,$5,$6,$7)',
      [id, missionId.slice(0, 50), buyer, seller, Math.round(amount), 'pending', Date.now()]);
    res.json({ ok: true, id });
  } catch (e) { fail(res, 'post escrow', e); }
});

app.put('/api/escrow/:id/release', requireAuth, async (req, res) => {
  try {
    const r = await pool.query('SELECT buyer_phone, status FROM escrows WHERE id = $1', [req.params.id]);
    if (!r.rows.length) return res.status(404).json({ error: 'پیدا نشد' });
    if (r.rows[0].buyer_phone !== req.auth.phone && !req.auth.isAdmin) return res.status(403).json(FORBIDDEN);
    await pool.query("UPDATE escrows SET status = 'released' WHERE id = $1 AND status = 'pending'", [req.params.id]);
    res.json({ ok: true });
  } catch (e) { fail(res, 'release escrow', e); }
});

/* تاریخچهٔ تراکنش‌های بیعانه: کاربر فقط تراکنش‌های خودش (خریدار یا فروشنده) را می‌بیند */
app.get('/api/escrows/:phone', requireAuth, async (req, res) => {
  try {
    if (!canActAs(req, req.params.phone)) return res.status(403).json(FORBIDDEN);
    const r = await pool.query(
      'SELECT id, mission_id, buyer_phone, seller_phone, amount, status, created_at FROM escrows WHERE buyer_phone = $1 OR seller_phone = $1 ORDER BY created_at DESC LIMIT 100',
      [req.params.phone]);
    res.json({
      escrows: r.rows.map(function (e) {
        return {
          id: e.id,
          missionId: e.mission_id,
          buyerPhone: e.buyer_phone,
          sellerPhone: e.seller_phone,
          amount: Number(e.amount),
          status: e.status,
          createdAt: Number(e.created_at),
        };
      }),
    });
  } catch (e) { fail(res, 'get escrows', e); }
});

/* ============ FAVORITES API ============ */
app.get('/api/favorites/:phone', softAuth, async (req, res) => {
  try {
    if (!canActAs(req, req.params.phone)) return res.status(403).json(FORBIDDEN);
    const r = await pool.query('SELECT * FROM favorites WHERE user_phone = $1 ORDER BY created_at DESC', [req.params.phone]);
    res.json({ favorites: r.rows });
  } catch (e) { fail(res, 'get favorites', e); }
});

app.post('/api/favorites', softAuth, async (req, res) => {
  try {
    const f = bodyOf(req);
    const phone = req.auth ? req.auth.phone : str(f.userPhone);
    const listingId = str(f.listingId);
    if (!isPhone(phone) || !listingId || listingId.length > 50) return res.status(400).json({ error: 'اطلاعات نامعتبر است' });
    if (!canActAs(req, phone)) return res.status(403).json(FORBIDDEN);
    const del = await pool.query('DELETE FROM favorites WHERE user_phone = $1 AND listing_id = $2 RETURNING id', [phone, listingId]);
    if (del.rows.length) return res.json({ ok: true, removed: true });
    const id = (typeof f.id === 'string' && SAFE_ID.test(f.id)) ? f.id : newId('F');
    await pool.query('INSERT INTO favorites (id, user_phone, listing_id, created_at) VALUES ($1,$2,$3,$4)', [id, phone, listingId, Date.now()]);
    res.json({ ok: true, added: true });
  } catch (e) { fail(res, 'favorite', e); }
});

/* ===== END PART 2b ===== */

/* ============ PUSH API ============ */
app.get('/api/push/public-key', (req, res) => {
  if (!PUSH_READY) return res.status(503).json({ error: 'اعلان فعال نیست' });
  res.json({ publicKey: process.env.VAPID_PUBLIC_KEY });
});

app.post('/api/push/subscribe', softAuth, async (req, res) => {
  try {
    if (!PUSH_READY) return res.status(503).json({ error: 'اعلان فعال نیست' });
    const b = bodyOf(req);
    const phone = req.auth ? req.auth.phone : str(b.userPhone);
    const sub = b.subscription;
    if (!isPhone(phone) || !sub || typeof sub !== 'object' || typeof sub.endpoint !== 'string' || sub.endpoint.length > 1000) {
      return res.status(400).json({ error: 'اطلاعات نامعتبر است' });
    }
    if (!canActAs(req, phone)) return res.status(403).json(FORBIDDEN);
    await pool.query('DELETE FROM push_subscriptions WHERE user_phone = $1', [phone]);
    await pool.query(
      'INSERT INTO push_subscriptions (id, user_phone, subscription, created_at) VALUES ($1,$2,$3,$4)',
      [newId('P'), phone, JSON.stringify(sub), Date.now()]);
    res.json({ ok: true });
  } catch (e) { fail(res, 'push subscribe', e); }
});

app.post('/api/push/send', requireAuth, async (req, res) => {
  try {
    if (!PUSH_READY) return res.status(503).json({ error: 'اعلان فعال نیست' });
    const b = bodyOf(req);
    const to = str(b.toPhone), title = str(b.title).slice(0, 200);
    if (!isPhone(to) || !title) return res.status(400).json({ error: 'اطلاعات نامعتبر است' });
    const w = await rateLimit('push:' + req.auth.phone, 60, 10 * MIN); if (w) return tooMany(res, w);
    if (to !== req.auth.phone && !req.auth.isAdmin) {
      const c = await pool.query(
        'SELECT 1 FROM conversations WHERE (buyer_phone=$1 AND seller_phone=$2) OR (buyer_phone=$2 AND seller_phone=$1) LIMIT 1',
        [req.auth.phone, to]);
      if (!c.rows.length) return res.status(403).json(FORBIDDEN);
    }
    const subs = await pool.query('SELECT * FROM push_subscriptions WHERE user_phone = $1', [to]);
    if (!subs.rows.length) return res.json({ ok: true, sent: 0 });
    const payload = JSON.stringify({
      title, body: rawStr(b.body).slice(0, 500),
      icon: '/web-app-manifest-192x192.png',
      data: (b.data && typeof b.data === 'object') ? b.data : {}
    });
    let sent = 0;
    for (const row of subs.rows) {
      try {
        const sub = typeof row.subscription === 'string' ? JSON.parse(row.subscription) : row.subscription;
        await webpush.sendNotification(sub, payload);
        sent++;
      } catch (err) {
        console.warn('push send failed:', err.message);
        if (err.statusCode === 410 || err.statusCode === 404) {
          await pool.query('DELETE FROM push_subscriptions WHERE id = $1', [row.id]).catch(() => {});
        }
      }
    }
    res.json({ ok: true, sent });
  } catch (e) { fail(res, 'push send', e); }
});

/* ============ READY PROFILES API ============ */
app.post('/api/ready', softAuth, async (req, res) => {
  try {
    const p = bodyOf(req);
    const phone = req.auth ? req.auth.phone : str(p.phone);
    if (!isPhone(phone)) return res.status(400).json({ error: 'شماره نامعتبر است' });
    if (!canActAs(req, phone)) return res.status(403).json(FORBIDDEN);
    await pool.query(
      `INSERT INTO ready_profiles (phone, name, is_ready, service_type, region, notes, updated_at)
       VALUES ($1,$2,$3,$4,$5,$6,$7)
       ON CONFLICT (phone) DO UPDATE SET name=$2, is_ready=$3, service_type=$4, region=$5, notes=$6, updated_at=$7`,
      [phone, str(p.name).slice(0, 100), p.is_ready === true, str(p.service_type).slice(0, 50),
       str(p.region).slice(0, 100), rawStr(p.notes).slice(0, 1000), Date.now()]);
    res.json({ ok: true });
  } catch (e) { fail(res, 'post ready', e); }
});

app.get('/api/ready/:serviceType', async (req, res) => {
  try {
    const r = await pool.query(
      'SELECT * FROM ready_profiles WHERE service_type = $1 AND is_ready = true ORDER BY updated_at DESC LIMIT 200',
      [req.params.serviceType]);
    res.json({ profiles: r.rows });
  } catch (e) { fail(res, 'get ready', e); }
});

/* ============ USER WATCHES API ============ */
app.post('/api/watches', softAuth, async (req, res) => {
  try {
    const w = bodyOf(req);
    const phone = req.auth ? req.auth.phone : str(w.user_phone);
    if (!isPhone(phone)) return res.status(400).json({ error: 'شماره نامعتبر است' });
    if (!canActAs(req, phone)) return res.status(403).json(FORBIDDEN);
    const cnt = await pool.query('SELECT COUNT(*)::int AS c FROM user_watches WHERE user_phone = $1', [phone]);
    if (cnt.rows[0].c >= 50) return res.status(400).json({ error: 'تعداد درخواست‌ها به سقف رسیده است' });
    const id = (typeof w.id === 'string' && SAFE_ID.test(w.id)) ? w.id : newId('W');
    await pool.query(
      'INSERT INTO user_watches (id, user_phone, service_type, route_from, route_to, notes, created_at) VALUES ($1,$2,$3,$4,$5,$6,$7)',
      [id, phone, str(w.service_type).slice(0, 50), str(w.route_from).slice(0, 100),
       str(w.route_to).slice(0, 100), rawStr(w.notes).slice(0, 1000), Date.now()]);
    res.json({ ok: true });
  } catch (e) { fail(res, 'post watch', e); }
});

app.get('/api/watches/:phone', softAuth, async (req, res) => {
  try {
    if (!canActAs(req, req.params.phone)) return res.status(403).json(FORBIDDEN);
    const r = await pool.query('SELECT * FROM user_watches WHERE user_phone = $1', [req.params.phone]);
    res.json({ watches: r.rows });
  } catch (e) { fail(res, 'get watches', e); }
});

/* ============ MATCH ALERT ============ */
app.post('/api/match-alert', softAuth, async (req, res) => {
  try {
    const b = bodyOf(req);
    const from = str(b.route_from), to = str(b.route_to);
    const title = str(b.title).slice(0, 150), region = str(b.region).slice(0, 100);
    const w = await rateLimit('match:' + (req.auth ? req.auth.phone : clientIp(req)), 20, 60 * MIN);
    if (w) return tooMany(res, w);
    if (!from && !to) return res.json({ ok: true, matched: 0 });
    const esc = s => s.replace(/[\\%_]/g, '\\$&');
    const conds = [], params = ['transport'];
    if (from) { params.push('%' + esc(from) + '%'); conds.push('route_from ILIKE $' + params.length); }
    if (to) { params.push('%' + esc(to) + '%'); conds.push('route_to ILIKE $' + params.length); }
    const r = await pool.query(
      'SELECT DISTINCT user_phone FROM user_watches WHERE service_type = $1 AND (' + conds.join(' OR ') + ') LIMIT 200', params);
    const now = Date.now();
    for (const d of r.rows) {
      await pool.query(
        'INSERT INTO notifications (id, user_phone, type, icon, title, body, read, created_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)',
        [newId('N'), d.user_phone, 'match', '🚛', 'بار جدید در مسیر شما!',
         'آگهی «' + title + '» در منطقه ' + region + ' ثبت شد.', false, now]);
    }
    res.json({ ok: true, matched: r.rows.length });
  } catch (e) { fail(res, 'match-alert', e); }
});

/* ============ DELETE ACCOUNT ============ */
async function wipeUser(phone) {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    await client.query('DELETE FROM messages WHERE conv_id IN (SELECT id FROM conversations WHERE buyer_phone=$1 OR seller_phone=$1)', [phone]);
    await client.query('DELETE FROM messages WHERE from_phone = $1', [phone]);
    await client.query('DELETE FROM conversations WHERE buyer_phone=$1 OR seller_phone=$1', [phone]);
    await client.query('DELETE FROM listings WHERE seller_phone = $1', [phone]);
    await client.query('DELETE FROM capacities WHERE owner_phone = $1', [phone]).catch(() => {});
    await client.query('DELETE FROM favorites WHERE user_phone = $1', [phone]);
    await client.query('DELETE FROM bookings WHERE customer_phone = $1', [phone]);
    await client.query('DELETE FROM ratings WHERE from_phone=$1 OR to_phone=$1', [phone]);
    await client.query('DELETE FROM notifications WHERE user_phone = $1', [phone]);
    await client.query('DELETE FROM missions WHERE owner_phone = $1', [phone]);
    await client.query('DELETE FROM push_subscriptions WHERE user_phone = $1', [phone]);
    await client.query('DELETE FROM ready_profiles WHERE phone = $1', [phone]);
    await client.query('DELETE FROM user_watches WHERE user_phone = $1', [phone]);
    await client.query('DELETE FROM escrows WHERE buyer_phone=$1 OR seller_phone=$1', [phone]);
    await client.query('DELETE FROM users WHERE phone = $1', [phone]);
    await client.query('COMMIT');
  } catch (e) {
    try { await client.query('ROLLBACK'); } catch (_) {}
    throw e;
  } finally { client.release(); }
}

async function deleteByToken(req, res) {
  try {
    if (!isPhone(req.params.phone)) return res.status(400).json({ error: 'شماره نامعتبر است' });
    if (req.auth.phone !== req.params.phone && !req.auth.isAdmin) return res.status(403).json(FORBIDDEN);
    await wipeUser(req.params.phone);
    res.json({ ok: true });
  } catch (e) { fail(res, 'delete user', e); }
}
app.delete('/api/users/:phone', requireAuth, deleteByToken);
app.delete('/api/users/:phone/delete', requireAuth, deleteByToken);

app.post('/api/auth/delete-account', requireAuth, async (req, res) => {
  try {
    const b = bodyOf(req);
    const phone = str(b.phone), password = rawStr(b.password);
    if (!phone || !password) return res.status(400).json({ error: 'شماره و پسورد لازمه' });
    if (!isPhone(phone) || password.length > PW_MAX) return res.status(401).json({ error: 'شماره یا پسورد اشتباه است' });
    if (req.auth.phone !== phone) return res.status(403).json(FORBIDDEN);
    const w1 = await rateLimit('del:phone:' + phone, 5, 15 * MIN); if (w1) return tooMany(res, w1);
    const w2 = await rateLimit('del:ip:' + clientIp(req), 5, 15 * MIN); if (w2) return tooMany(res, w2);
    const r = await pool.query('SELECT password_hash FROM users WHERE phone = $1', [phone]);
    if (!r.rows.length) return res.status(404).json({ error: 'کاربر پیدا نشد' });
    if (!r.rows[0].password_hash) return res.status(400).json({ error: 'پسورد تنظیم نشده' });
    if (!(await bcrypt.compare(password, r.rows[0].password_hash))) return res.status(401).json({ error: 'پسورد اشتباه است' });
    await wipeUser(phone);
    res.json({ ok: true, message: 'حساب کاربری حذف شد' });
  } catch (e) { fail(res, 'delete-account', e); }
});

/* ============ HEALTH + START ============ */
app.get('/', (req, res) => {
  res.json({ status: 'ok', app: 'taraz-backend', version: '1.1.0', time: new Date().toISOString() });
});

if (require.main === module) {
  const PORT = process.env.PORT || 3000;
  initDB().then(() => {
    app.listen(PORT, () => console.log('Taraz backend running on port ' + PORT));
  }).catch(err => console.error('Failed to init DB:', err.message));
}

module.exports = app;
