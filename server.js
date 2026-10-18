const express = require('express');
const { Pool } = require('pg');
const cors = require('cors');
const webpush = require('web-push');
const bcrypt = require('bcryptjs');

const VAPID_PUBLIC = 'BMOIr26aPjtSj2_1Kf8P9IaArzdvMhni2RX0gbwDqYEABs7k-wRQTQlAWpv0rrQSIAoY6GugdwQRZ92P__oSOG8';
const VAPID_PRIVATE = 'JEINa3anwSvwivBq4sDgue8qeSPQEg9zIcCTt37Ws_A';

webpush.setVapidDetails('mailto:mehranahmadibaloutaki@gmail.com', VAPID_PUBLIC, VAPID_PRIVATE);

// 1. تعریف اپ (باید قبل از استفاده از app باشه)
const app = express();

// 2. تنظیمات CORS (دقیقاً بعد از تعریف app)
app.use((req, res, next) => {
  const allowedOrigins = ['https://taraz-app.ir', 'https://www.taraz-app.ir'];
  const origin = req.headers.origin;
  if (allowedOrigins.includes(origin)) {
    res.setHeader('Access-Control-Allow-Origin', origin);
  }
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  if (req.method === 'OPTIONS') {
    return res.status(200).end();
  }
  next();
});


app.use(cors());
app.use(express.json({ limit: '10mb' }));

const pool = new Pool({
  connectionString: process.env.DATABASE_URL || 'postgres://root:hEfX84U6IaYkUVILJhvUjPYx@sahand.liara.cloud:32116/postgres',
  ssl: false
});

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
    )`
  ];
  
  for (const q of queries) {
    try { await pool.query(q); } catch (e) { console.error('DB init error:', e.message); }
  }
  
  /* Migration */
  try {
    await pool.query('ALTER TABLE listings ADD COLUMN IF NOT EXISTS location_lat NUMERIC');
    await pool.query('ALTER TABLE listings ADD COLUMN IF NOT EXISTS location_lng NUMERIC');
    await pool.query('ALTER TABLE users ADD COLUMN IF NOT EXISTS password_hash TEXT');
    await pool.query('ALTER TABLE users ADD COLUMN IF NOT EXISTS security_question TEXT');
    await pool.query('ALTER TABLE users ADD COLUMN IF NOT EXISTS security_answer_hash TEXT');
    console.log('✓ Migration done');
  } catch(e) {
    console.warn('Migration:', e.message);
  }
}

/* ============ AUTH API ============ */
app.post('/api/auth/register', async (req, res) => {
  try {
    const { phone, name, role, password } = req.body;
    if(!phone || !/^09\d{9}$/.test(phone)) return res.status(400).json({ error: 'شماره معتبر وارد کن' });
    if(!name || name.length < 3) return res.status(400).json({ error: 'نام معتبر وارد کن' });
    if(!password || password.length < 6) return res.status(400).json({ error: 'پسورد حداقل ۶ کاراکتر' });

    const existing = await pool.query('SELECT * FROM users WHERE phone = $1', [phone]);
    if(existing.rows.length){
      const hash = await bcrypt.hash(password, 10);
      await pool.query('UPDATE users SET password_hash = $1 WHERE phone = $2', [hash, phone]);
      res.json({ ok: true, message: 'پسورد اضافه شد', user: existing.rows[0] });
    } else {
      const hash = await bcrypt.hash(password, 10);
      await pool.query(
        'INSERT INTO users (phone, name, role, password_hash, joined_at) VALUES ($1, $2, $3, $4, $5)',
        [phone, name, role || 'کاربر', hash, Date.now()]
      );
      const result = await pool.query('SELECT * FROM users WHERE phone = $1', [phone]);
      res.json({ ok: true, message: 'ثبت‌نام موفق', user: result.rows[0] });
    }
  } catch (e) {
    console.error('register error:', e.message);
    res.status(500).json({ error: e.message });
  }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const { phone, password } = req.body;
    if(!phone || !password) return res.status(400).json({ error: 'شماره و پسورد لازمه' });

    const result = await pool.query('SELECT * FROM users WHERE phone = $1', [phone]);
    if(!result.rows.length) return res.status(404).json({ error: 'کاربر پیدا نشد' });

    const user = result.rows[0];
    if(!user.password_hash) return res.status(400).json({ error: 'برای این شماره پسورد تنظیم نشده' });

    const valid = await bcrypt.compare(password, user.password_hash);
    if(!valid) return res.status(401).json({ error: 'پسورد اشتباهه' });

    res.json({ ok: true, user: user });
  } catch (e) {
    console.error('login error:', e.message);
    res.status(500).json({ error: e.message });
  }
});

app.post('/api/auth/change-password', async (req, res) => {
  try {
    const { phone, oldPassword, newPassword } = req.body;
    if(!phone || !oldPassword || !newPassword) return res.status(400).json({ error: 'همه فیلدها لازمه' });
    if(newPassword.length < 6) return res.status(400).json({ error: 'پسورد جدید حداقل ۶ کاراکتر' });

    const result = await pool.query('SELECT * FROM users WHERE phone = $1', [phone]);
    if(!result.rows.length) return res.status(404).json({ error: 'کاربر پیدا نشد' });

    const user = result.rows[0];
    if(!user.password_hash) return res.status(400).json({ error: 'پسورد فعلی تنظیم نشده' });

    const valid = await bcrypt.compare(oldPassword, user.password_hash);
    if(!valid) return res.status(401).json({ error: 'پسورد فعلی اشتباهه' });

    const newHash = await bcrypt.hash(newPassword, 10);
    await pool.query('UPDATE users SET password_hash = $1 WHERE phone = $2', [newHash, phone]);
    res.json({ ok: true, message: 'پسورد تغییر کرد' });
  } catch (e) {
    console.error('change-password error:', e.message);
    res.status(500).json({ error: e.message });
  }
});

app.post('/api/auth/set-security', async (req, res) => {
  try {
    const { phone, question, answer } = req.body;
    if(!phone || !question || !answer) return res.status(400).json({ error: 'همه فیلدها لازمه' });
    if(answer.length < 2) return res.status(400).json({ error: 'جواب حداقل ۲ کاراکتر' });

    const answerHash = await bcrypt.hash(answer.toLowerCase().trim(), 10);
    await pool.query(
      'UPDATE users SET security_question = $1, security_answer_hash = $2 WHERE phone = $3',
      [question, answerHash, phone]
    );
    res.json({ ok: true, message: 'سوال امنیتی ذخیره شد' });
  } catch (e) {
    console.error('set-security error:', e.message);
    res.status(500).json({ error: e.message });
  }
});

app.get('/api/auth/security-question/:phone', async (req, res) => {
  try {
    const result = await pool.query('SELECT security_question FROM users WHERE phone = $1', [req.params.phone]);
    if(!result.rows.length) return res.status(404).json({ error: 'کاربر پیدا نشد' });
    if(!result.rows[0].security_question) return res.status(400).json({ error: 'سوال امنیتی تنظیم نشده' });
    res.json({ question: result.rows[0].security_question });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.post('/api/auth/recover', async (req, res) => {
  try {
    const { phone, answer, newPassword } = req.body;
    if(!phone || !answer || !newPassword) return res.status(400).json({ error: 'همه فیلدها لازمه' });
    if(newPassword.length < 6) return res.status(400).json({ error: 'پسورد جدید حداقل ۶ کاراکتر' });

    const result = await pool.query('SELECT * FROM users WHERE phone = $1', [phone]);
    if(!result.rows.length) return res.status(404).json({ error: 'کاربر پیدا نشد' });

    const user = result.rows[0];
    if(!user.security_answer_hash) return res.status(400).json({ error: 'سوال امنیتی تنظیم نشده' });

    const valid = await bcrypt.compare(answer.toLowerCase().trim(), user.security_answer_hash);
    if(!valid) return res.status(401).json({ error: 'جواب اشتباهه' });

    const newHash = await bcrypt.hash(newPassword, 10);
    await pool.query('UPDATE users SET password_hash = $1 WHERE phone = $2', [newHash, phone]);
    res.json({ ok: true, message: 'پسورد بازیابی شد' });
  } catch (e) {
    console.error('recover error:', e.message);
    res.status(500).json({ error: e.message });
  }
});

/* ============ USER API ============ */
app.post('/api/users/login', async (req, res) => {
  try {
    const { phone, name, role, avatar } = req.body;
    if (!phone || !name) return res.status(400).json({ error: 'phone and name required' });
    await pool.query(
      'INSERT INTO users (phone, name, role, avatar, joined_at) VALUES ($1, $2, $3, $4, $5) ON CONFLICT (phone) DO UPDATE SET name = $2, role = $3, avatar = COALESCE($4, users.avatar)',
      [phone, name, role || null, avatar || null, Date.now()]
    );
    const result = await pool.query('SELECT * FROM users WHERE phone = $1', [phone]);
    res.json({ user: result.rows[0] });
  } catch (e) {
    console.error('login error:', e.message);
    res.status(500).json({ error: e.message });
  }
});

app.get('/api/users/:phone', async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM users WHERE phone = $1', [req.params.phone]);
    if (!result.rows.length) return res.status(404).json({ error: 'not found' });
    res.json({ user: result.rows[0] });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.post('/api/users/:phone/avatar', async (req, res) => {
  try {
    const { avatar } = req.body;
    await pool.query('UPDATE users SET avatar = $1 WHERE phone = $2', [avatar, req.params.phone]);
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

/* ============ LISTINGS API ============ */
app.get('/api/listings', async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM listings ORDER BY created_at DESC LIMIT 200');
    res.json({ listings: result.rows });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.post('/api/listings', async (req, res) => {
  try {
    const l = req.body;
    await pool.query(
      'INSERT INTO listings (id, seller_phone, seller_name, category_id, title, qty, qty_num, price, old_price, region, description, urgent, urgent_reason, product_key, photos, location_lat, location_lng, created_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18)',
      [l.id, l.sellerPhone, l.sellerName, l.categoryId, l.title, l.qty, l.qtyNum, l.price, l.oldPrice || null, l.region, l.desc || null, l.urgent || false, l.urgentReason || null, l.productKey || null, JSON.stringify(l.photos || []), (l.location && l.location.lat) || null, (l.location && l.location.lng) || null, l.createdAt || Date.now()]
    );
    res.json({ ok: true, id: l.id });
  } catch (e) {
    console.error('listing error:', e.message);
    res.status(500).json({ error: e.message });
  }
});

app.delete('/api/listings/:id', async (req, res) => {
  try {
    await pool.query('DELETE FROM listings WHERE id = $1', [req.params.id]);
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

/* ============ CAPACITIES API ============ */
app.get('/api/capacities', async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM capacities ORDER BY created_at DESC LIMIT 200');
    res.json({ capacities: result.rows });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.post('/api/capacities', async (req, res) => {
  try {
    const c = req.body;
    await pool.query(
      'INSERT INTO capacities (id, owner_phone, owner_name, service_type, type_id, title, region, route_from, route_to, capacity_total, capacity_used, price, unit, available_from, available_to, rating, created_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17)',
      [c.id, c.ownerPhone, c.ownerName, c.serviceType, c.typeId, c.title, c.region, c.routeFrom || null, c.routeTo || null, c.capacityTotal, c.capacityUsed || 0, c.price, c.unit, c.availableFrom || null, c.availableTo || null, c.rating || 0, c.createdAt || Date.now()]
    );
    res.json({ ok: true, id: c.id });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

/* ============ CONVERSATIONS API ============ */
app.get('/api/conversations/:phone', async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT * FROM conversations WHERE buyer_phone = $1 OR seller_phone = $1 ORDER BY last_message_at DESC',
      [req.params.phone]
    );
    res.json({ conversations: result.rows });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.post('/api/conversations', async (req, res) => {
  try {
    const c = req.body;
    const existing = await pool.query(
      'SELECT * FROM conversations WHERE listing_id = $1 AND ((buyer_phone = $2 AND seller_phone = $3) OR (buyer_phone = $3 AND seller_phone = $2))',
      [c.listingId, c.buyerPhone, c.sellerPhone]
    );
    if (existing.rows.length) return res.json({ conversation: existing.rows[0] });
    await pool.query(
      'INSERT INTO conversations (id, listing_id, listing_title, buyer_phone, buyer_name, seller_phone, seller_name, created_at, last_message_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)',
      [c.id, c.listingId, c.listingTitle, c.buyerPhone, c.buyerName, c.sellerPhone, c.sellerName, Date.now(), Date.now()]
    );
    const result = await pool.query('SELECT * FROM conversations WHERE id = $1', [c.id]);
    res.json({ conversation: result.rows[0] });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

/* ============ MESSAGES API ============ */
app.get('/api/messages/:convId', async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT * FROM messages WHERE conv_id = $1 ORDER BY created_at ASC',
      [req.params.convId]
    );
    res.json({ messages: result.rows });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.post('/api/messages', async (req, res) => {
  try {
    const m = req.body;
    await pool.query(
      'INSERT INTO messages (id, conv_id, from_phone, text, read, created_at) VALUES ($1,$2,$3,$4,$5,$6)',
      [m.id, m.convId, m.fromPhone, m.text, false, Date.now()]
    );
    await pool.query('UPDATE conversations SET last_message_at = $1 WHERE id = $2', [Date.now(), m.convId]);
    res.json({ ok: true, id: m.id });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

/* ============ BOOKINGS API ============ */
app.get('/api/bookings/:phone', async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT * FROM bookings WHERE customer_phone = $1 ORDER BY created_at DESC',
      [req.params.phone]
    );
    res.json({ bookings: result.rows });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.post('/api/bookings', async (req, res) => {
  try {
    const b = req.body;
    await pool.query(
      'INSERT INTO bookings (id, capacity_id, customer_phone, customer_name, qty, total, status, created_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)',
      [b.id, b.capacityId, b.customerPhone, b.customerName, b.qty, b.total, 'pending', Date.now()]
    );
    await pool.query('UPDATE capacities SET capacity_used = capacity_used + $1 WHERE id = $2', [b.qty, b.capacityId]);
    res.json({ ok: true, id: b.id });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

/* ============ RATINGS API ============ */
app.get('/api/ratings/:phone', async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT * FROM ratings WHERE to_phone = $1 ORDER BY created_at DESC',
      [req.params.phone]
    );
    const avg = result.rows.length ? result.rows.reduce((a, b) => a + b.score, 0) / result.rows.length : 0;
    res.json({ ratings: result.rows, avg, count: result.rows.length });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.post('/api/ratings', async (req, res) => {
  try {
    const r = req.body;
    await pool.query(
      'INSERT INTO ratings (id, from_phone, from_name, to_phone, score, comment, created_at) VALUES ($1,$2,$3,$4,$5,$6,$7)',
      [r.id, r.fromPhone, r.fromName, r.toPhone, r.score, r.comment || null, Date.now()]
    );
    res.json({ ok: true, id: r.id });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

/* ============ NOTIFICATIONS API ============ */
app.get('/api/notifications/:phone', async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT * FROM notifications WHERE user_phone = $1 ORDER BY created_at DESC LIMIT 50',
      [req.params.phone]
    );
    res.json({ notifications: result.rows });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.post('/api/notifications', async (req, res) => {
  try {
    const n = req.body;
    await pool.query(
      'INSERT INTO notifications (id, user_phone, type, icon, title, body, read, created_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)',
      [n.id, n.userPhone, n.type, n.icon || '🔔', n.title, n.body, false, Date.now()]
    );
    res.json({ ok: true, id: n.id });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

/* ============ MISSIONS API ============ */
app.get('/api/missions/:phone', async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT * FROM missions WHERE owner_phone = $1 ORDER BY created_at DESC LIMIT 50',
      [req.params.phone]
    );
    res.json({ missions: result.rows });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.post('/api/missions', async (req, res) => {
  try {
    const m = req.body;
    await pool.query(
      'INSERT INTO missions (id, owner_phone, raw_text, steps, total, status, created_at) VALUES ($1,$2,$3,$4,$5,$6,$7)',
      [m.id, m.ownerPhone, m.rawText, JSON.stringify(m.steps || []), m.total, m.status || 'draft', Date.now()]
    );
    res.json({ ok: true, id: m.id });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

/* ============ FAVORITES API ============ */
app.get('/api/favorites/:phone', async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT * FROM favorites WHERE user_phone = $1 ORDER BY created_at DESC',
      [req.params.phone]
    );
    res.json({ favorites: result.rows });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.post('/api/favorites', async (req, res) => {
  try {
    const f = req.body;
    const existing = await pool.query(
      'SELECT * FROM favorites WHERE user_phone = $1 AND listing_id = $2',
      [f.userPhone, f.listingId]
    );
    if (existing.rows.length) {
      await pool.query('DELETE FROM favorites WHERE user_phone = $1 AND listing_id = $2', [f.userPhone, f.listingId]);
      return res.json({ ok: true, removed: true });
    }
    await pool.query(
      'INSERT INTO favorites (id, user_phone, listing_id, created_at) VALUES ($1, $2, $3, $4)',
      [f.id, f.userPhone, f.listingId, Date.now()]
    );
    res.json({ ok: true, added: true });
  } catch (e) {
    console.error('favorite error:', e.message);
    res.status(500).json({ error: e.message });
  }
});

/* ============ HEALTH CHECK ============ */
app.get('/', (req, res) => {
  res.json({
    status: 'ok',
    app: 'taraz-backend',
    version: '1.0.0',
    time: new Date().toISOString()
  });
});

/* ============ PUSH API ============ */
app.get('/api/push/public-key', (req, res) => {
  res.json({ publicKey: VAPID_PUBLIC });
});

app.post('/api/push/subscribe', async (req, res) => {
  try {
    const { userPhone, subscription } = req.body;
    if (!userPhone || !subscription) return res.status(400).json({ error: 'missing data' });
    await pool.query('DELETE FROM push_subscriptions WHERE user_phone = $1', [userPhone]);
    await pool.query(
      'INSERT INTO push_subscriptions (id, user_phone, subscription, created_at) VALUES ($1, $2, $3, $4)',
      ['P' + Date.now(), userPhone, JSON.stringify(subscription), Date.now()]
    );
    res.json({ ok: true });
  } catch (e) {
    console.error('push subscribe error:', e.message);
    res.status(500).json({ error: e.message });
  }
});

app.post('/api/push/send', async (req, res) => {
  try {
    const { toPhone, title, body, data } = req.body;
    if (!toPhone || !title) return res.status(400).json({ error: 'missing data' });

    const result = await pool.query('SELECT * FROM push_subscriptions WHERE user_phone = $1', [toPhone]);
    if (!result.rows.length) return res.json({ ok: true, sent: 0 });

    var payload = JSON.stringify({
      title: title,
      body: body || '',
      icon: '/web-app-manifest-192x192.png',
      data: data || {}
    });

    var sent = 0;
    for (var row of result.rows) {
      try {
        var sub = typeof row.subscription === 'string' ? JSON.parse(row.subscription) : row.subscription;
        await webpush.sendNotification(sub, payload);
        sent++;
      } catch (err) {
        console.warn('push send failed:', err.message);
        if (err.statusCode === 410 || err.statusCode === 404) {
          await pool.query('DELETE FROM push_subscriptions WHERE id = $1', [row.id]);
        }
      }
    }
    res.json({ ok: true, sent: sent });
  } catch (e) {
    console.error('push send error:', e.message);
    res.status(500).json({ error: e.message });
  }
});

/* ============ DELETE USER ============ */
app.delete('/api/users/:phone', async (req, res) => {
  try {
    await pool.query('DELETE FROM users WHERE phone = $1', [req.params.phone]);
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.post('/api/auth/delete-account', async (req, res) => {
  try {
    const { phone, password } = req.body;
    if(!phone || !password) return res.status(400).json({ error: 'شماره و پسورد لازمه' });

    const result = await pool.query('SELECT * FROM users WHERE phone = $1', [phone]);
    if(!result.rows.length) return res.status(404).json({ error: 'کاربر پیدا نشد' });

    const user = result.rows[0];
    if(!user.password_hash) return res.status(400).json({ error: 'پسورد تنظیم نشده' });

    const valid = await bcrypt.compare(password, user.password_hash);
    if(!valid) return res.status(401).json({ error: 'پسورد اشتباهه' });

    await pool.query('DELETE FROM listings WHERE seller_phone = $1', [phone]);
    await pool.query('DELETE FROM favorites WHERE user_phone = $1', [phone]);
    await pool.query('DELETE FROM conversations WHERE buyer_phone = $1 OR seller_phone = $1', [phone]);
    await pool.query('DELETE FROM messages WHERE from_phone = $1', [phone]);
    await pool.query('DELETE FROM bookings WHERE customer_phone = $1', [phone]);
    await pool.query('DELETE FROM ratings WHERE from_phone = $1 OR to_phone = $1', [phone]);
    await pool.query('DELETE FROM notifications WHERE user_phone = $1', [phone]);
    await pool.query('DELETE FROM missions WHERE owner_phone = $1', [phone]);
    await pool.query('DELETE FROM push_subscriptions WHERE user_phone = $1', [phone]);
    await pool.query('DELETE FROM users WHERE phone = $1', [phone]);

    res.json({ ok: true, message: 'حساب کاربری حذف شد' });
  } catch (e) {
    console.error('delete-account error:', e.message);
    res.status(500).json({ error: e.message });
  }
});

/* ============ START SERVER ============ */
const PORT = process.env.PORT || 3000;

initDB().then(() => {
  app.listen(PORT, () => {
    console.log('✓ Taraz backend running on port ' + PORT);
  });
}).catch(err => {
  console.error('✗ Failed to init DB:', err.message);
});


module.exports = app;
