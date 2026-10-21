'use strict';

const path = require('path');
const crypto = require('crypto');
const http = require('http');
const express = require('express');
const { Pool } = require('pg');
const { WebSocketServer } = require('ws');

const PORT = Number(process.env.PORT || 3000);
const REG_CODE = process.env.REG_CODE || '';
const DATABASE_URL = process.env.DATABASE_URL;
const SUPABASE_URL = (process.env.SUPABASE_URL || '').replace(/\/$/, '');
const SUPABASE_SECRET_KEY = process.env.SUPABASE_SECRET_KEY || '';
const STORAGE_BUCKET = 'snow-message-files';

if (!DATABASE_URL) throw new Error('Missing DATABASE_URL environment variable');
if (!SUPABASE_URL || !SUPABASE_SECRET_KEY) {
  throw new Error('Missing SUPABASE_URL or SUPABASE_SECRET_KEY environment variable');
}

const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl: { rejectUnauthorized: false },
  max: 5,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 10000
});

const hash = (password, salt) =>
  crypto.scryptSync(password, salt, 32).toString('hex');

function sameHash(a, b) {
  if (
    typeof a !== 'string' ||
    typeof b !== 'string' ||
    !/^[a-f0-9]{64}$/i.test(a) ||
    !/^[a-f0-9]{64}$/i.test(b)
  ) return false;

  return crypto.timingSafeEqual(
    Buffer.from(a, 'hex'),
    Buffer.from(b, 'hex')
  );
}

async function initDb() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS sm_users (
      username TEXT PRIMARY KEY,
      salt TEXT NOT NULL,
      password_hash TEXT NOT NULL,
      profile JSONB NOT NULL DEFAULT '{}'::jsonb,
      created_at BIGINT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS sm_sessions (
      token TEXT PRIMARY KEY,
      username TEXT NOT NULL REFERENCES sm_users(username) ON DELETE CASCADE,
      created_at BIGINT NOT NULL
    );

    CREATE INDEX IF NOT EXISTS sm_sessions_username_idx
      ON sm_sessions(username);

    CREATE TABLE IF NOT EXISTS sm_contacts (
      owner TEXT NOT NULL REFERENCES sm_users(username) ON DELETE CASCADE,
      contact TEXT NOT NULL REFERENCES sm_users(username) ON DELETE CASCADE,
      created_at BIGINT NOT NULL,
      PRIMARY KEY(owner, contact),
      CHECK (owner <> contact)
    );

    CREATE TABLE IF NOT EXISTS sm_messages (
      id TEXT PRIMARY KEY,
      sender TEXT NOT NULL REFERENCES sm_users(username) ON DELETE CASCADE,
      recipient TEXT NOT NULL REFERENCES sm_users(username) ON DELETE CASCADE,
      data JSONB NOT NULL,
      created_at BIGINT NOT NULL
    );

    CREATE INDEX IF NOT EXISTS sm_messages_pair_idx
      ON sm_messages(sender, recipient, created_at);

    CREATE TABLE IF NOT EXISTS sm_files (
      name TEXT PRIMARY KEY,
      owner TEXT NOT NULL REFERENCES sm_users(username) ON DELETE CASCADE,
      shared_with JSONB NOT NULL DEFAULT '[]'::jsonb,
      content_type TEXT NOT NULL DEFAULT 'application/octet-stream',
      created_at BIGINT NOT NULL
    );

    CREATE INDEX IF NOT EXISTS sm_files_owner_idx
      ON sm_files(owner);
  `);
}

const app = express();
app.disable('x-powered-by');
app.set('trust proxy', 1);

app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'no-referrer');
  res.setHeader(
    'Permissions-Policy',
    'camera=(), microphone=(self), geolocation=()'
  );
  next();
});

app.use(express.json({ limit: '16kb' }));

const buckets = new Map();

function allow(key, limit, windowMs = 1000) {
  const now = Date.now();
  let b = buckets.get(key);

  if (!b || now - b.start >= windowMs) {
    b = { start: now, count: 0 };
  }

  b.count++;
  buckets.set(key, b);

  if (buckets.size > 10000) {
    for (const [k, v] of buckets) {
      if (now - v.start >= windowMs) buckets.delete(k);
    }
  }

  return b.count <= limit;
}

function ipOf(req) {
  return req.ip || req.socket.remoteAddress || 'unknown';
}

async function getUser(username) {
  const r = await pool.query(
    'SELECT username, salt, password_hash, profile FROM sm_users WHERE username=$1',
    [username]
  );

  return r.rows[0] || null;
}

async function auth(req) {
  const token = req.headers['x-token'] || req.query.token;

  if (typeof token !== 'string' || token.length > 200) return null;

  const r = await pool.query(
    `SELECT s.username
     FROM sm_sessions s
     JOIN sm_users u ON u.username = s.username
     WHERE s.token = $1`,
    [token]
  );

  return r.rows[0]?.username || null;
}

function asyncRoute(fn) {
  return (req, res, next) =>
    Promise.resolve(fn(req, res, next)).catch(next);
}

function storageHeaders(contentType) {
  return {
    apikey: SUPABASE_SECRET_KEY,
    Authorization: `Bearer ${SUPABASE_SECRET_KEY}`,
    ...(contentType ? { 'Content-Type': contentType } : {})
  };
}

function storageObjectUrl(name) {
  return `${SUPABASE_URL}/storage/v1/object/${STORAGE_BUCKET}/${encodeURIComponent(name)}`;
}

async function storageUpload(name, buffer, contentType) {
  const r = await fetch(storageObjectUrl(name), {
    method: 'POST',
    headers: {
      ...storageHeaders(contentType),
      'x-upsert': 'false'
    },
    body: buffer
  });

  if (!r.ok) throw new Error(`Storage upload failed (${r.status})`);
}

async function storageDownload(name) {
  const url =
    `${SUPABASE_URL}/storage/v1/object/authenticated/` +
    `${STORAGE_BUCKET}/${encodeURIComponent(name)}`;

  const r = await fetch(url, {
    headers: storageHeaders()
  });

  if (!r.ok) throw new Error(`Storage download failed (${r.status})`);

  return {
    buffer: Buffer.from(await r.arrayBuffer()),
    contentType: r.headers.get('content-type') || 'application/octet-stream'
  };
}

async function storageDelete(name) {
  const r = await fetch(storageObjectUrl(name), {
    method: 'DELETE',
    headers: storageHeaders()
  });

  if (!r.ok && r.status !== 404) {
    throw new Error(`Storage delete failed (${r.status})`);
  }
}

app.get('/healthz', asyncRoute(async (_req, res) => {
  await pool.query('SELECT 1');
  res.json({ ok: true });
}));

app.post('/api/auth', asyncRoute(async (req, res) => {
  if (!allow('auth:' + ipOf(req), 5)) {
    return res.status(429).json({
      error: 'تعداد درخواست‌ها بیش از حد مجاز است.'
    });
  }

  const { mode, username, password, code } = req.body || {};

  if (
    typeof username !== 'string' ||
    username.length < 1 ||
    username.length > 40 ||
    /[\u0000-\u001f\u007f]/.test(username) ||
    typeof password !== 'string' ||
    password.length < 1 ||
    password.length > 256
  ) {
    return res.status(400).json({
      error: 'نام کاربری یا رمز عبور نامعتبر است.'
    });
  }

  if (mode === 'register') {
    if (!/^\w{3,20}$/.test(username)) {
      return res.status(400).json({
        error: 'نام کاربری ثبت‌نام باید ۳ تا ۲۰ حرف انگلیسی، عدد یا زیرخط باشد.'
      });
    }

    if (!REG_CODE) {
      return res.status(503).json({
        error: 'ثبت‌نام فعلاً غیرفعال است.'
      });
    }

    if (typeof code !== 'string' || code !== REG_CODE) {
      return res.status(403).json({
        error: 'کد دعوت اشتباه است.'
      });
    }

    if (password.length < 8) {
      return res.status(400).json({
        error: 'رمز عبور باید حداقل ۸ کاراکتر باشد.'
      });
    }

    const salt = crypto.randomBytes(16).toString('hex');

    try {
      await pool.query(
        `INSERT INTO sm_users
         (username, salt, password_hash, profile, created_at)
         VALUES ($1, $2, $3, $4, $5)`,
        [username, salt, hash(password, salt), {}, Date.now()]
      );
    } catch (e) {
      if (e.code === '23505') {
        return res.status(409).json({
          error: 'این نام کاربری قبلاً انتخاب شده است.'
        });
      }
      throw e;
    }
  } else if (mode === 'login') {
    const user = await getUser(username);

    if (!user || !sameHash(user.password_hash, hash(password, user.salt))) {
      return res.status(401).json({
        error: 'نام کاربری یا رمز عبور اشتباه است.'
      });
    }
  } else {
    return res.status(400).json({ error: 'Invalid mode' });
  }

  const token = crypto.randomBytes(32).toString('hex');

  await pool.query(
    'INSERT INTO sm_sessions(token, username, created_at) VALUES($1, $2, $3)',
    [token, username, Date.now()]
  );

  res.json({ token, username });
}));
app.post('/api/upload',
  asyncRoute(async (req, res) => {
    const username = await auth(req);
    if (!username) return res.sendStatus(401);

    if (
      !allow('upload:' + username, 2) ||
      !allow('upload-ip:' + ipOf(req), 4)
    ) {
      return res.status(429).json({
        error: 'تعداد ارسال فایل بیش از حد مجاز است.'
      });
    }

    const chunks = [];
    let size = 0;

    await new Promise((resolve, reject) => {
      req.on('data', chunk => {
        size += chunk.length;

        if (size > 50 * 1024 * 1024) {
          reject(Object.assign(new Error('File too large'), {
            status: 413
          }));
          req.destroy();
          return;
        }

        chunks.push(chunk);
      });

      req.on('end', resolve);
      req.on('error', reject);
    });

    const buffer = Buffer.concat(chunks);

    const allowedExt = [
      'jpg', 'jpeg', 'png', 'gif', 'webp', 'avif',
      'webm', 'm4a', 'mp3', 'ogg', 'wav', 'bin'
    ];

    const requestedExt = String(req.headers['x-ext'] || 'bin')
      .toLowerCase()
      .replace(/^\./, '');

    const ext = allowedExt.includes(requestedExt)
      ? requestedExt
      : 'bin';

    const mimeTypes = {
      jpg: 'image/jpeg',
      jpeg: 'image/jpeg',
      png: 'image/png',
      gif: 'image/gif',
      webp: 'image/webp',
      avif: 'image/avif',
      webm: 'audio/webm',
      m4a: 'audio/mp4',
      mp3: 'audio/mpeg',
      ogg: 'audio/ogg',
      wav: 'audio/wav',
      bin: 'application/octet-stream'
    };

    const name = crypto.randomBytes(12).toString('hex') + '.' + ext;
    const contentType = mimeTypes[ext];

    await storageUpload(name, buffer, contentType);

    try {
      await pool.query(
        `INSERT INTO sm_files
         (name, owner, shared_with, content_type, created_at)
         VALUES ($1, $2, '[]'::jsonb, $3, $4)`,
        [name, username, contentType, Date.now()]
      );
    } catch (e) {
      try {
        await storageDelete(name);
      } catch {}
      throw e;
    }

    res.json({ file: name });
  })
);

app.get('/files/:n', asyncRoute(async (req, res) => {
  const username = await auth(req);
  if (!username) return res.sendStatus(401);

  const name = req.params.n;

  if (!/^[a-f0-9]{24}\.[a-z0-9]{1,5}$/i.test(name)) {
    return res.sendStatus(400);
  }

  const r = await pool.query(
    `SELECT owner, shared_with, content_type
     FROM sm_files WHERE name = $1`,
    [name]
  );

  const meta = r.rows[0];

  if (
    !meta ||
    (meta.owner !== username &&
      !(Array.isArray(meta.shared_with) &&
        meta.shared_with.includes(username)))
  ) {
    return res.sendStatus(403);
  }

  const file = await storageDownload(name);

  res.setHeader('Content-Type', meta.content_type || file.contentType);
  res.setHeader('Cache-Control', 'private, max-age=300');
  res.send(file.buffer);
}));

app.get('/api/users/search', asyncRoute(async (req, res) => {
  const username = await auth(req);
  if (!username) return res.sendStatus(401);

  const q = typeof req.query.q === 'string'
    ? req.query.q.trim()
    : '';

  if (q.length < 2) return res.json([]);

  const r = await pool.query(
    `SELECT username FROM sm_users
     WHERE username ILIKE $1 AND username <> $2
     ORDER BY username LIMIT 20`,
    ['%' + q.replace(/[\\%_]/g, '\\$&') + '%', username]
  );

  res.json(r.rows);
}));

app.get('/api/contacts', asyncRoute(async (req, res) => {
  const username = await auth(req);
  if (!username) return res.sendStatus(401);

  const r = await pool.query(
    `SELECT c.contact AS username
     FROM sm_contacts c
     JOIN sm_users u ON u.username = c.contact
     WHERE c.owner = $1
     ORDER BY c.created_at`,
    [username]
  );

  res.json(r.rows.map(x => x.username));
}));

app.post('/api/contacts', asyncRoute(async (req, res) => {
  const username = await auth(req);
  if (!username) return res.sendStatus(401);

  const contact = req.body?.username;

  if (
    typeof contact !== 'string' ||
    contact === username ||
    !(await getUser(contact))
  ) {
    return res.status(400).json({ error: 'Invalid username' });
  }

  await pool.query(
    `INSERT INTO sm_contacts(owner, contact, created_at)
     VALUES($1, $2, $3)
     ON CONFLICT(owner, contact) DO NOTHING`,
    [username, contact, Date.now()]
  );

  res.json({ ok: true });
}));

app.delete('/api/contacts/:contact', asyncRoute(async (req, res) => {
  const username = await auth(req);

  if (!username) return res.sendStatus(401);

  await pool.query(
    'DELETE FROM sm_contacts WHERE owner=$1 AND contact=$2',
    [username, req.params.contact]
  );

  res.json({ ok: true });
}));

app.get('/api/profile/:username', asyncRoute(async (req, res) => {
  const viewer = await auth(req);
  if (!viewer) return res.sendStatus(401);

  const user = await getUser(req.params.username);
  if (!user) return res.sendStatus(404);

  const profile = user.profile || {};

  res.json({
    username: user.username,
    displayName:
      typeof profile.displayName === 'string' && profile.displayName.trim()
        ? profile.displayName.trim().slice(0, 40)
        : user.username,
    bio: typeof profile.bio === 'string' ? profile.bio.slice(0, 240) : '',
    avatar: typeof profile.avatar === 'string'
      ? profile.avatar.slice(0, 500)
      : ''
  });
}));

app.get('/api/avatar/:username', asyncRoute(async (req, res) => {
  const viewer = await auth(req);
  if (!viewer) return res.sendStatus(401);

  const user = await getUser(req.params.username);
  if (!user || typeof user.profile?.avatar !== 'string') {
    return res.sendStatus(404);
  }

  const filename = path.basename(user.profile.avatar);

  if (!/^[a-f0-9]{24}\.[a-z0-9]{1,5}$/i.test(filename)) {
    return res.sendStatus(404);
  }

  const r = await pool.query(
    'SELECT owner FROM sm_files WHERE name=$1',
    [filename]
  );

  if (!r.rows[0] || r.rows[0].owner !== user.username) {
    return res.sendStatus(404);
  }

  const file = await storageDownload(filename);

  res.setHeader('Content-Type', file.contentType);
  res.setHeader('Cache-Control', 'private, max-age=300');
  res.send(file.buffer);
}));

app.post('/api/profile', asyncRoute(async (req, res) => {
  const username = await auth(req);
  if (!username) return res.sendStatus(401);

  const body = req.body || {};

  if (
    typeof body.displayName !== 'string' ||
    typeof body.bio !== 'string' ||
    typeof body.avatar !== 'string' ||
    body.displayName.trim().length > 40 ||
    body.bio.length > 240 ||
    body.avatar.length > 500
  ) {
    return res.status(400).json({
      error: 'اطلاعات پروفایل معتبر نیست.'
    });
  }

  const profile = {
    displayName: body.displayName.trim(),
    bio: body.bio.trim(),
    avatar: body.avatar.trim()
  };

  await pool.query(
    'UPDATE sm_users SET profile=$1 WHERE username=$2',
    [JSON.stringify(profile), username]
  );

  res.json({ ok: true });
}));

app.use(express.static(path.join(__dirname, 'public')));

const server = http.createServer(app);

const wss = new WebSocketServer({
  server,
  maxPayload: 64 * 1024
});

const online = Object.create(null);

function send(username, data) {
  for (const ws of online[username] || []) {
    if (ws.readyState === 1) {
      ws.send(JSON.stringify(data));
    }
  }
}

function sendError(ws, error) {
  if (ws.readyState === 1) {
    ws.send(JSON.stringify({ t: 'error', error }));
  }
}

async function presence() {
  const r = await pool.query('SELECT username FROM sm_users');
  const list = r.rows.map(row => ({
    name: row.username,
    online: !!(online[row.username] && online[row.username].length)
  }));

  for (const name of Object.keys(online)) {
    send(name, { t: 'users', list });
  }
}
wss.on('connection', async (ws, req) => {
  let token;

  try {
    token = new URL(req.url, 'http://localhost').searchParams.get('token');
  } catch {
    ws.close(1008, 'Invalid request');
    return;
  }

  if (!token) {
    ws.close(1008, 'Unauthorized');
    return;
  }

  let me;

  try {
    const r = await pool.query(
      `SELECT s.username
       FROM sm_sessions s
       JOIN sm_users u ON u.username = s.username
       WHERE s.token = $1`,
      [token]
    );
    me = r.rows[0]?.username;
  } catch {
    ws.close(1011, 'Database error');
    return;
  }

  if (!me || ws.readyState !== 1) {
    ws.close(1008, 'Unauthorized');
    return;
  }

  if ((online[me] || []).length >= 5) {
    ws.close(1008, 'Connection limit reached');
    return;
  }

  online[me] = online[me] || [];
  online[me].push(ws);
  await presence();

  ws.on('message', async raw => {
    if (!allow('ws:' + me, 40)) {
      sendError(ws, 'Too many messages');
      return;
    }

    let m;

    try {
      m = JSON.parse(raw.toString());
    } catch {
      return;
    }

    if (!m || typeof m !== 'object') return;

    try {
      if (m.t === 'msg') {
        if (
          typeof m.to !== 'string' ||
          !(await getUser(m.to))
        ) return;

        const type = ['text', 'image', 'voice'].includes(m.type)
          ? m.type
          : 'text';

        const message = {
          id: crypto.randomUUID(),
          from: me,
          to: m.to,
          type,
          text: typeof m.text === 'string'
            ? m.text.slice(0, 5000)
            : '',
          ts: Date.now(),
          replyTo: typeof m.replyTo === 'string'
            ? m.replyTo.slice(0, 80)
            : ''
        };

        if (type === 'image' || type === 'voice') {
          if (typeof m.file !== 'string') return;

          const filename = path.basename(m.file);

          const fileResult = await pool.query(
            'SELECT owner, shared_with FROM sm_files WHERE name=$1',
            [filename]
          );

          const meta = fileResult.rows[0];

          if (!meta || meta.owner !== me) {
            sendError(ws, 'فایل پیدا نشد یا اجازه دسترسی به آن را ندارید.');
            return;
          }

          message.file = filename;

          if (m.to !== me) {
            await pool.query(
              `UPDATE sm_files
               SET shared_with =
                 CASE
                   WHEN shared_with @> $1::jsonb THEN shared_with
                   ELSE shared_with || $1::jsonb
                 END
               WHERE name=$2 AND owner=$3`,
              [JSON.stringify([m.to]), filename, me]
            );
          }
        }

        await pool.query(
          `INSERT INTO sm_messages(id, sender, recipient, data, created_at)
           VALUES($1, $2, $3, $4, $5)`,
          [message.id, me, m.to, JSON.stringify(message), message.ts]
        );

        send(me, { t: 'msg', m: message });

        if (m.to !== me) {
          send(m.to, { t: 'msg', m: message });
        }

      } else if (m.t === 'edit') {
        if (
          typeof m.id !== 'string' ||
          typeof m.text !== 'string'
        ) return;

        const r = await pool.query(
          `SELECT data FROM sm_messages
           WHERE id=$1 AND sender=$2`,
          [m.id, me]
        );

        if (!r.rows[0]) {
          sendError(ws, 'این پیام قابل ویرایش نیست.');
          return;
        }

        const item = r.rows[0].data;

        if (item.type !== 'text') {
          sendError(ws, 'این پیام قابل ویرایش نیست.');
          return;
        }

        const text = m.text.trim().slice(0, 5000);
        if (!text) return;

        item.text = text;
        item.edited = true;

        await pool.query(
          'UPDATE sm_messages SET data=$1 WHERE id=$2 AND sender=$3',
          [JSON.stringify(item), m.id, me]
        );

        send(item.from, { t: 'msg-update', m: item });
        send(item.to, { t: 'msg-update', m: item });

      } else if (m.t === 'delete') {
        if (typeof m.id !== 'string') return;

        const r = await pool.query(
          `SELECT data FROM sm_messages
           WHERE id=$1 AND (sender=$2 OR recipient=$2)`,
          [m.id, me]
        );

        if (!r.rows[0]) return;

        const item = r.rows[0].data;

        if (m.scope === 'both' && item.from === me) {
          await pool.query(
            'DELETE FROM sm_messages WHERE id=$1 AND sender=$2',
            [m.id, me]
          );

          send(item.from, { t: 'msg-delete', id: item.id });
          send(item.to, { t: 'msg-delete', id: item.id });

        } else {
          item.hiddenBy = Array.isArray(item.hiddenBy)
            ? item.hiddenBy
            : [];

          if (!item.hiddenBy.includes(me)) {
            item.hiddenBy.push(me);
          }

          await pool.query(
            'UPDATE sm_messages SET data=$1 WHERE id=$2',
            [JSON.stringify(item), item.id]
          );

          send(me, { t: 'msg-delete', id: item.id });
        }

      } else if (m.t === 'history') {
        if (
          typeof m.with !== 'string' ||
          !(await getUser(m.with))
        ) return;

        const r = await pool.query(
          `SELECT data FROM sm_messages
           WHERE (
             (sender=$1 AND recipient=$2) OR
             (sender=$2 AND recipient=$1)
           )
           ORDER BY created_at DESC
           LIMIT 200`,
          [me, m.with]
        );

        const list = r.rows
          .map(row => row.data)
          .reverse()
          .filter(item =>
            !(Array.isArray(item.hiddenBy) &&
              item.hiddenBy.includes(me))
          );

        if (ws.readyState === 1) {
          ws.send(JSON.stringify({
            t: 'history',
            with: m.with,
            list
          }));
        }

      } else if (m.t === 'signal') {
        if (
          typeof m.to !== 'string' ||
          !(await getUser(m.to)) ||
          !m.data ||
          typeof m.data !== 'object'
        ) return;

        send(m.to, {
          t: 'signal',
          from: me,
          data: m.data
        });
      }

    } catch (err) {
      console.error('WebSocket operation failed:', err.message);
      sendError(ws, 'عملیات انجام نشد؛ دوباره تلاش کنید.');
    }
  });

  ws.on('close', () => {
    online[me] = (online[me] || []).filter(s => s !== ws);

    if (!online[me].length) {
      delete online[me];
    }

    presence().catch(err =>
      console.error('Presence update failed:', err.message)
    );
  });
});

app.use((err, req, res, next) => {
  if (res.headersSent) return next(err);

  if (err.status === 413 || err.type === 'entity.too.large') {
    return res.status(413).json({
      error: 'حجم فایل بیش از ۵۰ مگابایت است.'
    });
  }

  console.error('Request error:', err.message);

  res.status(500).json({
    error: 'خطای داخلی سرور'
  });
});

async function start() {
  await initDb();

  server.listen(PORT, '0.0.0.0', () => {
    console.log(`Snow Message listening on port ${PORT}`);
  });
}

start().catch(err => {
  console.error('Server startup failed:', err.message);
  process.exit(1);
});

server.on('error', err => {
  console.error('Server error:', err.message);
});