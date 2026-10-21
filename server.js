
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const http = require('http');
const https = require('https');
const express = require('express');
const { WebSocketServer } = require('ws');

const PORT = Number(process.env.PORT || 3000);
const REG_CODE = process.env.REG_CODE || '';

const DATA = path.join(__dirname, 'data');
const UPLOADS = path.join(DATA, 'uploads');

fs.mkdirSync(UPLOADS, { recursive: true });

function load(file, fallback) {
  try {
    return JSON.parse(fs.readFileSync(path.join(DATA, file), 'utf8'));
  } catch {
    return fallback;
  }
}

function save(file, value) {
  const target = path.join(DATA, file);
  const temp = target + '.tmp';
  fs.writeFileSync(temp, JSON.stringify(value), { mode: 0o600 });
  fs.renameSync(temp, target);
}

let users = load('users.json', {});
let contacts = load('contacts.json', {});
let messages = load('messages.json', []);
let tokens = load('tokens.json', {});
let filesMeta = load('files.json', {});

const hash = (password, salt) =>
  crypto.scryptSync(password, salt, 32).toString('hex');

function sameHash(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string') return false;
  if (!/^[a-f0-9]{64}$/i.test(a) || !/^[a-f0-9]{64}$/i.test(b)) {
    return false;
  }
  return crypto.timingSafeEqual(
    Buffer.from(a, 'hex'),
    Buffer.from(b, 'hex')
  );
}

function auth(req) {
  const token = req.headers['x-token'] || req.query.token;
  if (typeof token !== 'string') return null;
  const username = tokens[token];
  return typeof username === 'string' && users[username]
    ? username
    : null;
}

const buckets = new Map();

function allow(key, limit, windowMs = 1000) {
  const now = Date.now();
  let bucket = buckets.get(key);

  if (!bucket || now - bucket.start >= windowMs) {
    bucket = { start: now, count: 0 };
  }

  bucket.count++;
  buckets.set(key, bucket);

  if (buckets.size > 10000) {
    for (const [k, b] of buckets) {
      if (now - b.start >= windowMs) buckets.delete(k);
    }
  }

  return bucket.count <= limit;
}

function ipOf(req) {
  return req.socket.remoteAddress || 'unknown';
}

const app = express();
app.disable('x-powered-by');

app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'no-referrer');
  next();
});

app.use(express.json({ limit: '16kb' }));

app.post('/api/auth', (req, res) => {
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

    if (users[username]) {
      return res.status(409).json({
        error: 'این نام کاربری قبلاً انتخاب شده است.'
      });
    }

    const salt = crypto.randomBytes(16).toString('hex');
    users[username] = { salt, hash: hash(password, salt) };

    try {
      save('users.json', users);
    } catch {
      delete users[username];
      return res.status(500).json({
        error: 'Could not save account'
      });
    }
  } else if (mode === 'login') {
    const user = users[username];

    if (!user || !sameHash(user.hash, hash(password, user.salt))) {
      return res.status(401).json({
        error: 'نام کاربری یا رمز عبور اشتباه است.'
      });
    }
  } else {
    return res.status(400).json({ error: 'Invalid mode' });
  }

  const token = crypto.randomBytes(32).toString('hex');
  tokens[token] = username;

  try {
    save('tokens.json', tokens);
  } catch {
    delete tokens[token];
    return res.status(500).json({
      error: 'Could not create session'
    });
  }

  res.json({ token, username });
});

app.post(
  '/api/upload',
  (req, res, next) => {
    const username = auth(req);

    if (!username) return res.sendStatus(401);

    if (
      !allow('upload:' + username, 2) ||
      !allow('upload-ip:' + ipOf(req), 4)
    ) {
      return res.status(429).json({
        error: 'تعداد ارسال فایل بیش از حد مجاز است.'
      });
    }

    req.uploadUser = username;
    next();
  },
  express.raw({ type: '*/*', limit: '50mb' }),
  (req, res) => {
    if (!Buffer.isBuffer(req.body)) {
      return res.status(400).json({ error: 'Invalid upload' });
    }

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

    const name = crypto.randomBytes(12).toString('hex') + '.' + ext;

    try {
      fs.writeFileSync(path.join(UPLOADS, name), req.body, {
        flag: 'wx',
        mode: 0o600
      });

      filesMeta[name] = {
        owner: req.uploadUser,
        sharedWith: [],
        createdAt: Date.now()
      };

      save('files.json', filesMeta);
      res.json({ file: name });
    } catch {
      try {
        fs.unlinkSync(path.join(UPLOADS, name));
      } catch {}
      delete filesMeta[name];
      res.status(500).json({ error: 'Upload failed' });
    }
  }
);

app.get('/files/:n', (req, res) => {
  const username = auth(req);
  if (!username) return res.sendStatus(401);

  const name = req.params.n;

  if (!/^[a-f0-9]{24}\.[a-z0-9]{1,5}$/i.test(name)) {
    return res.sendStatus(400);
  }

  const meta = filesMeta[name];

  if (
    !meta ||
    (meta.owner !== username &&
      !(meta.sharedWith || []).includes(username))
  ) {
    return res.sendStatus(403);
  }

  res.sendFile(path.join(UPLOADS, name), err => {
    if (err && !res.headersSent) res.sendStatus(404);
  });
});

app.get('/api/users/search', (req, res) => {
  const username = auth(req);
  if (!username) return res.sendStatus(401);

  const q = typeof req.query.q === 'string'
    ? req.query.q.trim().toLowerCase()
    : '';

  if (q.length < 2) return res.json([]);

  const results = Object.keys(users)
    .filter(name => name !== username && name.toLowerCase().includes(q))
    .slice(0, 20)
    .map(name => ({ username: name }));

  res.json(results);
});

app.get('/api/contacts', (req, res) => {
  const username = auth(req);
  if (!username) return res.sendStatus(401);

  const list = Array.isArray(contacts[username])
    ? contacts[username]
    : [];

  res.json(list.filter(name => users[name] && name !== username));
});

app.post('/api/contacts', (req, res) => {
  const username = auth(req);
  if (!username) return res.sendStatus(401);

  const contact = req.body?.username;

  if (
    typeof contact !== 'string' ||
    !users[contact] ||
    contact === username
  ) {
    return res.status(400).json({ error: 'Invalid username' });
  }

  if (!Array.isArray(contacts[username])) {
    contacts[username] = [];
  }

  if (!contacts[username].includes(contact)) {
    contacts[username].push(contact);

    try {
      save('contacts.json', contacts);
    } catch {
      contacts[username].pop();
      return res.sendStatus(500);
    }
  }

  res.json({ ok: true });
});

app.delete('/api/contacts/:contact', (req, res) => {
  const username = auth(req);
  if (!username) return res.sendStatus(401);

  const contact = req.params.contact;
  const previous = Array.isArray(contacts[username])
    ? contacts[username]
    : [];

  contacts[username] = previous.filter(name => name !== contact);

  try {
    save('contacts.json', contacts);
    res.json({ ok: true });
  } catch {
    contacts[username] = previous;
    res.status(500).json({
      error: 'حذف مخاطب ناموفق بود.'
    });
  }
});

app.get('/api/profile/:username', (req, res) => {
  const viewer = auth(req);
  if (!viewer) return res.sendStatus(401);

  const username = req.params.username;
  const user = users[username];
  if (!user) return res.sendStatus(404);

  const profile = user.profile && typeof user.profile === 'object'
    ? user.profile
    : {};

  res.json({
    username,
    displayName:
      typeof profile.displayName === 'string' && profile.displayName.trim()
        ? profile.displayName.trim().slice(0, 40)
        : username,
    bio: typeof profile.bio === 'string' ? profile.bio.slice(0, 240) : '',
    avatar: typeof profile.avatar === 'string'
      ? profile.avatar.slice(0, 500)
      : ''
  });
});

app.get('/api/avatar/:username', (req, res) => {
  const viewer = auth(req);
  if (!viewer) return res.sendStatus(401);

  const owner = req.params.username;
  const user = users[owner];

  if (!user || !user.profile || typeof user.profile.avatar !== 'string') {
    return res.sendStatus(404);
  }

  const filename = path.basename(user.profile.avatar);
  const meta = filesMeta[filename];

  if (
    !/^[a-f0-9]{24}\.[a-z0-9]{1,5}$/i.test(filename) ||
    !meta ||
    meta.owner !== owner ||
    !fs.existsSync(path.join(UPLOADS, filename))
  ) {
    return res.sendStatus(404);
  }

  res.setHeader('Cache-Control', 'private, max-age=300');
  res.sendFile(path.join(UPLOADS, filename), err => {
    if (err && !res.headersSent) res.sendStatus(404);
  });
});

app.post('/api/profile', (req, res) => {
  const username = auth(req);
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

  const previous = users[username].profile;

  users[username].profile = {
    displayName: body.displayName.trim(),
    bio: body.bio.trim(),
    avatar: body.avatar.trim()
  };

  try {
    save('users.json', users);
  } catch {
    if (previous === undefined) delete users[username].profile;
    else users[username].profile = previous;

    return res.status(500).json({
      error: 'ذخیره پروفایل ناموفق بود.'
    });
  }

  res.json({ ok: true });
});

app.use(express.static(path.join(__dirname, 'public')));

const certPath = path.join(__dirname, 'cert.pem');
const keyPath = path.join(__dirname, 'key.pem');
const hasCert = fs.existsSync(certPath) && fs.existsSync(keyPath);

const server = hasCert
  ? https.createServer({
      cert: fs.readFileSync(certPath),
      key: fs.readFileSync(keyPath)
    }, app)
  : http.createServer(app);

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

function presence() {
  const list = Object.keys(users).map(name => ({
    name,
    online: !!(online[name] && online[name].length)
  }));

  for (const name of Object.keys(online)) {
    send(name, { t: 'users', list });
  }
}

function sendError(ws, error) {
  if (ws.readyState === 1) {
    ws.send(JSON.stringify({ t: 'error', error }));
  }
}

wss.on('connection', (ws, req) => {
  let token;

  try {
    token = new URL(req.url, 'http://localhost')
      .searchParams.get('token');
  } catch {
    ws.close(1008, 'Invalid request');
    return;
  }

  const me = typeof token === 'string' ? tokens[token] : null;

  if (!me || !users[me]) {
    ws.close(1008, 'Unauthorized');
    return;
  }

  if ((online[me] || []).length >= 5) {
    ws.close(1008, 'Connection limit reached');
    return;
  }

  online[me] = online[me] || [];
  online[me].push(ws);
  presence();

  ws.on('message', raw => {
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

    if (m.t === 'msg') {
      if (typeof m.to !== 'string' || !users[m.to]) return;

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
        const meta = filesMeta[filename];

        if (
          !meta ||
          meta.owner !== me ||
          !fs.existsSync(path.join(UPLOADS, filename))
        ) {
          sendError(ws, 'فایل پیدا نشد یا اجازه دسترسی به آن را ندارید.');
          return;
        }

        message.file = filename;

        if (m.to !== me && !meta.sharedWith.includes(m.to)) {
          meta.sharedWith.push(m.to);
          try {
            save('files.json', filesMeta);
          } catch {
            meta.sharedWith = meta.sharedWith.filter(n => n !== m.to);
            sendError(ws, 'Could not share file');
            return;
          }
        }
      }

      messages.push(message);
      if (messages.length > 10000) {
        messages = messages.slice(-10000);
      }

      try {
        save('messages.json', messages);
      } catch {
        messages.pop();
        sendError(ws, 'پیام ذخیره نشد؛ دوباره تلاش کنید.');
        return;
      }

      send(me, { t: 'msg', m: message });
      if (m.to !== me) send(m.to, { t: 'msg', m: message });

    } else if (m.t === 'edit') {
      const item = messages.find(x => x.id === m.id && x.from === me);
      if (!item || item.type !== 'text' || typeof m.text !== 'string') {
        sendError(ws, 'این پیام قابل ویرایش نیست.');
        return;
      }

      const text = m.text.trim().slice(0, 5000);
      if (!text) return;

      const oldText = item.text;
      const wasEdited = item.edited;

      item.text = text;
      item.edited = true;

      try {
        save('messages.json', messages);
      } catch {
        item.text = oldText;
        item.edited = wasEdited;
        sendError(ws, 'ذخیره ویرایش ناموفق بود.');
        return;
      }

      send(item.from, { t: 'msg-update', m: item });
      send(item.to, { t: 'msg-update', m: item });

    } else if (m.t === 'delete') {
      const item = messages.find(
        x => x.id === m.id && (x.from === me || x.to === me)
      );
      if (!item) return;

      if (m.scope === 'both' && item.from === me) {
        const previous = messages;
        messages = messages.filter(x => x.id !== item.id);

        try {
          save('messages.json', messages);
        } catch {
          messages = previous;
          sendError(ws, 'حذف پیام ناموفق بود.');
          return;
        }

        send(item.from, { t: 'msg-delete', id: item.id });
        send(item.to, { t: 'msg-delete', id: item.id });

      } else {
        item.hiddenBy = Array.isArray(item.hiddenBy)
          ? item.hiddenBy
          : [];

        if (!item.hiddenBy.includes(me)) item.hiddenBy.push(me);

        try {
          save('messages.json', messages);
        } catch {
          item.hiddenBy = item.hiddenBy.filter(n => n !== me);
          sendError(ws, 'حذف پیام ناموفق بود.');
          return;
        }

        send(me, { t: 'msg-delete', id: item.id });
      }

    } else if (m.t === 'history') {
      if (typeof m.with !== 'string' || !users[m.with]) return;

      const list = messages
        .filter(x =>
          ((x.from === me && x.to === m.with) ||
          (x.from === m.with && x.to === me)) &&
          !(Array.isArray(x.hiddenBy) && x.hiddenBy.includes(me))
        )
        .slice(-200);

      ws.send(JSON.stringify({
        t: 'history',
        with: m.with,
        list
      }));

    } else if (m.t === 'signal') {
      if (
        typeof m.to !== 'string' ||
        !users[m.to] ||
        !m.data ||
        typeof m.data !== 'object'
      ) {
        return;
      }

      send(m.to, {
        t: 'signal',
        from: me,
        data: m.data
      });
    }
  });

  ws.on('close', () => {
    online[me] = (online[me] || []).filter(s => s !== ws);

    if (!online[me].length) {
      delete online[me];
    }

    presence();
  });
});

server.listen(PORT, '0.0.0.0', () => {
  console.log(
    `${hasCert ? 'https' : 'http'}://localhost:${PORT}`
  );

  if (!hasCert) {
    console.log('WARNING: HTTP only; not ready for public use.');
  }
});

server.on('error', err => {
  console.error('Server error:', err.message);
});

app.use((err, req, res, next) => {
  if (res.headersSent) return next(err);

  if (err.type === 'entity.too.large') {
    return res.status(413).json({
      error: 'Request too large'
    });
  }

  console.error('Request error:', err.message);
  res.status(500).json({
    error: 'Internal server error'
  });
});
