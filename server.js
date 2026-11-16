'use strict';
// FreeMemeAlerts — бесплатные мем-алерты для стрима. Без зависимостей: только Node.js 18+.
const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

// ---------- конфигурация ----------
const PORT = Number(process.env.PORT) || 3000;
const TRUST_PROXY = process.env.TRUST_PROXY === '1';
const PUBLIC_DIR = path.join(__dirname, 'public');
const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, 'data');
const SETTINGS_FILE = path.join(DATA_DIR, 'channels.json');
const SECRET_FILE = path.join(DATA_DIR, 'secret.txt');

const DEFAULTS = Object.freeze({
  name: 'Мой стрим', enabled: true, moderation: false,
  cooldownSec: 30, maxDurationSec: 15, volume: 70, showSender: true,
  randomPosition: true, sizePct: 40,
});
const BOOL_SETTINGS = ['enabled', 'moderation', 'showSender', 'randomPosition'];
const NUM_SETTINGS = { cooldownSec: [0, 3600], maxDurationSec: [3, 60], volume: [0, 100], sizePct: [15, 90] };
const OVERLAY_SETTINGS = ['volume', 'maxDurationSec', 'showSender', 'randomPosition', 'sizePct'];
const LIMITS = {
  pending: 30,           // мемов на модерации в одном канале
  history: 30,           // показанных мемов в истории
  clientsPerChannel: 10, // одновременных подключений панели и оверлея
  savedChannels: 5000,   // каналов с настройками на диске
  bodyBytes: 16384,
  coubCache: 300,
};
const MINUTE = 60 * 1000;
const CHANNEL_IDLE_MS = 30 * MINUTE;
const COUB_PER_PAGE = 24;
const COUB_MAX_PAGE = 50;

fs.mkdirSync(DATA_DIR, { recursive: true });

// ---------- ключи ----------
// Ключи каналов выводятся из секрета сервера, поэтому ссылки стримеров
// переживают перезапуск, даже если диск хостинга не сохраняется.
function loadSecret() {
  if (process.env.SERVER_SECRET) return process.env.SERVER_SECRET;
  try { return fs.readFileSync(SECRET_FILE, 'utf8').trim(); } catch {}
  const secret = crypto.randomBytes(32).toString('hex');
  fs.writeFileSync(SECRET_FILE, secret, { mode: 0o600 });
  return secret;
}
const SECRET = loadSecret();
const sign = (kind, id) =>
  crypto.createHmac('sha256', SECRET).update(`${kind}:${id}`).digest('base64url').slice(0, 24);
function safeEqual(a, b) {
  const x = Buffer.from(String(a)), y = Buffer.from(String(b));
  return x.length === y.length && crypto.timingSafeEqual(x, y);
}
const ID_ALPHABET = 'abcdefghijkmnpqrstuvwxyz23456789'; // 32 символа: без похожих 0/o и 1/l
const newId = () => Array.from(crypto.randomBytes(8), b => ID_ALPHABET[b % 32]).join('');

// ---------- проверка ввода ----------
function cleanText(value, max) {
  return String(value ?? '')
    .replace(/\p{Cf}/gu, '')                 // невидимые и управляющие направлением текста символы
    .replace(/[\p{Cc}\p{Zl}\p{Zp}\s]+/gu, ' ')
    .trim().slice(0, max);
}
function cleanSettings(input, base) {
  const s = { ...base };
  if (!input || typeof input !== 'object') return s;
  if (typeof input.name === 'string') s.name = cleanText(input.name, 40) || base.name;
  for (const k of BOOL_SETTINGS) if (typeof input[k] === 'boolean') s[k] = input[k];
  for (const [k, [min, max]] of Object.entries(NUM_SETTINGS)) {
    const n = Number(input[k]);
    if (k in input && Number.isFinite(n)) s[k] = Math.min(max, Math.max(min, Math.round(n)));
  }
  return s;
}

// ---------- хранилище настроек ----------
function loadSaved() {
  try { return new Map(Object.entries(JSON.parse(fs.readFileSync(SETTINGS_FILE, 'utf8')))); }
  catch { return new Map(); }
}
const saved = loadSaved();
let saveTimer = null;
function writeSaved() {
  clearTimeout(saveTimer); saveTimer = null;
  const tmp = SETTINGS_FILE + '.tmp';
  try { fs.writeFileSync(tmp, JSON.stringify(Object.fromEntries(saved))); fs.renameSync(tmp, SETTINGS_FILE); }
  catch (e) { console.error('Не удалось сохранить настройки:', e.message); }
}
function saveSettings(ch) {
  ch.fresh = false;
  saved.delete(ch.id);           // переставляем в конец: первыми вытесняются давно не менявшиеся
  saved.set(ch.id, ch.settings);
  if (saved.size > LIMITS.savedChannels) saved.delete(saved.keys().next().value);
  if (!saveTimer) saveTimer = setTimeout(writeSaved, 500);
}

// ---------- каналы ----------
const channels = new Map();
function getChannel(id, create) {
  let ch = channels.get(id);
  if (!ch && (create || saved.has(id))) {
    ch = {
      id, settings: { ...DEFAULTS, ...saved.get(id) }, fresh: !saved.has(id),
      pending: [], history: [], overlays: new Set(), dashboards: new Set(),
      cooldowns: new Map(), touched: 0,
    };
    channels.set(id, ch);
  }
  if (ch) ch.touched = Date.now();
  return ch;
}
function publicInfo(id) {
  const ch = getChannel(id, false);
  const s = ch ? ch.settings : DEFAULTS;
  return {
    id, name: s.name, enabled: s.enabled, moderation: s.moderation,
    cooldownSec: s.cooldownSec, maxDurationSec: s.maxDurationSec,
    live: !!ch && ch.overlays.size > 0,
  };
}

// ---------- события (Server-Sent Events) ----------
const sse = (res, event, data) => res.write(`event: ${event}\ndata: ${JSON.stringify(data)}\n\n`);
const overlaySettings = (ch) => Object.fromEntries(OVERLAY_SETTINGS.map(k => [k, ch.settings[k]]));
const dashState = (ch) => ({
  settings: ch.settings, pending: ch.pending, history: ch.history,
  overlayConnected: ch.overlays.size > 0, fresh: ch.fresh,
});
function toDash(ch) {
  if (!ch.dashboards.size) return;
  const state = dashState(ch);
  ch.dashboards.forEach(res => sse(res, 'state', state));
}
const toOverlay = (ch, event, data) => ch.overlays.forEach(res => sse(res, event, data));

function play(ch, item) {
  toOverlay(ch, 'play', item);
  ch.history.unshift({ ...item, playedAt: Date.now() });
  if (ch.history.length > LIMITS.history) ch.history.length = LIMITS.history;
}

// раз в 25 секунд: пинг соединений, чистка кулдаунов и выгрузка простаивающих каналов из памяти
setInterval(() => {
  const now = Date.now();
  for (const ch of channels.values()) {
    for (const res of ch.overlays) res.write(': ping\n\n');
    for (const res of ch.dashboards) res.write(': ping\n\n');
    for (const [ip, until] of ch.cooldowns) if (until < now) ch.cooldowns.delete(ip);
    const idle = !ch.overlays.size && !ch.dashboards.size && !ch.pending.length;
    if (idle && now - ch.touched > CHANNEL_IDLE_MS) channels.delete(ch.id);
  }
}, 25000).unref();

// ---------- Coub ----------
const COUB_API = 'https://coub.com/api/v2/';
const COUB_MEDIA_RE = /^https:\/\/[a-z0-9.-]+\.coub\.com\//i;
const coubCache = new Map(); // запрос -> { promise, exp }; одинаковые запросы не дублируются

async function fetchCoub(pathAndQuery) {
  const r = await fetch(COUB_API + pathAndQuery, {
    headers: { 'User-Agent': 'Mozilla/5.0 (FreeMemeAlerts)', Accept: 'application/json' },
    signal: AbortSignal.timeout(12000),
  });
  if (!r.ok) throw Object.assign(new Error('coub ' + r.status), { coubStatus: r.status });
  return r.json();
}
function coub(pathAndQuery, ttlMs = 5 * MINUTE) {
  const hit = coubCache.get(pathAndQuery);
  if (hit && hit.exp > Date.now()) return hit.promise;
  const entry = { promise: fetchCoub(pathAndQuery), exp: Date.now() + ttlMs };
  coubCache.delete(pathAndQuery);
  coubCache.set(pathAndQuery, entry);
  if (coubCache.size > LIMITS.coubCache) coubCache.delete(coubCache.keys().next().value);
  entry.promise.catch(() => { if (coubCache.get(pathAndQuery) === entry) coubCache.delete(pathAndQuery); });
  return entry.promise;
}
// Оставляет только то, что нужно сайту, и только ссылки на медиа самого Coub.
function normalize(c) {
  if (!c || !c.permalink || c.age_restricted || c.not_safe_for_work) return null;
  const v = c.file_versions?.html5?.video, a = c.file_versions?.html5?.audio;
  const video = v?.med?.url || v?.high?.url;
  const audio = a?.med?.url || a?.high?.url || null;
  if (!video || !COUB_MEDIA_RE.test(video) || (audio && !COUB_MEDIA_RE.test(audio))) return null;
  return {
    id: c.permalink, title: cleanText(c.title, 80) || 'Без названия',
    thumb: COUB_MEDIA_RE.test(c.picture || '') ? c.picture : null,
    video, audio, duration: Number(c.duration) || 0,
  };
}
const getMeme = async (permalink) => normalize(await coub('coubs/' + permalink.toLowerCase(), 30 * MINUTE));
async function listMemes(query, pageParam) {
  const link = /coub\.com\/(?:view|embed)\/([a-z0-9]+)/i.exec(query);
  if (link) {
    const one = await getMeme(link[1]);
    return { items: one ? [one] : [], page: 1, totalPages: 1 };
  }
  const page = Math.min(COUB_MAX_PAGE, Math.max(1, parseInt(pageParam, 10) || 1));
  const data = await coub(query
    ? `search/coubs?q=${encodeURIComponent(query)}&order_by=likes_count&per_page=${COUB_PER_PAGE}&page=${page}`
    : `timeline/hot?per_page=${COUB_PER_PAGE}&page=${page}`);
  return {
    items: (data.coubs || []).map(normalize).filter(Boolean),
    page, totalPages: Math.min(COUB_MAX_PAGE, data.total_pages || 1),
  };
}

// ---------- HTTP-помощники ----------
class HttpError extends Error {
  constructor(status, message) { super(message); this.status = status; }
}
function json(res, status, data) {
  res.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' });
  res.end(JSON.stringify(data));
}
function readBody(req) {
  return new Promise((resolve, reject) => {
    let size = 0;
    const chunks = [];
    req.on('data', chunk => {
      size += chunk.length;
      if (size > LIMITS.bodyBytes) { reject(new HttpError(413, 'Слишком большой запрос')); req.destroy(); }
      else chunks.push(chunk);
    });
    req.on('end', () => {
      let body;
      try { body = chunks.length ? JSON.parse(Buffer.concat(chunks).toString('utf8')) : {}; } catch {}
      if (body && typeof body === 'object' && !Array.isArray(body)) resolve(body);
      else reject(new HttpError(400, 'Некорректный запрос'));
    });
    req.on('error', reject);
  });
}
function clientIp(req) {
  if (TRUST_PROXY) {
    const forwarded = String(req.headers['x-forwarded-for'] || '').split(',')[0].trim();
    if (forwarded) return forwarded;
  }
  return req.socket.remoteAddress || '?';
}

// лимит запросов в минуту с одного IP
const hits = new Map();
setInterval(() => hits.clear(), MINUTE).unref();
function rateLimit(req, bucket, perMinute) {
  const key = bucket + clientIp(req);
  const n = (hits.get(key) || 0) + 1;
  hits.set(key, n);
  if (n > perMinute) throw new HttpError(429, 'Слишком много запросов, подождите минуту');
}

// ---------- статические файлы ----------
const MIME = {
  '.html': 'text/html; charset=utf-8', '.css': 'text/css; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8', '.svg': 'image/svg+xml', '.png': 'image/png',
  '.ico': 'image/x-icon', '.json': 'application/json',
};
const STATIC_HEADERS = {
  'Cache-Control': 'no-cache', // браузер хранит копию, но сверяет её по ETag
  'X-Content-Type-Options': 'nosniff',
  'Referrer-Policy': 'no-referrer',
  'Content-Security-Policy': [
    "default-src 'self'", "script-src 'self' 'unsafe-inline'", "style-src 'self' 'unsafe-inline'",
    "img-src 'self' data: https://*.coub.com", 'media-src https://*.coub.com', "connect-src 'self'",
    "object-src 'none'", "base-uri 'none'", "form-action 'self'",
  ].join('; '),
};
function sendFile(req, res, file) {
  fs.stat(file, (statErr, stat) => {
    if (statErr || !stat.isFile()) {
      res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' });
      return res.end('Не найдено');
    }
    const etag = `"${stat.size.toString(36)}-${Math.round(stat.mtimeMs).toString(36)}"`;
    if (req.headers['if-none-match'] === etag) { res.writeHead(304, { ...STATIC_HEADERS, ETag: etag }); return res.end(); }
    res.writeHead(200, {
      ...STATIC_HEADERS, ETag: etag, 'Content-Length': stat.size,
      'Content-Type': MIME[path.extname(file)] || 'application/octet-stream',
    });
    if (req.method === 'HEAD') return res.end();
    fs.createReadStream(file).on('error', () => res.destroy()).pipe(res);
  });
}
const PAGES = { c: 'viewer.html', dashboard: 'dashboard.html', overlay: 'overlay.html' };
function serveStatic(req, res, url) {
  if (req.method !== 'GET' && req.method !== 'HEAD') { res.writeHead(405); return res.end(); }
  const parts = url.pathname.split('/').filter(Boolean);
  if (parts.length === 2 && PAGES[parts[0]] && ID_RE.test(parts[1])) {
    return sendFile(req, res, path.join(PUBLIC_DIR, PAGES[parts[0]]));
  }
  let rel;
  try { rel = url.pathname === '/' ? 'index.html' : decodeURIComponent(url.pathname.slice(1)); }
  catch { res.writeHead(400); return res.end(); }
  const file = path.join(PUBLIC_DIR, rel);
  if (!file.startsWith(PUBLIC_DIR + path.sep)) { res.writeHead(403); return res.end(); }
  sendFile(req, res, file);
}

// ---------- API ----------
async function handleMemes(req, res, url) {
  rateLimit(req, 'memes', 60);
  const query = cleanText(url.searchParams.get('q'), 120);
  try {
    json(res, 200, await listMemes(query, url.searchParams.get('page')));
  } catch (e) {
    if (e.coubStatus === 404) throw new HttpError(404, 'Мем не найден');
    throw new HttpError(502, 'Coub сейчас недоступен, попробуйте ещё раз');
  }
}

async function handleCreate(req, res) {
  rateLimit(req, 'create', 10);
  const body = await readBody(req);
  const id = newId();
  const ch = getChannel(id, true);
  ch.settings = cleanSettings({ name: body.name }, ch.settings);
  saveSettings(ch);
  json(res, 200, { id, key: sign('admin', id), overlayKey: sign('overlay', id) });
}

function handleInfo(req, res, url, id) {
  json(res, 200, publicInfo(id));
}

function handleEvents(req, res, url, id) {
  const key = url.searchParams.get('key') || '';
  const isDash = safeEqual(key, sign('admin', id));
  if (!isDash && !safeEqual(key, sign('overlay', id))) throw new HttpError(403, 'Неверный ключ');
  const ch = getChannel(id, true);
  const clients = isDash ? ch.dashboards : ch.overlays;
  if (clients.size >= LIMITS.clientsPerChannel) throw new HttpError(429, 'Слишком много подключений к каналу');
  res.writeHead(200, {
    'Content-Type': 'text/event-stream; charset=utf-8', 'Cache-Control': 'no-cache, no-transform',
    Connection: 'keep-alive', 'X-Accel-Buffering': 'no',
  });
  res.write('retry: 3000\n\n');
  clients.add(res);
  if (isDash) sse(res, 'state', dashState(ch));
  else { sse(res, 'settings', overlaySettings(ch)); toDash(ch); }
  req.on('close', () => {
    clients.delete(res);
    ch.touched = Date.now();
    if (!isDash) toDash(ch);
  });
}

async function handleSend(req, res, url, id) {
  rateLimit(req, 'send', 30);
  const ch = getChannel(id, false);
  if (!ch || !ch.overlays.size) throw new HttpError(409, 'Стример сейчас не в эфире (оверлей не подключён)');
  if (!ch.settings.enabled) throw new HttpError(409, 'Стример временно отключил приём мемов');
  const ip = clientIp(req);
  const wait = Math.ceil(((ch.cooldowns.get(ip) || 0) - Date.now()) / 1000);
  if (wait > 0) throw new HttpError(429, `Подождите ещё ${wait} сек.`);
  if (ch.pending.length >= LIMITS.pending) throw new HttpError(429, 'Очередь переполнена, попробуйте позже');
  const body = await readBody(req);
  const memeId = String(body.memeId || '');
  if (!/^[a-z0-9]{1,20}$/i.test(memeId)) throw new HttpError(400, 'Некорректный мем');

  // Адреса видео и звука берём только с Coub, а не от клиента.
  ch.cooldowns.set(ip, Date.now() + 3000); // от двойных кликов, пока идёт проверка
  let meme;
  try { meme = await getMeme(memeId); } catch {}
  if (!meme) {
    ch.cooldowns.delete(ip);
    throw meme === null ? new HttpError(400, 'Этот мем нельзя отправить') : new HttpError(502, 'Не удалось получить мем с Coub');
  }
  ch.cooldowns.set(ip, Date.now() + ch.settings.cooldownSec * 1000);
  const item = {
    id: crypto.randomUUID(), meme, at: Date.now(),
    nick: cleanText(body.nick, 24) || 'Аноним', message: cleanText(body.message, 100),
  };
  if (ch.settings.moderation) ch.pending.push(item); else play(ch, item);
  toDash(ch);
  json(res, 200, { ok: true, moderation: ch.settings.moderation, cooldownSec: ch.settings.cooldownSec });
}

function takePending(ch, itemId) {
  const i = ch.pending.findIndex(p => p.id === itemId);
  return i < 0 ? null : ch.pending.splice(i, 1)[0];
}
const ADMIN_ACTIONS = {
  hello() {},
  settings(ch, body) {
    const before = ch.settings.cooldownSec;
    ch.settings = cleanSettings(body.settings, ch.settings);
    if (ch.settings.cooldownSec !== before) ch.cooldowns.clear();
    saveSettings(ch);
    toOverlay(ch, 'settings', overlaySettings(ch));
  },
  approve(ch, body) {
    const item = takePending(ch, body.itemId);
    if (item) play(ch, item);
  },
  reject(ch, body) { takePending(ch, body.itemId); },
  replay(ch, body) {
    const item = ch.history.find(h => h.id === body.itemId);
    if (item) toOverlay(ch, 'play', { ...item, id: crypto.randomUUID() });
  },
  skip(ch) { toOverlay(ch, 'skip', {}); },
  clear(ch) { ch.pending = []; toOverlay(ch, 'clear', {}); },
  async test(ch) {
    let meme = null;
    try {
      const { items } = await listMemes('', 1);
      meme = items[Math.floor(Math.random() * items.length)] || null;
    } catch {}
    toOverlay(ch, 'play', {
      id: crypto.randomUUID(), nick: 'FreeMemeAlerts', message: 'Тестовый алерт — всё работает!', at: Date.now(), meme,
    });
  },
};
async function handleAdmin(req, res, url, id) {
  const body = await readBody(req);
  if (!safeEqual(body.key || '', sign('admin', id))) throw new HttpError(403, 'Неверный ключ');
  if (!Object.hasOwn(ADMIN_ACTIONS, body.do)) throw new HttpError(400, 'Неизвестное действие');
  const ch = getChannel(id, true);
  await ADMIN_ACTIONS[body.do](ch, body);
  toDash(ch);
  json(res, 200, { ok: true, overlayKey: sign('overlay', id) });
}

const ID_RE = /^[a-z0-9]{8}$/;
const CHANNEL = '/api/channels/([a-z0-9]{8})';
const ROUTES = [
  ['GET', /^\/api\/memes$/, handleMemes],
  ['POST', /^\/api\/channels$/, handleCreate],
  ['GET', new RegExp(`^${CHANNEL}$`), handleInfo],
  ['GET', new RegExp(`^${CHANNEL}/events$`), handleEvents],
  ['POST', new RegExp(`^${CHANNEL}/send$`), handleSend],
  ['POST', new RegExp(`^${CHANNEL}/admin$`), handleAdmin],
];
async function handleApi(req, res, url) {
  for (const [method, pattern, handler] of ROUTES) {
    const match = req.method === method && pattern.exec(url.pathname);
    if (match) return handler(req, res, url, match[1]);
  }
  throw new HttpError(404, 'Не найдено');
}

// ---------- сервер ----------
const server = http.createServer((req, res) => {
  let url;
  try { url = new URL(req.url, 'http://localhost'); } catch { res.writeHead(400); return res.end(); }
  if (!url.pathname.startsWith('/api/')) return serveStatic(req, res, url);
  handleApi(req, res, url).catch(e => {
    if (!(e instanceof HttpError)) console.error(e);
    if (!res.headersSent) json(res, e.status || 500, { error: e instanceof HttpError ? e.message : 'Ошибка сервера' });
  });
});

function shutdown() {
  if (saveTimer) writeSaved();
  process.exit(0);
}
process.on('SIGINT', shutdown);
process.on('SIGTERM', shutdown);

server.listen(PORT, () => console.log(`FreeMemeAlerts запущен: http://localhost:${PORT}`));
