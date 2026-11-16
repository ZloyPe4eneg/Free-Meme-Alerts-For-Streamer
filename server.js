'use strict';
// FreeMemeAlerts — бесплатные мем-алерты для стрима. Без зависимостей: только Node.js 18+.
const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { promisify } = require('util');
const scrypt = promisify(crypto.scrypt);

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
  epoch: 0, // номер «поколения» ссылки оверлея: растёт при сбросе доступа, старые ссылки перестают работать
});
const BOOL_SETTINGS = ['enabled', 'moderation', 'showSender', 'randomPosition'];
const NUM_SETTINGS = {
  cooldownSec: [0, 3600], maxDurationSec: [3, 60], volume: [0, 100], sizePct: [15, 90], epoch: [0, 1e9],
};
const OVERLAY_SETTINGS = ['volume', 'maxDurationSec', 'showSender', 'randomPosition', 'sizePct'];
const LIMITS = {
  pending: 30,           // мемов на модерации в одном канале
  history: 30,           // показанных мемов в истории
  clientsPerChannel: 10, // одновременных подключений панели и оверлея
  deviceRequests: 5,     // устройств, ожидающих разрешения показывать оверлей
  loginFails: 20,        // неверных паролей к одному каналу за 10 минут
  savedChannels: 5000,   // каналов с настройками на диске
  bodyBytes: 16384,
  coubCache: 300,
};
const MINUTE = 60 * 1000;
const CHANNEL_IDLE_MS = 30 * MINUTE;
const SESSION_DAYS = 30;
const PASSWORD_MIN = 8, PASSWORD_MAX = 128;
const DENY_MS = 10 * MINUTE; // на сколько блокируется устройство после отказа стримера
const COUB_PER_PAGE = 24;
const COUB_MAX_PAGE = 50;

fs.mkdirSync(DATA_DIR, { recursive: true });

// ---------- секрет и подписи ----------
// Всё, что даёт доступ (пароль, сессия, ссылка оверлея, разрешение устройства), проверяется
// подписью на секрете сервера и нигде не хранится, поэтому доступ переживает перезапуск,
// даже если диск хостинга не сохраняется.
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
const toChars = (bytes) => Array.from(bytes, b => ID_ALPHABET[b % 32]).join('');
const randomChars = (n) => toChars(crypto.randomBytes(n));

// ---------- доступ стримера: пароль и сессия ----------
// Адрес канала = 8 случайных символов + 8 символов «отпечатка» пароля. Отпечаток подписан
// секретом сервера, поэтому по адресу пароль не подобрать, а серверу не нужно хранить пароли.
async function passwordTag(rand, password) {
  const hash = await scrypt(password.normalize('NFKC'), 'fma:' + rand, 32);
  const mac = crypto.createHmac('sha256', SECRET).update(`pw:${rand}:`).update(hash).digest();
  return toChars(mac.subarray(0, 8));
}
const validPassword = (p) => typeof p === 'string' && p.length >= PASSWORD_MIN && p.length <= PASSWORD_MAX;
async function passwordMatches(id, password) {
  return typeof password === 'string' && password.length <= PASSWORD_MAX
    && safeEqual(id.slice(8), await passwordTag(id.slice(0, 8), password));
}

const isHttps = (req) => !!req.socket.encrypted || (TRUST_PROXY && req.headers['x-forwarded-proto'] === 'https');
function setSessionCookie(req, res, id, days) {
  const exp = Math.floor(Date.now() / 1000) + days * 86400;
  const value = days > 0 ? `${exp}.${sign('session', `${id}:${exp}`)}` : '';
  res.setHeader('Set-Cookie', `fma_${id}=${value}; Path=/; Max-Age=${Math.max(0, days * 86400)}; HttpOnly; SameSite=Strict`
    + (isHttps(req) ? '; Secure' : ''));
}
function hasSession(req, id) {
  const name = `fma_${id}=`;
  const cookie = String(req.headers.cookie || '').split(';').map(s => s.trim()).find(s => s.startsWith(name));
  if (!cookie) return false;
  const [exp, sig] = cookie.slice(name.length).split('.');
  return Number(exp) * 1000 > Date.now() && safeEqual(sig || '', sign('session', `${id}:${exp}`));
}

// ---------- доступ оверлея: ссылка и разрешённые устройства ----------
// Одной ссылки мало: устройство должно получить от стримера разрешение (ticket) в панели.
const overlayKey = (ch) => sign('overlay', `${ch.id}:${ch.settings.epoch}`);
const makeTicket = (ch, deviceId) => `${deviceId}.${sign('ticket', `${ch.id}:${ch.settings.epoch}:${deviceId}`)}`;
function validTicket(ch, ticket) {
  const [deviceId, sig] = String(ticket || '').split('.');
  return !!deviceId && safeEqual(sig || '', sign('ticket', `${ch.id}:${ch.settings.epoch}:${deviceId}`));
}

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
      requests: new Map(), // устройства, ждущие разрешения: deviceId -> { res, code, ip, at }
      denied: new Map(),   // IP, которым стример отказал: ip -> до какого времени
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
  overlayConnected: ch.overlays.size > 0, overlays: ch.overlays.size, fresh: ch.fresh,
  requests: Array.from(ch.requests, ([deviceId, r]) => ({ deviceId, code: r.code, at: r.at })),
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
    for (const r of ch.requests.values()) r.res.write(': ping\n\n');
    for (const [ip, until] of ch.cooldowns) if (until < now) ch.cooldowns.delete(ip);
    for (const [ip, until] of ch.denied) if (until < now) ch.denied.delete(ip);
    const idle = !ch.overlays.size && !ch.dashboards.size && !ch.requests.size && !ch.pending.length;
    if (idle && now - ch.touched > CHANNEL_IDLE_MS) channels.delete(ch.id);
  }
}, 25000).unref();

// ---------- фильтр 18+ ----------
// Coub почти не размечает взрослый контент своими метками, поэтому мемы отсеиваются по словам
// в названии, тегах и имени канала автора. Проверяется каждое слово целиком или его начало,
// чтобы не было ложных срабатываний вроде «class» или «Essex».
const ADULT_PREFIXES = [
  // английские
  'porn', 'sex', 'erot', 'nsfw', 'xxx', 'hentai', 'ecchi', 'nude', 'nudi', 'naked', 'boob', 'titt', 'pussy',
  'vagin', 'penis', 'blowjob', 'handjob', 'cumshot', 'orgasm', 'masturb', 'fetish', 'bdsm', 'bondage',
  'stript', 'stripp', 'lingerie', 'topless', 'upskirt', 'twerk', 'onlyfans', 'brazzers', 'playboy', 'milf',
  'lewd', 'horny', 'slut', 'whore', 'hooker', 'oppai', 'ahegao', 'futanari', 'yaoi', 'loli', 'shota',
  'nipple', 'genital', 'dildo', 'vibrator', 'booty', 'camgirl', 'thong', '18plus',
  // русские (ё уже заменена на е)
  'порн', 'секс', 'эрот', 'хентай', 'этти', 'голышом', 'обнажен', 'нюдс', 'сиськ', 'сись', 'титьк',
  'пенис', 'вагин', 'минет', 'мастурб', 'оргазм', 'стрипт', 'шлюх', 'проститут', 'интим', 'тверк',
  'фетиш', 'бдсм', 'траха', 'трахн', 'дроч', 'онлифанс', 'плейбой', 'развратн', 'возбужд', 'похот',
  'нсфв', 'милф', 'ахегао', 'лоли', 'яой', 'пошл',
];
const ADULT_WORDS = new Set([
  'ass', 'asses', 'tit', 'tits', 'cum', 'bj', 'anal', 'dick', 'dicks', 'cock', 'cocks', 'kink', 'kinky', 'fap',
  'r34', 'rule34', 'голая', 'голые', 'голый', 'голых', 'голую', 'голой', 'ню', 'анал',
]);
const ADULT_MARK_RE = /(?:^|\D)(?:18|21)\s?\+|rule\s34/;
function isAdultText(text) {
  const s = String(text ?? '').toLowerCase().replaceAll('ё', 'е');
  if (ADULT_MARK_RE.test(s)) return true;
  return s.split(/[^\p{L}\p{N}]+/u).some(word =>
    word && (ADULT_WORDS.has(word) || ADULT_PREFIXES.some(prefix => word.startsWith(prefix))));
}
function isAdultCoub(c) {
  if (c.age_restricted || c.age_restricted_by_admin || c.not_safe_for_work || c.banned) return true;
  const texts = [c.title, c.channel?.title, c.channel?.permalink];
  for (const tag of Array.isArray(c.tags) ? c.tags : []) texts.push(tag?.title);
  for (const group of Array.isArray(c.communities) ? c.communities : []) texts.push(group?.permalink);
  return texts.some(isAdultText);
}

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
  if (!c || !c.permalink || isAdultCoub(c)) return null;
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
// неверные пароли по каналам: защита от перебора с разных адресов
const loginFails = new Map();
setInterval(() => loginFails.clear(), 10 * MINUTE).unref();

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
  if (isAdultText(query)) throw new HttpError(400, 'Такой запрос запрещён: контент 18+ нельзя показывать на стриме');
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
  if (!validPassword(body.password)) {
    throw new HttpError(400, `Пароль должен быть от ${PASSWORD_MIN} до ${PASSWORD_MAX} символов`);
  }
  const rand = randomChars(8);
  const id = rand + await passwordTag(rand, body.password);
  const ch = getChannel(id, true);
  ch.settings = cleanSettings({ name: body.name }, ch.settings);
  saveSettings(ch);
  setSessionCookie(req, res, id, SESSION_DAYS);
  json(res, 200, { id });
}

async function handleLogin(req, res, url, id) {
  rateLimit(req, 'login', 10);
  const fails = loginFails.get(id) || 0;
  if (fails >= LIMITS.loginFails) throw new HttpError(429, 'Слишком много попыток входа, подождите 10 минут');
  const body = await readBody(req);
  if (!await passwordMatches(id, body.password)) {
    loginFails.set(id, fails + 1);
    throw new HttpError(403, 'Неверный пароль');
  }
  setSessionCookie(req, res, id, SESSION_DAYS);
  json(res, 200, { ok: true });
}

function handleLogout(req, res, url, id) {
  setSessionCookie(req, res, id, 0);
  json(res, 200, { ok: true });
}

function requireSession(req, id) {
  if (!hasSession(req, id)) throw new HttpError(401, 'Войдите в панель по паролю');
}

function handleInfo(req, res, url, id) {
  json(res, 200, publicInfo(id));
}

function openStream(res) {
  res.writeHead(200, {
    'Content-Type': 'text/event-stream; charset=utf-8', 'Cache-Control': 'no-cache, no-transform',
    Connection: 'keep-alive', 'X-Accel-Buffering': 'no',
  });
  res.write('retry: 3000\n\n');
}
const tooManyClients = () => new HttpError(429, 'Слишком много подключений к каналу');

// Поток событий панели стримера: только с сессией (cookie).
function handleDashEvents(req, res, url, id) {
  requireSession(req, id);
  const ch = getChannel(id, true);
  if (ch.dashboards.size >= LIMITS.clientsPerChannel) throw tooManyClients();
  openStream(res);
  ch.dashboards.add(res);
  sse(res, 'state', dashState(ch));
  req.on('close', () => { ch.dashboards.delete(res); ch.touched = Date.now(); });
}

// Поток событий оверлея: нужна действующая ссылка И разрешение стримера для этого устройства.
// Без разрешения соединение ждёт: стример видит запрос с кодом в панели и решает.
function handleOverlayEvents(req, res, url, id) {
  rateLimit(req, 'overlay', 30);
  const ch = getChannel(id, false) || { id, settings: DEFAULTS };
  if (!safeEqual(url.searchParams.get('key') || '', overlayKey(ch))) {
    throw new HttpError(403, 'Ссылка оверлея недействительна');
  }
  const channel = getChannel(id, true);
  const ip = clientIp(req);
  const approved = validTicket(channel, url.searchParams.get('ticket'));
  if (!approved) {
    if ((channel.denied.get(ip) || 0) > Date.now()) throw new HttpError(403, 'Стример отклонил это устройство');
    if (channel.requests.size >= LIMITS.deviceRequests) throw tooManyClients();
  } else if (channel.overlays.size >= LIMITS.clientsPerChannel) throw tooManyClients();

  openStream(res);
  const deviceId = randomChars(12);
  if (approved) {
    channel.overlays.add(res);
    sse(res, 'settings', overlaySettings(channel));
  } else {
    const code = String(crypto.randomInt(1000, 10000));
    channel.requests.set(deviceId, { res, code, ip, at: Date.now() });
    sse(res, 'pending', { code });
  }
  toDash(channel);
  req.on('close', () => {
    channel.requests.delete(deviceId);
    channel.overlays.delete(res);
    channel.touched = Date.now();
    toDash(channel);
  });
}

// Отключает все оверлеи и ожидающие устройства (после сброса доступа).
function dropOverlays(ch) {
  for (const res of [...ch.overlays, ...Array.from(ch.requests.values(), r => r.res)]) {
    sse(res, 'denied', { reason: 'reset' });
    res.end();
  }
  ch.overlays.clear();
  ch.requests.clear();
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
    const before = ch.settings;
    ch.settings = cleanSettings(body.settings, before);
    // Поколение ссылки можно только поднять: так браузер стримера возвращает его после потери данных сервером.
    ch.settings.epoch = Math.max(before.epoch, ch.settings.epoch);
    if (ch.settings.cooldownSec !== before.cooldownSec) ch.cooldowns.clear();
    saveSettings(ch);
    if (ch.settings.epoch !== before.epoch) dropOverlays(ch);
    else toOverlay(ch, 'settings', overlaySettings(ch));
  },
  // Разрешить устройству показывать оверлей: оно получает разрешение и сразу начинает работать.
  allowDevice(ch, body) {
    const request = ch.requests.get(body.deviceId);
    if (!request || ch.overlays.size >= LIMITS.clientsPerChannel) return;
    ch.requests.delete(body.deviceId);
    ch.overlays.add(request.res);
    sse(request.res, 'ticket', { ticket: makeTicket(ch, body.deviceId) });
    sse(request.res, 'settings', overlaySettings(ch));
  },
  denyDevice(ch, body) {
    const request = ch.requests.get(body.deviceId);
    if (!request) return;
    ch.requests.delete(body.deviceId);
    ch.denied.set(request.ip, Date.now() + DENY_MS);
    sse(request.res, 'denied', { reason: 'denied' });
    request.res.end();
  },
  // Сбросить доступ оверлея: старая ссылка и все выданные разрешения перестают работать.
  resetOverlay(ch) {
    ch.settings = { ...ch.settings, epoch: ch.settings.epoch + 1 };
    saveSettings(ch);
    dropOverlays(ch);
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
  requireSession(req, id);
  const body = await readBody(req);
  if (!Object.hasOwn(ADMIN_ACTIONS, body.do)) throw new HttpError(400, 'Неизвестное действие');
  const ch = getChannel(id, true);
  await ADMIN_ACTIONS[body.do](ch, body);
  toDash(ch);
  json(res, 200, { ok: true, overlayKey: overlayKey(ch) });
}

const ID_RE = /^[a-z0-9]{16}$/;
const CHANNEL = '/api/channels/([a-z0-9]{16})';
const ROUTES = [
  ['GET', /^\/api\/memes$/, handleMemes],
  ['POST', /^\/api\/channels$/, handleCreate],
  ['GET', new RegExp(`^${CHANNEL}$`), handleInfo],
  ['POST', new RegExp(`^${CHANNEL}/login$`), handleLogin],
  ['POST', new RegExp(`^${CHANNEL}/logout$`), handleLogout],
  ['POST', new RegExp(`^${CHANNEL}/send$`), handleSend],
  ['POST', new RegExp(`^${CHANNEL}/admin$`), handleAdmin],
  ['GET', new RegExp(`^${CHANNEL}/events$`), handleDashEvents],
  ['GET', new RegExp(`^${CHANNEL}/overlay-events$`), handleOverlayEvents],
];
// Запросы на изменение принимаются только со страниц этого же сайта.
function checkOrigin(req) {
  const origin = req.headers.origin;
  if (!origin || req.method === 'GET') return;
  let host = '';
  try { host = new URL(origin).host; } catch {}
  if (host !== req.headers.host) throw new HttpError(403, 'Запрос с чужого сайта отклонён');
}
async function handleApi(req, res, url) {
  checkOrigin(req);
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
