'use strict';
// FreeMemeAlerts — бесплатные мем-алерты для стрима. Без зависимостей: только Node.js 18+.
const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const PORT = Number(process.env.PORT) || 3000;
const TRUST_PROXY = process.env.TRUST_PROXY === '1';
const PUBLIC_DIR = path.join(__dirname, 'public');
const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, 'data');
const SETTINGS_FILE = path.join(DATA_DIR, 'channels.json');

fs.mkdirSync(DATA_DIR, { recursive: true });

// ---------- ключи ----------
// Ключи каналов выводятся из секрета сервера, поэтому ссылки стримеров
// переживают перезапуск, даже если диск хостинга не сохраняется.
function loadSecret() {
  if (process.env.SERVER_SECRET) return process.env.SERVER_SECRET;
  const file = path.join(DATA_DIR, 'secret.txt');
  try { return fs.readFileSync(file, 'utf8').trim(); } catch {}
  const s = crypto.randomBytes(32).toString('hex');
  fs.writeFileSync(file, s);
  return s;
}
const SECRET = loadSecret();
const sign = (kind, id) =>
  crypto.createHmac('sha256', SECRET).update(`${kind}:${id}`).digest('base64url').slice(0, 24);
const safeEqual = (a, b) => {
  const x = Buffer.from(String(a)), y = Buffer.from(String(b));
  return x.length === y.length && crypto.timingSafeEqual(x, y);
};
const ID_RE = /^[a-z0-9]{8}$/;
const newId = () => {
  const abc = 'abcdefghijkmnpqrstuvwxyz23456789';
  return Array.from(crypto.randomBytes(8), b => abc[b % abc.length]).join('');
};

// ---------- каналы ----------
const DEFAULTS = {
  name: 'Мой стрим', enabled: true, moderation: false,
  cooldownSec: 30, maxDurationSec: 15, volume: 70, showSender: true,
};
const LIMITS = { pending: 30, history: 30 };

let savedSettings = {};
try { savedSettings = JSON.parse(fs.readFileSync(SETTINGS_FILE, 'utf8')); } catch {}
let saveTimer = null;
function persist() {
  clearTimeout(saveTimer);
  saveTimer = setTimeout(() => {
    fs.writeFile(SETTINGS_FILE, JSON.stringify(savedSettings), () => {});
  }, 500);
}

const channels = new Map();
function getChannel(id, create) {
  let ch = channels.get(id);
  if (!ch && (create || savedSettings[id])) {
    ch = {
      id, settings: { ...DEFAULTS, ...savedSettings[id] }, fresh: !savedSettings[id],
      pending: [], history: [], overlays: new Set(), dashboards: new Set(),
      cooldowns: new Map(),
    };
    channels.set(id, ch);
  }
  return ch;
}
const publicInfo = (id) => {
  const ch = getChannel(id, false);
  const s = ch ? ch.settings : DEFAULTS;
  return {
    id, name: s.name, enabled: s.enabled, moderation: s.moderation,
    cooldownSec: s.cooldownSec, maxDurationSec: s.maxDurationSec,
    live: !!ch && ch.overlays.size > 0,
  };
};

function cleanSettings(input, base) {
  const s = { ...base };
  const num = (v, min, max, d) => (Number.isFinite(+v) ? Math.min(max, Math.max(min, Math.round(+v))) : d);
  if (typeof input.name === 'string') s.name = cleanText(input.name, 40) || base.name;
  for (const k of ['enabled', 'moderation', 'showSender']) if (typeof input[k] === 'boolean') s[k] = input[k];
  if ('cooldownSec' in input) s.cooldownSec = num(input.cooldownSec, 0, 3600, base.cooldownSec);
  if ('maxDurationSec' in input) s.maxDurationSec = num(input.maxDurationSec, 3, 60, base.maxDurationSec);
  if ('volume' in input) s.volume = num(input.volume, 0, 100, base.volume);
  return s;
}
function cleanText(v, max) {
  return String(v ?? '').replace(/[\u0000-\u001f\u007f\u200b-\u200f\u2028-\u202e]/g, ' ').replace(/\s+/g, ' ').trim().slice(0, max);
}

// ---------- SSE ----------
function sse(res, event, data) {
  res.write(`event: ${event}\ndata: ${JSON.stringify(data)}\n\n`);
}
const overlaySettings = (ch) => ({
  volume: ch.settings.volume, maxDurationSec: ch.settings.maxDurationSec, showSender: ch.settings.showSender,
});
const dashState = (ch) => ({
  settings: ch.settings, pending: ch.pending, history: ch.history,
  overlayConnected: ch.overlays.size > 0, fresh: ch.fresh,
});
const toDash = (ch) => ch.dashboards.forEach(r => sse(r, 'state', dashState(ch)));
const toOverlay = (ch, event, data) => ch.overlays.forEach(r => sse(r, event, data));
setInterval(() => {
  for (const ch of channels.values()) {
    for (const r of [...ch.overlays, ...ch.dashboards]) r.write(': ping\n\n');
    const now = Date.now();
    for (const [k, t] of ch.cooldowns) if (t < now) ch.cooldowns.delete(k);
  }
}, 25000).unref();

function play(ch, item) {
  toOverlay(ch, 'play', item);
  ch.history.unshift({ ...item, playedAt: Date.now() });
  ch.history.length = Math.min(ch.history.length, LIMITS.history);
}

// ---------- Coub ----------
const COUB = 'https://coub.com/api/v2/';
const cache = new Map();
async function coub(pathAndQuery, ttlMs = 5 * 60 * 1000) {
  const hit = cache.get(pathAndQuery);
  if (hit && hit.exp > Date.now()) return hit.data;
  const r = await fetch(COUB + pathAndQuery, {
    headers: { 'User-Agent': 'Mozilla/5.0 (FreeMemeAlerts)', Accept: 'application/json' },
    signal: AbortSignal.timeout(12000),
  });
  if (!r.ok) throw Object.assign(new Error('coub ' + r.status), { status: r.status });
  const data = await r.json();
  if (cache.size > 300) cache.delete(cache.keys().next().value);
  cache.set(pathAndQuery, { data, exp: Date.now() + ttlMs });
  return data;
}
const CDN_RE = /^https:\/\/[a-z0-9.-]+\.coub\.com\//i;
function normalize(c) {
  if (!c || !c.permalink || c.age_restricted || c.not_safe_for_work) return null;
  const v = c.file_versions?.html5?.video, a = c.file_versions?.html5?.audio;
  const video = v?.med?.url || v?.high?.url;
  const audio = a?.med?.url || a?.high?.url || null;
  if (!video || !CDN_RE.test(video) || (audio && !CDN_RE.test(audio))) return null;
  return {
    id: c.permalink, title: cleanText(c.title, 80) || 'Без названия',
    thumb: CDN_RE.test(c.picture || '') ? c.picture : null,
    video, audio, duration: Number(c.duration) || 0, views: c.views_count || 0,
  };
}
async function listMemes(q, page) {
  const p = Math.min(50, Math.max(1, parseInt(page, 10) || 1));
  const link = /coub\.com\/(?:view|embed)\/([a-z0-9]+)/i.exec(q);
  if (link) {
    const one = normalize(await coub('coubs/' + link[1].toLowerCase()));
    return { items: one ? [one] : [], page: 1, totalPages: 1 };
  }
  const data = q
    ? await coub(`search/coubs?q=${encodeURIComponent(q)}&order_by=likes_count&per_page=24&page=${p}`)
    : await coub(`timeline/hot?per_page=24&page=${p}`);
  return {
    items: (data.coubs || []).map(normalize).filter(Boolean),
    page: p, totalPages: Math.min(50, data.total_pages || 1),
  };
}

// ---------- HTTP ----------
const MIME = {
  '.html': 'text/html; charset=utf-8', '.css': 'text/css; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8', '.svg': 'image/svg+xml', '.png': 'image/png',
  '.ico': 'image/x-icon', '.json': 'application/json',
};
function json(res, status, data) {
  res.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' });
  res.end(JSON.stringify(data));
}
const fail = (res, status, error) => json(res, status, { error });
function readBody(req) {
  return new Promise((resolve, reject) => {
    let size = 0; const chunks = [];
    req.on('data', c => {
      size += c.length;
      if (size > 16384) { reject(Object.assign(new Error('too large'), { status: 413 })); req.destroy(); }
      else chunks.push(c);
    });
    req.on('end', () => {
      try { resolve(chunks.length ? JSON.parse(Buffer.concat(chunks).toString('utf8')) : {}); }
      catch { reject(Object.assign(new Error('bad json'), { status: 400 })); }
    });
    req.on('error', reject);
  });
}
function clientIp(req) {
  if (TRUST_PROXY) {
    const xff = String(req.headers['x-forwarded-for'] || '').split(',')[0].trim();
    if (xff) return xff;
  }
  return req.socket.remoteAddress || '?';
}
function sendFile(res, file) {
  fs.readFile(file, (err, buf) => {
    if (err) { res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' }); return res.end('Не найдено'); }
    res.writeHead(200, {
      'Content-Type': MIME[path.extname(file)] || 'application/octet-stream',
      'Cache-Control': 'no-cache', 'X-Content-Type-Options': 'nosniff', 'Referrer-Policy': 'no-referrer',
    });
    res.end(buf);
  });
}

// общий лимит запросов с одного IP (защита от спама поиском и созданием каналов)
const hits = new Map();
setInterval(() => hits.clear(), 60000).unref();
function tooMany(req, bucket, perMinute) {
  const k = bucket + clientIp(req);
  const n = (hits.get(k) || 0) + 1;
  hits.set(k, n);
  return n > perMinute;
}

async function api(req, res, url) {
  const parts = url.pathname.split('/').filter(Boolean); // ['api', ...]
  const method = req.method;

  if (parts[1] === 'memes' && method === 'GET') {
    if (tooMany(req, 'm', 60)) return fail(res, 429, 'Слишком много запросов, подождите минуту');
    try {
      return json(res, 200, await listMemes(cleanText(url.searchParams.get('q'), 120), url.searchParams.get('page')));
    } catch (e) {
      return fail(res, e.status === 404 ? 404 : 502, e.status === 404 ? 'Мем не найден' : 'Coub сейчас недоступен, попробуйте ещё раз');
    }
  }

  if (parts[1] === 'channels' && parts.length === 2 && method === 'POST') {
    if (tooMany(req, 'c', 10)) return fail(res, 429, 'Слишком много запросов, подождите минуту');
    const body = await readBody(req);
    const id = newId();
    const ch = getChannel(id, true);
    ch.settings = cleanSettings({ name: body.name }, ch.settings);
    ch.fresh = false;
    savedSettings[id] = ch.settings; persist();
    return json(res, 200, { id, key: sign('admin', id), overlayKey: sign('overlay', id) });
  }

  if (parts[1] !== 'channels' || !ID_RE.test(parts[2] || '')) return fail(res, 404, 'Не найдено');
  const id = parts[2], action = parts[3];

  if (!action && method === 'GET') return json(res, 200, publicInfo(id));

  if (action === 'events' && method === 'GET') {
    const key = url.searchParams.get('key') || '';
    const role = safeEqual(key, sign('admin', id)) ? 'dash' : safeEqual(key, sign('overlay', id)) ? 'overlay' : null;
    if (!role) return fail(res, 403, 'Неверный ключ');
    const ch = getChannel(id, true);
    res.writeHead(200, {
      'Content-Type': 'text/event-stream; charset=utf-8', 'Cache-Control': 'no-cache, no-transform',
      Connection: 'keep-alive', 'X-Accel-Buffering': 'no',
    });
    res.write('retry: 3000\n\n');
    const set = role === 'dash' ? ch.dashboards : ch.overlays;
    set.add(res);
    if (role === 'dash') sse(res, 'state', dashState(ch));
    else { sse(res, 'settings', overlaySettings(ch)); toDash(ch); }
    req.on('close', () => { set.delete(res); if (role === 'overlay') toDash(ch); });
    return;
  }

  if (action === 'send' && method === 'POST') {
    const ch = getChannel(id, false);
    if (!ch || !ch.overlays.size) return fail(res, 409, 'Стример сейчас не в эфире (оверлей не подключён)');
    if (!ch.settings.enabled) return fail(res, 409, 'Стример временно отключил приём мемов');
    const ip = clientIp(req);
    const wait = Math.ceil(((ch.cooldowns.get(ip) || 0) - Date.now()) / 1000);
    if (wait > 0) return fail(res, 429, `Подождите ещё ${wait} сек.`);
    if (ch.pending.length >= LIMITS.pending) return fail(res, 429, 'Очередь переполнена, попробуйте позже');
    const body = await readBody(req);
    if (!/^[a-z0-9]{1,20}$/i.test(String(body.memeId || ''))) return fail(res, 400, 'Некорректный мем');
    // адреса видео и звука берём только с Coub, а не от клиента
    ch.cooldowns.set(ip, Date.now() + 3000); // от двойных кликов, пока идёт проверка
    let meme;
    try { meme = normalize(await coub('coubs/' + String(body.memeId).toLowerCase(), 30 * 60 * 1000)); }
    catch { ch.cooldowns.delete(ip); return fail(res, 502, 'Не удалось получить мем с Coub'); }
    if (!meme) { ch.cooldowns.delete(ip); return fail(res, 400, 'Этот мем нельзя отправить'); }
    ch.cooldowns.set(ip, Date.now() + ch.settings.cooldownSec * 1000);
    const item = {
      id: crypto.randomUUID(), meme, at: Date.now(),
      nick: cleanText(body.nick, 24) || 'Аноним', message: cleanText(body.message, 100),
    };
    if (ch.settings.moderation) ch.pending.push(item); else play(ch, item);
    toDash(ch);
    return json(res, 200, { ok: true, moderation: ch.settings.moderation, cooldownSec: ch.settings.cooldownSec });
  }

  if (action === 'admin' && method === 'POST') {
    const body = await readBody(req);
    if (!safeEqual(body.key || '', sign('admin', id))) return fail(res, 403, 'Неверный ключ');
    const ch = getChannel(id, true);
    const takePending = () => {
      const i = ch.pending.findIndex(p => p.id === body.itemId);
      return i < 0 ? null : ch.pending.splice(i, 1)[0];
    };
    switch (body.do) {
      case 'hello': break;
      case 'settings':
        ch.settings = cleanSettings(body.settings || {}, ch.settings);
        ch.fresh = false;
        ch.cooldowns.clear();
        savedSettings[id] = ch.settings; persist();
        toOverlay(ch, 'settings', overlaySettings(ch));
        break;
      case 'approve': { const it = takePending(); if (it) play(ch, it); break; }
      case 'reject': takePending(); break;
      case 'replay': { const it = ch.history.find(h => h.id === body.itemId); if (it) toOverlay(ch, 'play', { ...it, id: crypto.randomUUID() }); break; }
      case 'skip': toOverlay(ch, 'skip', {}); break;
      case 'clear': ch.pending = []; toOverlay(ch, 'clear', {}); break;
      case 'test': {
        let meme = null;
        try { const hot = (await listMemes('', 1)).items; meme = hot[Math.floor(Math.random() * hot.length)] || null; } catch {}
        toOverlay(ch, 'play', {
          id: crypto.randomUUID(), nick: 'FreeMemeAlerts', message: 'Тестовый алерт — всё работает!', at: Date.now(), meme,
        });
        break;
      }
      default: return fail(res, 400, 'Неизвестное действие');
    }
    toDash(ch);
    return json(res, 200, { ok: true, overlayKey: sign('overlay', id) });
  }

  return fail(res, 404, 'Не найдено');
}

const PAGES = { c: 'viewer.html', dashboard: 'dashboard.html', overlay: 'overlay.html' };
const server = http.createServer((req, res) => {
  let url;
  try { url = new URL(req.url, 'http://localhost'); } catch { res.writeHead(400); return res.end(); }
  if (url.pathname.startsWith('/api/')) {
    return api(req, res, url).catch(e => {
      if (!res.headersSent) fail(res, e.status || 500, e.status ? 'Некорректный запрос' : 'Ошибка сервера');
      if (!e.status) console.error(e);
    });
  }
  if (req.method !== 'GET' && req.method !== 'HEAD') { res.writeHead(405); return res.end(); }
  const parts = url.pathname.split('/').filter(Boolean);
  if (parts.length === 2 && PAGES[parts[0]] && ID_RE.test(parts[1])) return sendFile(res, path.join(PUBLIC_DIR, PAGES[parts[0]]));
  let rel;
  try { rel = url.pathname === '/' ? 'index.html' : decodeURIComponent(url.pathname.slice(1)); }
  catch { res.writeHead(400); return res.end(); }
  const file = path.join(PUBLIC_DIR, rel);
  if (!file.startsWith(PUBLIC_DIR + path.sep)) { res.writeHead(403); return res.end(); }
  sendFile(res, file);
});

server.listen(PORT, () => console.log(`FreeMemeAlerts запущен: http://localhost:${PORT}`));
