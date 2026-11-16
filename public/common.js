'use strict';
const $ = (sel, root = document) => root.querySelector(sel);

// el('div', {class: 'x', onclick: fn}, 'текст', child) — без innerHTML, чтобы ники и названия не могли вставить разметку
function el(tag, props, ...children) {
  const node = document.createElement(tag);
  for (const [k, v] of Object.entries(props || {})) {
    if (k.startsWith('on')) node.addEventListener(k.slice(2), v);
    else if (k === 'class') node.className = v;
    else if (v !== null && v !== undefined && v !== false) node.setAttribute(k, v === true ? '' : v);
  }
  for (const c of children.flat()) if (c !== null && c !== undefined && c !== false) node.append(c);
  return node;
}

async function api(path, body) {
  const r = await fetch('/api/' + path, body === undefined ? {} : {
    method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body),
  });
  let data = {};
  try { data = await r.json(); } catch {}
  if (!r.ok) throw Object.assign(new Error(data.error || 'Ошибка ' + r.status), { status: r.status });
  return data;
}

let toastTimer;
function toast(text, isError) {
  let t = $('#toast');
  if (!t) { t = el('div', { id: 'toast', role: 'status' }); document.body.append(t); }
  t.textContent = text;
  t.className = 'show' + (isError ? ' err' : '');
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => (t.className = ''), 3500);
}

const store = {
  get(key, fallback) { try { return JSON.parse(localStorage.getItem('fma:' + key)) ?? fallback; } catch { return fallback; } },
  set(key, value) { try { localStorage.setItem('fma:' + key, JSON.stringify(value)); } catch {} },
};

const channelId = () => location.pathname.split('/').filter(Boolean)[1] || '';

async function copyText(text) {
  try { await navigator.clipboard.writeText(text); toast('Скопировано'); }
  catch { toast('Не удалось скопировать — выделите и скопируйте вручную', true); }
}
