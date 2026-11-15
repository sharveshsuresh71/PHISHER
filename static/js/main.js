/* PhishGuard UI logic: API calls, rendering, micro-animations. */
import { createScene } from '/static/js/scene.js';

const $ = (s, r = document) => r.querySelector(s);
const el = (tag, props = {}, ...kids) => {
  const n = document.createElement(tag);
  for (const [k, v] of Object.entries(props)) {
    if (k === 'class') n.className = v;
    else if (k === 'style') n.setAttribute('style', v);
    else if (k === 'text') n.textContent = v;
    else n.setAttribute(k, v);
  }
  kids.flat().forEach((c) => n.append(c));
  return n;
};
const reduced = matchMedia('(prefers-reduced-motion: reduce)').matches;
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

/* ---------- 3D scene ---------- */
let scene = null;
try {
  const probe = document.createElement('canvas');
  if (!(probe.getContext('webgl2') || probe.getContext('webgl'))) throw new Error('WebGL unavailable');
  scene = createScene($('#stage'));
} catch (err) {
  console.warn('3D scene disabled:', err);
  document.body.classList.add('no-webgl');
}
const setState = (state, score) => {
  document.body.dataset.state = state;
  scene?.setState(state, score);
};

/* ---------- helpers ---------- */
function countUp(node, to, { suffix = '', decimals = 0, ms = 1400 } = {}) {
  const fmt = (v) => v.toLocaleString(undefined, { minimumFractionDigits: decimals, maximumFractionDigits: decimals }) + suffix;
  if (reduced) { node.textContent = fmt(to); return; }
  const t0 = performance.now();
  const tick = (t) => {
    const p = Math.min((t - t0) / ms, 1);
    node.textContent = fmt(to * (1 - Math.pow(1 - p, 3)));
    if (p < 1) requestAnimationFrame(tick);
  };
  requestAnimationFrame(tick);
}

const GLYPHS = 'ABCDEFGHJKLMNPRSTUVXYZ0123456789#%&*';
async function scramble(node, text, ms = 700) {
  if (reduced) { node.textContent = text; return; }
  const t0 = performance.now();
  await new Promise((resolve) => {
    const tick = (t) => {
      const p = Math.min((t - t0) / ms, 1);
      const settled = Math.floor(p * text.length);
      node.textContent = text.split('').map((c, i) => (i < settled || c === ' ') ? c : GLYPHS[(Math.random() * GLYPHS.length) | 0]).join('');
      p < 1 ? requestAnimationFrame(tick) : resolve();
    };
    requestAnimationFrame(tick);
  });
  node.textContent = text;
}

/* ---------- ambient micro-interactions ---------- */
document.querySelectorAll('.title span').forEach((s, i) => s.style.setProperty('--i', i));
addEventListener('pointermove', (e) => {
  document.documentElement.style.setProperty('--mx', e.clientX + 'px');
  document.documentElement.style.setProperty('--my', e.clientY + 'px');
}, { passive: true });

// scroll → scene + nav
const onScroll = () => {
  const max = document.documentElement.scrollHeight - innerHeight;
  scene?.setScroll(max > 0 ? scrollY / max : 0);
};
addEventListener('scroll', onScroll, { passive: true });

// reveal on scroll
const io = new IntersectionObserver((entries) => {
  entries.forEach((e) => { if (e.isIntersecting) { e.target.classList.add('in'); io.unobserve(e.target); } });
}, { threshold: 0.12 });
document.querySelectorAll('.reveal').forEach((n, i) => {
  n.style.setProperty('--d', (i % 4) * 90 + 'ms');
  io.observe(n);
});

// 3D tilt on cards
if (!reduced && matchMedia('(hover: hover)').matches) {
  document.querySelectorAll('.tilt').forEach((card) => {
    card.addEventListener('pointermove', (e) => {
      const r = card.getBoundingClientRect();
      const x = (e.clientX - r.left) / r.width - 0.5, y = (e.clientY - r.top) / r.height - 0.5;
      card.style.transform = `perspective(900px) rotateY(${x * 9}deg) rotateX(${-y * 9}deg) translateZ(6px)`;
    });
    card.addEventListener('pointerleave', () => { card.style.transform = ''; });
  });
}

/* ---------- API ---------- */
async function api(path, opts) {
  const res = await fetch(path, opts);
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.error || `Request failed (${res.status})`);
  return data;
}

async function loadStatus() {
  const box = $('.status'), txt = $('#status-text');
  try {
    await api('/api/health');
    box.classList.add('on'); txt.textContent = 'MODEL ONLINE';
  } catch {
    box.classList.add('off'); txt.textContent = 'API OFFLINE';
  }
}

async function loadStats() {
  try {
    const m = await api('/api/stats');
    $('#h-model').textContent = m.model;
    countUp($('#h-acc'), m.accuracy * 100, { suffix: '%', decimals: 1 });
    countUp($('#h-emails'), m.n_emails);
    countUp($('#h-feat'), m.n_features);
    $('#model-name').textContent = m.model;
    renderTelemetry(m);
  } catch (e) { console.warn(e); }
}

function renderTelemetry(m) {
  const rows = [['Accuracy', m.accuracy], ['Precision', m.precision], ['Recall', m.recall], ['F1 score', m.f1], ['ROC-AUC', m.roc_auc], ['CV F1', m.cv_f1]];
  const card = $('#metric-card');
  card.replaceChildren(
    el('div', { class: 'card-head' }, el('span', { text: 'HELD-OUT TEST METRICS' }), el('span', { class: 'mono dim', text: `${m.n_test} test emails` })),
    ...rows.map(([k, v]) => el('div', { class: 'metric' }, el('span', { text: k }), el('div', { class: 'track' }, el('i', { 'data-w': (v * 100).toFixed(1) })), el('b', { text: (v * 100).toFixed(1) + '%' }))),
  );
  const [[tp, fn], [fp, tn]] = m.confusion; // labels sorted: phishing, safe
  const max = Math.max(tp, fn, fp, tn, 1);
  const cell = (v) => el('div', { class: 'cell', style: `--v:${v / max}`, text: String(v) });
  $('#cm').replaceChildren(
    el('div'), el('div', { class: 'h', text: 'Pred. phish' }), el('div', { class: 'h', text: 'Pred. safe' }),
    el('div', { class: 'h', text: 'Phish' }), cell(tp), cell(fn),
    el('div', { class: 'h', text: 'Safe' }), cell(fp), cell(tn),
  );
  const fill = () => card.querySelectorAll('.track i').forEach((i) => { i.style.width = i.dataset.w + '%'; });
  new IntersectionObserver(([e], o) => { if (e.isIntersecting) { fill(); o.disconnect(); } }, { threshold: 0.3 }).observe(card);
}

/* ---------- samples ---------- */
const fields = { sender: $('#sender'), subject: $('#subject'), body: $('#body') };
async function loadSamples() {
  try {
    const samples = await api('/api/samples');
    const box = $('#samples');
    samples.forEach((s) => {
      const bad = /scam|fraud|fee/i.test(s.label);
      const b = el('button', { class: 'chip ' + (bad ? 'bad' : 'good'), type: 'button', text: s.label });
      b.addEventListener('click', () => {
        fields.sender.value = s.sender; fields.subject.value = s.subject; fields.body.value = s.body;
        analyze();
      });
      box.append(b);
    });
  } catch (e) { console.warn(e); }
}

/* ---------- analyze ---------- */
const btn = $('#analyze');
let busy = false;

function showError(msg) {
  const e = $('#error');
  e.textContent = msg; e.hidden = !msg;
}

async function analyze() {
  if (busy) return;
  const payload = { sender: fields.sender.value, subject: fields.subject.value, body: fields.body.value };
  if (!Object.values(payload).some((v) => v.trim())) {
    showError('Paste an email (or pick a sample) first.');
    fields.body.focus();
    return;
  }
  busy = true; showError('');
  btn.disabled = true; btn.classList.add('loading'); btn.firstElementChild.textContent = 'Scanning';
  setState('scanning');
  $('#r-sub').textContent = 'SCANNING…';
  scramble($('#verdict'), 'SCANNING', 500);

  try {
    const [res] = await Promise.all([
      api('/api/analyze', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload) }),
      sleep(reduced ? 0 : 1300), // let the scan animation breathe
    ]);
    await render(res);
  } catch (err) {
    setState('idle');
    $('#r-sub').textContent = 'ERROR';
    $('#verdict').textContent = 'NO SIGNAL';
    showError(err.message === 'Failed to fetch' ? 'Cannot reach the PhishGuard server. Is app.py running?' : err.message);
  } finally {
    busy = false; btn.disabled = false; btn.classList.remove('loading'); btn.firstElementChild.textContent = 'Analyze email';
  }
}

const STATE_OF = { SAFE: 'safe', SUSPICIOUS: 'suspicious', PHISHING: 'phishing' };

async function render(r) {
  const state = STATE_OF[r.verdict] || 'idle';
  setState(state, r.score);
  $('#r-sub').textContent = `VERDICT · ${r.model.toUpperCase()}`;
  $('#meter-fill').style.width = (r.score * 100).toFixed(1) + '%';
  countUp($('#score-num'), r.score * 100, { decimals: 1, ms: 1000 });
  scramble($('#verdict'), r.verdict, 600);

  $('#empty').hidden = true;
  $('#results').hidden = false;

  $('#signals').replaceChildren(...r.signals.map((s, i) =>
    el('li', { class: `signal ${s.kind}`, style: `--i:${i}` },
      el('span', { class: 'bar' }),
      el('div', {},
        el('strong', { text: s.title }),
        el('p', { text: s.detail }),
        el('div', { class: 'strength' }, el('i', { style: `--w:${Math.round(s.strength * 100)}%;--i:${i}` })),
      ))));

  $('#terms-wrap').hidden = !r.terms.length || r.verdict === 'SAFE';
  const maxW = Math.max(...r.terms.map((t) => t.weight), 0.0001);
  $('#terms').replaceChildren(...r.terms.map((t, i) =>
    el('span', { class: 'term', style: `--i:${i};--a:${(t.weight / maxW).toFixed(2)}`, text: t.term })));

  $('#urls-wrap').hidden = !r.urls.length;
  $('#urls').replaceChildren(...r.urls.map((u, i) => {
    const tags = [];
    if (u.ip) tags.push('raw IP');
    if (u.shortener) tags.push('shortener');
    if (u.bad_tld) tags.push('risky TLD');
    if (u.insecure) tags.push('http');
    u.lookalike.forEach((b) => tags.push('imitates ' + b));
    return el('li', { style: `--i:${i}` }, el('span', { text: u.url }),
      tags.length ? tags.map((t) => el('span', { class: 'tag', text: t })) : el('span', { class: 'tag ok', text: 'looks ok' }));
  }));

  if (innerWidth < 1100) $('#output-card').scrollIntoView({ behavior: reduced ? 'auto' : 'smooth', block: 'start' });
}

btn.addEventListener('click', analyze);
$('#clear').addEventListener('click', () => {
  Object.values(fields).forEach((f) => { f.value = ''; });
  showError('');
  setState('idle');
  $('#r-sub').textContent = 'STANDBY';
  scramble($('#verdict'), 'AWAITING', 400);
  $('#score-num').textContent = '0.0';
  $('#meter-fill').style.width = '0';
  $('#results').hidden = true;
  $('#empty').hidden = false;
  fields.body.focus();
});
addEventListener('keydown', (e) => {
  if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') { e.preventDefault(); analyze(); }
});

loadStatus();
loadStats();
loadSamples();
onScroll();
