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

/* ---------- mode (email / website) ---------- */
const fields = { sender: $('#sender'), subject: $('#subject'), body: $('#body') };
const urlField = $('#url');
let mode = 'email';
const btn = $('#analyze');
const btnLabel = () => (mode === 'email' ? 'Analyze email' : 'Check website');

function setMode(m) {
  mode = m;
  $('.tabs').dataset.mode = m;
  document.querySelectorAll('.tab').forEach((t) => t.setAttribute('aria-selected', String(t.dataset.mode === m)));
  $('#pane-email').hidden = m !== 'email';
  $('#pane-site').hidden = m !== 'site';
  if (!busy) btn.firstElementChild.textContent = btnLabel();
  $('#input-card .drop-text strong').textContent = 'Drop a screenshot here';
  $('#drop-sub').textContent = m === 'email'
    ? 'of the email · click to browse · or press Ctrl+V to paste one'
    : 'showing the page or its address bar · click or Ctrl+V';
}
document.querySelectorAll('.tab').forEach((t) => t.addEventListener('click', () => setMode(t.dataset.mode)));
document.querySelector('.tabs').addEventListener('keydown', (e) => {
  if (e.key === 'ArrowRight' || e.key === 'ArrowLeft') { setMode(mode === 'email' ? 'site' : 'email'); $('#tab-' + mode).focus(); }
});

/* ---------- samples ---------- */
const chip = (label, bad, onClick) => {
  const b = el('button', { class: 'chip ' + (bad ? 'bad' : 'good'), type: 'button', text: label });
  b.addEventListener('click', onClick);
  return b;
};
async function loadSamples() {
  try {
    (await api('/api/samples')).forEach((s) => $('#samples').append(chip(s.label, /scam|fraud|fee/i.test(s.label), () => {
      fields.sender.value = s.sender; fields.subject.value = s.subject; fields.body.value = s.body;
      analyze();
    })));
    (await api('/api/site-samples')).forEach((s) => $('#site-samples').append(chip(s.label, !/^real/i.test(s.label), () => {
      urlField.value = s.url; analyze();
    })));
  } catch (e) { console.warn(e); }
}

/* ---------- voice agent (speech output only) ---------- */
const voiceUI = { box: $('#voice'), btn: $('#speak'), label: $('#speak-label'), auto: $('#auto'), pick: $('#voice-pick'), rate: $('#rate'), cap: $('#caption') };
const synth = 'speechSynthesis' in window ? window.speechSynthesis : null;
let narration = null, speakToken = 0, voices = [];
const store = {
  get: (k, d) => { try { return localStorage.getItem(k) ?? d; } catch { return d; } },
  set: (k, v) => { try { localStorage.setItem(k, v); } catch { /* private mode */ } },
};

function loadVoices() {
  if (!synth) return;
  voices = synth.getVoices().filter((v) => /^en/i.test(v.lang));
  if (!voices.length) voices = synth.getVoices();
  const saved = store.get('pg-voice', '');
  voiceUI.pick.replaceChildren(...voices.map((v) => el('option', { value: v.voiceURI, text: v.name.replace(/Microsoft |Google /, '') + (v.localService ? '' : ' ☁') })));
  const pref = voices.find((v) => v.voiceURI === saved)
    || voices.find((v) => /natural|neural|samantha|google uk english female|aria|jenny/i.test(v.name))
    || voices.find((v) => v.default) || voices[0];
  if (pref) voiceUI.pick.value = pref.voiceURI;
}
if (synth) { loadVoices(); synth.addEventListener?.('voiceschanged', loadVoices); }
voiceUI.auto.checked = store.get('pg-auto', '1') === '1';
voiceUI.rate.value = store.get('pg-rate', '1');
voiceUI.auto.addEventListener('change', () => store.set('pg-auto', voiceUI.auto.checked ? '1' : '0'));
voiceUI.rate.addEventListener('change', () => store.set('pg-rate', voiceUI.rate.value));
voiceUI.pick.addEventListener('change', () => store.set('pg-voice', voiceUI.pick.value));

function setSpeaking(on) {
  document.body.classList.toggle('speaking', on);
  scene?.setSpeaking(on);
  voiceUI.btn.setAttribute('aria-pressed', String(on));
  voiceUI.label.textContent = on ? 'Stop' : (narration ? 'Replay' : 'Listen');
}

function stopSpeaking() {
  speakToken++;
  synth?.cancel();
  setSpeaking(false);
}

function speak(n) {
  if (!synth || !n?.chunks?.length) return;
  synth.cancel();
  const token = ++speakToken;
  const voice = voices.find((v) => v.voiceURI === voiceUI.pick.value);
  setSpeaking(true);
  const next = (i) => {
    if (token !== speakToken) return;
    if (i >= n.chunks.length) { setSpeaking(false); return; }
    const text = n.chunks[i];
    voiceUI.cap.textContent = text;
    const u = new SpeechSynthesisUtterance(text);
    if (voice) { u.voice = voice; u.lang = voice.lang; } else u.lang = 'en-US';
    u.rate = parseFloat(voiceUI.rate.value) || 1;
    u.pitch = 1;
    let beats = 0;
    u.onboundary = (e) => { if (e.name === 'word' || e.name === undefined) { scene?.beat(0.6 + 0.4 * Math.random()); beats++; } };
    // engines that don't emit word boundaries: keep a rhythmic beat so the crystal still "talks"
    const fallback = setInterval(() => { if (token === speakToken && beats < 2) scene?.beat(0.5); }, 330);
    const done = () => { clearInterval(fallback); next(i + 1); };
    u.onend = done;
    u.onerror = (e) => { clearInterval(fallback); if (e.error === 'interrupted' || e.error === 'canceled') return; next(i + 1); };
    synth.speak(u);
  };
  next(0);
}

voiceUI.btn.addEventListener('click', () => {
  if (document.body.classList.contains('speaking')) stopSpeaking();
  else if (narration) speak(narration);
});
addEventListener('keydown', (e) => { if (e.key === 'Escape') stopSpeaking(); });
addEventListener('pagehide', () => synth?.cancel());

/* ---------- analyze ---------- */
let busy = false;

function showError(msg) {
  const e = $('#error');
  e.textContent = msg; e.hidden = !msg;
}

async function analyze() {
  if (busy) return;
  let path, payload;
  if (mode === 'email') {
    payload = { sender: fields.sender.value, subject: fields.subject.value, body: fields.body.value };
    path = '/api/analyze';
    if (!Object.values(payload).some((v) => v.trim())) {
      showError('Paste an email, drop a screenshot, or pick a sample first.');
      fields.body.focus();
      return;
    }
  } else {
    payload = { url: urlField.value };
    path = '/api/analyze-url';
    if (!payload.url.trim()) { showError('Enter a website address, drop a screenshot, or pick a sample.'); urlField.focus(); return; }
  }
  stopSpeaking();
  busy = true; showError('');
  btn.disabled = true; btn.classList.add('loading'); btn.firstElementChild.textContent = 'Scanning';
  setState('scanning');
  $('#r-sub').textContent = 'SCANNING…';
  scramble($('#verdict'), 'SCANNING', 500);

  try {
    const [res] = await Promise.all([
      api(path, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload) }),
      sleep(reduced ? 0 : 1300), // let the scan animation breathe
    ]);
    await render(res);
  } catch (err) {
    setState('idle');
    $('#r-sub').textContent = 'ERROR';
    $('#verdict').textContent = 'NO SIGNAL';
    showError(err.message === 'Failed to fetch' ? 'Cannot reach the PhishGuard server. Is app.py running?' : err.message);
  } finally {
    busy = false; btn.disabled = false; btn.classList.remove('loading'); btn.firstElementChild.textContent = btnLabel();
  }
}

const STATE_OF = { SAFE: 'safe', SUSPICIOUS: 'suspicious', PHISHING: 'phishing' };

async function render(r) {
  const state = STATE_OF[r.verdict] || 'idle';
  setState(state, r.score);
  $('#r-sub').textContent = `${r.kind === 'website' ? 'WEBSITE' : 'EMAIL'} · ${r.model.toUpperCase()}`;
  $('#model-name').textContent = r.model;
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

  // voice briefing
  narration = r.narration || null;
  voiceUI.box.hidden = !synth || !narration;
  voiceUI.cap.textContent = '';
  setSpeaking(false);
  if (narration && synth && voiceUI.auto.checked) { await sleep(reduced ? 0 : 450); speak(narration); }

  if (innerWidth < 1100) $('#output-card').scrollIntoView({ behavior: reduced ? 'auto' : 'smooth', block: 'start' });
}

btn.addEventListener('click', analyze);
$('#clear').addEventListener('click', () => {
  stopSpeaking();
  Object.values(fields).forEach((f) => { f.value = ''; });
  urlField.value = '';
  clearThumb();
  narration = null; voiceUI.box.hidden = true;
  showError('');
  setState('idle');
  $('#r-sub').textContent = 'STANDBY';
  scramble($('#verdict'), 'AWAITING', 400);
  $('#score-num').textContent = '0.0';
  $('#meter-fill').style.width = '0';
  $('#results').hidden = true;
  $('#empty').hidden = false;
  (mode === 'email' ? fields.body : urlField).focus();
});
addEventListener('keydown', (e) => {
  if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') { e.preventDefault(); analyze(); }
});

/* ---------- screenshot input (drop / browse / paste) + OCR ---------- */
const drop = $('#drop'), fileInput = $('#file'), thumb = $('#drop-thumb');
let thumbUrl = '';
function clearThumb() {
  if (thumbUrl) URL.revokeObjectURL(thumbUrl);
  thumbUrl = ''; thumb.hidden = true; thumb.removeAttribute('src'); drop.classList.remove('has-img');
  $('#drop-title').textContent = 'Drop a screenshot here';
}
const setBusy = (on, text) => { $('#drop-busy').hidden = !on; if (text) $('#drop-busy-t').textContent = text; };

// Used only when the server has no Tesseract installed: OCR in the browser instead.
async function browserOcr(file) {
  setBusy(true, 'Loading OCR engine…');
  const T = await import('https://cdn.jsdelivr.net/npm/tesseract.js@5.1.1/dist/tesseract.esm.min.js');
  const rec = T.recognize || T.default?.recognize;
  const { data } = await rec(file, 'eng', { logger: (m) => { if (m.status === 'recognizing text') setBusy(true, `Reading text… ${Math.round(m.progress * 100)}%`); } });
  const text = data.text || '';
  const em = text.match(/[\w.+-]+@[\w-]+(?:\.[\w-]+)+/);
  const subj = text.match(/^\s*subject\s*[:：]\s*(.+)$/im);
  const url = (text.match(/(?:https?:\/\/|www\.)[^\s<>")\]']+/i) || text.match(/\b(?:[a-z0-9-]+\.)+[a-z]{2,24}(?:\/\S*)?/i) || [''])[0].replace(/[.,;:!?)\]]+$/, '');
  return { text, sender: em ? em[0] : '', subject: subj ? subj[1].trim() : '', body: text.trim(), url };
}

async function handleImage(file) {
  if (!file || !file.type.startsWith('image/')) { showError('That file is not an image. Drop a PNG, JPG or WebP screenshot.'); return; }
  if (file.size > 8 * 1024 * 1024) { showError('Image is larger than 8 MB.'); return; }
  showError('');
  stopSpeaking();
  clearThumb();
  thumbUrl = URL.createObjectURL(file);
  thumb.src = thumbUrl; thumb.hidden = false; drop.classList.add('has-img');
  $('#drop-title').textContent = file.name && file.name !== 'image.png' ? file.name : 'Pasted screenshot';
  setBusy(true, 'Reading text…');
  setState('scanning');
  try {
    let out;
    const fd = new FormData(); fd.append('image', file, file.name || 'screenshot.png');
    const res = await fetch('/api/ocr', { method: 'POST', body: fd });
    const data = await res.json().catch(() => ({}));
    if (res.ok) out = data;
    else if (data.fallback === 'browser') out = await browserOcr(file);
    else throw new Error(data.error || `Could not read that image (${res.status})`);
    if (!out.text?.trim()) throw new Error('No readable text found in that image.');

    if (mode === 'site') {
      if (!out.url) throw new Error('No web address found in that screenshot. Include the address bar or type it in.');
      urlField.value = out.url;
    } else {
      fields.sender.value = out.sender || '';
      fields.subject.value = out.subject || '';
      fields.body.value = out.body || out.text;
    }
    setBusy(false);
    $('#drop-sub').textContent = 'Text extracted. OCR can confuse 1 / l / 0 / O — fix any typo and re-scan';
    analyze();
  } catch (err) {
    setBusy(false);
    setState('idle');
    showError(err.message === 'Failed to fetch' ? 'Cannot reach the PhishGuard server. Is app.py running?' : err.message);
  }
}

drop.addEventListener('click', () => fileInput.click());
drop.addEventListener('keydown', (e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); fileInput.click(); } });
fileInput.addEventListener('change', () => { handleImage(fileInput.files[0]); fileInput.value = ''; });
['dragenter', 'dragover'].forEach((ev) => drop.addEventListener(ev, (e) => { e.preventDefault(); drop.classList.add('over'); }));
['dragleave', 'drop'].forEach((ev) => drop.addEventListener(ev, () => drop.classList.remove('over')));
drop.addEventListener('drop', (e) => { e.preventDefault(); handleImage(e.dataTransfer.files[0]); });
// let people drop anywhere on the input card, and stop the browser from navigating to a dropped file
addEventListener('dragover', (e) => e.preventDefault());
addEventListener('drop', (e) => { e.preventDefault(); if (!drop.contains(e.target)) handleImage(e.dataTransfer?.files?.[0]); });
addEventListener('paste', (e) => {
  const item = [...(e.clipboardData?.items || [])].find((i) => i.type.startsWith('image/'));
  if (item) { e.preventDefault(); handleImage(item.getAsFile()); }
});

setMode('email');
loadStatus();
loadStats();
loadSamples();
onScroll();
