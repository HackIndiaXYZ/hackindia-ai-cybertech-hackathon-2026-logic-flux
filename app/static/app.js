'use strict';
/* SentinelTrace front-end. All data comes from /api; every dynamic value is HTML-escaped. */

const PAGES = ['Overview', 'Email Analyzer', 'Header Forensics', 'Email Trace', 'Geolocation', 'Domain Intelligence',
  'Threat Intelligence', 'Relationship Graph', 'Campaigns', 'Cases', 'Evidence', 'Reports', 'Privacy & Settings'];
const DEMO_KINDS = { bec: 'PayPal BEC (invoice fraud)', credential: 'Credential phishing', ceo: 'CEO wire-transfer fraud',
  invoice: 'Suspicious invoice + attachment', legit: 'Legitimate email' };
const BUCKETS = [['legitimate', 'Legitimate', '#127A4E'], ['suspicious', 'Suspicious', '#B4650B'],
  ['phishing', 'Phishing', '#C0362C'], ['impersonation', 'Impersonation', '#6D28D9'], ['bec', 'Fraud / BEC', '#94A3B8']];
const LEVEL_COLOR = { high: '#C0362C', medium: '#B4650B', low: '#127A4E' };

const state = { page: 'Overview', current: null, config: null, file: null, caseId: null, query: '', seq: 0 };
let apiKey = sessionStorage.getItem('st_key') || '';

const $ = (s, r = document) => r.querySelector(s);
const esc = (s) => String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const slug = (s) => s.toLowerCase().replace(/[^a-z]+/g, '-');

/* ---------- helpers ---------- */
let toastTimer;
function toast(msg, isErr = false) {
  const t = $('#toast');
  t.textContent = msg;
  t.className = 'toast show' + (isErr ? ' err' : '');
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => { t.className = 'toast'; }, isErr ? 6000 : 2800);
}

async function api(path, opts = {}) {
  const headers = {};
  if (apiKey) headers['X-API-Key'] = apiKey;
  let body = opts.body;
  if (opts.json !== undefined) { headers['Content-Type'] = 'application/json'; body = JSON.stringify(opts.json); }
  let res;
  try {
    res = await fetch('/api' + path, { method: opts.method || 'GET', headers, body });
  } catch (e) {
    throw new Error('Cannot reach the server. Check your connection and try again.');
  }
  if (res.status === 401) {
    sessionStorage.removeItem('st_key'); apiKey = '';
    const k = window.prompt('This deployment is protected. Enter the API key:');
    if (k) { apiKey = k.trim(); sessionStorage.setItem('st_key', apiKey); syncKeyButton(); return api(path, opts); }
    throw new Error('API key required.');
  }
  if (opts.raw) {
    if (!res.ok) throw new Error('Request failed (' + res.status + ').');
    return res;
  }
  let data = null;
  try { data = await res.json(); } catch (e) { /* non-JSON error page */ }
  if (!res.ok) throw new Error((data && data.error) || 'Request failed (' + res.status + ').');
  return data;
}

function fmtTime(iso) {
  const d = new Date(iso);
  if (isNaN(d)) return '—';
  const same = d.toDateString() === new Date().toDateString();
  return same ? d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
    : d.toLocaleDateString([], { month: 'short', day: 'numeric' }) + ' ' + d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
}
const fmtFull = (iso) => { const d = new Date(iso); return isNaN(d) ? '—' : d.toLocaleString(); };

const riskCls = (lvl) => (lvl === 'high' ? 'high' : lvl === 'medium' ? 'med' : 'low');
const riskTag = (score, lvl) => `<span class="tag ${riskCls(lvl)}">${Number(score)}% ${esc(lvl[0].toUpperCase() + lvl.slice(1))}</span>`;
const confTag = (c, lvl) => `<span class="tag ${lvl === 'high' ? 'low' : lvl === 'medium' ? 'med' : 'gray'}">${Number(c)}% ${esc(lvl[0].toUpperCase() + lvl.slice(1))}</span>`;
function authTag(v) {
  const m = { pass: ['low', '✓ PASS'], fail: ['high', '✕ FAIL'], softfail: ['med', '⚠ SOFTFAIL'], neutral: ['med', '⚠ NEUTRAL'],
    permerror: ['med', '⚠ ERROR'], temperror: ['med', '⚠ ERROR'], none: ['gray', '— NONE'], missing: ['gray', '— NOT PRESENT'] };
  const [c, t] = m[v] || ['gray', v.toUpperCase()];
  return `<span class="tag ${c}">${esc(t)}</span>`;
}
const kvRow = (k, v, copy) => `<span class="k">${esc(k)}</span><span>${v}</span>` +
  (copy ? `<span class="copy" data-act="copy" data-v="${esc(copy)}">Copy</span>` : '<span></span>');
const kpi = (l, v, t) => `<div class="kpi"><div class="label">${esc(l)}</div><div class="val">${esc(v)}</div><div class="trend">${esc(t)}</div></div>`;
const head = (title, sub, right = '') => `<div class="page-head"><div><h1>${esc(title)}</h1>${sub ? `<p>${esc(sub)}</p>` : ''}</div><div style="display:flex;gap:8px;flex-wrap:wrap">${right}</div></div>`;
const emptyState = (title, text) => `<div class="empty"><h3>${esc(title)}</h3><p>${esc(text)}</p>
  <button class="btn primary" data-act="demo">Load Demo Threat</button> <button class="btn" data-act="goto" data-page="Email Analyzer">Open Email Analyzer</button></div>`;

/* ---------- navigation ---------- */
function buildNav() {
  const nav = $('#nav');
  PAGES.filter((p) => p !== 'Privacy & Settings').forEach((p) => {
    const d = document.createElement('div');
    d.className = 'nav-item';
    d.dataset.page = p;
    d.innerHTML = '<span class="nav-dot"></span>' + esc(p);
    nav.appendChild(d);
  });
}

function show(page, extra) {
  state.page = page;
  if (page !== 'Cases') state.caseId = null;
  document.querySelectorAll('.nav-item[data-page]').forEach((n) => n.classList.toggle('active', n.dataset.page === page));
  $('#sidebar').classList.remove('open');
  const mySeq = ++state.seq;
  const c = $('#content');
  c.innerHTML = '<div class="loader"><div class="spinner"></div><div>Loading…</div></div>';
  Promise.resolve(RENDER[page](extra)).then((html) => {
    if (mySeq !== state.seq || html === undefined) return;
    c.innerHTML = html;
    c.scrollTop = 0;
  }).catch((e) => {
    if (mySeq !== state.seq) return;
    c.innerHTML = `<div class="empty"><h3>Something went wrong</h3><p>${esc(e.message)}</p><button class="btn" data-act="goto" data-page="${esc(page)}">Retry</button></div>`;
  });
}

/* ---------- Overview ---------- */
function donut(dist) {
  const total = BUCKETS.reduce((a, [k]) => a + (dist[k] || 0), 0);
  let off = 25, segs = '';
  if (total > 0) {
    BUCKETS.forEach(([k, , col]) => {
      const pct = (dist[k] || 0) / total * 100;
      if (pct > 0) { segs += `<circle cx="21" cy="21" r="15.9155" fill="none" stroke="${col}" stroke-width="6" stroke-dasharray="${pct} ${100 - pct}" stroke-dashoffset="${off}"/>`; }
      off -= pct;
    });
  } else segs = '<circle cx="21" cy="21" r="15.9155" fill="none" stroke="#EEF1F5" stroke-width="6"/>';
  const legend = BUCKETS.map(([k, l, col]) => {
    const n = dist[k] || 0;
    return `<li><span class="swatch" style="background:${col}"></span>${esc(l)} — ${total ? Math.round(n / total * 100) : 0}% <span style="color:var(--muted)">(${n})</span></li>`;
  }).join('');
  return `<div class="donut-wrap"><svg class="donut-svg" viewBox="0 0 42 42" role="img" aria-label="Threat distribution">${segs}
    <text x="21" y="22.5" text-anchor="middle" class="num">${total}</text><text x="21" y="27" text-anchor="middle" class="lbl">EMAILS</text></svg>
    <ul class="legend">${legend}</ul></div>`;
}

function recentTable(rows) {
  if (!rows.length) return '<p style="color:var(--muted);margin:6px 0">No analyses yet. Click <b>Load Demo Threat</b> or analyze an email.</p>';
  return `<div class="scroll-x"><table><tr><th>Time</th><th>Sender</th><th>Subject</th><th>Threat Type</th><th>Risk</th><th>Origin Conf.</th><th>Status</th><th></th></tr>` +
    rows.map((r) => `<tr class="click" data-act="open" data-id="${esc(r.id)}"><td>${esc(fmtTime(r.created_at))}</td><td>${esc(r.sender)}</td>
      <td>${esc(r.subject)}</td><td>${esc(r.threat_type)}</td><td>${riskTag(r.risk, r.level)}</td>
      <td>${confTag(r.origin_conf, r.origin_conf >= 75 ? 'high' : r.origin_conf >= 45 ? 'medium' : 'low')}</td>
      <td>${esc(r.status)}</td><td><a class="link-btn">View Investigation</a></td></tr>`).join('') + '</table></div>';
}

async function renderOverview() {
  const q = state.query;
  const [st, rows] = await Promise.all([api('/stats'), api('/analyses?limit=12' + (q ? '&q=' + encodeURIComponent(q) : ''))]);
  const hero = q ? '' : `<section class="hero"><div><div class="eyebrow">SENTINELTRACE AI</div>
    <h1>AI-Powered Email Forensic &amp; Fraud Intelligence</h1><p class="tagline">Understand the risk before the click.</p></div>
    <div class="hero-actions"><button class="btn primary lg" data-act="demo">Load Demo Threat</button>
    <button class="btn ghost lg" data-act="goto" data-page="Email Analyzer">Analyze an Email</button></div></section>`;
  return hero + head('Security Overview', 'Live snapshot of email threat activity analysed by this deployment') +
    `<div class="grid-kpi">${kpi('Emails Analyzed', st.emails_analyzed.toLocaleString(), st.this_week + ' in the last 7 days')}
    ${kpi('Threats Detected', st.threats_detected.toLocaleString(), 'medium + high risk')}
    ${kpi('High Risk', st.high_risk.toLocaleString(), 'risk score ≥ 70')}
    ${kpi('Active Campaigns', st.active_campaigns, 'linked by shared infrastructure')}
    ${kpi('Cases Under Investigation', st.open_cases, 'open cases')}
    ${kpi('Threat Flag Rate', st.flag_rate + '%', 'share of mail flagged')}</div>
    <div class="row"><div class="card" style="flex:1"><h3>Threat Distribution</h3>${donut(st.distribution)}</div></div>
    <div class="card"><h3>${q ? 'Search results for “' + esc(q) + '” <a class="link-btn" data-act="clearsearch" style="margin-left:8px">clear</a>' : 'Recent Threats'}</h3>${recentTable(rows)}</div>`;
}

/* ---------- Analyzer ---------- */
function analyzerInput() {
  const kinds = Object.entries(DEMO_KINDS).map(([k, l]) => `<option value="${k}">${esc(l)}</option>`).join('');
  return `${head('Email Forensic Analyzer', 'Upload or paste a raw email to run a full forensic investigation')}
  <div class="card"><div class="dropzone" id="dropzone">
    <div class="big">Drop an .eml file here</div><div>or paste the raw email source (headers + body) below</div><div class="or">— or —</div>
    <textarea id="raw-input" maxlength="10485760" placeholder="Paste raw email headers and body here…" aria-label="Raw email source"></textarea>
    <div id="file-chip"></div>
    <div class="input-actions"><button class="btn" data-act="pickfile">Upload .eml</button>
      <button class="btn primary" id="scan-btn" data-act="scan">Analyze Email</button>
      <span style="color:var(--muted);font-size:12px">or try a sample:</span>
      <select id="demo-kind" aria-label="Sample email">${kinds}</select>
      <button class="btn" data-act="demo-select">Load Demo Threat</button></div></div></div>
  <div id="result">${state.current ? resultHTML(state.current) : ''}</div>`;
}

const LOADER_STEPS = ['Parsing MIME structure…', 'Evaluating SPF / DKIM / DMARC…', 'Checking sender & lookalike domains…',
  'Inspecting links and attachments…', 'Reconstructing SMTP trace…', 'Scoring risk & building explanation…'];

function showLoader() {
  const r = $('#result');
  if (!r) return () => {};
  r.innerHTML = '<div class="card"><div class="loader"><div class="spinner"></div><div class="step" id="loader-step"></div></div></div>';
  let i = 0;
  const tick = () => { const s = $('#loader-step'); if (s) s.textContent = LOADER_STEPS[i++ % LOADER_STEPS.length]; };
  tick();
  const t = setInterval(tick, 380);
  return () => clearInterval(t);
}

async function runScan(makeRequest) {
  state.seq++; // cancel any page render still in flight
  if (state.page !== 'Email Analyzer') { state.page = 'Email Analyzer'; $('#content').innerHTML = analyzerInput(); setActiveNav('Email Analyzer'); }
  const btn = $('#scan-btn');
  if (btn) btn.disabled = true;
  const stop = showLoader();
  try {
    const [res] = await Promise.all([makeRequest(), sleep(1300)]); // short minimum so the scan feels real
    state.current = res;
    stop();
    const r = $('#result');
    if (r) { r.innerHTML = resultHTML(res); r.scrollIntoView({ behavior: 'smooth', block: 'start' }); }
  } catch (e) {
    stop();
    const r = $('#result'); if (r) r.innerHTML = '';
    toast(e.message, true);
  } finally {
    const b = $('#scan-btn'); if (b) b.disabled = false;
  }
}

function setActiveNav(page) {
  document.querySelectorAll('.nav-item[data-page]').forEach((n) => n.classList.toggle('active', n.dataset.page === page));
}

const doDemo = (kind) => runScan(() => api('/demo?kind=' + encodeURIComponent(kind || 'bec'), { method: 'POST' }));
function doScan() {
  const text = ($('#raw-input') || {}).value || '';
  if (!state.file && !text.trim()) { toast('Paste raw email source or upload an .eml file first.', true); return; }
  runScan(() => {
    if (state.file) { const fd = new FormData(); fd.append('file', state.file); return api('/analyze', { method: 'POST', body: fd }); }
    return api('/analyze', { method: 'POST', json: { raw: text } });
  });
}
function setFile(f) {
  if (!f) return;
  if (f.size > ((state.config && state.config.max_upload_mb) || 10) * 1048576) { toast('File is too large.', true); return; }
  state.file = f;
  const chip = $('#file-chip');
  if (chip) chip.innerHTML = `<span class="filechip">📎 ${esc(f.name)} (${Math.max(1, Math.round(f.size / 1024))} KB) — ready to analyze</span>`;
}

/* ---------- Result view ---------- */
function gauge(score, level) {
  const col = LEVEL_COLOR[level];
  return `<svg class="gauge" viewBox="0 0 120 72" role="img" aria-label="Risk score ${score}%">
    <path d="M10 62 A50 50 0 0 1 110 62" pathLength="100" fill="none" stroke="#EEF1F5" stroke-width="12" stroke-linecap="round"/>
    <path class="gauge-fill" d="M10 62 A50 50 0 0 1 110 62" pathLength="100" fill="none" stroke="${col}" stroke-width="12" stroke-linecap="round" stroke-dasharray="${Math.max(0.01, score)} 100"/>
    <text x="60" y="56" text-anchor="middle" class="gauge-num">${score}%</text></svg>`;
}
const bar = (l, v, c) => `<div class="bar-row"><span>${esc(l)}</span><div class="bar-track"><div class="bar-fill" style="width:${Number(v)}%;background:${c}"></div></div><span>${Number(v)}%</span></div>`;
const reasonRow = (r) => `<div><div class="reason" data-act="toggle"><span><span class="sevdot ${esc(r.severity)}"></span>${esc(r.title)}</span><span class="link-btn">Why it matters →</span></div>
  <div class="reason-detail"><b>What we saw:</b> ${esc(r.detail)}<br><b>Why it matters:</b> ${esc(r.why)}</div></div>`;
const traceNode = (t, last) => `<div class="trace-node"><div><div class="trace-dot${t.risk ? ' warn' : ''}"></div>${last ? '' : '<div class="trace-line" style="height:30px"></div>'}</div>
  <div><div class="title">${esc(t.label)}</div><div class="meta">${esc(t.host)}${t.ip ? ' · ' + esc(t.ip) : ''} · ${esc(t.reputation)}</div></div></div>`;
const tlRow = (t) => `<div class="timeline-item"><span class="t" style="width:96px">${esc(t.t)}</span><span>${esc(t.event)}</span></div>`;
const traceHTML = (r) => `<div class="trace">${r.trace.map((t, i) => traceNode(t, i === r.trace.length - 1)).join('')}</div>`;
const originHTML = (r) => `<div class="kv">${kvRow('IP', r.origin.ip ? esc(r.origin.ip) : 'Not found', r.origin.ip)}${kvRow('Country', esc(r.origin.country))}
  ${kvRow('ISP / ASN', esc(r.origin.isp))}${kvRow('Origin Confidence', confTag(r.origin.confidence, r.origin.level))}</div>
  <div style="font-size:11.5px;color:var(--muted);margin-top:8px">${esc(r.origin.note)}</div>`;
const domainHTML = (r) => `<div class="kv">${kvRow('Domain', esc(r.domain.name))}${kvRow('Domain Age', esc(r.domain.age))}
  ${kvRow('Lookalike', r.domain.lookalike ? `<span class="tag high">YES — ${Number(r.domain.similarity)}% similarity</span>` : '<span class="tag gray">No typosquat detected</span>')}
  ${kvRow('Imitates', esc(r.domain.target || '—'))}${kvRow('Threat Intel Matches', `<span class="tag ${r.domain.intel_matches ? 'high' : 'gray'}">${Number(r.domain.intel_matches)}</span>`)}</div>`;
const intelHTML = (r) => `<table>${r.intel.map((i) => `<tr><td>${esc(i.type)}</td><td class="mono">${esc(i.value)}</td><td><span class="tag ${i.matches ? 'high' : 'gray'}">${Number(i.matches)} match${i.matches === 1 ? '' : 'es'}</span></td></tr>`).join('')}</table>
  <div style="font-size:11.5px;color:var(--muted);margin-top:8px">Matched against the local indicator list (data/threat_intel.json). No external feeds are queried.</div>`;
const authTable = (r) => `<table><tr><td>SPF</td><td>${authTag(r.auth.spf)}</td></tr><tr><td>DKIM</td><td>${authTag(r.auth.dkim)}</td></tr><tr><td>DMARC</td><td>${authTag(r.auth.dmarc)}</td></tr></table>`;
const rawHeaders = (r) => r.headers.map(([k, v]) => `${k}: ${v}`).join('\n');

function urlsAttachHTML(r) {
  const u = r.urls.length ? '<table>' + r.urls.map((x) => `<tr><td class="mono">${esc(x.url)}</td><td>${x.flags.length ? x.flags.map((f) => `<span class="flag">${esc(f)}</span>`).join('') : '<span class="tag low">No flags</span>'}</td></tr>`).join('') + '</table>' : '<p style="color:var(--muted);margin:0">No links found.</p>';
  const a = r.attachments.length ? '<table>' + r.attachments.map((x) => `<tr><td>${esc(x.name)}<div class="mono" style="color:var(--muted)">SHA-256 ${esc(x.sha256.slice(0, 24))}…</div></td><td>${Math.round(x.size / 1024) || 1} KB</td><td>${x.flags.length ? x.flags.map((f) => `<span class="flag">${esc(f)}</span>`).join('') : '<span class="tag low">No flags</span>'}</td></tr>`).join('') + '</table>' : '<p style="color:var(--muted);margin:0">No attachments.</p>';
  return `<div class="row wrap"><div class="card" style="flex:1;min-width:300px"><h3>Links (${r.urls.length})</h3>${u}</div><div class="card" style="flex:1;min-width:300px"><h3>Attachments (${r.attachments.length})</h3>${a}</div></div>`;
}

function resultHTML(r) {
  const lvl = r.risk.level;
  const id = r.identity;
  const warn = (r.warnings || []).map((w) => `<div class="banner">⚠ ${esc(w)}</div>`).join('');
  const statuses = ['New', 'Investigating', 'Confirmed Threat', 'False Positive', 'Resolved'];
  return `<div id="res-${esc(r.id)}">${warn}
  <div class="verdict-row">
    <div class="card"><h3>Risk Score</h3>${gauge(r.risk.score, lvl)}<div class="gauge-label" style="color:${LEVEL_COLOR[lvl]}">${esc(r.risk.label)} RISK</div></div>
    <div class="card"><h3>Threat Classification</h3><span class="badge ${esc(lvl)}">${esc(r.threat_type)}</span>
      <div style="font-size:13px;margin-bottom:10px"><b>AI classification:</b> ${esc(r.classification)}</div>
      <div class="pill-row"><span class="status-pill">${esc(r.status).toUpperCase()}</span><span style="font-size:12px;color:var(--muted)">Origin confidence</span>${confTag(r.origin.confidence, r.origin.level)}</div>
      <div style="font-size:11.5px;color:var(--muted);margin-top:10px">Analysis ${esc(r.id)} · ${esc(fmtFull(r.created_at))} · engine ${esc(r.engine.version)} (${Number(r.engine.duration_ms)} ms).
      Origin confidence reflects the reliability of technical evidence, not the identity of a person.</div></div>
    <div class="card"><h3>Recommended Action</h3><div class="action-head">${esc(r.recommended_action.headline)}</div>
      <ul class="action-list">${r.recommended_action.steps.map((s) => `<li>${esc(s)}</li>`).join('')}</ul></div>
  </div>
  <div class="card"><h3>Why was this email flagged? <span style="font-weight:400;color:var(--muted);font-size:12px">— Explainable AI breakdown</span></h3>
    ${r.reasons.length ? r.reasons.map(reasonRow).join('') : '<p style="color:var(--muted);margin:0">✓ No suspicious indicators were found in headers, content, links or attachments.</p>'}</div>
  <div class="row wrap">
    <div class="card" style="flex:1;min-width:300px"><h3>Email Identity</h3><div class="kv">
      ${kvRow('Sender', esc(id.sender), id.sender)}${kvRow('Display Name', esc(id.display_name), id.display_name)}${kvRow('Reply-To', esc(id.reply_to), id.reply_to)}
      ${kvRow('Recipient', esc(id.recipient), id.recipient)}${kvRow('Subject', esc(id.subject), id.subject)}${kvRow('Message-ID', esc(id.message_id), id.message_id)}</div></div>
    <div class="card" style="flex:1;min-width:300px"><h3>AI Fraud Detection — ${r.risk.score}% risk</h3>
      ${BUCKETS.map(([k, l, c]) => bar(l, r.distribution[k] || 0, c)).join('')}
      <div style="margin-top:8px;font-size:12.5px;color:var(--muted)">${r.reasons.length ? 'Detected: ' + esc(r.reasons.slice(0, 5).map((x) => x.title.toLowerCase()).join(', ')) + '.' : 'Nothing suspicious detected.'}</div></div>
  </div>
  <div class="row wrap">
    <div class="card" style="flex:1;min-width:300px"><h3>Header Analysis <button class="btn sm" style="float:right" data-act="rawtoggle">View Raw Headers</button></h3>
      <table><tr><td style="color:var(--muted)">From</td><td>${esc(id.sender)}</td></tr><tr><td style="color:var(--muted)">Return-Path</td><td>${esc(id.return_path)}</td></tr>
      <tr><td style="color:var(--muted)">Reply-To</td><td>${esc(id.reply_to)}</td></tr><tr><td style="color:var(--muted)">Date</td><td>${esc(id.date)}</td></tr></table>${authTable(r)}
      <pre class="raw">${esc(rawHeaders(r))}</pre></div>
    <div class="card" style="flex:1;min-width:300px"><h3>SMTP Trace Reconstruction</h3>${traceHTML(r)}</div>
  </div>
  <div class="row wrap">
    <div class="card" style="flex:1;min-width:300px"><h3>Origin IP Analysis</h3>${originHTML(r)}</div>
    <div class="card" style="flex:1;min-width:300px"><h3>Domain Intelligence — ${esc(r.domain.name)}</h3>${domainHTML(r)}</div>
  </div>
  <div class="row wrap">
    <div class="card" style="flex:1;min-width:300px"><h3>BEC Detection — ${Number(r.bec.confidence)}% confidence</h3>
      <div style="font-size:13px;line-height:2">${r.bec.indicators.map((i) => `<span class="${i.present ? 'check' : 'cross'}">${i.present ? '✓' : '✗'}</span> ${esc(i.name)}`).join('<br>')}</div></div>
    <div class="card" style="flex:1;min-width:300px"><h3>Threat Intelligence</h3>${intelHTML(r)}</div>
  </div>
  ${urlsAttachHTML(r)}
  <div class="card"><h3>Email Trace Timeline <span style="font-weight:400;color:var(--muted);font-size:12px">(UTC, measured)</span></h3>${r.timeline.map(tlRow).join('')}</div>
  <div style="display:flex;gap:10px;flex-wrap:wrap;align-items:center">
    <button class="btn primary" data-act="mkcase" data-id="${esc(r.id)}">Create Case</button>
    <button class="btn" data-act="goto" data-page="Evidence">Preserve Evidence</button>
    <button class="btn" data-act="report" data-id="${esc(r.id)}">Generate Report</button>
    <a class="btn" data-act="eml" data-id="${esc(r.id)}">Download .eml</a>
    <span style="margin-left:auto;font-size:12.5px;color:var(--muted)">Status
    <select data-change="astatus" data-id="${esc(r.id)}">${statuses.map((s) => `<option${s === r.status ? ' selected' : ''}>${esc(s)}</option>`).join('')}</select></span>
  </div></div>`;
}

/* ---------- pages driven by the active analysis ---------- */
const needCurrent = (title) => head(title, '') + emptyState('No email selected', 'Open an investigation from the Overview, or run an analysis, to populate this view.');

const withCurrent = (title, sub, build) => () => {
  const r = state.current;
  if (!r) return needCurrent(title);
  return head(title, sub + ' — ' + r.identity.subject) + build(r);
};

function graphHTML(r) {
  const nodes = [];
  const add = (label, type) => { if (label && label !== '—' && !nodes.some((n) => n.label === label)) nodes.push({ label, type }); };
  add(r.identity.sender.split('@').pop(), 'domain');
  if (r.identity.reply_to !== '—') add(r.identity.reply_to.split('@').pop(), 'reply');
  r.trace.forEach((t) => { if (t.ip) add(t.ip, 'ip'); });
  r.urls.slice(0, 5).forEach((u) => add(u.host, 'url'));
  r.attachments.slice(0, 3).forEach((a) => add(a.name, 'file'));
  const col = { domain: '#2554C7', reply: '#B4650B', ip: '#C0362C', url: '#6D28D9', file: '#127A4E' };
  const cx = 300, cy = 190, rx = 230, ry = 135;
  let edges = '', circles = '';
  nodes.forEach((n, i) => {
    const a = (i / nodes.length) * 2 * Math.PI - Math.PI / 2;
    const x = cx + rx * Math.cos(a), y = cy + ry * Math.sin(a);
    const label = n.label.length > 26 ? n.label.slice(0, 25) + '…' : n.label;
    edges += `<line x1="${cx}" y1="${cy}" x2="${x.toFixed(1)}" y2="${y.toFixed(1)}" stroke="#CBD5E1" stroke-width="1.5"/>`;
    circles += `<circle cx="${x.toFixed(1)}" cy="${y.toFixed(1)}" r="9" fill="${col[n.type]}"/><text x="${x.toFixed(1)}" y="${(y + 22).toFixed(1)}" text-anchor="middle">${esc(label)}</text>`;
  });
  const legend = Object.entries({ domain: 'Sender domain', reply: 'Reply-To domain', ip: 'IP address', url: 'Link host', file: 'Attachment' })
    .map(([k, l]) => `<li><span class="swatch" style="background:${col[k]}"></span>${l}</li>`).join('');
  return `<div class="card"><svg class="graph" viewBox="0 0 600 380" role="img" aria-label="Relationship graph">${edges}
    <circle cx="${cx}" cy="${cy}" r="16" fill="#0F172A"/><text x="${cx}" y="${cy + 30}" text-anchor="middle" style="font-weight:700">${esc(r.id)}</text>${circles}</svg>
    <ul class="legend" style="display:flex;gap:16px;flex-wrap:wrap">${legend}</ul></div>`;
}

/* ---------- Cases ---------- */
async function renderCases() {
  if (state.caseId) {
    const c = await api('/cases/' + encodeURIComponent(state.caseId));
    const sel = (opts, cur, id) => `<select id="${id}">${opts.map((o) => `<option${o === cur ? ' selected' : ''}>${esc(o)}</option>`).join('')}</select>`;
    return head('Case #' + c.id, c.title, `<button class="btn" data-act="goto" data-page="Cases">← All cases</button>` +
      (c.analysis_id ? `<button class="btn" data-act="open" data-id="${esc(c.analysis_id)}">Open Analysis</button><button class="btn primary" data-act="report" data-id="${esc(c.analysis_id)}">Generate Report</button>` : '')) +
      `<div class="card"><div class="kv">${kvRow('Status', sel(['Open', 'Under Investigation', 'Resolved', 'Closed'], c.status, 'case-status'))}
      ${kvRow('Priority', sel(['Low', 'Medium', 'High', 'Critical'], c.priority, 'case-priority'))}${kvRow('Assigned Analyst', esc(c.assignee))}
      ${kvRow('Opened', esc(fmtFull(c.created_at)))}${kvRow('Linked analysis', esc(c.analysis_id || '—'))}</div>
      <div style="margin-top:12px"><button class="btn primary" data-act="savecase" data-id="${esc(c.id)}">Save changes</button></div></div>
      <div class="card"><h3>Notes</h3><textarea class="note-in" id="note-in" maxlength="2000" placeholder="Add an investigation note…"></textarea>
      <div style="margin:8px 0 14px"><button class="btn" data-act="addnote" data-id="${esc(c.id)}">Add Note</button></div>
      ${c.notes.length ? c.notes.map((n) => `<div class="note"><div class="when">${esc(fmtFull(n.created_at))}</div>${esc(n.note)}</div>`).join('') : '<p style="color:var(--muted);margin:0">No notes yet.</p>'}</div>`;
  }
  const cases = await api('/cases');
  return head('Cases', 'Investigations opened from analysed emails') +
    (cases.length ? `<div class="card"><table><tr><th>Case</th><th>Title</th><th>Priority</th><th>Status</th><th>Opened</th></tr>` +
      cases.map((c) => `<tr class="click" data-act="opencase" data-id="${esc(c.id)}"><td>${esc(c.id)}</td><td>${esc(c.title)}</td>
        <td><span class="tag ${c.priority === 'High' || c.priority === 'Critical' ? 'high' : c.priority === 'Medium' ? 'med' : 'low'}">${esc(c.priority)}</span></td>
        <td><span class="status-pill">${esc(c.status).toUpperCase()}</span></td><td>${esc(fmtFull(c.created_at))}</td></tr>`).join('') + '</table></div>'
      : '<div class="empty"><h3>No cases yet</h3><p>Open an analysis and click <b>Create Case</b> to start an investigation.</p><button class="btn" data-act="goto" data-page="Overview">Go to Overview</button></div>');
}

/* ---------- other pages ---------- */
async function renderCampaigns() {
  const list = await api('/campaigns');
  return head('Campaigns', 'Flagged emails linked by shared sender, reply-to or link domains') +
    (list.length ? list.map((c) => `<div class="card"><h3>${esc(c.id)} — ${esc(c.name)}</h3><div class="kv">
      ${kvRow('Related Emails', c.emails)}${kvRow('Domains', esc(c.domains.join(', ') || '—'))}${kvRow('IP Addresses', esc(c.ips.join(', ') || '—'))}
      ${kvRow('Malicious URLs', c.urls)}${kvRow('First Seen', esc(fmtFull(c.first_seen)))}${kvRow('Last Seen', esc(fmtFull(c.last_seen)))}
      ${kvRow('Risk', riskTag(c.risk, c.level))}</div>
      <div style="margin-top:12px"><button class="btn" data-act="open" data-id="${esc(c.analysis_ids[0])}">View latest email</button></div></div>`).join('')
      : '<div class="empty"><h3>No campaigns detected</h3><p>A campaign appears when two or more flagged emails share a sender, reply-to or link domain.</p></div>');
}

async function renderEvidence() {
  const ev = await api('/evidence');
  return head('Evidence & Chain of Custody', 'Every original email is stored with a SHA-256 hash that is re-verified on each view') +
    `<div class="card">${ev.length ? `<div class="scroll-x"><table><tr><th>Evidence</th><th>Type</th><th>Timestamp</th><th>SHA-256</th><th>Size</th><th>Integrity</th><th></th></tr>` +
      ev.map((e) => `<tr><td>${esc(e.subject)}<div class="mono" style="color:var(--muted)">${esc(e.id)}</div></td><td>.eml</td><td>${esc(fmtFull(e.created_at))}</td>
      <td class="mono" title="${esc(e.sha256)}">${esc(e.sha256.slice(0, 20))}…</td><td>${Math.max(1, Math.round(e.size / 1024))} KB</td>
      <td><span class="tag ${e.verified ? 'low' : 'high'}">${e.verified ? 'VERIFIED' : 'HASH MISMATCH'}</span></td>
      <td><a class="link-btn" data-act="eml" data-id="${esc(e.id)}">Download</a></td></tr>
      <tr><td colspan="7" style="font-size:11.8px;color:var(--muted)">Custody: ${esc(e.custody.map((c) => c.action).join(' → ') || '—')}</td></tr>`).join('') + '</table></div>'
      : '<p style="color:var(--muted);margin:0">No evidence stored yet.</p>'}</div>`;
}

async function renderReports() {
  const rows = await api('/analyses?limit=25');
  return head('Forensic Investigation Reports', 'Printable reports built from the stored analysis. Use “PDF” then Save as PDF in the print dialog.') +
    `<div class="card">${rows.length ? `<table><tr><th>Analysis</th><th>Subject</th><th>Risk</th><th></th></tr>` +
      rows.map((r) => `<tr><td class="mono">${esc(r.id)}</td><td>${esc(r.subject)}</td><td>${riskTag(r.risk, r.level)}</td>
      <td style="white-space:nowrap"><button class="btn sm" data-act="report" data-id="${esc(r.id)}">Preview</button>
      <button class="btn sm" data-act="reportjson" data-id="${esc(r.id)}">Export JSON</button>
      <button class="btn sm primary" data-act="reportpdf" data-id="${esc(r.id)}">PDF</button></td></tr>`).join('') + '</table>'
      : '<p style="color:var(--muted);margin:0">Nothing to report on yet.</p>'}</div>`;
}

async function renderSettings() {
  const [cfg, audit] = await Promise.all([api('/config'), api('/audit')]);
  state.config = cfg;
  return head('Privacy, Settings & Audit', 'Deployment configuration and a tamper-evident record of analyst actions') +
    `<div class="row wrap"><div class="card" style="flex:1;min-width:300px"><h3>Deployment</h3><div class="kv">
      ${kvRow('Version', esc(cfg.version))}${kvRow('API key required', cfg.auth_required ? '<span class="tag low">Yes</span>' : '<span class="tag med">No — open access</span>')}
      ${kvRow('Data retention', cfg.retention_days ? cfg.retention_days + ' days' : 'Kept until deleted')}${kvRow('Max upload', cfg.max_upload_mb + ' MB')}
      ${kvRow('Demo data loaded', cfg.demo_data ? 'Yes' : 'No')}</div></div>
    <div class="card" style="flex:1;min-width:300px"><h3>Data handling</h3><div style="font-size:12.8px;line-height:1.9;color:var(--muted)">
      Original emails and analysis results are stored in this server's database only.<br>No email content is sent to third-party services; analysis runs locally.<br>
      Origin data describes infrastructure, never the identity of a person.</div></div></div>
    <div class="card"><h3>Audit Log</h3><div class="scroll-x"><table><tr><th>User</th><th>Action</th><th>Timestamp</th><th>Resource</th><th>Status</th></tr>` +
    audit.map((a) => `<tr><td>${esc(a.actor)}</td><td>${esc(a.action)}</td><td>${esc(fmtFull(a.ts))}</td><td class="mono">${esc(a.resource)}</td>
      <td><span class="tag ${a.status === 'OK' ? 'low' : 'high'}">${esc(a.status)}</span></td></tr>`).join('') + '</table></div></div>';
}

const RENDER = {
  'Overview': renderOverview,
  'Email Analyzer': () => analyzerInput(),
  'Header Forensics': withCurrent('Header Forensics', 'SPF, DKIM and DMARC analysis', (r) =>
    `<div class="row wrap"><div class="card" style="flex:1;min-width:300px"><h3>Authentication</h3>${authTable(r)}
    <div style="font-size:11.5px;color:var(--muted);margin-top:8px">Only trust Authentication-Results added by your own mail gateway; a sender can forge this header.</div></div>
    <div class="card" style="flex:1;min-width:300px"><h3>Identity</h3><div class="kv">${kvRow('From', esc(r.identity.sender), r.identity.sender)}${kvRow('Return-Path', esc(r.identity.return_path))}
    ${kvRow('Reply-To', esc(r.identity.reply_to))}${kvRow('Message-ID', esc(r.identity.message_id))}</div></div></div>
    <div class="card"><h3>All headers (${r.headers.length})</h3><pre class="raw open">${esc(rawHeaders(r))}</pre></div>`),
  'Email Trace': withCurrent('Email Trace', 'Reconstructed delivery path and processing timeline', (r) =>
    `<div class="row wrap"><div class="card" style="flex:1;min-width:300px"><h3>SMTP Trace</h3>${traceHTML(r)}</div>
    <div class="card" style="flex:1;min-width:300px"><h3>Processing Timeline (UTC)</h3>${r.timeline.map(tlRow).join('')}</div></div>`),
  'Geolocation': withCurrent('Geolocation', 'Origin candidate', (r) => `<div class="card"><h3>Origin candidate</h3>${originHTML(r)}</div>`),
  'Domain Intelligence': withCurrent('Domain Intelligence', 'Sender domain analysis', (r) => `<div class="card"><h3>${esc(r.domain.name)}</h3>${domainHTML(r)}</div>`),
  'Threat Intelligence': withCurrent('Threat Intelligence', 'Indicator matches', (r) => `<div class="card"><h3>Indicators</h3>${intelHTML(r)}</div>${urlsAttachHTML(r)}`),
  'Relationship Graph': withCurrent('Relationship Graph', 'Infrastructure connected to this email', graphHTML),
  'Campaigns': renderCampaigns,
  'Cases': renderCases,
  'Evidence': renderEvidence,
  'Reports': renderReports,
  'Privacy & Settings': renderSettings,
};

/* ---------- actions ---------- */
async function openAnalysis(id) {
  state.current = await api('/analyses/' + encodeURIComponent(id));
  show('Email Analyzer');
}

async function openReport(id, print) {
  const w = window.open('about:blank', '_blank');
  try {
    const res = await api(`/analyses/${encodeURIComponent(id)}/report`, { raw: true });
    const html = await res.text();
    const url = URL.createObjectURL(new Blob([html], { type: 'text/html' }));
    if (!w) { toast('Allow pop-ups to view the report.', true); return; }
    w.location.href = url;
    if (print) setTimeout(() => { try { w.print(); } catch (e) { /* user can print manually */ } }, 700);
  } catch (e) { if (w) w.close(); toast(e.message, true); }
}

async function download(path, filename) {
  const res = await api(path, { raw: true });
  const a = document.createElement('a');
  a.href = URL.createObjectURL(await res.blob());
  a.download = filename;
  document.body.appendChild(a); a.click(); a.remove();
}

const ACTIONS = {
  demo: () => doDemo('bec'),
  'demo-select': () => doDemo(($('#demo-kind') || {}).value),
  scan: doScan,
  goto: (el) => show(el.dataset.page),
  open: (el) => openAnalysis(el.dataset.id),
  pickfile: () => $('#file-input').click(),
  copy: async (el) => { try { await navigator.clipboard.writeText(el.dataset.v); toast('Copied'); } catch (e) { toast('Copy failed', true); } },
  toggle: (el) => el.nextElementSibling.classList.toggle('open'),
  rawtoggle: (el) => el.closest('.card').querySelector('pre.raw').classList.toggle('open'),
  clearsearch: () => { state.query = ''; $('#search').value = ''; show('Overview'); },
  mkcase: async (el) => { const c = await api(`/analyses/${encodeURIComponent(el.dataset.id)}/case`, { method: 'POST', json: {} }); state.caseId = c.id; show('Cases'); setActiveNav('Cases'); toast('Case ' + c.id + ' ready'); },
  opencase: (el) => { state.caseId = el.dataset.id; show('Cases'); setActiveNav('Cases'); },
  savecase: async (el) => { await api('/cases/' + encodeURIComponent(el.dataset.id), { method: 'PATCH', json: { status: $('#case-status').value, priority: $('#case-priority').value } }); toast('Case updated'); },
  addnote: async (el) => { const t = $('#note-in').value.trim(); if (!t) { toast('Write a note first.', true); return; } await api(`/cases/${encodeURIComponent(el.dataset.id)}/notes`, { method: 'POST', json: { note: t } }); show('Cases'); setActiveNav('Cases'); },
  report: (el) => openReport(el.dataset.id, false),
  reportpdf: (el) => openReport(el.dataset.id, true),
  reportjson: (el) => download(`/analyses/${encodeURIComponent(el.dataset.id)}/report?format=json`, el.dataset.id + '-report.json'),
  eml: (el) => download(`/analyses/${encodeURIComponent(el.dataset.id)}/eml`, el.dataset.id + '.eml'),
};

document.addEventListener('click', (e) => {
  const act = e.target.closest('[data-act]');
  if (act && ACTIONS[act.dataset.act]) {
    if (act.tagName === 'A') e.preventDefault();
    Promise.resolve(ACTIONS[act.dataset.act](act)).catch((err) => toast(err.message, true));
    return;
  }
  const nav = e.target.closest('.nav-item[data-page]');
  if (nav) {
    if (nav.dataset.page === 'Overview') { state.query = ''; $('#search').value = ''; }
    show(nav.dataset.page);
  }
});

document.addEventListener('change', async (e) => {
  const t = e.target;
  if (t.id === 'file-input') { setFile(t.files[0]); t.value = ''; return; }
  if (t.dataset && t.dataset.change === 'astatus') {
    try {
      await api('/analyses/' + encodeURIComponent(t.dataset.id), { method: 'PATCH', json: { status: t.value } });
      if (state.current && state.current.id === t.dataset.id) state.current.status = t.value;
      toast('Status updated');
    } catch (err) { toast(err.message, true); }
  }
});

['dragover', 'dragleave', 'drop'].forEach((ev) => document.addEventListener(ev, (e) => {
  const dz = e.target.closest && e.target.closest('#dropzone');
  if (!dz) return;
  e.preventDefault();
  dz.classList.toggle('drop-active', ev === 'dragover');
  if (ev === 'drop' && e.dataTransfer.files.length) setFile(e.dataTransfer.files[0]);
}));

$('#search').addEventListener('keydown', (e) => {
  if (e.key === 'Enter') { state.query = e.target.value.trim(); show('Overview'); }
});
$('#burger').addEventListener('click', () => $('#sidebar').classList.toggle('open'));

function syncKeyButton() { $('#apikey-reset').style.display = apiKey ? 'flex' : 'none'; }
$('#apikey-reset').addEventListener('click', () => { apiKey = ''; sessionStorage.removeItem('st_key'); syncKeyButton(); toast('API key cleared'); });

/* ---------- boot ---------- */
async function pollHealth() {
  const dot = $('#status-dot'), txt = $('#status-text');
  try {
    const res = await fetch('/api/health');
    const ok = res.ok;
    dot.style.background = ok ? '' : 'var(--red)';
    txt.textContent = ok ? 'All Systems Operational' : 'Degraded';
  } catch (e) { dot.style.background = 'var(--red)'; txt.textContent = 'Offline'; }
}

(async function boot() {
  buildNav();
  syncKeyButton();
  pollHealth();
  setInterval(pollHealth, 60000);
  try {
    state.config = await (await fetch('/api/config')).json();
    $('#demo-badge').style.display = state.config.demo_data ? '' : 'none';
  } catch (e) { /* non-fatal */ }
  show('Overview');
})();
