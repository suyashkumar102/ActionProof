// ═══════════════════════════════════════════════════════════════════
//  ActionProof — Frontend
//  Three.js background · GSAP animations · D3 transaction graph
// ═══════════════════════════════════════════════════════════════════

const API = '/v1';
const $  = id => document.getElementById(id);

// ── API ───────────────────────────────────────────────────────────
async function api(method, path, body) {
  const opts = { method, headers: { 'Content-Type': 'application/json' } };
  if (body) opts.body = JSON.stringify(body);
  const r = await fetch(API + path, opts);
  const data = await r.json();
  if (!r.ok) throw data;
  return data;
}

// ═══════════════════════════════════════════════════════════════════
//  THREE.JS — Particle network background
// ═══════════════════════════════════════════════════════════════════
(function initThree() {
  if (matchMedia('(prefers-reduced-motion: reduce)').matches || !window.THREE) return;
  const canvas = $('bg-canvas');
  let renderer;
  try {
    renderer = new THREE.WebGLRenderer({ canvas, alpha: true, antialias: true });
  } catch {
    return;
  }
  renderer.setPixelRatio(Math.min(window.devicePixelRatio, 2));

  const scene = new THREE.Scene();
  const camera = new THREE.PerspectiveCamera(60, 1, 0.1, 1000);
  camera.position.z = 80;

  // Particles
  const COUNT = 120;
  const positions = new Float32Array(COUNT * 3);
  const velocities = [];
  for (let i = 0; i < COUNT; i++) {
    positions[i * 3]     = (Math.random() - 0.5) * 160;
    positions[i * 3 + 1] = (Math.random() - 0.5) * 100;
    positions[i * 3 + 2] = (Math.random() - 0.5) * 40;
    velocities.push({
      x: (Math.random() - 0.5) * 0.04,
      y: (Math.random() - 0.5) * 0.04,
      z: (Math.random() - 0.5) * 0.01,
    });
  }

  const geo = new THREE.BufferGeometry();
  geo.setAttribute('position', new THREE.BufferAttribute(positions, 3));

  const mat = new THREE.PointsMaterial({ color: 0x1a3a6b, size: 1.2, transparent: true, opacity: 0.7 });
  const points = new THREE.Points(geo, mat);
  scene.add(points);

  // Connection lines
  const linePositions = new Float32Array(COUNT * COUNT * 6);
  const lineGeo = new THREE.BufferGeometry();
  lineGeo.setAttribute('position', new THREE.BufferAttribute(linePositions, 3));
  const lineMat = new THREE.LineSegments(
    lineGeo,
    new THREE.LineBasicMaterial({ color: 0x1a3a6b, transparent: true, opacity: 0.15 })
  );
  scene.add(lineMat);

  // Flash effect — called when a gateway event fires
  window.bgFlash = function(color) {
    const hex = color === 'red' ? 0x5a1e1b : color === 'green' ? 0x1a4731 : 0x5a3e0a;
    gsap.to(mat, { opacity: 1, duration: 0.1, yoyo: true, repeat: 1,
      onUpdate: () => { mat.color.setHex(hex); },
      onComplete: () => { mat.color.setHex(0x1a3a6b); mat.opacity = 0.7; }
    });
  };

  function resize() {
    const w = canvas.clientWidth, h = canvas.clientHeight;
    renderer.setSize(w, h, false);
    camera.aspect = w / h;
    camera.updateProjectionMatrix();
  }
  resize();
  window.addEventListener('resize', resize);

  let frame = 0;
  (function animate() {
    requestAnimationFrame(animate);
    frame++;
    const pos = geo.attributes.position.array;
    for (let i = 0; i < COUNT; i++) {
      pos[i*3]   += velocities[i].x;
      pos[i*3+1] += velocities[i].y;
      pos[i*3+2] += velocities[i].z;
      if (Math.abs(pos[i*3])   > 80) velocities[i].x *= -1;
      if (Math.abs(pos[i*3+1]) > 50) velocities[i].y *= -1;
      if (Math.abs(pos[i*3+2]) > 20) velocities[i].z *= -1;
    }
    geo.attributes.position.needsUpdate = true;

    // Update lines every 3 frames for performance
    if (frame % 3 === 0) {
      let lIdx = 0;
      const lp = lineGeo.attributes.position.array;
      for (let a = 0; a < COUNT; a++) {
        for (let b = a + 1; b < COUNT; b++) {
          const dx = pos[a*3]-pos[b*3], dy = pos[a*3+1]-pos[b*3+1];
          const dist = Math.sqrt(dx*dx + dy*dy);
          if (dist < 22 && lIdx + 6 <= lp.length) {
            lp[lIdx++]=pos[a*3]; lp[lIdx++]=pos[a*3+1]; lp[lIdx++]=pos[a*3+2];
            lp[lIdx++]=pos[b*3]; lp[lIdx++]=pos[b*3+1]; lp[lIdx++]=pos[b*3+2];
          }
        }
      }
      // zero out rest
      for (; lIdx < lp.length; lIdx++) lp[lIdx] = 0;
      lineGeo.attributes.position.needsUpdate = true;
      lineGeo.setDrawRange(0, lIdx / 3);
    }

    points.rotation.y += 0.0004;
    renderer.render(scene, camera);
  })();
})();

// ═══════════════════════════════════════════════════════════════════
//  D3 — Live transaction graph strip
// ═══════════════════════════════════════════════════════════════════
const txNodes = [];   // { id, decision, x, label }
const TX_COLORS = { ALLOW:'#3fb950', DENY:'#f85149', REQUIRE_APPROVAL:'#d29922',
                    BLOCKED:'#f85149', EXECUTED:'#3fb950', REJECTED:'#8b949e' };

function d3AddNode(decision, label) {
  const svg = d3.select('#tx-graph');
  const W = document.getElementById('tx-graph').clientWidth || 800;
  const NODE_R = 10;
  const spacing = 28;
  const id = `tx-${Date.now()}`;

  // Shift all existing nodes left
  txNodes.forEach(n => { n.x -= spacing; });
  // Remove nodes that scrolled off
  txNodes.splice(0, txNodes.filter(n => n.x < -20).length);
  // Add new node on right
  txNodes.push({ id, decision, x: W - 20, label });

  // Rebind
  const groups = svg.selectAll('g.tx-node').data(txNodes, d => d.id);

  const enter = groups.enter().append('g').attr('class', 'tx-node')
    .attr('transform', d => `translate(${d.x}, 24)`);

  enter.append('circle')
    .attr('r', 0)
    .attr('fill', d => TX_COLORS[d.decision] || '#8b949e')
    .attr('stroke', '#0d1117').attr('stroke-width', 2)
    .attr('opacity', 0.9)
    .transition().duration(300).attr('r', NODE_R);

  enter.append('text')
    .attr('y', NODE_R + 11)
    .attr('text-anchor', 'middle')
    .attr('fill', '#8b949e')
    .attr('font-size', '8px')
    .attr('font-family', 'DM Mono, monospace')
    .text(d => d.label);

  // Update existing
  groups.transition().duration(200)
    .attr('transform', d => `translate(${d.x}, 24)`);

  groups.exit().select('circle').transition().duration(200).attr('r', 0).end()
    .then(() => groups.exit().remove()).catch(() => {});

  // Draw connecting line
  if (txNodes.length > 1) {
    const lineData = txNodes.map(n => ({ x: n.x, y: 24 }));
    const line = d3.line().x(d => d.x).y(d => d.y).curve(d3.curveMonotoneX);
    svg.selectAll('path.tx-line').remove();
    svg.insert('path', ':first-child')
      .attr('class', 'tx-line')
      .attr('d', line(lineData))
      .attr('fill', 'none')
      .attr('stroke', '#30363d')
      .attr('stroke-width', 1)
      .attr('opacity', 0.5);
  }
}

// ═══════════════════════════════════════════════════════════════════
//  State
// ═══════════════════════════════════════════════════════════════════
let txCount = 0, sentCount = 0, running = false, pendingApproval = null;
let stats = { blocked: 0, allowed: 0, pending: 0 };

function updateStats(decision) {
  if (decision === 'ALLOW' || decision === 'EXECUTED') stats.allowed++;
  else if (decision === 'DENY' || decision === 'BLOCKED') stats.blocked++;
  else if (decision === 'REQUIRE_APPROVAL') stats.pending++;
  gsap.to($('stat-blocked'), { textContent: stats.blocked, snap: { textContent: 1 }, duration: .4 });
  gsap.to($('stat-allowed'), { textContent: stats.allowed, snap: { textContent: 1 }, duration: .4 });
  gsap.to($('stat-pending'), { textContent: stats.pending, snap: { textContent: 1 }, duration: .4 });
}

// ── Gateway badge ─────────────────────────────────────────────────
function setBadge(state, text) {
  const b = $('gateway-badge');
  gsap.to(b, { opacity: 0, duration: .1, onComplete: () => {
    b.className = 'gateway-badge ' + state;
    $('gateway-status-text').textContent = text;
    gsap.to(b, { opacity: 1, duration: .2 });
  }});
}

// ═══════════════════════════════════════════════════════════════════
//  GSAP helpers
// ═══════════════════════════════════════════════════════════════════
function animateIn(el, color) {
  gsap.set(el, { opacity: 0, y: -10, scale: .97 });
  gsap.to(el, { opacity: 1, y: 0, scale: 1, duration: .25, ease: 'power2.out' });
  if (color) window.bgFlash && window.bgFlash(color);
}

function shakeEl(el) {
  gsap.timeline()
    .to(el, { x: -6, duration: .06 })
    .to(el, { x:  6, duration: .06 })
    .to(el, { x: -4, duration: .05 })
    .to(el, { x:  4, duration: .05 })
    .to(el, { x:  0, duration: .05 });
}

function tickCounter(id) {
  const el = $(id);
  gsap.from(el, { opacity: 0.3, duration: .3 });
}

// ═══════════════════════════════════════════════════════════════════
//  DOM helpers
// ═══════════════════════════════════════════════════════════════════
function el(tag, cls, html) {
  const e = document.createElement(tag);
  if (cls) e.className = cls;
  if (html) e.innerHTML = html;
  return e;
}

function prepend(parent, child) {
  parent.insertBefore(child, parent.firstChild);
}

function setIdle(id, text) {
  $(id).innerHTML = `<div class="feed-idle">${text}</div>`;
}

// ═══════════════════════════════════════════════════════════════════
//  Inbox
// ═══════════════════════════════════════════════════════════════════
async function loadInbox() {
  try {
    const data = await api('GET', '/inbox');
    const list = $('inbox-list');
    if (!data.messages.length) { list.innerHTML = '<div class="inbox-empty">No messages.</div>'; return; }
    list.innerHTML = '';
    data.messages.forEach((m, i) => {
      const dangerous = m.body && (m.body.includes('SEND:') || m.body.includes('URGENT'));
      const item = el('div', `inbox-item ${dangerous ? 'inbox-danger' : ''}`,
        `<div class="inbox-from">${m.from || m.from_address || '?'}</div>
         <div class="inbox-subject">${m.subject}</div>
         ${m.attachment ? `<div class="inbox-attach">📎 ${m.attachment}</div>` : ''}`);
      list.appendChild(item);
      gsap.from(item, { opacity: 0, x: -10, duration: .3, delay: i * .08 });
    });
  } catch { $('inbox-list').innerHTML = '<div class="inbox-empty">Could not load inbox.</div>'; }
}

// ═══════════════════════════════════════════════════════════════════
//  Sent mailbox
// ═══════════════════════════════════════════════════════════════════
async function loadSent() {
  try {
    const data = await api('GET', '/mailbox/sent');
    sentCount = data.messages.length;
    $('sent-count').textContent = sentCount;
    $('mailbox-count').textContent = `${sentCount} sent`;
    const feed = $('sent-feed');
    if (!sentCount) { setIdle('sent-feed', 'No emails delivered yet.'); return; }
    feed.innerHTML = '';
    data.messages.forEach(m => {
      const item = el('div', 'sent-item',
        `<div class="sent-to">To: <b>${m.to}</b></div>
         <div class="sent-meta">${m.subject} · 📎 ${m.attachment}</div>`);
      prepend(feed, item);
      animateIn(item, 'green');
    });
  } catch {}
}

// ═══════════════════════════════════════════════════════════════════
//  Agent feed
// ═══════════════════════════════════════════════════════════════════
function agentThink(text) {
  const row = el('div', 'agent-row think-row',
    `<span class="agent-icon">💭</span><span class="agent-text">${text}</span>`);
  prepend($('agent-feed'), row);
  animateIn(row);
}

function agentToolCall(tool, args) {
  const argStr = args ? Object.entries(args).map(([k, v]) =>
    `<div class="arg-row"><span class="arg-key">${k}</span>
     <span class="arg-val ${k==='to' && String(v).includes('evil') ? 'danger-val' : ''}">${v}</span></div>`
  ).join('') : '';
  const row = el('div', 'agent-row tool-row',
    `<div class="tool-header"><span class="agent-icon">⚙</span><span class="tool-name">${tool}()</span></div>
     <div class="tool-args">${argStr}</div>`);
  prepend($('agent-feed'), row);
  animateIn(row, 'blue');
}

function agentEmail(msg) {
  const isInjected = msg.body && (msg.body.includes('SEND:') || msg.body.includes('URGENT'));
  const bodyPreview = (msg.body || '').slice(0, 160) + ((msg.body||'').length > 160 ? '…' : '');
  const injMatch = msg.body ? msg.body.match(/SEND:.*?(?=\n|$)/) : null;
  const row = el('div', `agent-row email-row ${isInjected ? 'email-injected' : ''}`,
    `<div class="email-meta">
       <span class="agent-icon">✉</span>
       <span class="email-from">${msg.from || '?'}</span>
       <span class="email-subject">${msg.subject}</span>
     </div>
     <div class="email-body-preview">${bodyPreview.replace(/\n/g, ' ')}</div>
     ${isInjected ? `<div class="injected-tag">⚠ INJECTED INSTRUCTION DETECTED<br><code>${injMatch ? injMatch[0] : ''}</code></div>` : ''}
     ${msg.attachment ? `<div class="email-attach">📎 ${msg.attachment}</div>` : ''}`);
  prepend($('agent-feed'), row);
  animateIn(row, isInjected ? 'red' : null);
}

// ═══════════════════════════════════════════════════════════════════
//  Filesystem agent events
// ═══════════════════════════════════════════════════════════════════
function agentFsList(entries) {
  if (!entries || !entries.length) return;
  const LABEL_CLS = { confidential: 'danger-val', internal: 'warn-val', public: 'safe-val' };
  const rows = entries.map(e =>
    `<div class="arg-row">
       <span class="arg-key">${e.name}</span>
       <span class="arg-val ${LABEL_CLS[e.label] || ''}">${e.label || 'unclassified'}</span>
     </div>`
  ).join('');
  const row = el('div', 'agent-row tool-row',
    `<div class="tool-header"><span class="agent-icon">📁</span><span class="tool-name">list_directory() result</span></div>
     <div class="tool-args">${rows}</div>`);
  prepend($('agent-feed'), row);
  animateIn(row);

  // Populate filesystem panel in right col
  const feed = $('fs-feed');
  feed.innerHTML = '';
  $('fs-label-count').textContent = `${entries.length} files`;
  entries.forEach((e, i) => {
    const cls = e.label === 'confidential' ? 'fs-confidential' : e.label === 'internal' ? 'fs-internal' : 'fs-public';
    const item = el('div', `fs-item ${cls}`,
      `<span class="fs-name">📄 ${e.name}</span><span class="fs-label">${e.label || 'unclassified'}</span>`);
    feed.appendChild(item);
    gsap.from(item, { opacity: 0, x: 8, duration: .25, delay: i * 0.06 });
  });
}

function agentFileRead(data) {
  const isConf = data.label === 'confidential';
  const row = el('div', `agent-row ${isConf ? 'email-injected' : 'tool-row'}`,
    `<div class="tool-header">
       <span class="agent-icon">${isConf ? '🔒' : '📄'}</span>
       <span class="tool-name">read_file("${data.path}")</span>
       <span class="fs-label-badge ${isConf ? 'label-confidential' : 'label-internal'}">${data.label}</span>
     </div>
     <div class="file-preview">${(data.preview || '')}…</div>
     ${isConf ? '<div class="injected-tag">⚠ CONFIDENTIAL label detected — data egress protection active</div>' : ''}`);
  prepend($('agent-feed'), row);
  animateIn(row, isConf ? 'red' : null);
}

// ═══════════════════════════════════════════════════════════════════
//  Gateway feed
// ═══════════════════════════════════════════════════════════════════
function showDecision(title, detail, tone) {
  const panel = $('decision-panel');
  panel.dataset.tone = tone;
  $('decision-title').textContent = title;
  $('decision-detail').textContent = detail || '';
  panel.hidden = false;
}

function gwDecision(decision, reason, txId, fingerprint) {
  const titles = { ALLOW: 'Action allowed', DENY: 'Action denied', REQUIRE_APPROVAL: 'Approval required',
    REJECTED: 'Action rejected', BLOCKED: 'Action blocked', EXECUTED: 'Action executed' };
  showDecision(titles[decision] || decision, reason, decision);
  txCount++;
  $('tx-count').textContent = `${txCount} transaction${txCount===1?'':'s'}`;
  tickCounter('tx-count');
  updateStats(decision);
  d3AddNode(decision, decision.slice(0,4));

  const cls = { ALLOW:'gw-allow', DENY:'gw-deny', REQUIRE_APPROVAL:'gw-approval',
                BLOCKED:'gw-block', EXECUTED:'gw-executed', REJECTED:'gw-block' }[decision] || 'gw-block';
  const icon = (decision==='ALLOW'||decision==='EXECUTED') ? '✓' : decision==='REQUIRE_APPROVAL' ? '◎' : '✗';
  const row = el('div', `gw-row ${cls}`,
    `<div class="gw-decision-line">
       <span class="gw-icon">${icon}</span>
       <span class="gw-decision">${decision}</span>
       <span class="gw-txid">${txId ? txId.slice(-8) : ''}</span>
     </div>
     <div class="gw-reason">${reason}</div>
     ${fingerprint ? `<div class="gw-fingerprint">FP: ${fingerprint.slice(0,30)}…</div>` : ''}`);
  prepend($('gateway-feed'), row);
  const color = (decision==='ALLOW'||decision==='EXECUTED') ? 'green' : decision==='REQUIRE_APPROVAL' ? 'amber' : 'red';
  animateIn(row, color);
}

function gwBlocked(reason, code, extra) {
  showDecision('Action blocked', reason, 'BLOCKED');
  txCount++;
  $('tx-count').textContent = `${txCount} transaction${txCount === 1 ? '' : 's'}`;
  updateStats('BLOCKED');
  d3AddNode('BLOCKED', 'BLKD');
  let extraHtml = '';
  if (extra?.approved_to) extraHtml = `<div class="tamper-diff">
    <span class="diff-approved">Approved: <b>${extra.approved_to}</b></span>
    <span class="diff-arrow">→</span>
    <span class="diff-attempted">Attempted: <b>${extra.attempted_to}</b></span></div>`;
  if (extra?.replay) extraHtml = `<div class="replay-tag">Token already consumed on first use</div>`;
  if (extra?.egress_protection) extraHtml = `
    <div class="egress-block">
      <span class="egress-label">DATA EGRESS BLOCKED</span>
      <div class="egress-detail">File label: <b>${extra.file_label}</b> → attempted destination: <b>${extra.attempted_destination}</b></div>
    </div>`;
  const row = el('div', 'gw-row gw-block',
    `<div class="gw-decision-line">
       <span class="gw-icon">✗</span>
       <span class="gw-decision">BLOCKED</span>
       <span class="gw-code">${code||''}</span>
     </div>
     <div class="gw-reason">${reason}</div>${extraHtml}`);
  prepend($('gateway-feed'), row);
  animateIn(row, 'red');
  shakeEl(row);
}

function gwExecuted(txId, to) {
  showDecision('Email delivered', to, 'EXECUTED');
  updateStats('EXECUTED');
  d3AddNode('EXECUTED', 'EXEC');
  const row = el('div', 'gw-row gw-executed',
    `<div class="gw-decision-line">
       <span class="gw-icon">✓</span>
       <span class="gw-decision">EXECUTED</span>
       <span class="gw-txid">${txId ? txId.slice(-8) : ''}</span>
     </div>
     <div class="gw-reason">Email delivered → ${to}</div>`);
  prepend($('gateway-feed'), row);
  animateIn(row, 'green');
}

function showRegistryEvent(data) {
  const row = el('div', `gw-row ${data.tampered ? 'gw-block' : 'gw-allow'}`,
    `<div class="gw-decision-line">
       <span class="gw-icon">${data.tampered ? '⚠' : '✓'}</span>
       <span class="gw-decision">REGISTRY ${data.tampered ? 'DRIFT DETECTED' : data.restored ? 'RESTORED' : 'CLEAN'}</span>
     </div>
     <div class="gw-reason">${data.hash}</div>
     ${data.injected ? `<div class="injected-tag">Injected: "${data.injected.slice(0,80)}…"</div>` : ''}`);
  prepend($('gateway-feed'), row);
  animateIn(row, data.tampered ? 'red' : 'green');
  if (data.tampered) shakeEl(row);
  d3AddNode(data.tampered ? 'BLOCKED' : 'ALLOW', data.tampered ? 'DRFT' : 'REG');
}

// ═══════════════════════════════════════════════════════════════════
//  Approval queue
// ═══════════════════════════════════════════════════════════════════
function showApprovalCard(data) {
  pendingApproval = data;
  $('approval-status').textContent = '1 pending';
  const q = $('approval-queue');
  q.innerHTML = `
    <div class="approval-card" id="active-approval">
      <div class="approval-header">
        <span class="approval-badge">⚠ AWAITING YOUR APPROVAL</span>
        <span class="approval-fp">FP: ${(data.fingerprint||'').slice(0,18)}…</span>
      </div>
      <dl class="approval-dl">
        <dt>Recipient</dt><dd>${data.args.to || '?'}</dd>
        <dt>Subject</dt><dd>${data.args.subject || '?'}</dd>
        <dt>Attachment</dt><dd>📎 ${data.args.attachment || 'none'}</dd>
        <dt>Transaction</dt><dd class="mono">${(data.transaction_id||'').slice(-12)}</dd>
      </dl>
      <p class="approval-warning">Any field change invalidates the token.</p>
      <div class="approval-btns">
        <button class="btn-approve" onclick="doApprove()">Approve exact action</button>
        <button class="btn-reject" onclick="doReject()">Reject</button>
      </div>
    </div>`;
  setBadge('needs-approval', 'AWAITING APPROVAL');
  animateIn($('active-approval'), 'amber');
  // Pulse the card
  gsap.to($('active-approval'), { boxShadow: '0 0 20px rgba(210,153,34,0.4)', repeat: -1, yoyo: true, duration: 1 });
}

function clearApprovalCard() {
  pendingApproval = null;
  $('approval-status').textContent = 'idle';
  gsap.killTweensOf($('active-approval'));
  setIdle('approval-queue', 'No pending approvals.');
  setBadge('active', 'GATEWAY ACTIVE');
}

async function doApprove() {
  if (!pendingApproval) return;
  const { transaction_id } = pendingApproval;
  const approveBtns = document.querySelector('.btn-approve');
  const rejectBtn   = document.querySelector('.btn-reject');
  if (approveBtns) approveBtns.disabled = true;
  if (rejectBtn)   rejectBtn.disabled   = true;
  try {
    const ap = await api('POST', `/transactions/${transaction_id}/approve`);
    const card = $('active-approval');
    if (card) {
      card.className = 'approval-card approved-card';
      card.querySelector('.approval-header').innerHTML =
        `<span class="approval-badge approved-badge">✓ APPROVED</span>
         <span class="approval-fp">Expires: ${new Date(ap.expires_at).toLocaleTimeString()}</span>`;
      const btns = card.querySelector('.approval-btns');
      if (btns) btns.remove();
      gsap.to(card, { boxShadow: '0 0 20px rgba(63,185,80,0.4)', duration: .4 });
    }
    const inv = { server_id: 'mock-email-v1', tool_name: 'send_email', arguments: pendingApproval.args };
    await api('POST', `/transactions/${transaction_id}/execute`, { invocation: inv, approval_token: ap.token });
    gwExecuted(transaction_id, pendingApproval.args.to);
    await loadSent();
    clearApprovalCard();
  } catch(e) {
    const code = e.detail?.code || 'BLOCKED';
    const msg  = e.detail?.message || JSON.stringify(e);
    gwBlocked(msg, code);
    if ($('active-approval')) shakeEl($('active-approval'));
    clearApprovalCard();
  }
}

async function doReject() {
  if (!pendingApproval) return;
  await api('POST', `/transactions/${pendingApproval.transaction_id}/reject`);
  gwDecision('REJECTED', 'User rejected the transaction.', pendingApproval.transaction_id, '');
  clearApprovalCard();
}

// ═══════════════════════════════════════════════════════════════════
//  Workflow runner
// ═══════════════════════════════════════════════════════════════════
const WORKFLOW_META = {
  read_and_act:    { title: 'Read & Act', sub: 'Agent reads inbox → finds injected instruction → gateway blocks exfiltration' },
  approval_tamper: { title: 'Approval Tampering', sub: 'User approves recipient → agent swaps to attacker → fingerprint mismatch' },
  registry_tamper: { title: 'Tool Definition Poisoning', sub: 'Tool description poisoned after registration → registry drift detected' },
  token_replay:    { title: 'Token Replay', sub: 'Approval token consumed on first use → rejected on second' },
  file_exfil:      { title: 'File Exfiltration', sub: 'Agent reads confidential file → attempts to email it externally → data egress blocked' },
};

async function runWorkflow(wf) {
  if (running) return;
  running = true;
  const controls = document.querySelectorAll('.wf-btn, #btn-reset, #start-demo');
  controls.forEach(button => button.disabled = true);
  try {
    await streamWorkflow(wf);
  } catch {
    $('agent-status').textContent = 'interrupted';
    setBadge('idle', 'RUN INTERRUPTED');
    setIdle('agent-feed', 'The demo connection was interrupted. Select a workflow to try again.');
  } finally {
    running = false;
    controls.forEach(button => button.disabled = false);
  }
}

async function streamWorkflow(wf) {
  $('decision-panel').hidden = true;
  $('demo-intro').hidden = true;
  stats = { blocked: 0, allowed: 0, pending: 0 };
  ['stat-blocked', 'stat-allowed', 'stat-pending'].forEach(id => $(id).textContent = '0');
  txCount = 0; txNodes.length = 0;
  d3.select('#tx-graph').selectAll('*').remove();

  const meta = WORKFLOW_META[wf];

  // Animate header in
  gsap.from('#workflow-title', { opacity: 0, y: -6, duration: .3 });
  gsap.from('#workflow-sub',   { opacity: 0, y: -4, duration: .3, delay: .1 });
  $('workflow-title').textContent = meta.title;
  $('workflow-sub').textContent   = meta.sub;
  $('tx-count').textContent = '0 transactions';
  $('agent-status').textContent = 'running';
  $('agent-feed').innerHTML   = '';
  $('gateway-feed').innerHTML = '';
  setIdle('approval-queue', 'No pending approvals.');
  setIdle('sent-feed', 'No emails delivered yet.');
  setBadge('active', 'GATEWAY ACTIVE');

  document.querySelectorAll('.wf-btn').forEach(b => b.classList.remove('active'));
  document.querySelector(`[data-wf="${wf}"]`).classList.add('active');

  try { await api('POST', '/demo/reset'); await loadInbox(); await loadSent(); } catch {}

  const resp = await fetch(API + '/agent/run', {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ workflow: wf }),
  });

  if (!resp.ok || !resp.body) throw new Error('Workflow stream unavailable');
  const reader = resp.body.getReader();
  const decoder = new TextDecoder();
  let buffer = '';

  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    buffer += decoder.decode(value, { stream: true });
    const lines = buffer.split('\n');
    buffer = lines.pop();

    for (const line of lines) {
      if (!line.startsWith('data: ')) continue;
      let event;
      try { event = JSON.parse(line.slice(6)); } catch { continue; }
      const { kind, data } = event;

      await new Promise(r => setTimeout(r, 220));

      if      (kind === 'think')            agentThink(data);
      else if (kind === 'email')            agentEmail(data);
      else if (kind === 'tool_call')        agentToolCall(data.tool, data.args);
      else if (kind === 'filesystem_list')  agentFsList(data.entries);
      else if (kind === 'file_read')        agentFileRead(data);
      else if (kind === 'gateway') {
        gwDecision(data.decision, data.reason, data.transaction_id, data.fingerprint);
        if (data.decision === 'REQUIRE_APPROVAL')
          showApprovalCard({ transaction_id: data.transaction_id,
                             fingerprint: data.fingerprint, args: data.args || {} });
      }
      else if (kind === 'approval_requested')
        showApprovalCard({ transaction_id: data.transaction_id,
                           fingerprint: data.fingerprint, args: data.args || {} });
      else if (kind === 'approved')
        agentThink(`Token issued — expires ${new Date(data.expires_at).toLocaleTimeString()}`);
      else if (kind === 'executed') {
        gwExecuted(data.transaction_id, data.to);
        await loadSent();
        if (pendingApproval) clearApprovalCard();
      }
      else if (kind === 'blocked') {
        gwBlocked(data.reason, data.code, data);
        if (pendingApproval) clearApprovalCard();
      }
      else if (kind === 'registry_status') showRegistryEvent(data);
      else if (kind === 'done') break;
      else if (kind === 'error') throw new Error(data.message);
    }
  }

  $('agent-status').textContent = 'done';
  setBadge('idle', 'GATEWAY IDLE');
}

// ═══════════════════════════════════════════════════════════════════
//  Reset
// ═══════════════════════════════════════════════════════════════════
$('btn-reset').addEventListener('click', async () => {
  if (running) return;
  gsap.to('.sidebar', { x: -4, duration: .08, yoyo: true, repeat: 1 });
  await api('POST', '/demo/reset');
  $('agent-feed').innerHTML   = '';
  $('gateway-feed').innerHTML = '';
  setIdle('agent-feed',    'Run a workflow to watch the agent act in real time.');
  setIdle('gateway-feed',  'Every tool call is intercepted here before execution.');
  setIdle('approval-queue','No pending approvals.');
  setIdle('sent-feed',     'No emails delivered yet.');
  setIdle('fs-feed',       'Run File Exfiltration workflow to see files.');
  txCount = 0; sentCount = 0;
  stats = { blocked:0, allowed:0, pending:0 };
  txNodes.length = 0;
  d3.select('#tx-graph').selectAll('*').remove();
  ['stat-blocked','stat-allowed','stat-pending'].forEach(id => $(id).textContent = '0');
  $('tx-count').textContent = '0 transactions';
  $('sent-count').textContent = '0';
  $('mailbox-count').textContent = '0 sent';
  $('demo-intro').hidden = false;
  $('decision-panel').hidden = true;
  $('workflow-title').textContent = 'Gateway console';
  $('workflow-sub').textContent   = 'Inspect agent actions, approvals and delivery.';
  $('agent-status').textContent   = 'waiting';
  $('approval-status').textContent = 'idle';
  setBadge('idle', 'GATEWAY IDLE');
  document.querySelectorAll('.wf-btn').forEach(b => b.classList.remove('active'));
  pendingApproval = null;
  await loadInbox();
});

// ═══════════════════════════════════════════════════════════════════
//  Wire buttons & init
// ═══════════════════════════════════════════════════════════════════
document.querySelectorAll('.wf-btn').forEach(btn =>
  btn.addEventListener('click', () => runWorkflow(btn.dataset.wf))
);

$('start-demo').addEventListener('click', () => runWorkflow('read_and_act'));

loadInbox();
loadSent();
