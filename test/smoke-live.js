// Live HTTP smoke test — starts the server on a test port with a throwaway
// HMAC secret and exercises it over real HTTP.
//
// Run: node test/smoke-live.js
// Exit code 0 = all assertions passed. The server is stopped afterwards.

const crypto = require('crypto');
const { spawn } = require('child_process');
const path = require('path');

const PORT = 18081;
const SECRET = 'smoke-test-secret-' + crypto.randomBytes(8).toString('hex');
const BASE = `http://127.0.0.1:${PORT}`;

let passed = 0;
let failed = 0;

function check(name, cond, extra) {
  if (cond) {
    passed++;
    console.log(`  PASS ${name}`);
  } else {
    failed++;
    console.log(`  FAIL ${name}${extra ? ' — ' + extra : ''}`);
  }
}

function hmac(raw) {
  return crypto.createHmac('sha256', SECRET).update(raw).digest('hex');
}

async function post(pathname, body, sign = true) {
  const raw = JSON.stringify(body);
  const headers = { 'Content-Type': 'application/json' };
  if (sign) headers['x-agent-games-signature'] = hmac(raw);
  const res = await fetch(BASE + pathname, { method: 'POST', headers, body: raw });
  const text = await res.text();
  let json = null;
  try {
    json = JSON.parse(text);
  } catch { /* not JSON */ }
  return { status: res.status, json, text, sig: res.headers.get('x-agent-games-signature'), raw: text };
}

const VK_A = '0x' + '11'.repeat(32);
const VK_B = '0x' + '22'.repeat(32);
const ADDR = '0xDe42' + '00'.repeat(18) + '9f01';

function task(id, inputOverrides = {}) {
  return {
    type: 'agent-games.proof-gatekeeper.v1',
    task_id: id,
    mode: 'competition',
    issued_at: new Date().toISOString(),
    deadline_at: new Date(Date.now() + 60000).toISOString(),
    input: {
      registered_vk: VK_A,
      proof_vk: VK_A,
      minimum: '1000',
      public_balance: '1460',
      expiry_block: 19842201,
      current_block: 19832000,
      recipient: ADDR,
      condition_recipient: ADDR,
      amount: '500',
      max_transfer: '1000',
      proof_tx: '0x' + 'aa'.repeat(32),
      ...inputOverrides,
    },
  };
}

async function waitForHealth(tries = 20) {
  for (let i = 0; i < tries; i++) {
    try {
      const res = await fetch(BASE + '/health');
      if (res.ok) return await res.json();
    } catch { /* not up yet */ }
    await new Promise((r) => setTimeout(r, 500));
  }
  throw new Error('server did not come up');
}

async function main() {
  const child = spawn('node', [path.join(__dirname, '..', 'src', 'server.js')], {
    env: { ...process.env, PORT: String(PORT), AGENT_GAMES_HMAC_SECRET: SECRET },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  let serverLog = '';
  child.stdout.on('data', (d) => { serverLog += d.toString(); });
  child.stderr.on('data', (d) => { serverLog += d.toString(); });

  try {
    console.log('== 1. health ==');
    const health = await waitForHealth();
    check('health responds', health && health.ok === true);
    check('health reports HMAC configured', health.hmacConfigured === true);
    // The startup self-test runs async; give it a moment, then re-read.
    await new Promise((r) => setTimeout(r, 3000));
    const health2 = await (await fetch(BASE + '/health')).json();
    check('startup self-test ran and passed', health2.selfTest && health2.selfTest.ran && health2.selfTest.proveOk && health2.selfTest.verified, JSON.stringify(health2.selfTest));

    console.log('== 2. preflight ==');
    const pf = await post('/gatekeeper', { type: 'agent-games.preflight.v1' });
    check('preflight returns 200 + ok/v1', pf.status === 200 && pf.json && pf.json.ok === true && pf.json.protocolVersion === 'v1');
    check('preflight response is signed', typeof pf.sig === 'string' && pf.sig.length === 64);
    check('preflight signature verifies over raw body', pf.sig === hmac(pf.raw));

    console.log('== 3. auth ==');
    const bad = await post('/gatekeeper', { type: 'agent-games.preflight.v1' }, false);
    check('unsigned request -> 401', bad.status === 401);
    const wrong = await post('/gatekeeper', { type: 'agent-games.preflight.v1' }, true);
    // (signed with the right secret — sanity: this one must pass)
    check('correctly signed request passes', wrong.status === 200);

    console.log('== 4. valid task -> APPROVE + proof ==');
    const t0 = Date.now();
    const ok = await post('/gatekeeper', task('gk_smoke_001'));
    const ms = Date.now() - t0;
    console.log(`  (task answered in ${ms}ms)`);
    check('valid task 200', ok.status === 200, `status ${ok.status}: ${ok.text.slice(0, 200)}`);
    check('decision APPROVE / VALID_CONDITION', ok.json && ok.json.decision === 'APPROVE' && ok.json.reason_code === 'VALID_CONDITION');
    check('proof present with 13 public signals', ok.json && ok.json.proof && Array.isArray(ok.json.public_signals) && ok.json.public_signals.length === 13);
    check('response is signed', typeof ok.sig === 'string' && ok.sig.length === 64);
    check('answered inside 60s', ms < 60000);

    console.log('== 5. trap task -> REJECT + proof ==');
    // NOTE: a distinct proof_tx — reusing the first task's proof_tx under a
    // new task_id is PROOF_REUSED (checked before threshold), by design.
    const trap = await post('/gatekeeper', task('gk_smoke_002', { public_balance: '500', proof_tx: '0x' + 'bb'.repeat(32) }));
    check('trap task REJECT/THRESHOLD_MISMATCH', trap.json && trap.json.decision === 'REJECT' && trap.json.reason_code === 'THRESHOLD_MISMATCH');
    check('trap response still carries a proof', trap.json && trap.json.proof && trap.json.public_signals && trap.json.public_signals.length === 13);

    console.log('== 6. retry + reuse ==');
    const retry = await post('/gatekeeper', task('gk_smoke_001'));
    check('same task_id retry returns cached APPROVE', retry.json && retry.json.decision === 'APPROVE' && retry.json.reason_code === 'VALID_CONDITION');
    const reuse = await post('/gatekeeper', task('gk_smoke_003')); // same proof_tx, new task_id
    check('same proof_tx under new task_id -> PROOF_REUSED, no proof', reuse.json && reuse.json.reason_code === 'PROOF_REUSED' && !reuse.json.proof);
  } finally {
    child.kill('SIGTERM');
    await new Promise((r) => setTimeout(r, 500));
  }

  console.log(`\n${passed} passed, ${failed} failed`);
  process.exit(failed ? 1 : 0);
}

main().catch((e) => {
  console.error('smoke test crashed:', e);
  process.exit(2);
});
