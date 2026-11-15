// Live HTTP smoke test for Steal the VFY — starts the server on a test
// port with a throwaway HMAC secret and throwaway strategy (params
// [10,0,0,0,0,0,0,0], random salt) and exercises POST /steal over real
// HTTP, plus a Gatekeeper preflight sanity check (the server must still
// serve Gatekeeper unchanged).
//
// Run:  node test/smoke-steal.js
// Exit code 0 = all assertions passed. The server is stopped afterwards.

const crypto = require('crypto');
const { spawn } = require('child_process');
const path = require('path');
const { verifyLocally } = require('../src/snark');
const { publicInputsHash } = require('../src/steal-prove');

const PORT = 18082;
const SECRET = 'smoke-steal-secret-' + crypto.randomBytes(8).toString('hex');
const SALT = '0x' + crypto.randomBytes(16).toString('hex');
const PARAMS = '10,0,0,0,0,0,0,0';
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

function hmac(raw, secret = SECRET) {
  return crypto.createHmac('sha256', secret).update(raw).digest('hex');
}

async function post(pathname, body, sign = true, secret = SECRET) {
  const raw = JSON.stringify(body);
  const headers = { 'Content-Type': 'application/json' };
  if (sign) headers['x-agent-games-signature'] = hmac(raw, secret);
  const res = await fetch(BASE + pathname, { method: 'POST', headers, body: raw });
  const text = await res.text();
  let json = null;
  try {
    json = JSON.parse(text);
  } catch { /* not JSON */ }
  return { status: res.status, json, text, sig: res.headers.get('x-agent-games-signature'), raw: text };
}

const MATCH = '9f4e1b2a-0000-0000-0000-000000000001';

function turn(turnNo, stateOverrides = {}, commitment) {
  return {
    protocolVersion: 'v1',
    eventId: 'steal-the-vfy',
    mode: 'competition',
    matchId: MATCH,
    turn: turnNo,
    issuedAt: new Date().toISOString(),
    deadlineAt: new Date(Date.now() + 30000).toISOString(),
    state: { selfBalance: '95', opponentBalance: '105', selfFortifiedUntilTurn: null, opponentFortifiedUntilTurn: null, ...stateOverrides },
    strategyCommitment: { hash: commitment },
    resolverVersion: 'v1',
    nonce: 'test-nonce-' + turnNo,
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
    env: {
      ...process.env,
      PORT: String(PORT),
      AGENT_GAMES_HMAC_SECRET: SECRET,
      STEAL_STRATEGY_PARAMS: PARAMS,
      STEAL_STRATEGY_SALT: SALT,
    },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  let serverLog = '';
  child.stdout.on('data', (d) => { serverLog += d.toString(); });
  child.stderr.on('data', (d) => { serverLog += d.toString(); });

  try {
    console.log('== 1. health ==');
    const health = await waitForHealth();
    check('health responds', health && health.ok === true);
    check('health reports steal ready', health.steal && health.steal.ready === true, JSON.stringify(health.steal));
    check('health reports a commitment hash', health.steal && /^0x[0-9a-f]{64}$/.test(health.steal.commitment || ''), health.steal && health.steal.commitment);
    const commitment = health.steal.commitment;
    // The startup self-tests run async; give them a moment, then re-read.
    await new Promise((r) => setTimeout(r, 4000));
    const health2 = await (await fetch(BASE + '/health')).json();
    check('steal startup self-test ran and passed',
      health2.steal && health2.steal.selfTest && health2.steal.selfTest.ran
      && health2.steal.selfTest.proveOk && health2.steal.selfTest.verified,
      JSON.stringify(health2.steal && health2.steal.selfTest));
    check('gatekeeper startup self-test still passes',
      health2.selfTest && health2.selfTest.ran && health2.selfTest.proveOk && health2.selfTest.verified,
      JSON.stringify(health2.selfTest));

    console.log('== 2. preflight on /steal ==');
    const pf = await post('/steal', { type: 'agent-games.preflight.v1' });
    check('preflight returns 200 + ok/v1', pf.status === 200 && pf.json && pf.json.ok === true && pf.json.protocolVersion === 'v1');
    check('preflight body is the SPACED form', pf.raw === '{"ok": true, "protocolVersion": "v1"}', pf.raw);
    check('preflight response is signed', typeof pf.sig === 'string' && pf.sig.length === 64);
    check('preflight signature verifies over raw body', pf.sig === hmac(pf.raw));

    console.log('== 3. auth ==');
    const bad = await post('/steal', { type: 'agent-games.preflight.v1' }, false);
    check('unsigned request -> 401', bad.status === 401);
    const wrong = await post('/steal', turn(1, {}, commitment), true, '00'.repeat(32));
    check('wrong-secret signed request -> 401', wrong.status === 401);

    console.log('== 4. valid turn -> EXTRACT 10 + proof ==');
    const t0 = Date.now();
    const ok = await post('/steal', turn(3, {}, commitment));
    const ms = Date.now() - t0;
    console.log(`  (turn answered in ${ms}ms)`);
    check('valid turn 200', ok.status === 200, `status ${ok.status}: ${ok.text.slice(0, 200)}`);
    check('action EXTRACT amount 10', ok.json && ok.json.action && ok.json.action.type === 'EXTRACT' && ok.json.action.amount === 10);
    check('matchId + turn echoed', ok.json && ok.json.matchId === MATCH && ok.json.turn === 3);
    check('policyProof has circuitVersion v1', ok.json && ok.json.policyProof && ok.json.policyProof.circuitVersion === 'v1');
    check('proof + public_signals sit INSIDE policyProof',
      ok.json && ok.json.policyProof && ok.json.policyProof.proof
      && Array.isArray(ok.json.policyProof.public_signals) && ok.json.policyProof.public_signals.length === 9);
    check('proof + public_signals also at top level',
      ok.json && ok.json.proof && Array.isArray(ok.json.public_signals) && ok.json.public_signals.length === 9);
    check('publicInputsHash present and well-formed',
      ok.json && ok.json.policyProof && /^0x[0-9a-f]{64}$/.test(ok.json.policyProof.publicInputsHash || ''));
    check('publicInputsHash matches local recomputation',
      ok.json && ok.json.policyProof && ok.json.policyProof.publicInputsHash === publicInputsHash({
        commitment, matchId: MATCH, turn: 3, selfBalance: '95', opponentBalance: '105',
        action: 'EXTRACT', amount: 10, circuitVersion: 'v1',
      }));
    check('response proof verifies locally',
      ok.json && await verifyLocally('vfyPolicy', ok.json.policyProof.public_signals, ok.json.policyProof.proof));
    check('response is signed', typeof ok.sig === 'string' && ok.sig.length === 64);
    check('answered well inside the turn window', ms < 30000, `${ms}ms`);

    console.log('== 5. commitment mismatch -> HOLD without proof ==');
    const mm = await post('/steal', turn(4, {}, '0x' + 'ff'.repeat(32)));
    check('mismatch 200 + HOLD', mm.status === 200 && mm.json && mm.json.action && mm.json.action.type === 'HOLD');
    check('mismatch carries no proof', mm.json && !mm.json.proof && !(mm.json.policyProof && mm.json.policyProof.proof));
    check('HOLD action has no amount field', mm.json && mm.json.action && !('amount' in mm.json.action));

    console.log('== 6. opponent at 0 -> HOLD, no amount ==');
    const hold = await post('/steal', turn(5, { opponentBalance: '0' }, commitment));
    check('opp 0 -> HOLD', hold.status === 200 && hold.json && hold.json.action && hold.json.action.type === 'HOLD');
    check('HOLD response still carries a proof (policy proof for HOLD)',
      hold.json && hold.json.policyProof && hold.json.policyProof.proof
      && Array.isArray(hold.json.policyProof.public_signals) && hold.json.policyProof.public_signals.length === 9);

    console.log('== 7. retry + malformed ==');
    const retry = await post('/steal', turn(3, {}, commitment));
    check('same (matchId, turn) retry returns identical idempotencyKey',
      retry.json && retry.json.idempotencyKey === ok.json.idempotencyKey);
    const malformed = await post('/steal', { matchId: MATCH, turn: 9 });
    check('missing state -> 400', malformed.status === 400);

    console.log('== 8. gatekeeper still works ==');
    const gk = await post('/gatekeeper', { type: 'agent-games.preflight.v1' });
    check('gatekeeper preflight still 200 + ok/v1', gk.status === 200 && gk.json && gk.json.ok === true && gk.json.protocolVersion === 'v1');
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
