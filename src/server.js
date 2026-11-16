// Agent Games — Proof Gatekeeper + Steal the VFY agent server (Node.js, plain http).
//
// Endpoints:
//   GET  /health      — liveness + self-test status (no auth)
//   POST /gatekeeper  — Proof Gatekeeper tasks (register this full path)
//   POST /steal       — Steal the VFY turns (register this full path)
//                      * both verify x-agent-games-signature over the RAW
//                        body; both answer preflight with the SPACED body
//                        '{"ok": true, "protocolVersion": "v1"}' (signed)
//                      * verifies x-agent-games-signature over the RAW body
//                      * preflight {"type":"agent-games.preflight.v1"} ->
//                        {"ok":true,"protocolVersion":"v1"} (signed)
//                      * task {"type":"agent-games.proof-gatekeeper.v1", ...} ->
//                        {"decision","reason_code","proof_tx","proof","public_signals"}
//                        (signed; PROOF_REUSED carries no proof)
//
// Configuration (env vars; see .env.example — never commit secrets):
//   PORT                         default 8080
//   AGENT_GAMES_HMAC_SECRET      from the dashboard ("Rotate Secret"); without
//                                it, inbound HMAC verification is DISABLED
//                                (health shows it) — set it before going live
//   AGENT_GAMES_HMAC_FORMAT      "hex" (default), "sha256=", "base64", or "sha256=base64"
//   GATEKEEPER_TASK_ID_MODE      "keccak" (default), "numeric", or "hex"
//   KURIER_API_KEY               optional; free key from https://kurier.xyz
//   KURIER_API_URL               default https://api.kurier.xyz/api/v1
//
// Rules the server follows (official rules §1.2–§1.4, build guide §02–§04):
//   - 60s hard deadline per task; fail closed (REJECT, no proof) on any
//     timeout or uncertainty rather than crashing or timing out.
//   - Task IDs are idempotency keys: a retry of the same task_id returns the
//     cached response and is NOT a proof reuse.
//   - The platform may retry after a network failure; the server must be
//     up continuously during rounds (an offline agent forfeits tasks).

const fs = require('fs');
const http = require('http');
const path = require('path');
const crypto = require('crypto');

const { signatureFor, verifySignature } = require('./hmac');
const { decide, store } = require('./decide');
const { proveTask } = require('./prove');
const { verifyLocally } = require('./snark');
const { submitProof } = require('./kurier');
const { toHexString, strategyCommitment } = require('./field');
const { policy, validateParams } = require('./steal-policy');
const { proveTurn } = require('./steal-prove');

// --- minimal .env loader (no dependency; never overrides real env) ---
(function loadDotEnv() {
  try {
    const envPath = path.join(__dirname, '..', '.env');
    const lines = fs.readFileSync(envPath, 'utf8').split('\n');
    for (const line of lines) {
      const m = line.match(/^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)\s*$/);
      if (!m || process.env[m[1]] !== undefined) continue;
      let v = m[2].trim();
      if ((v.startsWith('"') && v.endsWith('"')) || (v.startsWith("'") && v.endsWith("'"))) {
        v = v.slice(1, -1);
      }
      process.env[m[1]] = v;
    }
  } catch { /* no .env file — env vars only */ }
})();

const PORT = parseInt(process.env.PORT || '8080', 10);
const HMAC_SECRET = process.env.AGENT_GAMES_HMAC_SECRET || '';
const HMAC_FORMAT = process.env.AGENT_GAMES_HMAC_FORMAT || 'hex';
const TASK_ID_MODE = process.env.GATEKEEPER_TASK_ID_MODE || 'keccak';
const KURIER_API_KEY = process.env.KURIER_API_KEY || '';
const KURIER_WAIT_MS = 20000; // bounded; proof gen ~0.4s, total stays << 60s
const KURIER_WAIT_MS_STEAL = 12000; // bounded; vfy-policy proof ~1.8s

// --- Steal the VFY configuration (env) ---
// STEAL_STRATEGY_PARAMS: 8 comma-separated numbers, e.g. "10,0,0,0,0,0,0,0".
// STEAL_STRATEGY_SALT: random hex (never logged, never committed).
// STEAL_STRATEGY_COMMITMENT: optional override — the hash registered in the
//   dashboard. If unset, it is computed as Poseidon(params + salt) at
//   startup and MUST equal the registered hash, or every Steal proof fails.
// If params/salt are unset, the server still runs: Steal answers HOLD
// without a proof (fail closed) and Gatekeeper is unaffected.
const STEAL_PARAMS_RAW = (process.env.STEAL_STRATEGY_PARAMS || '').trim();
const STEAL_SALT_RAW = (process.env.STEAL_STRATEGY_SALT || '').trim();
const STEAL_COMMITMENT_ENV = (process.env.STEAL_STRATEGY_COMMITMENT || '').trim();
let stealParams = null;
let stealSalt = '';
let stealCommitment = '';
let stealReady = false;
let stealStatus = 'not-configured';
(function initSteal() {
  if (!STEAL_PARAMS_RAW || !STEAL_SALT_RAW) {
    stealStatus = 'not-configured (set STEAL_STRATEGY_PARAMS + STEAL_STRATEGY_SALT — Steal answers HOLD without a proof)';
    return;
  }
  const params = STEAL_PARAMS_RAW.split(',').map((s) => s.trim());
  const err = validateParams(params);
  if (err) {
    stealStatus = 'invalid: ' + err;
    return;
  }
  stealParams = params;
  stealSalt = toHexString(STEAL_SALT_RAW);
  try {
    stealCommitment = STEAL_COMMITMENT_ENV
      ? toHexString(STEAL_COMMITMENT_ENV)
      : strategyCommitment(params, stealSalt);
  } catch (e) {
    stealStatus = 'invalid: commitment failed — ' + e.message;
    return;
  }
  stealReady = true;
  stealStatus = 'ready';
})();

// Idempotency cache for Steal turns: a retry of the same (matchId, turn)
// returns the identical response (same idempotencyKey, same proof).
const stealResponses = {};

const startedAt = Date.now();
const health = {
  ok: true,
  hmacConfigured: Boolean(HMAC_SECRET),
  hmacFormat: HMAC_FORMAT,
  preflightBody: 'spaced',
  taskIdMode: TASK_ID_MODE,
  kurierConfigured: Boolean(KURIER_API_KEY),
  selfTest: { ran: false, proveOk: false, verified: false, ms: null, error: null },
  steal: {
    status: stealStatus,
    ready: stealReady,
    commitment: stealCommitment || null,
    selfTest: { ran: false, proveOk: false, verified: false, ms: null, error: null },
  },
};

function log(...args) {
  console.log(new Date().toISOString(), ...args);
}

function sendJson(res, status, obj, sign) {
  const body = JSON.stringify(obj);
  const headers = { 'Content-Type': 'application/json' };
  if (sign && HMAC_SECRET) {
    headers['x-agent-games-signature'] = signatureFor(HMAC_SECRET, body, HMAC_FORMAT);
  }
  res.writeHead(status, headers);
  res.end(body);
}

function sendRaw(res, status, rawBody, sign) {
  const headers = { 'Content-Type': 'application/json' };
  if (sign && HMAC_SECRET) {
    headers['x-agent-games-signature'] = signatureFor(HMAC_SECRET, rawBody, HMAC_FORMAT);
  }
  res.writeHead(status, headers);
  res.end(rawBody);
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;
    req.on('data', (c) => {
      size += c.length;
      if (size > 1024 * 1024) return reject(new Error('body too large'));
      chunks.push(c);
    });
    req.on('end', () => resolve(Buffer.concat(chunks)));
    req.on('error', reject);
  });
}

// A valid APPROVE scenario used for the startup self-test (never sent to
// the platform; only proves the local circuit + witness path works).
function selfTestTask() {
  return {
    task_id: 'selftest-gk-0001',
    input: {
      registered_vk: '0x' + '11'.repeat(32),
      proof_vk: '0x' + '11'.repeat(32),
      minimum: '1000',
      public_balance: '1460',
      expiry_block: 19842201,
      current_block: 19832000,
      recipient: '0xDe42' + '00'.repeat(18) + '9f01',
      condition_recipient: '0xDe42' + '00'.repeat(18) + '9f01',
      amount: '500',
      max_transfer: '1000',
      proof_tx: '0x' + 'aa'.repeat(32),
    },
  };
}

async function runSelfTest() {
  const t0 = Date.now();
  try {
    const task = selfTestTask();
    const d = decide(task, {});
    if (d.decision !== 'APPROVE') throw new Error('self-test decision was ' + d.decision);
    const { proof, publicSignals } = await proveTask(task, 'APPROVE', TASK_ID_MODE);
    const verified = await verifyLocally('gatekeeper', publicSignals, proof);
    health.selfTest = { ran: true, proveOk: true, verified, ms: Date.now() - t0, error: null };
    log(`[self-test] APPROVE proof generated + verified locally in ${health.selfTest.ms}ms`);
  } catch (e) {
    health.selfTest = { ran: true, proveOk: false, verified: false, ms: Date.now() - t0, error: e.message };
    log('[self-test] FAILED:', e.message);
  }
  // Steal self-test (only when the strategy is configured): prove an
  // EXTRACT turn and verify it locally against the vfy-policy circuit.
  const st0 = Date.now();
  try {
    if (!stealReady) {
      health.steal.selfTest = { ran: false, proveOk: false, verified: false, ms: null, error: 'strategy not configured' };
      log('[self-test] steal SKIPPED (strategy not configured)');
      return;
    }
    const turn = { matchId: '9f4e1b2a-0000-0000-0000-000000000001', turn: 3, state: { selfBalance: '95', opponentBalance: '105' } };
    const action = policy(turn.state, stealParams);
    if (action.type !== 'EXTRACT') throw new Error('self-test action was ' + action.type);
    const { proof, publicSignals } = await proveTurn(turn, action, stealCommitment, stealSalt, stealParams);
    const verified = await verifyLocally('vfyPolicy', publicSignals, proof);
    health.steal.selfTest = { ran: true, proveOk: true, verified, ms: Date.now() - st0, error: null };
    log(`[self-test] steal EXTRACT proof generated + verified locally in ${health.steal.selfTest.ms}ms`);
  } catch (e) {
    health.steal.selfTest = { ran: true, proveOk: false, verified: false, ms: Date.now() - st0, error: e.message };
    log('[self-test] steal FAILED:', e.message);
  }
}

async function handleGatekeeper(req, res) {
  const t0 = Date.now();
  let raw;
  try {
    raw = await readBody(req);
  } catch (e) {
    return sendJson(res, 400, { error: e.message }, false);
  }

  // 1. Verify the inbound signature over the RAW body before parsing.
  if (HMAC_SECRET) {
    const sig = req.headers['x-agent-games-signature'];
    if (!verifySignature(HMAC_SECRET, raw, sig, HMAC_FORMAT)) {
      log('[gatekeeper] 401 bad signature');
      return sendJson(res, 401, { error: 'bad signature' }, false);
    }
  } else {
    log('[gatekeeper] WARNING: HMAC secret not configured — accepting unsigned request (dev mode)');
  }

  let msg;
  try {
    msg = JSON.parse(raw.toString('utf8'));
  } catch {
    return sendJson(res, 400, { error: 'invalid JSON' }, true);
  }

  // 2. Preflight: {"type":"agent-games.preflight.v1"} ->
  //    {"ok": true, "protocolVersion": "v1"} (signed, SPACED body).
  //    The platform rejected the minified body in all 4 signature
  //    encodings (hex, sha256=, base64, sha256=base64) even with a fresh
  //    secret, while our signing code is byte-identical to the reference
  //    implementation (which was only ever tested locally, never against
  //    the live platform). Likely cause: the verifier re-serializes the
  //    JSON before checking (Python json.dumps style: space after ':'
  //    and ','). Sending + signing the spaced form passes BOTH a
  //    raw-body verifier and a re-serializing verifier.
  if (msg.type === 'agent-games.preflight.v1') {
    log('[gatekeeper] preflight OK');
    return sendRaw(res, 200, '{"ok": true, "protocolVersion": "v1"}', true);
  }

  if (msg.type !== 'agent-games.proof-gatekeeper.v1' || !msg.task_id || !msg.input) {
    return sendJson(res, 400, { error: 'unknown message type or missing task' }, true);
  }

  const task = msg;

  // 3. Idempotency: a retry of the same task_id returns the cached response.
  const cached = store.responses[task.task_id];
  if (cached) {
    log(`[gatekeeper] ${task.task_id} retry -> cached ${cached.decision}/${cached.reason_code}`);
    return sendJson(res, 200, cached, true);
  }

  // 4. Decide (deterministic 7-trap checklist; first failing trap wins).
  const seen = store.seen;
  const { decision, reason_code } = decide(task, seen);
  const proofTx = String(task.input.proof_tx || '');
  const response = { decision, reason_code, proof_tx: proofTx };

  // 4b. Atomically mark the proof as seen NOW (synchronously, before the
  // async proof generation below) so a concurrent task carrying the same
  // proof_tx is caught as PROOF_REUSED. Skipped when the decision itself
  // is PROOF_REUSED (the reference is already recorded under the original
  // task_id). This is the fix for the 18:04 WIB practice failure, where a
  // reused proof_tx was approved because the seen set was empty after a
  // redeploy — the in-memory set is now the source of truth and the file
  // is write-through, so a record used to decide is never lost within
  // this container's lifetime.
  if (reason_code !== 'PROOF_REUSED') {
    store.markSeen(task);
  }

  // 5. Prove (except PROOF_REUSED, which carries no proof by platform rule).
  if (reason_code !== 'PROOF_REUSED') {
    try {
      const { proof, publicSignals } = await proveTask(task, decision, TASK_ID_MODE);
      const verified = await verifyLocally('gatekeeper', publicSignals, proof);
      if (!verified) throw new Error('local proof verification failed');
      response.proof = proof;
      response.public_signals = publicSignals;
      // 6. Kurier (optional, best-effort, bounded wait; never blocks the reply).
      if (KURIER_API_KEY && Date.now() - t0 < 30000) {
        const k = await submitProof(KURIER_API_KEY, 'gatekeeper', proof, publicSignals, KURIER_WAIT_MS);
        if (k && k.proofReference) response.proofReference = k.proofReference;
      }
    } catch (e) {
      // Fail closed-ish: send the decision WITHOUT a proof rather than
      // crashing or timing out (a missing proof costs -2; a timeout also
      // costs -2 and forfeits the task entirely).
      log(`[gatekeeper] ${task.task_id} proof generation failed (${e.message}) — responding without proof`);
    }
  }

  // 7. Cache the full response (proof included, if any) for idempotent
  // retries, then reply (signed). The seen-set was already marked in
  // step 4b, before proving.
  store.cacheResponse(task, response);
  log(`[gatekeeper] ${task.task_id} ${decision}/${reason_code} in ${Date.now() - t0}ms${response.proof ? ' +proof' : ' (no proof)'}${response.proofReference ? ' +kurier' : ''}`);
  return sendJson(res, 200, response, true);
}

// --- Steal the VFY ---
// Turn envelope (official /build §06):
//   { protocolVersion, eventId: "steal-the-vfy", mode, matchId, turn,
//     issuedAt, deadlineAt,
//     state: { selfBalance, opponentBalance, selfFortifiedUntilTurn,
//              opponentFortifiedUntilTurn },
//     strategyCommitment: { hash }, resolverVersion, nonce }
// Response (official /build §06 — proof + public_signals MUST sit INSIDE
// policyProof; the guide calls leaving them out the #1 cause of lost
// turns. We ALSO carry them at the top level (belt-and-braces, mirroring
// the gatekeeper shape and the public reference); see STEAL.md.
// action.amount is present ONLY for EXTRACT — the schema rejects it on
// HOLD/FORTIFY even as 0.)
// Fail closed: any uncertainty -> HOLD without a proof (a missing proof
// costs -2 and resolves as HOLD; a timeout or crash forfeits the turn).
async function handleSteal(req, res) {
  const t0 = Date.now();
  let raw;
  try {
    raw = await readBody(req);
  } catch (e) {
    return sendJson(res, 400, { error: e.message }, false);
  }

  // 1. Verify the inbound signature over the RAW body before parsing.
  if (HMAC_SECRET) {
    const sig = req.headers['x-agent-games-signature'];
    if (!verifySignature(HMAC_SECRET, raw, sig, HMAC_FORMAT)) {
      log('[steal] 401 bad signature');
      return sendJson(res, 401, { error: 'bad signature' }, false);
    }
  } else {
    log('[steal] WARNING: HMAC secret not configured — accepting unsigned request (dev mode)');
  }

  let msg;
  try {
    msg = JSON.parse(raw.toString('utf8'));
  } catch {
    return sendJson(res, 400, { error: 'invalid JSON' }, true);
  }

  // 2. Preflight: same handshake as Gatekeeper, same SPACED body
  // (the platform's verifier re-serializes JSON before checking the
  // signature — the minified body was rejected live for Gatekeeper).
  if (msg.type === 'agent-games.preflight.v1') {
    log('[steal] preflight OK');
    return sendRaw(res, 200, '{"ok": true, "protocolVersion": "v1"}', true);
  }

  const matchId = msg.matchId || '';
  const turn = msg.turn;
  const state = msg.state || {};
  const envelopeCommitment = msg.strategyCommitment && msg.strategyCommitment.hash;

  const holdResponse = (withProof) => {
    const body = {
      matchId, turn,
      action: { type: 'HOLD' },
      agentTimestamp: new Date().toISOString(),
      idempotencyKey: crypto.randomUUID(),
    };
    if (withProof) {
      body.policyProof = withProof.policyProof;
      body.proof = withProof.proof;
      body.public_signals = withProof.publicSignals;
    } else {
      body.policyProof = { circuitVersion: 'v1' };
    }
    return { status: 200, body };
  };

  if (!matchId || turn === undefined || turn === null
      || state.selfBalance === undefined || state.opponentBalance === undefined) {
    return sendJson(res, 400, { error: 'malformed turn envelope' }, true);
  }

  // 3. Idempotency: a retry of the same (matchId, turn) returns the
  // identical response (same idempotencyKey, same proof).
  const cacheKey = `${matchId}:${turn}`;
  if (stealResponses[cacheKey]) {
    log(`[steal] ${cacheKey} retry -> cached ${stealResponses[cacheKey].action.type}`);
    return sendJson(res, 200, stealResponses[cacheKey], true);
  }

  // 4. Strategy not configured -> HOLD without a proof (fail closed).
  if (!stealReady) {
    log(`[steal] ${cacheKey} strategy not configured — HOLD without proof`);
    const r = holdResponse(null);
    stealResponses[cacheKey] = r.body;
    return sendJson(res, 200, r.body, true);
  }

  // 5. The envelope's frozen commitment must match the registered one.
  if (envelopeCommitment && String(envelopeCommitment).toLowerCase() !== stealCommitment.toLowerCase()) {
    log(`[steal] ${cacheKey} envelope commitment mismatch — HOLD without proof`);
    const r = holdResponse(null);
    stealResponses[cacheKey] = r.body;
    return sendJson(res, 200, r.body, true);
  }

  // 6. Decide (deterministic threshold policy — must match the circuit).
  const action = policy(
    { selfBalance: BigInt(state.selfBalance), opponentBalance: BigInt(state.opponentBalance) },
    stealParams
  );

  // 7. Prove. On any failure, answer HOLD without a proof (fail closed).
  let response;
  try {
    const { proof, publicSignals, publicInputsHash } = await proveTurn(
      { matchId, turn, state }, action, stealCommitment, stealSalt, stealParams
    );
    const verified = await verifyLocally('vfyPolicy', publicSignals, proof);
    if (!verified) throw new Error('local proof verification failed');
    const policyProof = { circuitVersion: 'v1', proof, public_signals: publicSignals, publicInputsHash };
    // Kurier (optional, best-effort, bounded wait; never blocks the reply).
    if (KURIER_API_KEY && Date.now() - t0 < 15000) {
      const k = await submitProof(KURIER_API_KEY, 'vfyPolicy', proof, publicSignals, KURIER_WAIT_MS_STEAL);
      if (k && k.proofReference) policyProof.proofReference = k.proofReference;
    }
    const actionOut = { type: action.type };
    if (action.type === 'EXTRACT') actionOut.amount = action.amount;
    response = {
      matchId, turn, action: actionOut, policyProof,
      proof, public_signals: publicSignals,
      agentTimestamp: new Date().toISOString(),
      idempotencyKey: crypto.randomUUID(),
    };
  } catch (e) {
    log(`[steal] ${cacheKey} proof generation failed (${e.message}) — HOLD without proof`);
    const r = holdResponse(null);
    stealResponses[cacheKey] = r.body;
    return sendJson(res, 200, r.body, true);
  }

  // 8. Cache, then reply (signed).
  stealResponses[cacheKey] = response;
  log(`[steal] ${cacheKey} ${action.type}${action.amount ? ' ' + action.amount : ''} +proof in ${Date.now() - t0}ms`);
  return sendJson(res, 200, response, true);
}

const server = http.createServer(async (req, res) => {
  try {
    if (req.method === 'GET' && req.url === '/health') {
      return sendJson(res, 200, {
        ...health,
        uptimeSeconds: Math.floor((Date.now() - startedAt) / 1000),
      }, false);
    }
    if (req.method === 'POST' && req.url === '/gatekeeper') {
      return await handleGatekeeper(req, res);
    }
    if (req.method === 'POST' && req.url === '/steal') {
      return await handleSteal(req, res);
    }
    return sendJson(res, 404, { error: 'not found' }, false);
  } catch (e) {
    log('[server] unhandled error:', e.message);
    try {
      sendJson(res, 500, { error: 'internal error' }, false);
    } catch { /* socket already gone */ }
  }
});

server.listen(PORT, () => {
  log(`[server] listening on :${PORT} (taskIdMode=${TASK_ID_MODE}, hmac=${HMAC_SECRET ? 'configured' : 'NOT CONFIGURED'}, hmacFormat=${HMAC_FORMAT}, kurier=${KURIER_API_KEY ? 'configured' : 'not configured'})`);
  log(`[server] steal: ${stealStatus}${stealCommitment ? ' commitment=' + stealCommitment : ''}`);
  runSelfTest();
});

module.exports = { server };
