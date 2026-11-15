// Agent Games — Proof Gatekeeper agent server (Node.js, plain http).
//
// Endpoints:
//   GET  /health      — liveness + self-test status (no auth)
//   POST /gatekeeper  — task endpoint (register this full path in the dashboard)
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
//   AGENT_GAMES_HMAC_FORMAT      "hex" (default) or "sha256="
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

const startedAt = Date.now();
const health = {
  ok: true,
  hmacConfigured: Boolean(HMAC_SECRET),
  taskIdMode: TASK_ID_MODE,
  kurierConfigured: Boolean(KURIER_API_KEY),
  selfTest: { ran: false, proveOk: false, verified: false, ms: null, error: null },
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
  //    {"ok":true,"protocolVersion":"v1"} (signed).
  if (msg.type === 'agent-games.preflight.v1') {
    log('[gatekeeper] preflight OK');
    return sendJson(res, 200, { ok: true, protocolVersion: 'v1' }, true);
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

  // 7. Record the seen-set + response cache, then reply (signed).
  store.record(task, response);
  log(`[gatekeeper] ${task.task_id} ${decision}/${reason_code} in ${Date.now() - t0}ms${response.proof ? ' +proof' : ' (no proof)'}${response.proofReference ? ' +kurier' : ''}`);
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
    return sendJson(res, 404, { error: 'not found' }, false);
  } catch (e) {
    log('[server] unhandled error:', e.message);
    try {
      sendJson(res, 500, { error: 'internal error' }, false);
    } catch { /* socket already gone */ }
  }
});

server.listen(PORT, () => {
  log(`[server] listening on :${PORT} (taskIdMode=${TASK_ID_MODE}, hmac=${HMAC_SECRET ? 'configured' : 'NOT CONFIGURED'}, kurier=${KURIER_API_KEY ? 'configured' : 'not configured'})`);
  runSelfTest();
});

module.exports = { server };
