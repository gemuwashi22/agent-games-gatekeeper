// Seen-proof store test — proves the PROOF_REUSED fix end-to-end over HTTP.
//
// The 2026-11-16 18:04 WIB practice failure: the agent APPROVED a proof_tx
// that had already been approved in a prior task, because the seen set was
// empty after a redeploy (data/ is gitignored and not deployed) and the old
// store re-read the file on every access and recorded only after the async
// proof generation. This test covers, against a local server instance with
// an isolated SEEN_DATA_DIR:
//   (a) same proof_tx under a new task_id -> PROOF_REUSED, no proof
//   (b) different proof_tx values -> both decided normally
//   (c) the store file is written, and after a server restart the reloaded
//       store still rejects the repeated reference
//   (+) a same-task_id retry returns the cached response, not a reuse
//
// Run: node test/test-seen-store.js
// Exit code 0 = all assertions passed. The server is stopped afterwards
// and the temporary data dir is removed.

const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawn } = require('child_process');

const PORT = 18082;
const SECRET = 'seen-store-test-secret-' + crypto.randomBytes(8).toString('hex');
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

async function post(pathname, body) {
  const raw = JSON.stringify(body);
  const headers = { 'Content-Type': 'application/json', 'x-agent-games-signature': hmac(raw) };
  const res = await fetch(BASE + pathname, { method: 'POST', headers, body: raw });
  const text = await res.text();
  let json = null;
  try { json = JSON.parse(text); } catch { /* not JSON */ }
  return { status: res.status, json, text };
}

const VK_A = '0x' + '11'.repeat(32);
const ADDR = '0xDe42' + '00'.repeat(18) + '9f01';

function task(id, proofTx, inputOverrides = {}) {
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
      proof_tx: proofTx,
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

function startServer(dataDir) {
  const child = spawn('node', [path.join(__dirname, '..', 'src', 'server.js')], {
    env: { ...process.env, PORT: String(PORT), AGENT_GAMES_HMAC_SECRET: SECRET, SEEN_DATA_DIR: dataDir },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  let serverLog = '';
  child.stdout.on('data', (d) => { serverLog += d.toString(); });
  child.stderr.on('data', (d) => { serverLog += d.toString(); });
  return { child, get log() { return serverLog; } };
}

async function stopServer(server) {
  server.child.kill('SIGTERM');
  await new Promise((r) => setTimeout(r, 800));
}

async function main() {
  const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'seen-store-test-'));
  console.log(`  (isolated SEEN_DATA_DIR: ${dataDir})`);
  let server = null;
  try {
    const P1 = '0x' + '11'.repeat(32);
    const P2 = '0x' + '22'.repeat(32);
    const P3 = '0x' + '33'.repeat(32);

    console.log('== 1. first server instance ==');
    server = startServer(dataDir);
    await waitForHealth();
    await new Promise((r) => setTimeout(r, 3000)); // let the startup self-test finish

    console.log('== (a) same proof_tx under a new task_id -> PROOF_REUSED ==');
    const a = await post('/gatekeeper', task('seen_a_001', P1));
    check('first use of P1 decided normally (APPROVE)', a.status === 200 && a.json && a.json.decision === 'APPROVE' && a.json.reason_code === 'VALID_CONDITION', `status ${a.status}: ${a.text.slice(0, 200)}`);
    check('first use carries a proof', a.json && a.json.proof && Array.isArray(a.json.public_signals) && a.json.public_signals.length === 13);
    const b = await post('/gatekeeper', task('seen_a_002', P1));
    check('second use of P1 (new task_id) -> REJECT/PROOF_REUSED, no proof', b.status === 200 && b.json && b.json.decision === 'REJECT' && b.json.reason_code === 'PROOF_REUSED' && !b.json.proof, `status ${b.status}: ${b.text.slice(0, 200)}`);

    console.log('== (b) different proof_tx values -> both decided normally ==');
    const c = await post('/gatekeeper', task('seen_b_001', P2));
    check('P2 decided normally (APPROVE)', c.status === 200 && c.json && c.json.decision === 'APPROVE' && c.json.reason_code === 'VALID_CONDITION');
    const d = await post('/gatekeeper', task('seen_b_002', P3));
    check('P3 decided normally (APPROVE)', d.status === 200 && d.json && d.json.decision === 'APPROVE' && d.json.reason_code === 'VALID_CONDITION');

    console.log('== (+) same-task_id retry returns the cached response ==');
    const retry = await post('/gatekeeper', task('seen_a_001', P1));
    check('retry of seen_a_001 returns cached APPROVE (not a reuse)', retry.status === 200 && retry.json && retry.json.decision === 'APPROVE' && retry.json.reason_code === 'VALID_CONDITION');

    console.log('== (c) store file is written ==');
    const seenFile = path.join(dataDir, 'seen.json');
    check('seen.json exists in the data dir', fs.existsSync(seenFile));
    const seenOnDisk = JSON.parse(fs.readFileSync(seenFile, 'utf8'));
    check('seen.json holds P1 -> seen_a_001', seenOnDisk[P1.toLowerCase()] === 'seen_a_001', JSON.stringify(seenOnDisk));
    check('seen.json holds P2 and P3', seenOnDisk[P2.toLowerCase()] === 'seen_b_001' && seenOnDisk[P3.toLowerCase()] === 'seen_b_002');
    check('seen.json does NOT record the PROOF_REUSED task itself', !Object.values(seenOnDisk).includes('seen_a_002'));

    console.log('== 2. restart the server (same data dir) ==');
    await stopServer(server);
    server = startServer(dataDir);
    await waitForHealth();
    await new Promise((r) => setTimeout(r, 3000));

    console.log('== (c) reloaded store still rejects the repeated reference ==');
    const e = await post('/gatekeeper', task('seen_c_001', P1));
    check('P1 under a new task_id after restart -> PROOF_REUSED, no proof', e.status === 200 && e.json && e.json.decision === 'REJECT' && e.json.reason_code === 'PROOF_REUSED' && !e.json.proof, `status ${e.status}: ${e.text.slice(0, 200)}`);
    const f = await post('/gatekeeper', task('seen_c_002', P2));
    check('P2 under a new task_id after restart -> PROOF_REUSED, no proof', f.status === 200 && f.json && f.json.decision === 'REJECT' && f.json.reason_code === 'PROOF_REUSED' && !f.json.proof);
    const retry2 = await post('/gatekeeper', task('seen_a_001', P1));
    check('retry of seen_a_001 after restart still returns cached APPROVE', retry2.status === 200 && retry2.json && retry2.json.decision === 'APPROVE' && retry2.json.reason_code === 'VALID_CONDITION');
    const g = await post('/gatekeeper', task('seen_c_003', '0x' + '44'.repeat(32)));
    check('a fresh proof_tx after restart is still decided normally', g.status === 200 && g.json && g.json.decision === 'APPROVE' && g.json.reason_code === 'VALID_CONDITION');
  } finally {
    if (server) await stopServer(server);
    try { fs.rmSync(dataDir, { recursive: true, force: true }); } catch { /* already gone */ }
  }

  console.log(`\n${passed} passed, ${failed} failed`);
  process.exit(failed ? 1 : 0);
}

main().catch((e) => {
  console.error('seen-store test crashed:', e);
  process.exit(2);
});
