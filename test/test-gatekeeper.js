// Gatekeeper test harness — replays sample task envelopes end-to-end
// against the local server logic and asserts decisions + proofs.
//
// Covers: all 7 trap types, the inclusive boundaries (balance == minimum
// and amount == max are VALID), the strict expiry boundary
// (current_block == expiry_block is EXPIRED), proof-reuse detection, a
// same-task retry NOT being a reuse, HMAC sign/verify round-trip, and a
// full Groth16 prove + local verify for an APPROVE and a REJECT scenario.
//
// Run: node test/test-gatekeeper.js
// Exit code 0 = all assertions passed.

const crypto = require('crypto');
const { decide } = require('../src/decide');
const { proveTask } = require('../src/prove');
const { verifyLocally } = require('../src/snark');
const { signatureFor, verifySignature } = require('../src/hmac');

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

const VK_A = '0x' + '11'.repeat(32);
const VK_B = '0x' + '22'.repeat(32);
const ADDR = '0xDe42' + '00'.repeat(18) + '9f01';
const ADDR_OTHER = '0xBeef' + '00'.repeat(18) + 'cafe';

function baseTask(overrides = {}, inputOverrides = {}) {
  return {
    task_id: 'gk_test_001',
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
    ...overrides,
  };
}

async function main() {
  console.log('== 1. trap checklist (decide) ==');
  let seen = {};
  check('valid -> APPROVE/VALID_CONDITION', (() => {
    const d = decide(baseTask(), seen);
    return d.decision === 'APPROVE' && d.reason_code === 'VALID_CONDITION';
  })());
  check('VK substitution -> REJECT/VK_SUBSTITUTION', (() => {
    const d = decide(baseTask({}, { proof_vk: VK_B }), seen);
    return d.decision === 'REJECT' && d.reason_code === 'VK_SUBSTITUTION';
  })());
  check('threshold -> REJECT/THRESHOLD_MISMATCH', (() => {
    const d = decide(baseTask({}, { public_balance: '999' }), seen);
    return d.decision === 'REJECT' && d.reason_code === 'THRESHOLD_MISMATCH';
  })());
  check('expired -> REJECT/EXPIRED_CONDITION', (() => {
    const d = decide(baseTask({}, { current_block: 19842202 }), seen);
    return d.decision === 'REJECT' && d.reason_code === 'EXPIRED_CONDITION';
  })());
  check('recipient -> REJECT/RECIPIENT_MISMATCH', (() => {
    const d = decide(baseTask({}, { recipient: ADDR_OTHER }), seen);
    return d.decision === 'REJECT' && d.reason_code === 'RECIPIENT_MISMATCH';
  })());
  check('amount -> REJECT/AMOUNT_OVERFLOW', (() => {
    const d = decide(baseTask({}, { amount: '1001' }), seen);
    return d.decision === 'REJECT' && d.reason_code === 'AMOUNT_OVERFLOW';
  })());
  check('reuse -> REJECT/PROOF_REUSED', (() => {
    const s = { ['0x' + 'aa'.repeat(32)]: 'gk_other_999' };
    const d = decide(baseTask(), s);
    return d.decision === 'REJECT' && d.reason_code === 'PROOF_REUSED';
  })());
  check('same task_id retry is NOT a reuse', (() => {
    const s = { ['0x' + 'aa'.repeat(32)]: 'gk_test_001' };
    const d = decide(baseTask(), s);
    return d.decision === 'APPROVE' && d.reason_code === 'VALID_CONDITION';
  })());

  console.log('== 2. boundaries ==');
  check('balance == minimum is VALID', (() => {
    const d = decide(baseTask({}, { public_balance: '1000' }), seen);
    return d.decision === 'APPROVE';
  })());
  check('amount == max_transfer is VALID', (() => {
    const d = decide(baseTask({}, { amount: '1000' }), seen);
    return d.decision === 'APPROVE';
  })());
  check('current_block == expiry_block is EXPIRED (strict)', (() => {
    const d = decide(baseTask({}, { current_block: 19842201 }), seen);
    return d.decision === 'REJECT' && d.reason_code === 'EXPIRED_CONDITION';
  })());
  check('trap precedence: VK beats threshold', (() => {
    const d = decide(baseTask({}, { proof_vk: VK_B, public_balance: '1' }), seen);
    return d.reason_code === 'VK_SUBSTITUTION';
  })());

  console.log('== 3. HMAC round-trip ==');
  const secret = crypto.randomBytes(32).toString('hex');
  const body = Buffer.from(JSON.stringify({ hello: 'world' }));
  const sig = signatureFor(secret, body, 'hex');
  check('valid signature verifies', verifySignature(secret, body, sig, 'hex') === true);
  check('tampered body fails', verifySignature(secret, Buffer.from('{"hello":"mars"}'), sig, 'hex') === false);
  check('wrong secret fails', verifySignature('00'.repeat(32), body, sig, 'hex') === false);
  const sig2 = signatureFor(secret, body, 'sha256=');
  check('sha256= format round-trips', verifySignature(secret, body, sig2, 'sha256=') === true);

  console.log('== 4. Groth16 prove + local verify (real circuit) ==');
  const t0 = Date.now();
  const taskApprove = baseTask({ task_id: 'gk_test_approve' });
  const { proof: p1, publicSignals: s1 } = await proveTask(taskApprove, 'APPROVE', 'keccak');
  console.log(`  (APPROVE proof generated in ${Date.now() - t0}ms, ${s1.length} public signals)`);
  check('APPROVE proof has 13 public signals', s1.length === 13);
  check('APPROVE proof verifies locally', await verifyLocally('gatekeeper', s1, p1));
  // Public signals are decimal strings: [hash, registeredVkHash,
  // proofVkHash, minimum, publicBalance, expiryBlock, currentBlock,
  // recipient, conditionRecipient, amount, maxTransfer, decision, taskId]
  const { toField } = require('../src/field');
  check('public signals echo the task fields', BigInt(s1[1]) === toField(VK_A) && BigInt(s1[2]) === toField(VK_A) && BigInt(s1[3]) === 1000n && s1[11] === '1');

  const t1 = Date.now();
  const taskReject = baseTask({ task_id: 'gk_test_reject' }, { proof_vk: VK_B });
  const dReject = decide(taskReject, {});
  check('REJECT scenario decides VK_SUBSTITUTION', dReject.reason_code === 'VK_SUBSTITUTION');
  const { proof: p2, publicSignals: s2 } = await proveTask(taskReject, 'REJECT', 'keccak');
  console.log(`  (REJECT proof generated in ${Date.now() - t1}ms)`);
  check('REJECT proof verifies locally', await verifyLocally('gatekeeper', s2, p2));

  console.log('== 5. wrong decision must fail witness generation ==');
  let threw = false;
  try {
    await proveTask(taskApprove, 'REJECT', 'keccak');
  } catch (e) {
    threw = true;
  }
  check('APPROVE task proven as REJECT throws (circuit is the referee)', threw);

  console.log(`\n${passed} passed, ${failed} failed`);
  process.exit(failed ? 1 : 0);
}

main().catch((e) => {
  console.error('harness crashed:', e);
  process.exit(2);
});
