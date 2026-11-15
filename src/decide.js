// Proof Gatekeeper — the deterministic 7-trap checklist.
//
// The platform POSTs a task envelope; the first failing trap wins. All
// comparisons are on the envelope fields the platform itself signed (HMAC),
// so the checks are pure functions of the task. Boundaries, verified
// against the official circuit (a wrong decision fails witness generation,
// so the circuit is the referee):
//   - balance == minimum is VALID; amount == max_transfer is VALID
//   - expiry is STRICT: current_block == expiry_block is EXPIRED
//     (valid only while current_block < expiry_block)
//   - a retry of the SAME task_id is NOT a proof reuse; only a proof_tx
//     seen under a DIFFERENT task_id is PROOF_REUSED.
//
// Reason codes are the platform's own: VALID_CONDITION, VK_SUBSTITUTION,
// PROOF_REUSED, THRESHOLD_MISMATCH, EXPIRED_CONDITION, RECIPIENT_MISMATCH,
// AMOUNT_OVERFLOW.

const fs = require('fs');
const path = require('path');

const DATA_DIR = path.join(__dirname, '..', 'data');
const SEEN_FILE = path.join(DATA_DIR, 'seen.json');       // proof_tx -> task_id
const RESPONSES_FILE = path.join(DATA_DIR, 'responses.json'); // task_id -> response

function loadJson(file, fallback) {
  try {
    return JSON.parse(fs.readFileSync(file, 'utf8'));
  } catch {
    return fallback;
  }
}

function saveJson(file, obj) {
  fs.mkdirSync(DATA_DIR, { recursive: true });
  fs.writeFileSync(file, JSON.stringify(obj, null, 2));
}

function normAddr(a) {
  return String(a || '').toLowerCase();
}

function normHash(h) {
  return String(h || '').toLowerCase();
}

// Pure decision function: returns { decision, reason_code }.
// `seen` is a { proof_tx: task_id } map; the caller owns persistence.
function decide(task, seen) {
  const input = task.input || task; // accept a bare input object too
  const registeredVk = normHash(input.registered_vk);
  const proofVk = normHash(input.proof_vk);
  const minimum = BigInt(input.minimum);
  const balance = BigInt(input.public_balance);
  const expiryBlock = BigInt(input.expiry_block);
  const currentBlock = BigInt(input.current_block);
  const recipient = normAddr(input.recipient);
  const conditionRecipient = normAddr(input.condition_recipient);
  const amount = BigInt(input.amount);
  const maxTransfer = BigInt(input.max_transfer);
  const proofTx = normHash(input.proof_tx);
  const taskId = String(task.task_id || '');

  // Trap order matters: the first failing trap wins.
  if (proofVk !== registeredVk) {
    return { decision: 'REJECT', reason_code: 'VK_SUBSTITUTION' };
  }
  if (proofTx && seen[proofTx] && seen[proofTx] !== taskId) {
    return { decision: 'REJECT', reason_code: 'PROOF_REUSED' };
  }
  if (balance < minimum) {
    return { decision: 'REJECT', reason_code: 'THRESHOLD_MISMATCH' };
  }
  if (currentBlock >= expiryBlock) {
    return { decision: 'REJECT', reason_code: 'EXPIRED_CONDITION' };
  }
  if (recipient !== conditionRecipient) {
    return { decision: 'REJECT', reason_code: 'RECIPIENT_MISMATCH' };
  }
  if (amount > maxTransfer) {
    return { decision: 'REJECT', reason_code: 'AMOUNT_OVERFLOW' };
  }
  return { decision: 'APPROVE', reason_code: 'VALID_CONDITION' };
}

// Seen-set + response cache backed by data/seen.json and
// data/responses.json. Responses are cached by task_id because the platform
// may retry a delivery after a network failure (rules §1.2: task IDs are
// idempotency keys) — a retry must get the same answer, and must NOT be
// flagged as a proof reuse.
const store = {
  get seen() {
    return loadJson(SEEN_FILE, {});
  },
  get responses() {
    return loadJson(RESPONSES_FILE, {});
  },
  record(task, result) {
    const seen = this.seen;
    const proofTx = normHash((task.input || task).proof_tx);
    const taskId = String(task.task_id || '');
    // Only record the proof reference for decisions that ACCEPT the proof
    // (a REJECT for another trap does not consume the reference; a retry
    // of the same task_id reuses the same record).
    if (proofTx && result.reason_code !== 'PROOF_REUSED') {
      seen[proofTx] = taskId;
      saveJson(SEEN_FILE, seen);
    }
    const responses = this.responses;
    responses[taskId] = result;
    saveJson(RESPONSES_FILE, responses);
  },
};

module.exports = { decide, store, normAddr, normHash };
