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

// Where the runtime state lives. SEEN_DATA_DIR (optional) lets the operator
// point the store at a persistent volume (e.g. a Railway volume mounted at
// /data) so the seen set survives a container replace; without it the store
// lives in data/ next to the repo, which a fresh deploy starts empty (the
// known limit: proofs seen before a redeploy are not in it).
const DATA_DIR = process.env.SEEN_DATA_DIR
  ? path.resolve(process.env.SEEN_DATA_DIR)
  : path.join(__dirname, '..', 'data');
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

// Seen-set + response cache. The in-memory maps are the source of truth:
// they are loaded ONCE at startup from data/seen.json and
// data/responses.json, and every update writes through to disk
// synchronously, so a record that was already used to decide is never lost
// (within the lifetime of this container). Responses are cached by task_id
// because the platform may retry a delivery after a network failure
// (rules §1.2: task IDs are idempotency keys) — a retry must get the same
// answer, and must NOT be flagged as a proof reuse.
//
// Atomicity: the request path calls markSeen() synchronously right after
// decide() and BEFORE any await (proof generation), so the check and the
// record are atomic within a request — a concurrent task carrying the same
// proof_tx is caught. cacheResponse() is called after the response is
// complete (proof included, if any) so a retry gets the full answer.
//
// The proof reference is input.proof_tx (lowercase-normalized): the
// envelope's own transaction hash for the proof. It is identical for the
// same proof across tasks and distinct for different proofs, and it is NOT
// a circuit input (the gatekeeper circuit's 13 public signals are the
// task fields + decision + taskId), so reuse detection is an envelope-level
// check. A task with no proof_tx is never flagged as a reuse.
let seenMap = loadJson(SEEN_FILE, {});
let responsesMap = loadJson(RESPONSES_FILE, {});

const store = {
  get seen() {
    return seenMap;
  },
  get responses() {
    return responsesMap;
  },
  // Synchronously mark a proof_tx as seen (proof_tx -> task_id) and write
  // the file through. Call right after decide(), before any await, for
  // every processed task EXCEPT a PROOF_REUSED decision itself (the
  // reference is already recorded under the original task_id; overwriting
  // it would lose the first-use record). A missing/empty proof_tx is a
  // no-op (such a task is never flagged as a reuse).
  markSeen(task) {
    const proofTx = normHash((task.input || task).proof_tx);
    const taskId = String(task.task_id || '');
    if (!proofTx) return;
    seenMap[proofTx] = taskId;
    saveJson(SEEN_FILE, seenMap);
  },
  // Synchronously cache the full response by task_id and write through.
  // Called after the response is complete (proof included, if any).
  cacheResponse(task, response) {
    const taskId = String(task.task_id || '');
    responsesMap[taskId] = response;
    saveJson(RESPONSES_FILE, responsesMap);
  },
};

module.exports = { decide, store, normAddr, normHash };
