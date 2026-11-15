// Steal the VFY — Groth16 policy-proof generation + publicInputsHash.
//
// Circuit inputs (official vfy-policy circuit, verified by probing its
// wasm — 17 inputs, 9 public signals):
//   commitment, matchId, turnNumber, selfBalance, opponentBalance,
//   action (HOLD 0, FORTIFY 1, EXTRACT 2), amount, circuitVersion,
//   salt (private), strategyParams[8] (private).
// Public signals (9): [hash, commitment, matchId, turnNumber, selfBalance,
//   opponentBalance, action, amount, circuitVersion] — the first signal is
//   a salt-dependent binding hash; the other 8 are the turn fields.
//
// publicInputsHash (sent in the response, recomputed independently by the
// platform — NOT a circuit signal): keccak256 of the ABI-packed fields,
// each padded to 32 bytes big-endian, in the exact order from the official
// /build spec:
//   [commitment, matchId (hyphens stripped, as 0x hex), turn, selfBalance,
//    opponentBalance, action enum, amount (0 for HOLD/FORTIFY),
//    circuitVersion ("v1" -> 1)]
//
// The commitment is Poseidon(strategyParams[0..7], salt) — params first,
// salt last. It MUST equal the hash registered in the dashboard, or the
// platform rejects every turn.

const { toField, toHexString, to32Bytes, keccak256Hex, strategyCommitment } = require('./field');
const { prove } = require('./snark');
const { ACTIONS } = require('./steal-policy');

function matchIdToField(matchId) {
  const hex = String(matchId || '').replace(/-/g, '');
  return toField(BigInt('0x' + hex));
}

function publicInputsHash({ commitment, matchId, turn, selfBalance, opponentBalance, action, amount, circuitVersion }) {
  const versionNum = circuitVersion === 'v1' ? 1 : Number(circuitVersion);
  const hash = keccak256Hex([
    to32Bytes(commitment),
    to32Bytes(matchIdToField(matchId)),
    to32Bytes(turn),
    to32Bytes(selfBalance),
    to32Bytes(opponentBalance),
    to32Bytes(ACTIONS[action]),
    to32Bytes(amount),
    to32Bytes(versionNum),
  ]);
  return hash;
}

function buildInput(turn, action, commitment, salt, params) {
  return {
    commitment: String(commitment),
    matchId: '0x' + String(turn.matchId || '').replace(/-/g, ''),
    turnNumber: String(turn.turn),
    selfBalance: String(turn.state.selfBalance),
    opponentBalance: String(turn.state.opponentBalance),
    action: String(ACTIONS[action.type]),
    amount: String(action.type === 'EXTRACT' ? action.amount : 0),
    circuitVersion: '1',
    salt: toHexString(salt),
    strategyParams: params.map((p) => String(p)),
  };
}

async function proveTurn(turn, action, commitment, salt, params) {
  const input = buildInput(turn, action, commitment, salt, params);
  const { proof, publicSignals } = await prove('vfyPolicy', input);
  const hash = publicInputsHash({
    commitment,
    matchId: turn.matchId,
    turn: turn.turn,
    selfBalance: turn.state.selfBalance,
    opponentBalance: turn.state.opponentBalance,
    action: action.type,
    amount: action.type === 'EXTRACT' ? action.amount : 0,
    circuitVersion: 'v1',
  });
  return { proof, publicSignals, publicInputsHash: hash };
}

module.exports = { matchIdToField, publicInputsHash, buildInput, proveTurn, strategyCommitment };
