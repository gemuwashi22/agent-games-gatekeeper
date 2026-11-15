// Steal the VFY test harness — validates the policy function against the
// official vfy-policy circuit itself over a grid of states and strategy
// params, and checks the commitment hash, the publicInputsHash formula,
// and a full Groth16 proof round-trip.
//
// A grid case passes only if policy() returns the action the circuit
// accepts (witness calc succeeds for that action and fails for the other
// two) — the circuit is the referee, so this is the strongest local check
// available before a live practice turn.
//
// Run:  node test/test-steal.js
// Exit code 0 = all assertions passed.

const fs = require('fs');
const { WitnessCalculatorBuilder } = require('circom_runtime');
const { policy, validateParams } = require('../src/steal-policy');
const { proveTurn, publicInputsHash, matchIdToField, strategyCommitment } = require('../src/steal-prove');
const { verifyLocally } = require('../src/snark');
const { toField } = require('../src/field');

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

const SALT = '0x00000000000000000000000000000001';
const OUR_PARAMS = [10, 0, 0, 0, 0, 0, 0, 0]; // GEMUWASHI 2 strategy

async function circuitAccepts(wc, params, state, action) {
  const input = {
    commitment: strategyCommitment(params, SALT),
    matchId: '0x9f4e1b2a000000000000000000000001',
    turnNumber: '3',
    selfBalance: String(state.selfBalance),
    opponentBalance: String(state.opponentBalance),
    action: String({ HOLD: 0, FORTIFY: 1, EXTRACT: 2 }[action.type]),
    amount: String(action.type === 'EXTRACT' ? action.amount : 0),
    circuitVersion: '1',
    salt: SALT,
    strategyParams: params.map(String),
  };
  try {
    await wc.calculateWitness(input);
    return true;
  } catch {
    return false;
  }
}

async function main() {
  console.log('== 1. param validation ==');
  check('our params [10,0,0,0,0,0,0,0] are valid', validateParams(OUR_PARAMS) === null);
  check('reference default [5,50,0,0,0,0,0,0] is valid', validateParams([5, 50, 0, 0, 0, 0, 0, 0]) === null);
  check('7 params rejected', validateParams([10, 0, 0, 0, 0, 0, 0]) !== null);
  check('extract 0 rejected', validateParams([0, 0, 0, 0, 0, 0, 0, 0]) !== null);
  check('extract 11 rejected', validateParams([11, 0, 0, 0, 0, 0, 0, 0]) !== null);
  check('mode 2 rejected', validateParams([10, 0, 0, 2, 0, 0, 0, 0]) !== null);
  check('reserved param nonzero rejected', validateParams([10, 0, 0, 0, 1, 0, 0, 0]) !== null);

  console.log('== 2. policy decisions ==');
  check('[10,0,0,0] 100/100 -> EXTRACT 10', (() => {
    const a = policy({ selfBalance: 100, opponentBalance: 100 }, OUR_PARAMS);
    return a.type === 'EXTRACT' && a.amount === 10;
  })());
  check('[10,0,0,0] 100/0 -> HOLD (nothing to steal)', (() => {
    const a = policy({ selfBalance: 100, opponentBalance: 0 }, OUR_PARAMS);
    return a.type === 'HOLD' && a.amount === undefined;
  })());
  check('[10,0,0,0] 0/0 -> HOLD', (() => {
    const a = policy({ selfBalance: 0, opponentBalance: 0 }, OUR_PARAMS);
    return a.type === 'HOLD';
  })());
  check('[10,0,0,0] 30/100 -> EXTRACT 10 (no fortify threshold)', (() => {
    const a = policy({ selfBalance: 30, opponentBalance: 100 }, OUR_PARAMS);
    return a.type === 'EXTRACT' && a.amount === 10;
  })());
  check('[5,50,0,0] 100/100 -> EXTRACT 5', (() => {
    const a = policy({ selfBalance: 100, opponentBalance: 100 }, [5, 50, 0, 0, 0, 0, 0, 0]);
    return a.type === 'EXTRACT' && a.amount === 5;
  })());
  check('[5,50,0,0] 30/100 -> FORTIFY (self < 50)', (() => {
    const a = policy({ selfBalance: 30, opponentBalance: 100 }, [5, 50, 0, 0, 0, 0, 0, 0]);
    return a.type === 'FORTIFY';
  })());
  check('[5,50,0,0] 50/100 -> EXTRACT 5 (boundary: self == threshold)', (() => {
    const a = policy({ selfBalance: 50, opponentBalance: 100 }, [5, 50, 0, 0, 0, 0, 0, 0]);
    return a.type === 'EXTRACT' && a.amount === 5;
  })());
  check('[5,50,0,0] 100/0 -> HOLD', (() => {
    const a = policy({ selfBalance: 100, opponentBalance: 0 }, [5, 50, 0, 0, 0, 0, 0, 0]);
    return a.type === 'HOLD';
  })());
  check('[3,100,20,0] 100/15 -> HOLD (opp <= 20)', (() => {
    const a = policy({ selfBalance: 100, opponentBalance: 15 }, [3, 100, 20, 0, 0, 0, 0, 0]);
    return a.type === 'HOLD';
  })());
  check('[3,100,20,0] 100/21 -> EXTRACT 3 (boundary: opp == 21 > 20)', (() => {
    const a = policy({ selfBalance: 100, opponentBalance: 21 }, [3, 100, 20, 0, 0, 0, 0, 0]);
    return a.type === 'EXTRACT' && a.amount === 3;
  })());
  check('[3,100,20,0] 99/100 -> FORTIFY (self < 100)', (() => {
    const a = policy({ selfBalance: 99, opponentBalance: 100 }, [3, 100, 20, 0, 0, 0, 0, 0]);
    return a.type === 'FORTIFY';
  })());
  check('mode 1 [5,0,0,1] 100/100 -> HOLD (always)', (() => {
    const a = policy({ selfBalance: 100, opponentBalance: 100 }, [5, 0, 0, 1, 0, 0, 0, 0]);
    return a.type === 'HOLD';
  })());

  console.log('== 3. policy vs circuit grid (witness calc) ==');
  const wc = await WitnessCalculatorBuilder(fs.readFileSync(__dirname + '/../circuits/vfy-policy.wasm'));
  const PARAM_SETS = [
    OUR_PARAMS,
    [5, 50, 0, 0, 0, 0, 0, 0],
    [3, 100, 20, 0, 0, 0, 0, 0],
    [5, 0, 0, 1, 0, 0, 0, 0], // hold-only mode
  ];
  const STATES = [
    { selfBalance: 100, opponentBalance: 100 },
    { selfBalance: 30, opponentBalance: 100 },
    { selfBalance: 100, opponentBalance: 0 },
    { selfBalance: 100, opponentBalance: 15 },
    { selfBalance: 49, opponentBalance: 200 },
    { selfBalance: 50, opponentBalance: 200 },
    { selfBalance: 0, opponentBalance: 0 },
    { selfBalance: 200, opponentBalance: 5 },
  ];
  for (const params of PARAM_SETS) {
    for (const state of STATES) {
      const action = policy(state, params);
      const okPolicy = await circuitAccepts(wc, params, state, action);
      const others = ['HOLD', 'FORTIFY', 'EXTRACT'].filter((t) => t !== action.type);
      let othersRejected = true;
      for (const t of others) {
        const alt = t === 'EXTRACT' ? { type: 'EXTRACT', amount: params[0] } : { type: t };
        if (await circuitAccepts(wc, params, state, alt)) othersRejected = false;
      }
      const ok = okPolicy && othersRejected;
      if (ok) passed++; else failed++;
      console.log(`  ${ok ? 'PASS' : 'FAIL'}  params=[${params}] self${state.selfBalance}/opp${state.opponentBalance} -> ${action.type}${action.amount ? ' ' + action.amount : ''} (circuit accepts: ${okPolicy}, others rejected: ${othersRejected})`);
    }
  }

  console.log('== 4. commitment ==');
  const c1 = strategyCommitment(OUR_PARAMS, SALT);
  const c2 = strategyCommitment(OUR_PARAMS, SALT);
  check('commitment is deterministic', c1 === c2);
  check('commitment is 0x + 64 hex', /^0x[0-9a-f]{64}$/.test(c1), c1);
  check('commitment changes with salt', strategyCommitment(OUR_PARAMS, '0x00000000000000000000000000000002') !== c1);
  check('commitment changes with params', strategyCommitment([5, 50, 0, 0, 0, 0, 0, 0], SALT) !== c1);
  console.log(`  (our-params commitment with test salt: ${c1})`);

  console.log('== 5. publicInputsHash ==');
  const turn = { matchId: '9f4e1b2a-0000-0000-0000-000000000001', turn: 3, state: { selfBalance: '95', opponentBalance: '105' } };
  const base = { commitment: c1, matchId: turn.matchId, turn: 3, selfBalance: '95', opponentBalance: '105', action: 'EXTRACT', amount: 10, circuitVersion: 'v1' };
  const h1 = publicInputsHash(base);
  const h2 = publicInputsHash(base);
  check('publicInputsHash is deterministic', h1 === h2);
  check('publicInputsHash is 0x + 64 hex', /^0x[0-9a-f]{64}$/.test(h1), h1);
  check('publicInputsHash changes when a field changes', publicInputsHash({ ...base, turn: 4 }) !== h1
    && publicInputsHash({ ...base, amount: 5 }) !== h1
    && publicInputsHash({ ...base, action: 'HOLD', amount: 0 }) !== h1);
  check('matchIdToField strips hyphens', matchIdToField('9f4e1b2a-0000-0000-0000-000000000001') === toField(BigInt('0x9f4e1b2a000000000000000000000001')));

  console.log('== 6. full prove + local verify (real circuit) ==');
  const action = policy(turn.state, OUR_PARAMS);
  check('turn action is EXTRACT 10', action.type === 'EXTRACT' && action.amount === 10);
  const t0 = Date.now();
  const { proof, publicSignals, publicInputsHash: h3 } = await proveTurn(turn, action, c1, SALT, OUR_PARAMS);
  console.log(`  (EXTRACT 10 proof generated in ${Date.now() - t0}ms, ${publicSignals.length} public signals)`);
  check('proof has 9 public signals', publicSignals.length === 9);
  check('proof verifies locally', await verifyLocally('vfyPolicy', publicSignals, proof));
  check('proveTurn hash matches direct hash', h3 === h1);
  // Public signals are decimal strings: [hash, commitment, matchId,
  // turnNumber, selfBalance, opponentBalance, action, amount,
  // circuitVersion] — the first is a salt-dependent binding hash; the
  // other 8 echo the turn fields.
  check('public signals echo the turn fields',
    BigInt(publicSignals[1]) === toField(c1)
    && BigInt(publicSignals[2]) === matchIdToField(turn.matchId)
    && publicSignals[3] === '3' && publicSignals[4] === '95' && publicSignals[5] === '105'
    && publicSignals[6] === '2' && publicSignals[7] === '10' && publicSignals[8] === '1');

  console.log('== 7. wrong action must fail witness generation ==');
  let threw = false;
  try {
    await proveTurn(turn, { type: 'HOLD' }, c1, SALT, OUR_PARAMS);
  } catch (e) {
    threw = true;
  }
  check('EXTRACT turn proven as HOLD throws (circuit is the referee)', threw);

  console.log(`\n${passed} passed, ${failed} failed`);
  process.exit(failed ? 1 : 0);
}

main().catch((e) => {
  console.error('harness crashed:', e);
  process.exit(2);
});
