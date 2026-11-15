// Steal the VFY — compute the strategy commitment hash to register in the
// dashboard. Reads STEAL_STRATEGY_PARAMS (8 comma-separated numbers) and
// STEAL_STRATEGY_SALT from the environment / .env and prints ONLY the
// commitment hash — never the params or the salt.
//   commitment = Poseidon(strategyParams[0..7], salt)   [params first, salt last]
// Register the printed hash in the dashboard (My Agents -> Edit agent ->
// Steal the VFY section -> "Set up strategy commitment") BEFORE the next
// Swiss pairing; it is frozen once matches are paired, and every turn proof
// is checked against it.
//
// Usage:
//   STEAL_STRATEGY_PARAMS="10,0,0,0,0,0,0,0" STEAL_STRATEGY_SALT="<hex>" \
//     node src/steal-commitment.js
// Generate a salt with:  openssl rand -hex 16
// (and save it in .env as STEAL_STRATEGY_SALT — never commit .env)
const fs = require('fs');
const path = require('path');

(function loadEnv() {
  const envFile = path.join(__dirname, '..', '.env');
  try {
    for (const line of fs.readFileSync(envFile, 'utf8').split('\n')) {
      const m = /^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)\s*$/.exec(line);
      if (m && !(m[1] in process.env)) process.env[m[1]] = m[2].replace(/^['"]|['"]$/g, '');
    }
  } catch { /* no .env */ }
})();

const { strategyCommitment } = require('./field');
const { validateParams } = require('./steal-policy');

const raw = (process.env.STEAL_STRATEGY_PARAMS || '').trim();
const salt = (process.env.STEAL_STRATEGY_SALT || '').trim();
if (!raw || !salt) {
  console.error('Set STEAL_STRATEGY_PARAMS and STEAL_STRATEGY_SALT first (in .env or env).');
  console.error('Generate a salt with: openssl rand -hex 16');
  process.exit(1);
}
const params = raw.split(',').map((s) => s.trim());
const err = validateParams(params);
if (err) {
  console.error('Invalid STEAL_STRATEGY_PARAMS: ' + err);
  process.exit(1);
}
console.log(strategyCommitment(params, salt));
