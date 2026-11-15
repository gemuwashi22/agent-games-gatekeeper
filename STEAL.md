# Steal the VFY — agent implementation (GEMUWASHI 2)

Built **Mon 2026-11-16 ~06:30–07:00 WIB** for zkVerify Agent Games Season 01.
The Steal server lives in the same repo as the Gatekeeper agent
(`~/workspace/agent-games/`) and runs as a **second Railway service**
with agent GEMUWASHI 2's own HMAC secret. Gatekeeper (service 1,
GEMUWASHI 1) is untouched.

## Status at build time

- Steal entry **still open** (browser-verified 2026-11-16 ~06:23 WIB):
  "EVENT 02 / OPEN NOW", mid-tournament registration allowed — "register
  mid-tournament to join from the next Swiss round, until the final round
  is paired." Current round R3; **4 Swiss rounds remain (R4–R7)** + Top 16
  knockout; tournament 13–17 Nov. Daily play window **17:30–03:30 WIB**.
- **Deadline: the strategy commitment must be registered before the next
  Swiss pairing — 17:30 WIB today (Mon 2026-11-16, R4).** After that the
  agent joins from the following round instead.
- GEMUWASHI 2 is registered for Steal (dashboard shows the warning "One
  more step for Steal the VFY — Your agent won't be paired until it holds
  an active strategy commitment" with a "Set up strategy commitment →"
  link). Its HMAC secret is issued at registration — the user supplies it
  to Railway service 2 (never in chat).

## Protocol (official /build §06 + /api/circuit-info; verified against the circuit)

### Game

- 1v1 Swiss, 7 rounds → Top 16 knockout. **20 turns per match**,
  starting balance **100 VFY** per agent; **highest balance wins**.
- Actions (per turn, simultaneous):
  - **HOLD** — 0 VFY. No transfer. Safe pass, but gives the opponent a
    free extraction window.
  - **FORTIFY** — 2 VFY. Blocks up to 6 VFY of incoming extraction
    **this turn**.
  - **EXTRACT N** — 0 VFY. Steals up to N VFY (max 10) from the
    opponent's spendable balance. A **fortified opponent reduces the
    effective gain by 6**. Both agents can EXTRACT simultaneously.
- Scoring per turn is not published in detail on /build; the guide only
  states a missing/invalid proof costs **−2 and resolves as HOLD**, a
  stale matchId/turn is rejected, and reusing an `idempotencyKey` across
  turns means only the first submission is accepted. Match outcome is by
  final balance; Swiss standings determine the bracket.

### Turn envelope (POST to the registered endpoint)

```json
{
  "protocolVersion": "v1",
  "eventId": "steal-the-vfy",
  "mode": "competition",
  "matchId": "9f4e1b2a-...",
  "turn": 3,
  "issuedAt": "<issued-at>",
  "deadlineAt": "<deadline-at>",
  "state": {
    "selfBalance": "95",
    "opponentBalance": "105",
    "selfFortifiedUntilTurn": null,
    "opponentFortifiedUntilTurn": null
  },
  "strategyCommitment": { "hash": "0x..." },
  "resolverVersion": "v1",
  "nonce": "3c2f1a..."
}
```

The envelope is HMAC-signed (`x-agent-games-signature` over the raw
body) and must be verified **before** parsing — same as Gatekeeper.

### Response

```json
{
  "matchId": "9f4e1b2a-...",
  "turn": 3,
  "action": { "type": "EXTRACT", "amount": 10 },
  "policyProof": {
    "circuitVersion": "v1",
    "proof": { "pi_a": [...], "pi_b": [...], "pi_c": [...], "protocol": "groth16", "curve": "bn128" },
    "public_signals": ["... 9 values ..."],
    "publicInputsHash": "0x...",
    "proofReference": "0x... (optional, Kurier)"
  },
  "proof": { ... },
  "public_signals": ["... 9 values ..."],
  "agentTimestamp": "<iso>",
  "idempotencyKey": "<fresh UUID per turn>"
}
```

- **`action.amount` is present ONLY for EXTRACT** — the platform schema
  rejects it on HOLD/FORTIFY even as 0.
- **`proof` + `public_signals` MUST sit INSIDE `policyProof`** (official
  guide: leaving them out is the #1 cause of lost turns — "the response
  is accepted, but offline verification finds no proof, so every such
  turn is −2 and resolved as HOLD"). This server ALSO carries them at
  the top level (belt-and-braces, mirroring the Gatekeeper shape and the
  public reference implementation). If the practice turn ever shows the
  proof not verified, the first thing to try is dropping the top-level
  copies — but the guide's wording only says top-level fields "don't
  count", not that they are rejected.
- `publicInputsHash` is keccak256 of the ABI-packed fields, each padded
  to 32 bytes big-endian, in this exact order (official /build spec):
  `[commitment, matchId (hyphens stripped, as 0x hex), turn,
  selfBalance, opponentBalance, action enum (HOLD 0 / FORTIFY 1 /
  EXTRACT 2), amount (0 for HOLD/FORTIFY), circuitVersion ("v1" → 1)]`.
  It is an audit pointer only — the platform verifies the Groth16 proof
  + public_signals; a correct hash alone does NOT pass a turn.
- `idempotencyKey` must be unique per turn (a fresh UUID per turn; a
  retry of the same `(matchId, turn)` returns the cached response with
  the same key).

### Circuit (vfy-policy, Groth16/BN128, Circom 2.x)

- vkHash `0x6c56509f1c56fd1fd4e9737f906d2220f4b95f1d507f1adf6899085bd74be047`
  (from `/api/circuit-info`, mainnet).
- Artifacts (official, downloaded 2026-11-16, sha256 matches the public
  reference's copies exactly):
  - `circuits/vfy-policy.wasm` — 2,991,212 B, sha256
    `bc0998250d2baf75b89deef5306867ffa7085a08d4f7d2caf0dd63a060b134d2`
  - `circuits/vfy-policy_final.zkey` — 810,586 B, sha256
    `f9666a1655279ef27f7fee6d535ac8aa9e39286ac40ff6279fea87c21ab6ce41`
- Circuit inputs (17): `commitment, matchId, turnNumber, selfBalance,
  opponentBalance, action, amount, circuitVersion, salt (private),
  strategyParams[8] (private)`.
- Public signals (9): `[hash, commitment, matchId, turnNumber,
  selfBalance, opponentBalance, action, amount, circuitVersion]` — the
  first is a salt-dependent binding hash; the other 8 echo the turn
  fields. snarkjs returns them in output-then-public order; pass them
  through unchanged.
- Proof generation measured on this VM: **~0.6–1.2 s** per turn
  (smoke test: full turn answered in 585 ms; circuit test: 1,087 ms),
  far inside the turn window.

### Strategy commitment

- `commitment = Poseidon(strategyParams[0..7], salt)` — params first,
  salt last (Poseidon-9 over 9 field elements). Verified against the
  circuit: only this ordering passes witness calculation.
- Registered in the dashboard **before the next Swiss pairing** (see
  "Register the commitment" below). It is **frozen once matches are
  paired**; any turn response using a different circuit version /
  commitment is rejected.
- The server checks the envelope's `strategyCommitment.hash` against its
  own commitment on every turn and answers HOLD (no proof) on a
  mismatch.

## Strategy: always EXTRACT 10

```
STEAL_STRATEGY_PARAMS = "10,0,0,0,0,0,0,0"
```

Policy (enforced by the circuit, so the server cannot deviate):

| params | meaning |
|---|---|
| `[0] = 10` | extract amount on EXTRACT (max allowed) |
| `[1] = 0` | fortify threshold — FORTIFY while `selfBalance < 0`, i.e. **never** |
| `[2] = 0` | min opponent balance — EXTRACT while `opponentBalance > 0` |
| `[3] = 0` | mode 0 = normal |
| `[4..7] = 0` | reserved, must be 0 |

In plain terms: **EXTRACT 10 every turn; HOLD only when the opponent's
balance is 0** (nothing left to steal — the circuit forces HOLD there).

### Why this is the right choice (game-theoretic rationale)

All of this follows from the documented mechanics (FORTIFY costs 2 and
blocks 6 this turn; EXTRACT costs 0 and steals up to N, max 10; both
agents act simultaneously):

1. **Extract 10 dominates any smaller amount.** Gain is
   `min(N, opponentBalance)` minus 6 if the opponent is fortified
   (floored at 0). 10 always gains at least as much as 5 (10 vs 5
   unfortified; 4 vs 0 fortified) at the same cost (0). There is no
   documented downside to a larger N.
2. **FORTIFY is dominated by EXTRACT in a single turn.** Against an
   opponent extracting 10: extracting back nets `+10 − 10 = 0`;
   fortifying nets `−2 (cost) − 4 (10−6 blocked) = −6`. Against HOLD:
   extract `+10`, fortify `−2`. Against FORTIFY: extract `+4`,
   fortify `−2`. Fortify never wins a turn — it only pays 2 and
   forgoes your own extraction. Hence threshold 0 (never fortify).
3. **minOpponentBalance 0 is right.** A higher threshold forces HOLD
   while the opponent still has balance — and HOLD while the opponent
   extracts lets them take 10 from you for free. Extracting back at
   least partly offsets it (you gain `min(10, oppBalance)` while they
   gain 10 from you; holding gains 0). When the opponent is at 0,
   extracting gains 0 anyway, so the forced HOLD costs nothing.
4. **The strategy is unbeaten, not just aggressive.** The only reply
   that avoids losing to always-extract-10 is the mirror (extract 10
   back → 100–100 draw). Any other policy loses balance against it:
   against the public reference's default `[5,50,0,0,0,0,0,0]`, this
   strategy pulls ahead 10/turn while the opponent extracts 5, then
   10/turn once the opponent drops below 50 and starts fortifying
   (paying 2/turn for protection that still leaks 4/turn) — a
   decisive win by ~turn 19. Against always-HOLD it wins in 10 turns.
5. **Knowing the strategy doesn't help the opponent.** Even if a rival
   reads this file, their best response to always-extract-10 is the
   mirror (a draw) — there is no counter that wins. The only thing
   that must stay secret is the **salt** (a private circuit input);
   the params are documented here by design.

### Trade-offs / what this gives up

- **No endgame or score-aware play.** The circuit policy cannot see
  the turn number, the fortify flags, or the opponent's strategy — it
  only sees the two balances. So there is no "protect a lead in the
  last turns" mode; extracting 10 is still the best single-turn action
  in every state, including when ahead.
- **Mirror matches draw.** If a rival also plays always-extract-10,
  the match ends 100–100. In Swiss that is presumably a shared point
  rather than a loss — and no other policy does better against the
  mirror.
- **If FORTIFY actually lasts multiple turns** (the envelope carries
  `selfFortifiedUntilTurn` / `opponentFortifiedUntilTurn`, which hints
  at a duration, though the guide says "blocks up to 6 VFY of incoming
  extraction **this turn**"), a fortify-heavy policy could in theory
  be stronger — but the circuit still cannot condition on fortify
  state, and a threshold policy would re-fortify (and re-pay 2) every
  turn it stays below threshold. Extract-10 remains the robust choice
  under either reading. This is the one game-mechanics assumption
  worth re-checking if the practice turn behaves unexpectedly.

## The exact values to register

Generated 2026-11-16 ~06:35 WIB with `node src/steal-commitment.js`:

| Value | Where it goes |
|---|---|
| **Strategy params:** `10,0,0,0,0,0,0,0` | Railway service 2 env `STEAL_STRATEGY_PARAMS` |
| **Salt:** `0a2d728e44684a49d6d8f21369266c79` | Railway service 2 env `STEAL_STRATEGY_SALT` — **SECRET. Never in chat, never in the repo, never in a screenshot.** The parent agent holds it; the user pastes it into Railway. |
| **Commitment:** `0x0bfddb9d54008554f717a00e0c9939efd5b8fab8b9bb34fce0ca4af73ecd16c5` | Dashboard strategy-commitment form (public value) |

The commitment was verified end-to-end with these exact values: a real
EXTRACT 10 turn proved in 1,228 ms and **verified locally** against the
vfy-policy circuit, with public signals echoing the turn fields
(`[hash, commitment, matchId, 1, 100, 100, 2, 10, 1]`).

To regenerate (or rotate to a fresh salt — which requires re-registering
the new commitment in the dashboard BEFORE the next pairing):

```bash
SALT=$(openssl rand -hex 16)
STEAL_STRATEGY_PARAMS="10,0,0,0,0,0,0,0" STEAL_STRATEGY_SALT="$SALT" node src/steal-commitment.js
# prints ONLY the commitment hash — never the params or the salt
```

## Register the commitment (dashboard)

1. Dashboard → **My Agents** → GEMUWASHI 2 → **Edit agent** → the
   **Steal the VFY** section → **"Set up strategy commitment"**.
2. The form asks for the **precomputed commitment hash** (this is what
   the official build guide and the public reference both describe:
   "Register the printed hash in the dashboard"). Paste exactly:
   `0x0bfddb9d54008554f717a00e0c9939efd5b8fab8b9bb34fce0ca4af73ecd16c5`
3. Submit **before 17:30 WIB today (Mon 2026-11-16)** — the next Swiss
   pairing (R4). A mid-tournament entry joins from the next round, not
   one already in progress.
4. **Do NOT enter random values.** The registered commitment must match
   the params + salt the server plays with, or every turn proof fails.
   If the form instead asks for the 8 strategy params themselves (not
   verified — I could not inspect the form from here), enter
   `10,0,0,0,0,0,0,0` and tell the parent agent, so the commitment can
   be recomputed and checked against the server's startup log.

## Deployment checklist (Railway service 2)

Same repo, same Railway account/project ("gallant-growth"), same GitHub
account/repo as service 1 — **only the secret differs**.

1. **Railway → project "gallant-growth" → + New Service → GitHub repo**
   `gemuwashi22/agent-games-gatekeeper` (same repo as service 1).
   It deploys the same code; `npm start` = `node src/server.js`.
2. **Variables** on service 2 (Railway dashboard — never in chat):
   - `AGENT_GAMES_HMAC_SECRET` = GEMUWASHI 2's secret (from the
     dashboard "Rotate Secret" — shown once).
   - `STEAL_STRATEGY_PARAMS` = `10,0,0,0,0,0,0,0`
   - `STEAL_STRATEGY_SALT` = `0a2d728e44684a49d6d8f21369266c79`
   - `STEAL_STRATEGY_COMMITMENT` = leave **unset** (the server computes
     it as Poseidon(params + salt) at startup — it must equal the
     dashboard value; the startup log prints it for checking).
   - `AGENT_GAMES_HMAC_FORMAT` = leave **unset** (defaults to `hex`,
     the working format).
   - `KURIER_API_KEY` = optional (same as service 1; omit if unset).
3. **Generate Domain** on service 2 (Settings → Networking → Generate
   Domain). The endpoint URL is:
   `https://<service-2-domain>/steal`
   (the **full handler path** — the platform posts to the URL exactly
   as registered; a root path returns 404).
4. **Dashboard → My Agents → GEMUWASHI 2 → set the endpoint** to that
   URL (edit agent if it was left blank at registration).
5. **Check the service logs**: it must print
   `[server] steal: ready commitment=0x0bfddb9d54008554f717a00e0c9939efd5b8fab8b9bb34fce0ca4af73ecd16c5`
   and `[self-test] steal EXTRACT proof generated + verified locally`.
   If the commitment in the log differs from the dashboard value,
   STOP — the params/salt in Railway do not match the registered
   commitment; fix the env vars and redeploy.
6. **Preflight** (dashboard, for GEMUWASHI 2): must pass. The server
   answers preflight on `/steal` with the SPACED body
   `{"ok": true, "protocolVersion": "v1"}` signed with hex HMAC — the
   same combination that passed for Gatekeeper. (The platform's
   verifier re-serializes JSON before checking the signature; the
   minified body was rejected live for Gatekeeper in all 4 encodings.)
7. **Practice turn** (dashboard): dispatch a practice turn and confirm
   the result shows the action taken and **Proof: VERIFIED**. If the
   proof is not verified, first try dropping the top-level
   `proof`/`public_signals` from the response (keep them inside
   `policyProof` only) — see "Response" above.
8. **Enter the Steal event**: Events page → Steal the VFY → Enter
   event, for GEMUWASHI 2. Do this **before 17:30 WIB today** so the
   agent is paired for R4. (Entry is one agent per owner per event —
   GEMUWASHI 1 stays in Gatekeeper, GEMUWASHI 2 goes to Steal.)
9. **Leave service 2 running** through the last round (17 Nov).
   After the tournament ends, the services can be stopped/deleted to
   stop the cost. Estimated cost for service 2: ~$0.75 for the
   remaining play days, inside the $5 Railway trial.

## Files

```
src/steal-policy.js        threshold policy + param validation (matches the circuit)
src/steal-prove.js         circuit input mapping, publicInputsHash, proveTurn
src/steal-commitment.js    CLI: prints ONLY the commitment hash (node src/steal-commitment.js)
src/steal-*.js (above) + src/server.js  POST /steal handler, preflight, idempotency cache
src/field.js               + strategyCommitment() (Poseidon-9, poseidon-lite)
src/snark.js               + vfyPolicy circuit (wasm + zkey)
test/test-steal.js         circuit harness: policy grid + commitment + hash + full prove
test/smoke-steal.js        live HTTP smoke test: real server, signed turns, auth, retry
circuits/vfy-policy.wasm / vfy-policy_final.zkey   official artifacts (see hashes above)
.env.example               STEAL_STRATEGY_PARAMS / SALT / COMMITMENT documented
STEAL.md                   this file
```

## Tests (all local, 2026-11-16 ~06:40 WIB)

```
npm run test:steal        # 65 passed, 0 failed
npm run test:smoke-steal  # 30 passed, 0 failed
npm run test:gatekeeper   # 22 passed, 0 failed (re-run after the change)
npm run test:smoke        # 17 passed, 0 failed (re-run after the change)
```

- `test-steal.js` (65): param validation (7), policy decisions incl.
  boundaries (12), policy-vs-circuit grid — 4 param sets × 8 states,
  each requiring the circuit to accept the policy action and reject the
  other two (32), commitment determinism/sensitivity (4),
  publicInputsHash determinism/sensitivity (4), full EXTRACT 10 prove +
  local verify with 9 public signals echoing the turn fields (5), and
  a wrong-action proof that must throw (1). Proof generated in
  1,087 ms.
- `smoke-steal.js` (30): real server on 127.0.0.1:18082 with throwaway
  secret/salt: /health reports steal ready + commitment + both startup
  self-tests pass; preflight on /steal returns the SPACED body with a
  signature that verifies over the raw body; unsigned and wrong-secret
  requests → 401; a valid signed turn → EXTRACT 10 with proof +
  public_signals inside policyProof AND at top level, a correct
  publicInputsHash, and a locally-verifying proof — answered in
  585 ms; commitment mismatch → HOLD without proof; opponent at 0 →
  HOLD (with a valid HOLD proof); same-turn retry → identical
  idempotencyKey; malformed envelope → 400; Gatekeeper preflight
  still works on the same server.
- Gatekeeper suites re-run after the server change: **22/22** and
  **17/17**, unchanged. The Gatekeeper code path was not modified
  (the /steal handler is additive; only imports, the steal config
  block, health fields, and the startup self-test were added).

## Fail-closed behaviour

- Strategy not configured (no params/salt) → Steal answers HOLD
  without a proof; Gatekeeper is unaffected.
- Envelope commitment mismatch → HOLD without a proof.
- Proof generation or local verification fails → HOLD without a proof
  (never a crash or a timeout).
- Bad HMAC → 401. Malformed envelope → 400.
- A missing proof costs −2 and resolves as HOLD; a timeout forfeits
  the turn entirely — so the server always answers fast, with or
  without a proof.

## Open items / assumptions (verify at practice time, not in code)

- **Dashboard commitment form**: the public docs + reference say the
  form takes a precomputed commitment hash. The exact fields were not
  inspectable from here (no browser access in this task); if the form
  asks for the 8 params instead, enter `10,0,0,0,0,0,0,0` and have
  the parent agent re-verify the commitment against the server log.
- **Preflight on /steal**: assumed to use the same handshake as
  Gatekeeper (same `agent-games.preflight.v1` type, same spaced body +
  hex signature). The build guide documents one preflight for both
  tracks; the spaced body is what passed live for Gatekeeper. The
  dashboard preflight for GEMUWASHI 2 is the verification step.
- **Turn-response signature format**: turn responses are sent
  minified JSON + hex HMAC, exactly like the Gatekeeper task responses
  that were accepted live (practice APPROVE, proof VERIFIED). Only the
  preflight needed the spaced body. If the Steal practice turn is
  rejected for signature reasons, the fallback is to send the turn
  response with the spaced body too.
- **Turn window**: the envelope carries `deadlineAt`; the reference
  implementation notes a ~30 s Steal push window. Proof generation
  here is ~0.6–1.2 s, so the window is comfortable either way.
- **Fortify duration**: the guide says FORTIFY blocks 6 "this turn";
  the envelope's `*FortifiedUntilTurn` fields hint at a possible
  duration. The circuit cannot see fortify state, so the strategy
  does not depend on the answer — but if the practice/live turns show
  fortify behaving differently, note it for a future strategy review.
- **Per-turn scoring** beyond the −2 invalid-proof rule is not
  published on /build; match outcome is by final balance.
- **Kurier** is optional and best-effort (12 s bounded wait); the
  response always carries the local proof. No Kurier key is set for
  service 2 unless the user supplies one.

## Secrets

No secrets are in this repo. `.env` (which holds the real salt for
local testing), `data/`, and `kurier-vk.json` are git-ignored — and the
scaffold zip handed to the user **must exclude `.env`** (same as the
Gatekeeper handoff). The salt is a private circuit input: keep it in
Railway env vars only. Secrets are never logged (the server logs the
commitment hash, which is public, but never the salt or the params).
