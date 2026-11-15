# Agent Games — Proof Gatekeeper agent

Scaffold for **@gemuwashi** (registered via X, 2026-11-16 ~03:10 WIB),
zkVerify Agent Games Season 01. Competition closes **2026-11-21T22:00Z**.
Proof Gatekeeper: 8 daily rounds 13–20 Nov, 8 tasks/agent/round, 60s window,
cumulative scoring. Round 4 opens Mon 16 Nov 17:30 WIB.

## What it does

Plain Node.js `http` server (no framework). `POST /gatekeeper`:

1. Verifies `x-agent-games-signature` (HMAC-SHA256) over the **raw** body
   before parsing anything.
2. Answers preflight `{"type":"agent-games.preflight.v1"}` with
   `{"ok":true,"protocolVersion":"v1"}` (signed).
3. Decides each task with the deterministic 7-trap checklist (first failing
   trap wins): `VK_SUBSTITUTION` → `PROOF_REUSED` → `THRESHOLD_MISMATCH` →
   `EXPIRED_CONDITION` → `RECIPIENT_MISMATCH` → `AMOUNT_OVERFLOW` →
   `VALID_CONDITION` (APPROVE). Boundaries: balance == minimum and amount ==
   max are VALID; expiry is strict (`current_block == expiry_block` is
   EXPIRED). A retry of the same `task_id` returns the cached response and
   is NOT a proof reuse.
4. Generates a Groth16 proof locally with snarkjs + the official circuit
   (13 inputs / 13 public signals) and verifies it locally before replying.
   If proof generation fails, the decision is sent **without** a proof
   rather than crashing (fail closed).
5. Optionally submits the proof to Kurier (best-effort, bounded 20s wait)
   and attaches `proofReference`. Without a Kurier key the response still
   carries the local proof — Kurier never blocks a reply.

`GET /health` reports HMAC/Kurier config and the startup proof self-test.

## Run

```
npm install
cp .env.example .env   # fill in AGENT_GAMES_HMAC_SECRET (dashboard)
node src/server.js     # or: npm start
```

## Test

```
npm run test:gatekeeper
```

Replays all 7 traps, the boundaries, reuse/retry semantics, HMAC
round-trip, and real Groth16 prove + local verify for an APPROVE and a
REJECT scenario (plus a wrong-decision proof that must fail witness
generation — the circuit is the referee).

## Files

```
src/server.js        entry point (GET /health, POST /gatekeeper)
src/decide.js        7-trap checklist + seen-set + response cache (data/)
src/prove.js         circuit input mapping, taskId -> field element
src/field.js         BN128 field arithmetic, keccak256
src/hmac.js          HMAC-SHA256 verify/sign
src/snark.js         snarkjs wrapper (prove / verifyLocally)
src/kurier.js        Kurier submit-proof + poll to Finalized (optional)
test/test-gatekeeper.js
circuits/            official gatekeeper.wasm + gatekeeper_final.zkey
                     vkHash 0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0
```

## Dashboard steps (user, in the browser)

1. **Register the endpoint:** dashboard → My Agents → endpoint URL
   `https://<your-public-host>/gatekeeper` (HTTPS, full handler path).
2. **Rotate Secret** → paste the one-time secret into `.env` as
   `AGENT_GAMES_HMAC_SECRET`, restart the server.
3. **Preflight + practice task** — confirms the HMAC format and the
   `taskId` mapping. If the practice proof is rejected, set
   `GATEKEEPER_TASK_ID_MODE=numeric` (or `hex`) in `.env` and retry.
4. **Kurier (optional):** sign up at https://kurier.xyz (free, email),
   paste the key as `KURIER_API_KEY`, restart.
5. Enter the Proof Gatekeeper event from the Events page.

## Open items (confirm in practice, not in code)

- `taskId` mapping: default is `keccak256(task_id) mod p`. The circuit
  needs a field element for the string task_id; if the platform rejects
  the practice proof, switch `GATEKEEPER_TASK_ID_MODE`.
- HMAC header format: default bare hex; `sha256=` is the fallback.
- The agent trusts the envelope fields the platform HMAC-signed; it does
  not independently query zkVerify for on-chain proof status (the trap
  checks are all defined on envelope fields). The circuit proof it
  generates attests to its own decision.

## Secrets

No secrets are in this repo. `.env`, `data/`, and `kurier-vk.json` are
git-ignored. Secrets are never logged.
