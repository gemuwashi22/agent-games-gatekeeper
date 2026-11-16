# Agent Games — Proof Gatekeeper scaffold: PROGRESS

Built: **Mon 2026-11-16 ~03:10–03:20 WIB** (scaffold subagent). User @gemuwashi
registered via X ~03:10 WIB. No registration, sign-in, credential use, or
platform submission was done by this work — code + research only.

## What was built

A working Proof Gatekeeper agent server in `~/workspace/agent-games/` —
plain Node.js `http`, no framework. It was tested end-to-end locally
(see "Test results" below); it is NOT deployed anywhere yet.

### Files

| File | What it is |
|---|---|
| `src/server.js` | Entry point: `GET /health`, `POST /gatekeeper` (preflight + tasks), raw-body HMAC verify, signed responses, idempotency cache, fail-closed proof handling |
| `src/decide.js` | Deterministic 7-trap checklist + persistent seen-set (`data/seen.json`) + response cache (`data/responses.json`) — in-memory source of truth with synchronous write-through; see the PROOF_REUSED fix below |
| `src/prove.js` | Circuit input mapping (13 inputs) + `taskId` → field element |
| `src/field.js` | BN128 field arithmetic, keccak256 (js-sha3 — Node's crypto has SHA3-256, NOT Keccak-256) |
| `src/hmac.js` | HMAC-SHA256 verify/sign (hex default, `sha256=` fallback) |
| `src/snark.js` | snarkjs wrapper: `groth16.fullProve` / `verify` / export VK |
| `src/kurier.js` | Kurier `register-vk` / `submit-proof` / poll to Finalized — optional, best-effort, never blocks a reply |
| `test/test-gatekeeper.js` | Unit harness: 7 traps, boundaries, reuse/retry, HMAC, real prove+verify, wrong-decision-must-throw |
| `test/test-seen-store.js` | Seen-proof store test (HTTP): same-proof reuse, different-proof normal, file write + restart persistence, same-task retry cached (14/14) |
| `test/smoke-live.js` | Live HTTP smoke test: starts the real server, exercises /health, preflight, auth, task, trap, retry, reuse |
| `circuits/gatekeeper.wasm` | Official circuit, 1,755,820 B, sha256 `be00aefe3c8ba910951a242f50e55937bf82a0375ad4b69c2ef10629ab92764f` |
| `circuits/gatekeeper_final.zkey` | Official proving key, 309,750 B, sha256 `adfe95a439a7063a82a4967ef026d2dd6857a4d02c63b3caf63dac02e01af80d` |
| `circuits/circuit-info.json` | vkHash `0x6b79c6012a6d8651f3e13bc4d2a20370280ab49700c90c5316d4168bfbad77b0` (network mainnet; source `/api/circuit-info`) |
| `.env.example`, `.gitignore` | Env template; `.env`, `data/`, `kurier-vk.json` are ignored — no secrets in the repo |
| `README.md` | Run/test instructions + dashboard steps |
| `package.json` | `agent-games-gatekeeper` 0.1.0, Node >= 22; deps: snarkjs 0.7.6, js-sha3 0.14.0, poseidon-lite 0.3.0, circom_runtime 0.1.28 |

### Protocol facts baked in (verified from the official pages + circuit)

- Task envelope: `{type:"agent-games.proof-gatekeeper.v1", task_id, mode, issued_at, deadline_at, input:{registered_vk, proof_vk, minimum, public_balance, expiry_block, current_block, recipient, condition_recipient, amount, max_transfer, proof_tx}}`.
- Response: `{decision, reason_code, proof_tx, proof:{pi_a,pi_b,pi_c,protocol:"groth16",curve:"bn128"}, public_signals:[13 values]}`; `PROOF_REUSED` carries no proof. Every response signed with `x-agent-games-signature` (HMAC-SHA256 over the raw body).
- Preflight: `{"type":"agent-games.preflight.v1"}` → `{"ok":true,"protocolVersion":"v1"}`, signed.
- Trap order (first failing trap wins): `VK_SUBSTITUTION` (proof_vk ≠ registered_vk) → `PROOF_REUSED` (proof_tx seen under a different task_id) → `THRESHOLD_MISMATCH` (balance < minimum) → `EXPIRED_CONDITION` (current_block ≥ expiry_block) → `RECIPIENT_MISMATCH` → `AMOUNT_OVERFLOW` (amount > max_transfer) → `VALID_CONDITION` (APPROVE). Boundaries: balance == minimum and amount == max are VALID; expiry is STRICT.
- Circuit inputs (13): registeredVkHash, proofVkHash, minimum, publicBalance, expiryBlock, currentBlock, recipient, conditionRecipient, amount, maxTransfer, decision (1/0), taskId, salt (private). Public signals (13): [salt-binding hash, + the 12 task fields + decision + taskId]. A wrong decision fails witness generation at circuit line 102 — the circuit is the referee.
- Scoring: correct +12, wrong APPROVE −6, wrong REJECT −3, timeout −2, missing/invalid proof −2, reliability bonus +0..+5 (pro-rated by verified proofs; PROOF_REUSED tasks excluded).
- Rounds: 8 daily, 13–20 Nov, 17:30–03:30 WIB, 8 tasks/agent/round, cumulative. Round 4 opens Mon 16 Nov 17:30 WIB. Rounds 1–3 are already gone — a new entrant starts 0 points behind agents with 3 rounds banked.
- Rules that shaped the code: public HTTPS endpoint, no localhost/custom ports; task IDs are idempotency keys (platform retries); offline agent forfeits tasks; one agent per owner; no manual play; practice mode capped at 10 dispatches/agent/hour.

## Test results (all local, 2026-11-16 ~03:13 WIB)

- `npm run test:gatekeeper`: **22 passed, 0 failed.** All 7 traps, boundaries (balance==minimum VALID, amount==max VALID, current==expiry EXPIRED), trap precedence, reuse vs same-task retry, HMAC round-trip (hex + `sha256=`), real APPROVE proof (864ms, 13 public signals, verifies locally, signals echo the task fields), real REJECT proof (304ms, verifies), and a wrong-decision proof that correctly throws at circuit line 102.
- `npm run test:smoke`: **17 passed, 0 failed.** Real server on 127.0.0.1:18081 with a throwaway HMAC secret: /health + startup self-test PASS, preflight 200 + signed + signature verifies, unsigned request → 401, valid task → APPROVE + proof in 280ms, trap task → REJECT/THRESHOLD_MISMATCH + proof, same-task retry → cached APPROVE, same proof_tx under a new task_id → PROOF_REUSED with no proof. (One smoke-test bug found and fixed during the run: the trap case initially reused the first task's proof_tx, which correctly triggered PROOF_REUSED — the server was right, the test was wrong.)

## How to run + test locally

```
cd ~/workspace/agent-games
npm install            # already done once; 37 packages
cp .env.example .env   # fill in AGENT_GAMES_HMAC_SECRET before going live
npm start              # node src/server.js, default :8080
npm run test:gatekeeper
npm run test:smoke
```

## HOSTING — the blocker (measured on this VM, 2026-11-16 ~03:14 WIB)

**Recommendation: deploy on Railway (or the user's own PC/VPS). This VM cannot host the public endpoint.**

Evidence:
- The VM has **no public IP**: its addresses are `198.19.0.2` (CGNAT, not routable) and a ULA IPv6. Egress IP `104.29.194.33` belongs to the egress proxy, not the VM. Nothing can connect inbound to this VM.
- **Egress proxy blocks tunnel services**: `api.trycloudflare.com` returns **403** (measured); `cloudflared tunnel --url` (v2026.11.0, downloaded for the test) fails with `tls: first record does not look like a TLS handshake` — the proxy intercepts TLS. Tunnelmole's service endpoint was likewise measured returning 502 through this proxy (independent measurement by another competitor on the same VM class, 2026-11-15).
- **No tunnel/hosting CLIs or credentials on this VM**: `cloudflared`, `railway`, `wrangler` all NOT installed; no `~/.cloudflared`; no Cloudflare/Railway token in env or config.
- **Cloudflare Workers is not a drop-in host**: the user's `gemuwashi.rajaaku28.workers.dev` domain exists (vAPI quote API), but that Worker was deployed by the owner following instructions — no deploy credential lives on this VM — and this agent is a long-running Node process (snarkjs + 2 MB circuit files), not a Worker script. Porting proving into a Worker is unproven work, not a deployment path.
- **VM restarts kill background processes**, and a random tunnel URL would change on restart (re-registration in the dashboard each time).

What the host needs: Node >= 22, always-on during rounds (17:30–03:30 WIB daily through 20 Nov; a sleeping free tier forfeits tasks), public HTTPS URL on a standard port, ~66 MB for the project (mostly node_modules) + the 2 MB circuit files. Railway is the proven path for this exact agent (the public reference implementation by @rday98 runs on Railway from a public GitHub repo). Any VPS or an always-on home PC works too.

## Still needed from the USER (exact dashboard steps)

1. **Register the endpoint** (after hosting is chosen): dashboard → My Agents → endpoint URL `https://<public-host>/gatekeeper` (HTTPS, full handler path, no custom port).
2. **Rotate Secret** in the dashboard → paste the one-time 32-byte secret into `.env` as `AGENT_GAMES_HMAC_SECRET` and restart the server. (The secret is shown exactly once; never paste it into a chat message — hand it over via the Secure Vault / env file path the parent agent specifies.)
3. **Preflight + at least one practice task** from the dashboard — this confirms the HMAC format and the `taskId` mapping. If the practice proof is rejected, set `GATEKEEPER_TASK_ID_MODE=numeric` (or `hex`) in `.env` and retry; the mapping is one function in `src/prove.js`.
4. **Kurier API key (optional but recommended for the reliability bonus pointer):** free signup at https://kurier.xyz (email) → paste as `KURIER_API_KEY` in `.env`, restart. Without it the server still responds with the local proof.
5. **Enter the Proof Gatekeeper event** from the Events page once the agent is registered and preflight passes. Do this BEFORE round 4 opens (Mon 16 Nov 17:30 WIB) to catch the remaining rounds 4–8.
6. **Hosting decision**: Railway account (recommended) or own PC/VPS — the agent cannot run on this VM (see above). If Railway: link the repo / deploy `~/workspace/agent-games` (Node 22, `npm start`, set the env vars in Railway, not in the repo).

## Steal the VFY — added Mon 2026-11-16 ~06:30–07:00 WIB (coordinator task)

- Same server, additive `POST /steal` handler; Gatekeeper code path untouched (re-ran 22/22 + 17/17, unchanged).
- Protocol from official /build §06 + /api/circuit-info, validated against the official vfy-policy circuit (sha256-identical to the public reference's copies). Full docs in STEAL.md.
- Strategy **"always EXTRACT 10"** (`10,0,0,0,0,0,0,0`): extract 10 dominates smaller amounts (same 0 cost, gain 10 vs 5 unfortified / 4 vs 0 fortified); FORTIFY is dominated by EXTRACT in every single-turn comparison (costs 2, blocks 6, forgoes your own extract); minOpponentBalance 0 avoids forced HOLDs while the opponent still extracts from you. Unbeaten except by the mirror (draw). See STEAL.md for the full analysis.
- Commitment for those params: `0x0bfddb9d54008554f717a00e0c9939efd5b8fab8b9bb34fce0ca4af73ecd16c5` (salt in local `.env`, gitignored — NEVER in the repo or the scaffold zip). Verified end-to-end: real-values EXTRACT 10 proof in 1,228 ms, verifies locally.
- Tests: `test-steal.js` **65/65**, `smoke-steal.js` **30/30** (turn answered in 585 ms; proof inside policyProof AND at top level; commitment-mismatch → HOLD; retry → cached).
- Still needed from the user (before 17:30 WIB today, R4): register the commitment in the dashboard (My Agents → Edit agent → Steal the VFY → "Set up strategy commitment"), create Railway service 2 with agent 2's HMAC secret + the steal env vars, set its endpoint to `https://<service-2-domain>/steal`, preflight + practice, enter the Steal event. Full checklist in STEAL.md.
- Open items: the exact dashboard commitment-form fields (hash per the docs/reference — unconfirmed from here); turn-response signature format assumed minified like Gatekeeper (preflight needs the spaced body); fortify duration ("this turn" per the guide vs `*FortifiedUntilTurn` fields); per-turn scoring beyond the −2 invalid-proof rule is unpublished.

## PROOF_REUSED fix — Mon 2026-11-16 ~18:15–18:25 WIB (fix coordinator)

- **The bug (verified by a practice dispatch 2026-11-16 18:04 WIB):** the agent APPROVED a proof that had already been approved in a prior task. Expected REJECT, proof FAILED, platform error verbatim: "This proof transaction was already approved in a prior task." Trap type PROOF_REUSED. The agent correctly rejects EXPIRED_CONDITION and VK_SUBSTITUTION (verified in Railway logs); only reuse detection was broken.
- **Root cause (deeper than the brief's "stateless" premise):** the code ALREADY had the PROOF_REUSED trap and a file-backed store (`data/seen.json`, `data/responses.json`) — but `data/` is gitignored, so it is NOT in the GitHub repo, and every fresh Railway deploy starts with an EMPTY seen set. The 06:52 WIB redeploy (Steal code upload) replaced the container, wiping the in-container seen.json that held the 06:02 practice approval (proof_tx `0x1e97f1fa...`, whose prefix matches the 06:02 practice task ID `practice_1e97f1fa-...`). At 18:04 the reused proof_tx was not in the empty seen set → APPROVE (wrong). Secondary issue: the old store re-read the file on every access (no single in-memory source of truth) and recorded only AFTER the async proof generation (~300 ms gap), so check+record was not atomic.
- **Proof-reference determination: `input.proof_tx`** (0x-prefixed 32-byte hex, lowercase-normalized). Evidence: the task envelope carries `input.proof_tx` (decide.js, prove.js, server.js, tests); the platform error calls it "this proof transaction"; build guide §04 lists "The proof reference has not already been used for another task" among the checks; the gatekeeper circuit's 13 public signals do NOT include proof_tx (envelope-level identifier, not a circuit input); the 18:04 proof_tx shares its prefix with the 06:02 practice task ID, confirming the platform reuses proof_tx values across practice dispatches. The guide's envelope section does not name the field explicitly — the code + platform error establish it.
- **The fix (src/decide.js + src/server.js, no circuit/proof/Steal changes):** the store now holds a single in-memory Map loaded ONCE at startup (source of truth) with synchronous write-through to disk on every update; `store.markSeen(task)` is called synchronously right after `decide()` and BEFORE the async `proveTask`, so check+record is atomic within a request; `store.cacheResponse(task, response)` is called after the response is complete (proof included, if any) so a retry gets the full answer; the old `store.record()` (post-prove) was removed. The proof reference is recorded for every processed task regardless of the decision, EXCEPT a PROOF_REUSED decision itself (the reference is already recorded under the original task_id — overwriting would lose the first-use record). A task with no proof_tx is never flagged as a reuse. New optional env var `SEEN_DATA_DIR` (defaults to the existing `data/`) lets the operator point the store at a persistent volume (e.g. a Railway volume mounted at `/data`) so the seen set survives a container replace; backwards-compatible, no other behaviour change. Preflight path untouched; the Gatekeeper circuit and proof generation untouched; Steal code untouched.
- **Tests (all re-run after the fix, Node v24.22.1):** `test-gatekeeper.js` **22/22**, `smoke-live.js` **17/17**, `test-steal.js` **65/65**, `smoke-steal.js` **30/30** — no regressions. New `test/test-seen-store.js` (npm run `test:seen-store`) **14 passed, 0 failed** over HTTP against a local server with an isolated `SEEN_DATA_DIR`: (a) same proof_tx under a new task_id → first APPROVE/VALID_CONDITION with a proof, second REJECT/PROOF_REUSED with no proof; (b) two different proof_tx values → both APPROVE; (c) `seen.json` written (P1 → seen_a_001, P2, P3 present; the PROOF_REUSED task_id NOT recorded) and after a server restart the reloaded store still rejects P1 and P2 under new task_ids, a same-task retry still returns the cached APPROVE, and a fresh proof_tx is still decided normally. Real-env boot test: server boots with the real `.env`, `/health` self-test PASS (APPROVE proof 1,102 ms), Steal self-test PASS (706 ms), Steal commitment `0x0bfddb9d...` matches the registered value, preflight 200 `{"ok": true, "protocolVersion": "v1"}` (spaced body, untouched). (Local `.env` has no HMAC secret by design — `hmacConfigured: false`, dev mode — the real secret lives only in Railway.)
- **Known limits (state plainly):** the store starts EMPTY on this deploy — proofs seen before the redeploy (including the 06:02 and 18:04 practice approvals) are NOT in it, so a proof reused from before the redeploy would not be caught until it is seen once after the redeploy. A future container restart/replace also clears it UNLESS a Railway volume is mounted and `SEEN_DATA_DIR` points at it (the volume is NOT set up yet — optional follow-up, needs a Railway dashboard step: add a volume to service 1, mount at `/data`, set `SEEN_DATA_DIR=/data`). The store file is gitignored runtime state and is NOT in the deploy zip by design.
- **Deploy:** rebuild `~/workspace/agent-games-scaffold.zip` with the fix (same exclusions: `.env`, `node_modules/`, `data/`, `kurier-vk.json`); user uploads to https://github.com/gemuwashi22/agent-games-gatekeeper (web upload, main branch) and Railway auto-deploys service 1. Verify after deploy: log lines `[server] listening on:8080 (taskIdMode=keccak, hmac=configured, ...)` and `[server] steal: ready commitment=0x0bfddb9d...`; then a practice dispatch should PASS (and a repeated proof_tx in a second practice task should be REJECTED as PROOF_REUSED).

## Open items (confirm in practice, not in code)

- `taskId` mapping default `keccak256(task_id) mod p` — unconfirmed until a practice task's proof is accepted; `numeric`/`hex` are the fallbacks.
- HMAC header format default bare hex — `sha256=` is the fallback if preflight is rejected.
- The agent trusts the platform-HMAC-signed envelope fields; it does not independently query zkVerify for on-chain proof status (all 7 traps are defined on envelope fields). The circuit proof it generates attests to its own decision.
- Steal the VFY was NOT scaffolded (Swiss Round 1 opened 13 Nov; late entry is likely closed — confirm in the dashboard if ever wanted).

## Sources

- https://agentgames.zkverify.io/build, /guide, /rules, /events/proof-gatekeeper, /api/circuit-info (fetched 2026-11-16 ~03:10 WIB)
- Public reference implementation by competitor @rday98 (MIT-unlicensed public repo, studied for protocol facts only — circuit input mapping, trap order/boundaries, response shape, Kurier flow, hosting measurements; all code in `~/workspace/agent-games/src/` was written fresh): https://github.com/subastian1998/agent-games-season-01
