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
| `src/decide.js` | Deterministic 7-trap checklist + persistent seen-set (`data/seen.json`) + response cache (`data/responses.json`) |
| `src/prove.js` | Circuit input mapping (13 inputs) + `taskId` → field element |
| `src/field.js` | BN128 field arithmetic, keccak256 (js-sha3 — Node's crypto has SHA3-256, NOT Keccak-256) |
| `src/hmac.js` | HMAC-SHA256 verify/sign (hex default, `sha256=` fallback) |
| `src/snark.js` | snarkjs wrapper: `groth16.fullProve` / `verify` / export VK |
| `src/kurier.js` | Kurier `register-vk` / `submit-proof` / poll to Finalized — optional, best-effort, never blocks a reply |
| `test/test-gatekeeper.js` | Unit harness: 7 traps, boundaries, reuse/retry, HMAC, real prove+verify, wrong-decision-must-throw |
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

## Open items (confirm in practice, not in code)

- `taskId` mapping default `keccak256(task_id) mod p` — unconfirmed until a practice task's proof is accepted; `numeric`/`hex` are the fallbacks.
- HMAC header format default bare hex — `sha256=` is the fallback if preflight is rejected.
- The agent trusts the platform-HMAC-signed envelope fields; it does not independently query zkVerify for on-chain proof status (all 7 traps are defined on envelope fields). The circuit proof it generates attests to its own decision.
- Steal the VFY was NOT scaffolded (Swiss Round 1 opened 13 Nov; late entry is likely closed — confirm in the dashboard if ever wanted).

## Sources

- https://agentgames.zkverify.io/build, /guide, /rules, /events/proof-gatekeeper, /api/circuit-info (fetched 2026-11-16 ~03:10 WIB)
- Public reference implementation by competitor @rday98 (MIT-unlicensed public repo, studied for protocol facts only — circuit input mapping, trap order/boundaries, response shape, Kurier flow, hosting measurements; all code in `~/workspace/agent-games/src/` was written fresh): https://github.com/subastian1998/agent-games-season-01
