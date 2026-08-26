# Lockdown External Audit Brief

**Prepared for external security review.**

This repository is a self-contained codebase for external security review. Clone
the repository with submodules and run `forge test` immediately. The contract's
external Solidity dependencies are the pinned OpenZeppelin Contracts submodule
(MIT) and the pinned safe-smart-account submodule (LGPL-3.0, used for the Safe
v1.5.0 interfaces, `Enum`, `MultiSendCallOnly`, and the Safe-derived fallback
handler surface). The test suite additionally uses `forge-std` (MIT OR
Apache-2.0, vendored submodule) and requires no private keys. See
`LICENSING.md` for the mixed-license model: Runtime Capital original code is MIT;
`src/handlers/LockdownFallbackHandler.sol` is LGPL-3.0-only.

## Status: v1.0.0 Solidity audit candidate

This brief describes the public **v1.0.0 audit candidate**, currently in
`src/LockdownTimelock.sol:LockdownTimelock`, which inherits the concrete
lockdown-only base in `src/Lockdown.sol:Lockdown`. `LockdownTimelock` is the
production deployment target submitted for external review; `Lockdown` is kept
as the no-timelock base and is tested directly.

The candidate supersedes earlier development iterations that were never
released. The exact candidate commit and source tree supplied for review are
the authoritative audit target.

### Implementation status (2026-08-12, PR #69 refresh)

- `src/Lockdown.sol`: V1 ERC-7913 signer-identity base implemented per
  SPEC_V1.md. Signers are stored as bytes identities:
  20-byte EOA/ERC-1271 addresses, or `verifier || key` for ERC-7913 verifiers.
- `src/LockdownTimelock.sol`: production singleton deployment target. Extends
  `Lockdown` with owner-path and module-path timelock, bypass, scheduling,
  sweep, and transient module in-flight guard logic.
- `@openzeppelin/contracts/interfaces/IERC7913.sol`: ERC-7913 verifier
  interface used directly from the pinned OpenZeppelin Contracts submodule.
- `test/mocks/MockSecretVerifier.sol`: test-only preimage-of-commitment
  verifier (production-forbidden), used to exercise the non-ECDSA dispatch
  path.
- `test/Lockdown.t.sol`: 198 unit + fuzz tests (V1 core, incl. INV-SIGN-7
  burnt-keys, F-M2-01 phantom-recovery closure, H.19 recovery-owner
  validation, uninstall/reinstall persistence pins).
- `test/LockdownTimelock.t.sol`: 93 V1 timelock + sweep + refund-gate +
  stale-ticket-reinstall tests.
- `test/fuzz/DecoderDifferentialTest.t.sol`: 5 focused differential tests for
  the MultiSend calldata decoder and non-canonical `bytes` encodings.
- `test/integration/SafeIntegration.t.sol`: 26 real-Safe integration tests
  (owner-path + module-path + timelock over a genuine Safe v1.5.0
  deployment via `SafeProxyFactory`).
- `test/verifiers/PasswordVerifier.t.sol`: 10 unit + fuzz tests.
- `test/verifiers/WebAuthnVerifier.t.sol`: 10 unit tests over OZ
  WebAuthn/P256 with a real secp256r1 fixture.
- `test/mocks/MockSecretVerifier.sol`: test-only preimage-of-commitment
  verifier exercising the non-ECDSA dispatch path. Production-forbidden.
- `test/mocks/MockAdversarialVerifiers.sol`: seven adversarial mocks used to
  validate trigger-time STATICCALL revert/return normalisation:
  `MockRevertingVerifier`, `MockWrongMagicVerifier`,
  `MockEmptyReturnVerifier`, `MockAlwaysMagicVerifier`,
  `MockSelectiveMagicVerifier`, `MockSelectiveRevertingVerifier`
  (a selectively-malicious signer is neutralised by per-signer
  `removeLockdownSigner` plus the L.3 revert normalisation), and
  `MockToggleVerifier` (pins that a failed trigger attempt leaves no
  burnt-signer state behind).
- `test/echidna/EchidnaLockdown.sol`: V1 harness with 15 stateful
  invariants (cross-key isolation × 2, signersCount bound = 32,
  no-owner-path-during-lockdown,
  no-module-path-during-recovery, allowlistCountNeverZero (recovery owners),
  module-path-cannot-reach-singleton, burnt-signer-never-resurrects,
  removed-selective-magic-signer-cannot-trigger,
  recovery-admin-selectors-rejected,
  resume-delay-cannot-reopen-incident (INV-LIFE-1 / F-M2-01),
  V1: bypassRejectedDuringIncident (INV-TIME-7),
  sweepClearsExpiredOwnerTicketSlot (INV-TIME-8),
  disarmGatedByTimelock (INV-LIVE-1), lockdownCoversTimelock
  (INV-LIVE-3)). The harness uses `vm.warp` for
  time advancement so post-resume Normal is reachable during fuzz.
- `scripts/preflight-install-v1.sh` and `scripts/verify-install-v1.sh` assume
  the V1 ABI (`getConfigSnapshot` with 5 fields, ERC-5267 `eip712Domain()`,
  no `Guard.SAFE()`).
- `docs/V1_REVIEW_PROMPT.md`: focused independent-review brief.
- `docs/V1_NON_GOALS.md`: explicit V1 scope freeze and future-work exclusions.
- `docs/DESIGN_DECISIONS.md`: concise public record of v1.0.0 decisions and
  accepted limitations.
- `docs/V1_HARDWARE_WALLET_UX.md` and the descriptors under
  `docs/clear-signing/`:
  signer-facing UX guide and ERC-7730-inspired template for the V1 ABI.
- `forge test`: **483 passed total** (198 Lockdown + 95 Timelock + 5 decoder
  differential fuzz + 26 real-Safe integration tests + 10 PasswordVerifier +
  10 WebAuthnVerifier + 2 captured-device WebAuthn fixture tests + 137 `test/poc/`
  adversarial proofs from the pre-tag review, see below);
  the unit suite covers EIP-712 binding, single-use burn, cross-key isolation,
  registration sanity (20-byte EOA/ERC-1271 or verifier code + key-length
  bounds), recovery whitelist (with the V1 hardening:
  `removeLockdownSigner` during Recovering [H.4],
  `ModuleCallToSingletonDenied` even pre-init [H.12],
  `onlyNormal`/`InvalidState` state gate, `swapOwner` exact-length, `SafeDormant` event on
  every signersCount→0 transition [H.15], signer identity in `SafeLockedDown`
  [H.16], verifier revert normalisation to `BadSignature`,
  pure `testSigner` view for
  drills [H.17]).

Auditor: please read `specs/SPEC_V1.md` first for the intended behaviour.
Pay particular attention to the **Hardening log** at the bottom of SPEC_V1:
it lists behavioural changes made during pre-audit review and the questions
they surfaced.

## Auditor Start Here (6 files)

1. `AUDIT_BRIEF.md` (this file) - threat model + questions
2. `specs/SPEC_V1.md` - design contract (including Hardening log H.1-H.22
   and the V1 timelock section)
3. `docs/V1_REVIEW_PROMPT.md` - independent-review brief and explicit review goals
4. `docs/V1_USER_SCENARIOS.md` - operator's mental model: every supported
   scenario, organised by lifecycle phase (install / normal / incident /
   recovery / post-resume / forensics), with code references and rationale.
   §8.3.9 ranks the production verifiers by adversarial robustness.
5. `src/LockdownTimelock.sol` - the production singleton (17,590 B runtime,
   6,986 B EIP-170 margin) and `src/Lockdown.sol` - the lockdown-only base
   (12,320 B runtime). Use `scripts/contract-sizes.sh`; `forge build --sizes`
   can omit these production artifacts in this via-IR setup.
6. `test/Lockdown.t.sol` + `test/LockdownTimelock.t.sol` +
   `test/verifiers/*` (plus generated captured-device fixtures) - the
   forge-std-based test suite

Superseded internal-design drafts and scripts are intentionally absent from the
release tree. The supplied commit and `specs/SPEC_V1.md` are authoritative;
reviewing earlier Git history is not required.

Date: 2026-07-15

## One-line summary

`Lockdown` is a Safe v1.5.0 dual guard (`ITransactionGuard` +
`IModuleGuard`) that lets any authorized lockdownSigner trigger a panic lockdown. During
lockdown and recovery, owner-path and module-path execution are blocked except
for a deliberately narrow owner-path recovery whitelist.

## Primary target

Review `src/LockdownTimelock.sol` and its base/components:
`src/Lockdown.sol`, `src/base/StateMachine.sol`,
`src/base/LockdownSigners.sol`, `src/base/RecoveryOwners.sol`,
`src/base/Timelock.sol`, and the companion
`src/handlers/LockdownFallbackHandler.sol` (drop-in fallback handler that
freezes the Safe's ERC-1271 surface during an incident; `initialize`
requires it installed), plus `src/utils/LockdownLib.sol` (module-transaction
hash construction shared by the guard and timelock paths).

### Scope and line counts

In-scope production code is `src/LockdownTimelock.sol`, `src/Lockdown.sol`,
`src/base/StateMachine.sol`, `src/base/LockdownSigners.sol`,
`src/base/RecoveryOwners.sol`, `src/base/Timelock.sol`,
`src/handlers/LockdownFallbackHandler.sol`,
`src/utils/LockdownLib.sol`,
`src/verifiers/PasswordVerifier.sol`, and `src/verifiers/WebAuthnVerifier.sol`
plus the pinned OpenZeppelin and safe-smart-account integration surface.

Line counts for the in-scope Solidity (nSLOC = non-blank, non-comment source
lines; regenerate before freezing the candidate, since sources may still
change):

| File | LOC | nSLOC |
| --- | --: | --: |
| `src/Lockdown.sol` | 579 | 339 |
| `src/LockdownTimelock.sol` | 365 | 177 |
| `src/base/Timelock.sol` | 432 | 192 |
| `src/base/StateMachine.sol` | 196 | 115 |
| `src/handlers/LockdownFallbackHandler.sol` | 248 | 102 |
| `src/base/LockdownSigners.sol` | 133 | 67 |
| `src/base/RecoveryOwners.sol` | 101 | 52 |
| `src/utils/LockdownLib.sol` | 66 | 42 |
| `src/verifiers/WebAuthnVerifier.sol` | 93 | 14 |
| `src/verifiers/PasswordVerifier.sol` | 99 | 18 |
| **Total (10 files)** | **2312** | **1118** |

The pinned OpenZeppelin Contracts submodule (WebAuthn, P256, ECDSA,
MessageHashUtils) is audited upstream: it is in scope as integration surface
(how the wrappers call it, wire formats, malleability assumptions), not for
re-audit of the OZ code itself.

The requested audit scope is **Solidity only**. Tests, mocks, specifications,
and previous assurance reports are supplied as review evidence and context;
they are not separate findings targets. Shell scripts, deployment tooling,
clear-signing descriptors, the HTML operator helper, hosted services, and prose
documentation are explicitly out of scope. Informational observations about
them are welcome but must not consume the Solidity review budget.

## Intended production use

The contract must be installed on a Safe v1.5.0 with all three slots wired:

- transaction guard via `setGuard(address)`;
- module guard via `setModuleGuard(address)`;
- fallback handler via `setFallbackHandler(address)` to a
  `LockdownFallbackHandler` whose `LOCKDOWN()` points to the same singleton.

The contracts are chain-agnostic. Runtime Capital intends to launch on every
network that has a canonical Safe v1.5.0 deployment and Transaction Service
support and that passes the per-chain manifest, codehash, source-verification,
and operator-flow gates. The final deployment manifest, not this brief, is the
authoritative network list. Network onboarding does not expand the Solidity
audit scope because every deployment must reproduce the same audited runtime.

The Safe must already be on v1.5.0 before installation. Any v1.4.x -> v1.5.0
migration happens in a separate hosted product flow and is never part of the
Lockdown installation transaction. Installation wires the three slots and
initializes the singleton first; signer provisioning, timelock activation, and
bypasser policy are intentionally separate, later Safe governance
transactions.

## Threat model

In scope:

- physical coercion / kidnapping / wrench attack;
- any registered lockdown signer triggering `triggerLockdown(...)` (Safe
  owners are NOT implicit signers; they must register explicitly);
- owner-path Safe transactions;
- Safe v1.5.0 module-path transactions;
- pre-signed Safe transactions collected during coercion;
- malicious or compromised modules trying to execute during lockdown/recovery.

Out of scope:

- attacker already controls Safe quorum before lockdown;
- direct owner calls to `approveHash(bytes32)` outside `execTransaction`;
- protocol-level bugs in assets held by the Safe;
- long-running malware or social engineering before the incident;
- a full DeFi semantic policy engine. Any normal-mode policy review and other
  off-chain guarantees are separate from this repository and audit.

## Design rationale

Read `specs/SPEC_V1.md` before code review. The short version:

- Safe v1.5.0 is required because v1.4.1 transaction guards do not cover
  module execution.
- After `lockdownUntil`, recovery stays active for `resumeDelay`; once
  `lockdownUntil + resumeDelay` elapses the Safe auto-resumes to Normal purely
  on time (no resume transaction, no event, no `Resumable` state). The public
  views are self-consistent: `getState` returns Normal and `getLockdownUntil` /
  `lastReasonHash` normalise to `0` / `bytes32(0)` once the window elapses. The
  raw incident fields linger until the next trigger or a later Normal-state
  `setResumeDelay`; that setter clears the elapsed incident before applying the
  new delay so it cannot reopen the old recovery window.
- Recovery allows only nonce burns, exact-length `swapOwner` to a
  pre-registered backup, exact-length `disableModule` to neutralise a module,
  and `removeLockdownSigner(bytes signer)` to cull surviving compromised
  signers (a compromised verifier is swept by removing each affected signer,
  batchable via MultiSend). No `add`, no `rotate`, no scalar setter during
  recovery.
- `recoveryOwnerAllowlist` is immutable during lockdown/recovery to stop an
  attacker from pre-signing "add attacker as recovery owner" during coercion.
- `removeOwner`, `addOwnerWithThreshold`, and `changeThreshold` are rejected
  during recovery because they degrade the owner set or threshold with coerced
  signatures.
- There is no `cancelLockdown`: a coercion attacker could force the victim to
  cancel.

## Load-bearing invariants

1. Guard hooks and admin functions are restricted to `msg.sender == SAFE` where
   appropriate.
2. Locked down state rejects every owner-path and module-path transaction.
3. Recovery rejects every module-path transaction.
4. Recovery owner-path whitelist cannot move value indirectly through Safe gas
   refunds (enforced: `RecoveryRefundDenied`). It also cannot move value directly,
   but that is NOT enforced by the guard: `value == 0` is checked only on the
   empty-data nonce-burn arm, and the `swapOwner` / `disableModule` /
   `removeLockdownSigner` arms pass any `value` through. Nothing moves because those
   callees are non-payable and the whitelist admits no third-party `to`, so such a
   transaction reverts with EMPTY return data rather than a guard error. Corrected
   pre-tag 2026-08-25; pinned by `test/poc/RecoveryWhitelistEnvelope.t.sol`.
5. Recovery only allows `swapOwner` toward pre-registered backups. The top-level
   `operation` may be a `DELEGATECALL` to canonical `MultiSendCallOnly` (every leaf
   re-validated at every depth); the earlier "CALL only" wording was wrong.
6. Recovery rejects `addOwnerWithThreshold`, `removeOwner`, and
   `changeThreshold`.
7. Recovery rejects every singleton self-call EXCEPT
   `removeLockdownSigner(bytes signer)`. The Safe-targeted recovery calls are
   nonce burn, exact-length `swapOwner` to a recovery owner, and exact-length
   `disableModule`. The module path cannot call the singleton in any state
   (`ModuleCallToSingletonDenied`).
8. Return to Normal is auto-resume: purely time-based once
   `lockdownUntil + resumeDelay` elapses, no resume call and no state mutation.
9. `recoveryOwnerAllowlist` cannot be changed during lockdown/recovery and cannot
   be emptied in normal mode.
10. `MultiSendCallOnly` parser cannot hide an inner delegatecall to any
    target other than the canonical `MultiSendCallOnly` (recursed into), and
    cannot hide a `setFallbackHandler` self-call whose handler is not a
    `LockdownFallbackHandler` bound to this singleton. Inner CALLs to the
    calling Safe, the singleton, or `address(0)` (aliased to the Safe) are
    intentionally ALLOWED: they stay Safe-quorum-gated and are reviewed via
    the scheduled outer Safe transaction hash (SPEC_V1 §11.7).
11. `checkModuleTransaction` covers both Safe v1.5.0 module entrypoints and
    cannot be bypassed by enabled modules.

## Recently fixed critical issue

The latest adversarial pass found a critical Safe refund bypass.

Safe v1.5.0 can call `handlePayment()` after `checkTransaction` when
`gasPrice > 0`. That refund can transfer ETH or ERC20 from the Safe to
`refundReceiver`, even when the business transaction has `value == 0` and even
when the target call fails later.

Without explicitly rejecting non-zero refund fields during recovery, an
otherwise whitelisted recovery transaction, such as an empty Safe self-call
nonce burn, could move assets through the refund path.

Mitigation implemented:

- `RecoveryRefundDenied()`;
- recovery-time `checkTransaction` requires `safeTxGas`, `baseGas`, `gasPrice`,
  `gasToken`, and `refundReceiver` to be zero.

Please challenge this patch and the surrounding assumptions carefully.

## Adversarial proof suite (`test/poc/`)

Added by the pre-tag review of 2026-08-25. Every claim in this brief that concerns
an adversarial behaviour is backed by an executable test rather than by prose, and
the naming convention states the verdict:

- `test_confirmed_*` - the behaviour exists as described.
- `test_refuted_*` - the attack does NOT work; the test docstring names the exact
  `file:line` that prevents it and whether that protection is DELIBERATE or an
  ACCIDENTAL consequence of something else (a non-payable callee, a compiler
  panic, gas exhaustion). The distinction matters: an accidental protection is one
  refactor away from disappearing.
- `test_limitation_*` - a real, accepted limitation, asserted so it cannot rot.
- `test_regression_*` - a defect found by this review and FIXED in `src/`; the test
  pins the fix.
- `test_control_*` - a positive control proving the neighbouring negative tests fail
  for the intended reason.

| File | Surface |
|---|---|
| `RecoveryWhitelistEnvelope.t.sol` | INV-REC-1's `value` and `operation` clauses; the recovery MultiSend envelope at depth |
| `TimelockBypassRefundLane.t.sol` | T-BYPASS-7 replayed on the inline bypasser lane, both CALL and DELEGATECALL, incl. the uncapped `gasToken` refund |
| `ModuleTicketPreimage.t.sol` | Whether the module ticket hash binds every field of the call it authorises (it does) |
| `ArmedButInert.t.sol` | Every way a Safe looks armed and has no working trigger, incl. EIP-7702; `testSigner` detectability |
| `Erc1271IncidentSignature.t.sol` | Whether the ERC-1271 freeze prevents or merely defers |
| `TimelockAccounting.t.sol` | Ticket lifecycle as resource accounting; bypasser re-arm; exact-second TTL and state boundaries |
| `SafeIntegrationLifecycle.t.sol` | Install / partial install / uninstall / reinstall / A→B singleton migration; threshold-N; both module entry points |
| `CalldataEncoding.t.sol` | MultiSend parser, ABI decoding, exact-length checks, `address(0)` aliasing |
| `DecodeCalldataBytesAdversarial.t.sol` | Guard/executor agreement on non-canonical ABI offsets, truncated tails, padding and overflow families |
| `DrillEvasionVerifier.t.sol` | Regression pin for verify-before-burn ordering and the shared `testSigner` verification path |
| `VerifierAndGriefing.t.sol` | Hostile and mutable verifier dispatch; griefing and denial |
| `TicketRevival.t.sol` | AR-16 owner-authorisation persistence after ticket deletion |

Three defects found by this review are fixed in `src/` and pinned by
`test_regression_*` tests: the wrapping bounds arithmetic in
`Lockdown._decodeCalldataBytes`, the silent no-op in `removeRecoveryOwner`,
and the remove-before-verify ordering in `triggerLockdown`.

## Known limitations and accepted risks

See also `specs/SPEC_V1.md`.

### Accepted-risk register (consolidated)

Every entry below is a deliberate, documented design decision, not an
oversight. Findings that re-state an entry without a new exploit path will
be triaged as known. Findings that show an escalation BEYOND the documented
impact are exactly what we are paying for: please challenge the rationale.

| # | Accepted residual | Where documented |
|---|---|---|
| 1 | Direct owner `approveHash(bytes32)` outside `execTransaction` is not intercepted (Safe v1.5.0 guard limitation); watchers handle it off-chain | SPEC_V1 §14 |
| 2 | 1-of-N grief: any registered signer can lock the Safe; intentional for panic activation | SPEC_V1 §14 |
| 3 | No `cancelLockdown`: a false positive waits `lockdownDuration + resumeDelay`; since PR #59 remaining signers can re-trigger to extend/re-lock (bounded `≤ (remaining signers) × lockdownDuration`) | SPEC_V1 §14 / INV-LIFE-2 |
| 4 | Post-resume zero-signer window until quorum re-registers signers; `addLockdownSigner` deliberately NOT recovery-whitelisted | SPEC_V1 §14 |
| 5 | The supported ERC-7913 product domain is limited to the immutable, closed-world verifier bytecodes shipped and codehash-pinned by this repository. The contract deliberately has no verifier allowlist and accepts third-party verifier addresses with code; outside the supported domain no behavioural or drill-reliability guarantee is offered. Any OOG, revert or invalid return condemns the whole identity, which operators remove/rotate without reusing that verifier | SPEC_V1 §14; deploy manifest and verify-install tooling |
| 6 | Privacy: one `eth_getLogs` over the singleton enumerates every protected Safe | SPEC_V1 §14 |
| 7 | `PasswordVerifier` tier-2 exposure set: T-PWD-MEMPOOL (cleartext in calldata), T-PWD-REPLAY (not hash-bound), T-PWD-CROSS-CHAIN (chainId does not separate), T-PWD-LEAK-BEFORE-BURN (revert-before-burn leak, operator containment runbook) | SPEC_V1 §H.18 threat block; `docs/V1_USER_SCENARIOS.md` §8.3.9 tier 2 |
| 8 | Timelock bypasser is off-chain trust only: sees the hash, no on-chain content check; HSM compromise = full owner-path bypass authority (T-BYPASS-1..7), including permanent forced burn of panic identities (T-BYPASS-8) | SPEC_V1 timelock section; README assumption 5 |
| 9 | Deployment trust: address/codehash do not authenticate future behaviour of external verifiers (T-DEPLOY-1/2, T-VERIFIER-UPGRADE); install correctness rests on the secure-by-default preflight scripts (T-INSTALL-1, T-UPGRADE-1) | SPEC_V1 §14.1, §14.2 |
| 10 | Pre-signed in-recovery disarm (`removeLockdownSigner` collected under coercion at an idle nonce): kept, fenced by nonce burn + INV-SIGN-7 + rotation; fresh-post-trigger-signature requirement rejected 2026-06-10 | SPEC_V1 §17 (resolved entry) |
| 11 | H.19 residual: recovery-owner validity is a registration-time snapshot; a Safe whose entire allowlist became current owners has no recovery `swapOwner` until Normal-mode cleanup | SPEC_V1 §H.19; question 11 below |
| 12 | Per-Safe state (config, incident state, burnt keys, tickets within TTL) persists across guard uninstall/re-install; ticket epoch deliberately not adopted; runbook nonce burn at uninstall | question 12 below; `docs/PRIOR_ART_SAFERSAFES.md` §6 |
| 13 | `timelockDelay == 0` means no schedule gating (unconfigured pass-through anti-brick); the verify script WARNs on it | SPEC_V1 §7.1; `scripts/verify-install-v1.sh` |
| 14 | Worst-case self-inflicted freeze = `lockdownDuration + resumeDelay` (max 30d + 7d) with INV-LIVE-3 floor `lockdownDuration >= timelockDelay`; no rescue hatch by design | SPEC_V1 §14.2 (T-LIVE-2) |
| 15 | **AR-15 — ERC-1271 authorisations are deferred, not invalidated, by the fallback handler.** A Safe signature produced before or during an incident validates again after auto-resume if the signing owner remains. Successful recovery must swap the affected owner; without that swap, the handler has only delayed the authorisation. Standing approvals and orders require the same operational treatment | `test/poc/Erc1271IncidentSignature.t.sol`; SPEC_V1 §14; `src/handlers/LockdownFallbackHandler.sol` |
| 16 | **AR-16 — Owner authorisation survives ticket deletion.** `cancelTransaction` and `sweepExpiredOwnerTicket` delete the current ticket slot, but the same public `scheduleTransaction` calldata and valid owner signatures can recreate it while their signed nonce has not been surpassed; the attacker must then wait `timelockDelay` again. From current Safe nonce `n`, durably invalidating a transaction signed at `n+k` requires advancing `Safe.nonce()` to `n+k+1`: `k+1` nonce-consuming transactions from `n`, or `k` additional burns after a cancel has already consumed `n`. This underlying non-revocability comes from Safe's signature model, not the guard | `test/poc/TicketRevival.t.sol`; SPEC_V1 INV-TIME-8 / T-BYPASS-6; `docs/PRIOR_ART_SAFERSAFES.md` §5 |
| 17 | **AR-17 — A fully green Safe can have no working trigger.** Registration accepts strictly more than verification requires (verifier code is demanded only for identities longer than 20 bytes; key shape is never validated; nothing is re-checked after registration). All cheap observables - three slots wired, initialised, `getState` Normal, `getLockdownSignerCount > 0`, preflight green - can be satisfied by a Safe with no fireable panic identity. `testSigner` against the exact EIP-712 trigger digest is the on-chain discriminator for the executed inert-identity cases, so the pre-incident drill remains mandatory inside the supported, codehash-pinned verifier domain; it is not a general guarantee for arbitrary third-party verifier behaviour | `test/poc/ArmedButInert.t.sol`; SPEC_V1 §6.4 and §14 |
| 18 | **AR-18 — An EOA panic identity delegated under EIP-7702 changes verification branch silently.** OZ `SignatureChecker` branches on `signer.code.length`, so a delegation moves a registered 20-byte identity from ECDSA to ERC-1271 with no Safe or Lockdown transaction to observe. A non-ERC-1271 delegation makes the identity inert; an always-accepting one makes `triggerLockdown` PERMISSIONLESS (an unrelated address can freeze the Safe with one byte). The same permissionless outcome holds for an ERC-7913 verifier upgraded to always-accept. Registers #2/#5/#9 stated this class as "a malicious verifier can trigger"; the accurate statement is "anyone can". Operator obligation: never delegate a registered panic EOA; drill with `testSigner` | `test/poc/ArmedButInert.t.sol`; `test/poc/VerifierAndGriefing.t.sol`; SPEC_V1 §14.1 |
| 19 | **AR-19 — ERC-1271 signatures and owner tickets are deferred, not invalidated, by an incident.** A signature produced before or during LockedDown/Recovering validates again at auto-resume if the signing owner remains; recovery must swap that owner to kill it. A pre-incident timelock ticket can execute at the exact auto-resume second with no fresh delay if its original TTL window still covers that timestamp, and `cancelTransaction` is not recovery-whitelisted. Operator obligations: complete the affected owner swap, burn through the signed nonce for dangerous tickets, and minimise standing approvals/orders | `test/poc/Erc1271IncidentSignature.t.sol`; `test/poc/TimelockAccounting.t.sol`; SPEC_V1 §14 and timelock recovery interaction |
| 20 | **AR-20 — Installation integrity is checked at initialization, not continuously by Solidity.** Later partial removal/reinstallation of the transaction guard, module guard or fallback handler can leave views reporting an incident while an uncovered execution surface remains. A valid `triggerLockdown` deliberately freezes every path it still can: it neither rejects degraded protection nor emits an incident-time configuration warning that would also reveal a possible route to the coercer. The lifecycle UI and monitoring must read all three slots before an incident, alert privately, and propose repair | `test/poc/SafeIntegrationLifecycle.t.sol`; SPEC_V1 §12 and §14; `deploy/lockdown-lifecycle.html` diagnostic |
| 21 | **AR-21 — Administrative removal permanently burns signer identities.** A coerced quorum can add/remove enumerable identities and poison them for future use. V1 keeps this behaviour because `PasswordVerifier` ignores the signed digest, so permanent burn carries its replay defence, and adding a registration epoch would require an RPC state read before emergency signing. Operators re-arm with freshly generated ERC-7913 key material; an epoch remains a V1.2 candidate | `test/poc/VerifierAndGriefing.t.sol::test_confirmed_burntHistoryIsUnbounded`; SPEC_V1 §H.17 and §14 |

- Direct owner `approveHash(bytes32)` calls are not intercepted by guards.
- A single owner or extra lockdownSigner can grief-lockdown the Safe. This is accepted
  because the primary use case requires 1-of-N panic activation.
- There is no early cancel. A false positive waits `lockdownDuration +
  resumeDelay`; since PR #59 remaining signers can re-trigger to extend/re-lock
  (bounded by `≤ (remaining signers) × lockdownDuration`, INV-LIFE-2).
- Normal-mode owner-path admin changes are timelocked once
  `timelockDelay > 0`, except for the explicit anti-brick/carve-out paths
  described in the timelock section. Off-chain monitoring must still flag
  them and verify that the expected ticket was consumed.
- Modules and automation are intentionally blocked during lockdown/recovery.
- Installing against non-canonical Safe v1.5.0, non-canonical
  `MultiSendCallOnly`, or unpinned codehashes can brick or bypass protection.
  This is intentionally handled by secure-by-default preflight checks
  (`scripts/preflight-install-v1.sh` and the lifecycle UI), not by an on-chain
  upgrade or rescue hatch.
- Hardware-wallet display quality is operationally critical and must be tested
  before production install. See `docs/V1_HARDWARE_WALLET_UX.md`.

## Commands

Toolchain versions and per-target prerequisites are listed in
`docs/DEV_ENVIRONMENT.md`.

Minimal:

```bash
forge test
scripts/contract-sizes.sh
```

Standard local check:

```bash
make audit-check
```

Full optional check. Slither, Halmos, Docker (Echidna), and Node/Playwright
(browser smoke) are hard prerequisites: their steps FAIL the chain if the tool
is missing. Aderyn, Semgrep, Medusa, and Gambit steps skip with a printed
notice when not installed - check the output rather than assuming a green run
covered them:

```bash
make audit-check-full
```

Manual equivalents:

```bash
forge test
forge build
scripts/contract-sizes.sh
forge coverage --ir-minimum --report summary
slither . --compile-force-framework foundry --filter-paths "test|script|lib" --exclude timestamp,assembly,naming-convention --fail-none
aderyn . -s src -o /tmp/safe-lockdown-aderyn.md
make echidna # pinned image digest + crytic-compile compatibility override
make build-info
make sourcify-rehearsal
make semgrep
make medusa
```

Optional targeted mutation campaign, if Gambit is installed:

```bash
make mutation-gambit
```

See `docs/GAMBIT_MUTATION_PLAN.md` for scope and survivor triage rules. The
recorded mutation campaigns are historical assurance artifacts; after the split,
a fresh campaign must cover both `src/Lockdown.sol` and
`src/LockdownTimelock.sol` before its result is treated as current.

Expected current results:

- Foundry unit/fuzz tests: 483/483 passing by default.
- Build profile pinned: solc `0.8.35`, EVM `prague`, optimizer `200`, `via_ir`.
- Runtime sizes: `scripts/contract-sizes.sh` reads build artifacts directly
  because `forge build --sizes` can omit `Lockdown` / `LockdownTimelock`.
- Build-info generation succeeds via `make build-info`.
- Sourcify rehearsal dry-run succeeds without a deployed address; deployed
  candidate verification requires constructor args.
- Coverage caveat: `forge coverage` CANNOT instrument `src/Lockdown.sol`.
  The contract compiles only with via-ir (plain solc hits stack-too-deep)
  and Foundry's `--ir-minimum` mode silently drops the contract from the
  report (no source map anchors; verified on forge 1.0.0 and 1.5.1). Do not
  expect a line-coverage number for the singleton. Verifier coverage is
  exercised by the PasswordVerifier and WebAuthnVerifier suites. Singleton
  test strength is evidenced instead by the 483-test suite and the 15 Echidna
  stateful invariants. Gambit campaigns are useful but historical until a fresh
  post-split campaign covers both `Lockdown.sol` and `LockdownTimelock.sol`.
- Slither: 7 low/informational results, zero high/medium; every one is
  triaged (FP or intentional, with rationale and spec pointers) in
  `docs/STATIC_ANALYSIS_TRIAGE.md`. Slither currently prints an internal IR
  warning on the transient slot helper; see the triage doc.
- Aderyn: one raw high detector class (three instances in one scheduler flow),
  triaged as a STATICCALL false positive; eight low classes, all triaged in
  `docs/STATIC_ANALYSIS_TRIAGE.md`. Net actionable high/medium: zero.
- Semgrep: one registry performance finding on the Safe-derived fallback
  handler's inherited string `require`; local Safe-guard tripwires are clean.
- Halmos: 2/2 focused symbolic checks passing (`make halmos`; last verified
  2026-07-15 with halmos 0.3.3).
- Echidna: 15/15 stateful invariants passing. PR #69 refresh (2026-08-12):
  `--test-limit 50000`, seed `1890813470952091695`, 50,142 calls, 3,586
  unique instructions covered, corpus size 19, zero falsifications. Note: the
  harness initialises lazily on the first fuzz call (H.19 made `initialize`
  staticcall `isOwner` on the caller, which is impossible during the
  harness's own constructor), and SAFE_B's only signer commitment is
  `bytes32(1)` (no known keccak preimage) so the cross-Safe isolation
  invariants cannot be confounded by Echidna constant-mining a literal
  secret from the harness source.
- Medusa: 54/54 discovered harness tests passing, zero violations, at the
  500,000-transaction limit (Medusa 1.5.1, PR #69 refresh 2026-08-12).

## Prior art: audited patterns shared with Optimism SaferSafes

Optimism's `TimelockGuard`/`SaferSafes` (Spearbit review, Nov 2025, 0
critical/high; deployed mainnet singleton, Safe v1.4.1 only) is the closest
audited prior art for the V1 timelock layer. `docs/PRIOR_ART_SAFERSAFES.md`
has the full comparison. For the auditor, the shared idioms their review
covered without findings:

- `safeTxHash` recomputation at `nonce() - 1` inside `checkTransaction`
  (their guard and our `_verifyOwnerTimelock` use the same idiom);
- unconfigured pass-through anti-brick (`timelockDelay == 0` => allow), with
  atomic install-then-configure guidance;
- guard-removal-exposes-outstanding-signatures (their iSAFE-013 / Medium
  5.1.1, remediated by runbook nonce burns; our recovery whitelist includes
  the empty self-call nonce burn for the same reason);
- hard revert on re-scheduling an already-scheduled hash (their iSAFE-009;
  our `TicketAlreadyExists`). Our owner scheduling has the same exposure class
  as iSAFE-013 / Medium 5.1.1: the detached owner signatures are public in the
  `scheduleTransaction` calldata, and deleting a ticket does not invalidate
  them. The mitigation is the AR-16 nonce-burn runbook: advance `Safe.nonce()`
  beyond the signed nonce, using the exact `k+1` rule above.

Deliberate divergences from the audited OP design, documented and
intentional: module-path coverage via the v1.5.0 module guard (their
iSAFE-014 declares modules out of scope; we invert that), hash-only
owner-path scheduling (intent privacy under coercion vs their full-params
monitoring queue), success-gated post-hook ticket consumption (INV-TIME-4)
vs their pre-hook burn, `TICKET_TTL` expiry vs their immortal queue,
an allowlisted bypasser lane (they have none), and no executor-must-be-owner
check (their iSAFE-008; our scheduling verifies quorum signatures before
opening a ticket).

## Questions for the auditor

1. Is the Safe v1.5.0 execution model correctly understood?
2. Is module-guard coverage complete for both module entrypoints?
3. Are there any Safe side channels like refunds, handlers, `approveHash`,
   modules, or nested MultiSend execution that can move assets during
   lockdown/recovery?
4. Can a normal-mode MultiSend batch hide a non-canonical delegatecall or a
   `setFallbackHandler` swap that is not bound to this singleton?
5. Are there calldata parsing edge cases in `_checkCall`'s recursive
   MultiSend parser?
6. Are there griefing or bricking paths that exceed the accepted threat model?
7. Recovery-owner validation (H.19, fixed): `_validateRecoveryOwner` now
    rejects zero, the sentinel `0x1`, the Safe itself, and current owners at
    registration (`initialize` + `addRecoveryOwner`), and
    `_isRecoveryTransaction` re-checks `isOwner(newOwner)` at hook time for
    the dynamic case. Removal stays unvalidated on purpose (cleanup path).
    Please challenge the residual: a Safe whose entire allowlist became
    current owners has no recovery `swapOwner` until Normal-mode cleanup.
    (Derived from Spearbit SaferSafes findings 5.3.1/5.3.5; SPEC_V1 H.19.)
8. Stale per-Safe state across guard uninstall/re-install (tested
    semantics): config, `lockdownUntil`, burnt keys, and tickets within
    `TICKET_TTL` persist in the singleton across removal and
    re-installation. Pinned by tests: past-nonce owner tickets are dead by
    hash construction; future-nonce owner tickets and module tickets (no
    nonce binding) survive as quorum-authorized, single-use, TTL-bounded
    tickets; an active incident is still enforced after re-install.
    Operational backstop: runbook nonce burn at uninstall. Challenge whether
    any persisting state breaks an assumption. (SaferSafes answers this
    class with a config-generation bump, iSAFE-012; we deliberately did not
    adopt it - signer registrations and the recovery allowlist must survive
    re-installation.)
13. Configure-while-not-installed: all setters enforce INV-LIVE-3
    unconditionally, whether or not the guard is currently installed on the
    calling Safe. Confirm no invariant relies on checks that only run while
    installed (the SaferSafes Low 5.2.1 pattern).
14. Should V1.2 fold a per-Safe generation counter into the ticket-key derivation, and advance that generation on `cancelTransaction`, to make cancellation terminal? What is the cost of that finality in storage and implementation complexity, including its effect on unrelated pending tickets? See the **Config-generation nonce** V1.2 candidate in `docs/PRIOR_ART_SAFERSAFES.md` §5.
