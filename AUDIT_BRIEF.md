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
  sweep, and module-ticket consume / restore-on-failure logic.
- `@openzeppelin/contracts/interfaces/IERC7913.sol`: ERC-7913 verifier
  interface used directly from the pinned OpenZeppelin Contracts submodule.
- `test/mocks/MockSecretVerifier.sol`: test-only preimage-of-commitment
  verifier (production-forbidden), used to exercise the non-ECDSA dispatch
  path.
- `test/Lockdown.t.sol`: 203 unit + fuzz tests (V1 core, incl. INV-SIGN-7
  burnt-keys, F-M2-01 phantom-recovery closure, H.19 recovery-owner
  validation, uninstall/reinstall persistence pins).
- `test/LockdownTimelock.t.sol`: 96 V1 timelock + sweep + refund-gate +
  stale-ticket-reinstall tests.
- `test/fuzz/DecoderDifferentialTest.t.sol`: 5 focused differential tests for
  the MultiSend calldata decoder and non-canonical `bytes` encodings.
- `test/integration/SafeIntegration.t.sol`: 32 real-Safe integration tests
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
- `test/echidna/EchidnaLockdown.sol`: V1 harness with 16 stateful
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
  (INV-LIVE-3), moduleTicketSingleUse (INV-TIME-4 / NM-1060 6.6)). The harness uses `vm.warp` for
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
- `forge test`: **601 passed total** (203 Lockdown + 96 Timelock + 5 decoder
  differential fuzz + 32 real-Safe integration tests + 10 PasswordVerifier +
  10 WebAuthnVerifier + 2 captured-device WebAuthn fixture tests + 237 `test/poc/`
  adversarial proofs from the pre-tag review + 6 focused `test/daybreak/` proofs);
  the unit suite covers EIP-712 binding, single-use burn, cross-key isolation,
  registration sanity (20-byte EOA/ERC-1271 or verifier code + key-length
  bounds), recovery whitelist (with the V1 hardening:
  `removeLockdownSigner` during Recovering [H.4],
  `ModuleCallToSingletonDenied` even pre-init [H.12],
  `onlyNormal`/`InvalidState` state gate, `swapOwner` exact-length, `SafeDormant` event on
  every signersCount→0 transition [H.15], signer identity in `SafeLockedDown`
  [H.16], verifier revert normalisation to `BadSignature`,
  no on-chain drill view: the H.17 `testSigner` view was removed so trigger
  signatures are never sent to an RPC; drills run off-chain via
  `script/DrillSigner.s.sol`, which takes the trigger digest from the
  signature-free `hashLockdownTrigger` view that `triggerLockdown` shares
  [H.29]).

Auditor: please read `specs/SPEC_V1.md` first for the intended behaviour.
Pay particular attention to the **Hardening log** at the bottom of SPEC_V1:
it lists behavioural changes made during pre-audit review and the questions
they surfaced.

## Auditor Start Here (6 files)

1. `AUDIT_BRIEF.md` (this file) - threat model + questions
2. `specs/SPEC_V1.md` - design contract (including Hardening log H.1-H.29
   and the V1 timelock section)
3. `docs/V1_REVIEW_PROMPT.md` - independent-review brief and explicit review goals
4. `docs/V1_USER_SCENARIOS.md` - operator's mental model: every supported
   scenario, organised by lifecycle phase (install / normal / incident /
   recovery / post-resume / forensics), with code references and rationale.
   §8.3.9 ranks the production verifiers by adversarial robustness.
5. `src/LockdownTimelock.sol` - the production singleton (17,937 B runtime,
   6,639 B EIP-170 margin) and `src/Lockdown.sol` - the lockdown-only base
   (12,555 B runtime). Use `scripts/contract-sizes.sh`; `forge build --sizes`
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
`src/base/Erc1271Policy.sol`, `src/base/Timelock.sol`, and the companion
`src/handlers/LockdownFallbackHandler.sol` (fallback handler whose ERC-1271
surface is disabled unless the Safe opted in via `setErc1271Allowed` (H.27)
and frozen during an incident; `initialize` requires it installed), plus `src/utils/LockdownLib.sol` (module-transaction
hash construction shared by the guard and timelock paths).

### Scope and line counts

In-scope production code is `src/LockdownTimelock.sol`, `src/Lockdown.sol`,
`src/base/StateMachine.sol`, `src/base/LockdownSigners.sol`,
`src/base/RecoveryOwners.sol`, `src/base/Erc1271Policy.sol`,
`src/base/Timelock.sol`, `src/handlers/LockdownFallbackHandler.sol`,
`src/utils/LockdownLib.sol`,
`src/verifiers/PasswordVerifier.sol`, and `src/verifiers/WebAuthnVerifier.sol`
plus the pinned OpenZeppelin and safe-smart-account integration surface.

Line counts for the in-scope Solidity (nSLOC = non-blank, non-comment source
lines; regenerate before freezing the candidate, since sources may still
change):

| File | LOC | nSLOC |
| --- | --: | --: |
| `src/Lockdown.sol` | 627 | 362 |
| `src/LockdownTimelock.sol` | 348 | 163 |
| `src/base/Timelock.sol` | 429 | 189 |
| `src/base/StateMachine.sol` | 199 | 117 |
| `src/handlers/LockdownFallbackHandler.sol` | 271 | 105 |
| `src/base/LockdownSigners.sol` | 133 | 67 |
| `src/base/RecoveryOwners.sol` | 101 | 52 |
| `src/base/Erc1271Policy.sol` | 39 | 15 |
| `src/utils/LockdownLib.sol` | 66 | 42 |
| `src/verifiers/WebAuthnVerifier.sol` | 93 | 14 |
| `src/verifiers/PasswordVerifier.sol` | 99 | 18 |
| **Total (11 files)** | **2405** | **1144** |

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
| `ArmedButInert.t.sol` | Every way a Safe looks armed and has no working trigger, incl. EIP-7702; off-chain drill (`DrillSigner`) detectability |
| `Erc1271IncidentSignature.t.sol` | Whether the ERC-1271 freeze prevents or merely defers |
| `TimelockAccounting.t.sol` | Ticket lifecycle as resource accounting; bypasser re-arm; exact-second TTL and state boundaries |
| `SafeIntegrationLifecycle.t.sol` | Install / partial install / uninstall / reinstall / A→B singleton migration; threshold-N; both module entry points |
| `CalldataEncoding.t.sol` | MultiSend parser, ABI decoding, exact-length checks, `address(0)` aliasing |
| `DecodeCalldataBytesAdversarial.t.sol` | Guard/executor agreement on non-canonical ABI offsets, truncated tails, padding and overflow families |
| `DrillEvasionVerifier.t.sol` | Regression pin for verify-before-burn ordering; the off-chain drill observes the same pre-burn state as the trigger |
| `DrillSignatureExposure.t.sol` | External audit NM-1060: no on-chain drill view; a drill signature remains a live trigger; rotation revokes a leaked one |
| `VerifierAndGriefing.t.sol` | Hostile and mutable verifier dispatch; griefing and denial |
| `TicketRevival.t.sol` | AR-16 owner-authorisation persistence after ticket deletion |
| `daybreak/parser_executor/ParserExecutorDaybreak.t.sol` | Genuine Safe/MultiSend parser-executor constructions and the same-transaction lockdown atomicity boundary |
| `daybreak/stateful_hooks/InCallIncidentTransition.t.sol` | Owner/module ticket behavior when a callback activates lockdown after the pre-hook |
| `daybreak/supported_liveness/SupportedLiveness.t.sol` | Shipped WebAuthn end-to-end control and correlated ERC-1271 Safe-signer liveness |
| `TriggerIdentityBinding.t.sol` | External audit NM-1060: trigger signatures bound to the signer identity (WebAuthn UV/no-UV, two verifier deployments, EOA + wrapping ERC-1271); password residual |

Three defects found by this review are fixed in `src/` and pinned by
`test_regression_*` tests: the wrapping bounds arithmetic in
`Lockdown._decodeCalldataBytes`, the silent no-op in `removeRecoveryOwner`,
and the remove-before-verify ordering in `triggerLockdown`. External audit NM-1060's
cross-identity trigger replay is fixed by binding the signer in the EIP-712 message
(SPEC_V1 §H.23) and pinned by `TriggerIdentityBinding.t.sol`; its drill-signature
exposure is answered by removing the on-chain `testSigner` view in favour of
off-chain drills (SPEC_V1 §H.25), pinned by `DrillSignatureExposure.t.sol`.

## Known limitations and accepted risks

See also `specs/SPEC_V1.md`.

### Accepted-risk register (consolidated)

Every entry below is a deliberate, documented design decision, not an
oversight. Findings that re-state an entry without a new exploit path will
be triaged as known. Findings that show an escalation BEYOND the documented
impact are exactly what we are paying for: please challenge the rationale.

| # | Accepted residual | Where documented |
|---|---|---|
| 1 | Direct owner `approveHash(bytes32)` outside `execTransaction` is not intercepted (Safe v1.5.0 guard limitation); watchers handle it off-chain. **Clarified 2026-10-22:** it works in every state, LockedDown included, so an owner can arm a hash during the incident; once enough owners approved it, anyone can execute it with `v = 1` signatures and no key at submission time. It is a stored signature, not new authority: execution still runs `execTransaction`, so the guard refuses it in LockedDown, applies the recovery whitelist in Recovering and the timelock in Normal. It is nonce-bound, so the AR-16 nonce burn fences it, and it is visible on-chain (`ApproveHash`), unlike an off-chain signature. Its sibling `signedMessages` is NOT writable after install: only `SignMessageLib` writes it, through a DELEGATECALL the guard refuses (`DelegateCallDenied`); pre-install entries are AR-15/AR-19 | SPEC_V1 §14 |
| 2 | 1-of-N grief: any registered signer can lock the Safe; intentional for panic activation | SPEC_V1 §14 |
| 3 | No `cancelLockdown`: a false positive waits `lockdownDuration + resumeDelay`; since PR #59 remaining signers can re-trigger to extend/re-lock (worst case `k × (D + R) − (k − 1)` s for `k` remaining signers, re-triggering at the last second of each Recovering; see AR-14, H.24) | SPEC_V1 §14 / INV-LIFE-2 |
| 4 | Post-resume zero-signer window until quorum re-registers signers; `addLockdownSigner` deliberately NOT recovery-whitelisted | SPEC_V1 §14 |
| 5 | The supported ERC-7913 product domain is limited to the immutable, closed-world verifier bytecodes shipped and codehash-pinned by this repository. The contract deliberately has no verifier allowlist and accepts third-party verifier addresses with code; outside the supported domain no behavioural or drill-reliability guarantee is offered. Any OOG, revert or invalid return condemns the whole identity, which operators remove/rotate without reusing that verifier | SPEC_V1 §14; deploy manifest and verify-install tooling |
| 6 | Privacy: one `eth_getLogs` over the singleton enumerates every protected Safe | SPEC_V1 §14 |
| 7 | `PasswordVerifier` tier-2 exposure set: T-PWD-MEMPOOL (cleartext in calldata), T-PWD-REPLAY (not hash-bound), T-PWD-CROSS-CHAIN (chainId does not separate), T-PWD-LEAK-BEFORE-BURN (revert-before-burn leak, operator containment runbook), T-PWD-MULTI-IDENTITY (one commitment under two identities stays replayable, NM-1060 residual) | SPEC_V1 §H.18 threat block; `docs/V1_USER_SCENARIOS.md` §8.3.9 tier 2 |
| 8 | Timelock bypasser is off-chain trust only: sees the hash, no on-chain content check; HSM compromise = full authority to REMOVE THE DELAY on the owner path (T-BYPASS-1..7). **Precision added 2026-08-28**: it removes the delay, it does not grant authority. `bypassTimelock` only writes `executableAt = now`, and execution still needs Safe quorum signatures, so a compromised bypasser ALONE can do nothing, including the T-BYPASS-8 forced burn of panic identities, which needs the quorum too. The risk is the COMBINATION: bypasser plus a coerced or compromised quorum collapses the whole timelock window to a single block, which is exactly the defence the timelock exists to provide. Executed: the bypasser writes into an empty slot, over a live immature ticket, and over one the quorum just cancelled, but only in Normal state | SPEC_V1 timelock section; README assumption 5 |
| 9 | Deployment trust: address/codehash do not authenticate future behaviour of external verifiers (T-DEPLOY-1/2, T-VERIFIER-UPGRADE); install correctness rests on the secure-by-default preflight scripts (T-INSTALL-1, T-UPGRADE-1) | SPEC_V1 §14.1, §14.2 |
| 10 | Pre-signed in-recovery disarm (`removeLockdownSigner` collected under coercion at an idle nonce): kept, fenced by nonce burn + INV-SIGN-7 + rotation; fresh-post-trigger-signature requirement rejected 2026-06-10 | SPEC_V1 §17 (resolved entry) |
| 11 | H.19 residual: recovery-owner validity is a registration-time snapshot; a Safe whose entire allowlist became current owners has no recovery `swapOwner` until Normal-mode cleanup. **Clarification added 2026-08-28**: recovery owners are `swapOwner` TARGETS, not a quorum substitute. The recovery whitelist is evaluated in `checkTransaction`, which runs only inside `execTransaction`, so every recovery action still requires a live Safe quorum. V1 therefore offers NO recovery from loss of the owner keys themselves, and the allowlist must not be read as a key-loss backup | SPEC_V1 §H.19; question 11 below |
| 12 | Per-Safe state (config, incident state, burnt keys, tickets within TTL) persists across guard uninstall/re-install; ticket epoch deliberately not adopted; runbook nonce burn at uninstall | question 12 below; `docs/PRIOR_ART_SAFERSAFES.md` §6 |
| 13 | `timelockDelay == 0` means no schedule gating (unconfigured pass-through anti-brick); the verify script WARNs on it | SPEC_V1 §7.1; `scripts/verify-install-v1.sh` |
| 14 | **CORRECTED 2026-08-28.** A SINGLE trigger costs `lockdownDuration + resumeDelay` (max 30d + 7d). That is NOT the worst case, and this entry previously said it was. Since PR #59 each surviving signer can re-trigger, so the true worst case is `k × (D + R) − (k − 1)` seconds for `k` surviving signers (**corrected again 2026-10-26, NM-1060 6.8**: a re-trigger made at the last second of Recovering restarts a full `D + R` cycle, so `R` is paid `k` times, not once; stacking inside LockedDown, H.24, only reaches `k × D + R`), which at the caps (k = 32, D = 30 d, R = 7 d) is ≈ **1,184 days**, not 967 and not 37. Each such re-trigger returns the Safe to LockedDown and closes the repair window until that freeze expires. The bound is still self-limiting (each trigger burns one single-use signer, INV-SIGN-7, and none can be added during an incident, INV-LIFE-3) and the quorum can break the chain with `removeLockdownSigner` during Recovering. INV-LIVE-3 floor `lockdownDuration >= timelockDelay`; no rescue hatch by design | SPEC_V1 §14.2 (T-LIVE-2) and §14 line 913, which already carried the correct form; AR-3; INV-LIFE-2 |
| 15 | **AR-15 — ERC-1271 is an operator choice (default disabled); allowing it re-opens NM-1060 6.1 by choice, and allowed authorisations are deferred, not invalidated, by an incident.** Since H.27 the fallback handler refuses ERC-1271 (`Erc1271Disabled`) on both the inline-signature and the `signedMessages` branch unless the Safe called `setErc1271Allowed(true)`, an owner-path, `onlyNormal`, timelocked config call; the storage default `false` is fail-closed, including for pre-install `signedMessages` entries and uninitialised Safes. **Accepted residual by operator choice:** a Safe that allows ERC-1271 while `timelockDelay > 0` re-opens NM-1060 6.1: a coerced quorum's off-chain signature (permit, EIP-3009, Permit2, CoW, Seaport) settles without `execTransaction`, so with no timelock reaction window. The choice cannot be made instantly under a timelock (it waits the delay), and modules cannot make it. Activating the timelock does not reset the flag: a Safe that opted in at delay 0 must turn it off in the same activation batch (`[setErc1271Allowed(false), setTimelockDelay(N)]`, atomic and ticket-free at delay 0; the lifecycle helper builds it), otherwise turning it off later waits the full delay. UX cost of the default: no off-chain message signing, no nested-Safe owner signatures through this Safe, and the Safe cannot act as another Safe's 20-byte ERC-1271 panic identity (AR-22); on-chain flows (`approve`, CoW `setPreSignature`) remain; V1.1 follow-up is a per-Safe message registry with expiry and epoch. For an opted-in Safe, the incident freeze still applies whatever the flag, but a Safe signature produced before or during an incident validates again after auto-resume if the signing owner remains (the flag is not cleared by an incident). Successful recovery must swap the affected owner, or the quorum may opt back out; without that, the handler has only delayed the authorisation. Standing approvals and orders require the same operational treatment. Outside the handler's reach (Safe-specific, pinned by `test/poc/Erc1271BypassRoutes.t.sol`): a contract calling the Safe's public `checkSignatures` / `checkNSignatures` directly instead of ERC-1271 is never gated; an owner-path `setFallbackHandler` to a shim that answers `LOCKDOWN()` passes the binding check (dominated by `setGuard(0)`, equally timelocked); a bypasser enables the flag with no wait | `test/poc/Erc1271OptIn.t.sol`; `test/poc/Erc1271BypassRoutes.t.sol`; `test/poc/Erc1271IncidentSignature.t.sol`; SPEC_V1 §14, H.27; `src/handlers/LockdownFallbackHandler.sol` |
| 16 | **AR-16 — Owner authorisation survives ticket deletion.** `cancelTransaction` and `sweepExpiredOwnerTicket` delete the current ticket slot, but the same public `scheduleTransaction` calldata and valid owner signatures can recreate it while their signed nonce has not been surpassed; the attacker must then wait `timelockDelay` again. From current Safe nonce `n`, durably invalidating a transaction signed at `n+k` requires advancing `Safe.nonce()` to `n+k+1`: `k+1` nonce-consuming transactions from `n`, or `k` additional burns after a cancel has already consumed `n`. This underlying non-revocability comes from Safe's signature model, not the guard. **Two clarifications added 2026-08-28, both executed.** The relevant attacker is the *public replayer*, who holds no key and resubmits published calldata; the `k+1` burn rule defeats them, and a *quorum attacker* who can re-sign is a different and strictly stronger actor who no guard-local revocation touches. And `sweepExpiredOwnerTicket` is not merely another route to deletion: because it is permissionless, a keyless third party can sweep an expired ticket and thereby strip the quorum's own `cancelTransaction` handle (it then reverts `TicketNotFound`) while leaving the authorisation reschedulable, so sweep strictly weakens the defender. It needs the full TTL, so it is slow rather than instant | `test/poc/TicketRevival.t.sol`; `test/poc/CancellationSemantics.t.sol`; SPEC_V1 INV-TIME-8 / T-BYPASS-6; `docs/PRIOR_ART_SAFERSAFES.md` §5 |
| 17 | **AR-17 — A fully green Safe can have no working trigger.** Registration accepts strictly more than verification requires (verifier code is demanded only for identities longer than 20 bytes; key shape is never validated; nothing is re-checked after registration). All cheap observables - three slots wired, initialised, `getState` Normal, `getLockdownSignerCount > 0`, preflight green - can be satisfied by a Safe with no fireable panic identity. The off-chain drill `script/DrillSigner.s.sol`, run on a local fork against the exact `hashLockdownTrigger` digest and the real verifier dispatch, is the only discriminator for the executed inert-identity cases; the lifecycle UI's local signature check is a sanity check on the signature itself and passes inert identities (it never calls the verifier, so a codeless verifier, a non-1271 20-byte contract or an over-long key all look fine there), so the pre-incident drill remains mandatory inside the supported, codehash-pinned verifier domain; it is not a general guarantee for arbitrary third-party verifier behaviour, and it cannot see state changes after the drill (e.g. EIP-7702 delegation). There is deliberately no on-chain drill view: a trigger signature is a bearer credential and must not be sent to an RPC | `test/poc/ArmedButInert.t.sol`; SPEC_V1 §6.4 and §14 |
| 18 | **AR-18 — An EOA panic identity delegated under EIP-7702 changes verification branch silently.** OZ `SignatureChecker` branches on `signer.code.length`, so a delegation moves a registered 20-byte identity from ECDSA to ERC-1271 with no Safe or Lockdown transaction to observe. A non-ERC-1271 delegation makes the identity inert; an always-accepting one makes `triggerLockdown` PERMISSIONLESS (an unrelated address can freeze the Safe with one byte). The same permissionless outcome holds for an ERC-7913 verifier upgraded to always-accept. Registers #2/#5/#9 stated this class as "a malicious verifier can trigger"; the accurate statement is "anyone can". Operator obligation: never delegate a registered panic EOA; drill off-chain with `script/DrillSigner.s.sol` | `test/poc/ArmedButInert.t.sol`; `test/poc/VerifierAndGriefing.t.sol`; SPEC_V1 §14.1 |
| 19 | **AR-19 — ERC-1271 signatures and owner tickets are deferred, not invalidated, by an incident.** A signature produced before or during LockedDown/Recovering validates again at auto-resume if the signing owner remains and the Safe has opted in to ERC-1271 (default disabled, H.27; AR-15 covers the opt-in and its timelock residual); recovery must swap that owner to kill it. A pre-incident timelock ticket can execute at the exact auto-resume second with no fresh delay if its original TTL window still covers that timestamp, and `cancelTransaction` is not recovery-whitelisted. **Operator obligations, and they DIFFER BY PATH. This distinction was added 2026-08-29 after cross-audit mining; the earlier single instruction was correct only for the owner path and would have been the wrong countermeasure on the module path.** Owner path: complete the affected owner swap, and burn through the signed nonce for dangerous tickets. The burn must target the SAFE ITSELF (`to == safe`, empty data): an empty self-call addressed to `address(0)` is refused `RecoveryActive` during an incident, because the guard reads the literal top-level `to` and Safe's `address(0)` aliasing does not apply there. Module path: **a nonce burn defuses NOTHING.** A module ticket key is `moduleTxHash(safe, module, to, value, dataHash, operation)` and contains no nonce, so it survives any number of burns and fires at the exact auto-resume second. The correct and recovery-whitelisted defusal is exact-length `disableModule(prevModule, module)`: a disabled module can no longer call `execTransactionFromModule`, so the ticket becomes unreachable before the guard is consulted. `cancelModuleTransaction` is NOT recovery-whitelisted and is unavailable exactly when it is wanted. **Module-ticket scope, restated by NM-1060 6.5 (Low, no fix).** A module ticket scheduled before the incident survives nonce burns AND owner swaps, because its key binds neither the nonce nor the owner set, and it is executable at the first second of Normal after auto-resume while its TTL window still covers that timestamp. `disableModule` is the only in-incident remedy, and it is not durable: the ticket itself is untouched, so re-enabling the same module within the TTL revives it; cancel or let it expire before re-enabling. Considered and rejected for now: a per-Safe ticket epoch bumped inside `triggerLockdown` (one SSTORE) that would invalidate every pre-incident owner and module ticket. It would also kill legitimate defensive tickets that cost up to 30 days to mature, forcing a full reschedule after every drill or false positive, and it touches every ticket-key derivation on a frozen Solidity surface for a residual that `disableModule` already contains (`docs/V1_NON_GOALS.md`). Both paths: minimise standing approvals and orders | `test/poc/Erc1271IncidentSignature.t.sol`; `test/poc/TimelockAccounting.t.sol`; `test/poc/MixBytesCrossAuditLeads.t.sol::test_confirmed_nonceBurnDoesNotDefuseAPendingModuleTicket`, `::test_confirmed_disableModuleDefusesPendingModuleTicket`, `::test_limitation_cancelModuleTransactionIsUnreachableDuringRecovering`; SPEC_V1 §14 and timelock recovery interaction. Survival across owner swaps and revival on re-enable follow from the key derivation and are not separately pinned |
| 20 | **AR-20 — Installation integrity is checked at initialization, not continuously by Solidity.** Later partial removal/reinstallation of the transaction guard, module guard or fallback handler can leave views reporting an incident while an uncovered execution surface remains. A valid `triggerLockdown` deliberately freezes every path it still can: it neither rejects degraded protection nor emits an incident-time configuration warning that would also reveal a possible route to the coercer. The lifecycle UI and monitoring must read all three slots before an incident, alert privately, and propose repair. **Continuous installation integrity is four values, not three**: the Safe's own `masterCopy` belongs with the guard, module-guard and fallback-handler slots, because a quorum-approved downgrade to a Safe version without `IModuleGuard` would leave all three Lockdown slots looking correct while the module freeze silently stops existing. That fourth check is already implemented off-chain and is not a gap: `scripts/preflight-install-v1.sh:253-265` and `scripts/verify-install-v1.sh:257-265` read proxy slot 0 and compare its `EXTCODEHASH` against `deploy/manifest.json:63` `safeMasterCopyCodehash`, and `deploy/lockdown-lifecycle.html` reads, snapshots and diffs it between operator sessions. It goes through the same fail-closed pin gate as the singleton, `MultiSendCallOnly` and fallback-handler hashes: while the manifest entry is the `0xFILL` placeholder (and no `--safe-codehash` is given) both scripts `FAIL`, downgraded to `WARN` only by the dev/test `--allow-unpinned-codehash` flag. `scripts/operator-e2e-anvil.sh` exercises both outcomes against real Safe v1.5.0 bytecode | `test/poc/SafeIntegrationLifecycle.t.sol`; SPEC_V1 §12 and §14; `deploy/lockdown-lifecycle.html` diagnostic; `scripts/preflight-install-v1.sh:253-265`; `scripts/verify-install-v1.sh:257-265`; `scripts/operator-e2e-anvil.sh` |
| 21 | **AR-21 — Administrative removal permanently burns signer identities.** A coerced quorum can add/remove enumerable identities and poison them for future use. V1 keeps this behaviour because `PasswordVerifier` ignores the signed digest, so permanent burn carries its replay defence, and adding a registration epoch would require an RPC state read before emergency signing. Operators re-arm with freshly generated ERC-7913 key material; an epoch remains a V1.2 candidate. **Redeploying a verifier does NOT re-arm:** verifiers deploy by CREATE2 with a fixed salt, so the address and therefore the identity bytes (`verifier || key`) are identical and still burnt. Two real paths exist: a new credential (cleanest, re-enrolment cost), or the same passkey under the sibling verifier `WebAuthnVerifierNoUV` / `WebAuthnVerifier` (a different address, so a fresh identity; UV is a deliberate option, not a stronger default, for an anti-coercion primitive). Re-using a credential that was just exercised under coercion is an operator decision to make explicitly | `test/poc/VerifierAndGriefing.t.sol::test_confirmed_burntHistoryIsUnbounded`; SPEC_V1 §H.17 and §14 |
| 22 | **AR-22 — A Lockdown-protected Safe is a correlated-liveness dependency when used as another Safe's native ERC-1271 panic identity.** Since H.27 the signer Safe must opt in to ERC-1271 first (default disabled: the drill already fails in Normal). Once opted in, the identity can pass an exact off-chain drill (`script/DrillSigner.s.sol`) in Normal, then reject the same pre-signed trigger while the signer Safe is LockedDown or Recovering because its fallback handler intentionally freezes ERC-1271. **Strengthened by NM-1060 6.3 (Low, no fix): such a Safe must not be registered as a 20-byte lockdown signer of another Safe at all, nor of itself.** The failure is adversarial, not only correlated: an attacker holding one of the signer Safe's own panic identities freezes it, and with it every trigger that depends on it, exactly when it is needed. The general principle: quorum signers and lockdown signers face opposite expectations. Owners optimise for security and deliberation; lockdown signers for independence and reactivity. A Safe (multi-party, slow, possibly frozen) is a very bad lockdown signer. Use independent EOAs or separately approved verifier identities in another failure domain. Follow-up, not implemented: the install scripts could WARN when a registered 20-byte signer has code and answers `LOCKDOWN()` / `getState` for the same singleton (`verify-install-v1.sh` can enumerate `getLockdownSigners`; `preflight-install-v1.sh` only sees the planned `initialSigners`) | `test/daybreak/supported_liveness/SupportedLiveness.t.sol`; SPEC_V1 §14; `docs/V1_USER_SCENARIOS.md` §8.3.9 |
| 23 | **AR-23 — Lockdown enforcement is entry-time, not an interrupt inside an executing EVM call tree.** A transaction whose pre-hook begins in Normal can activate lockdown in a callback and still complete later instructions in the same atomic transaction. This grants no new authority because the exact call was already owner/module-authorized, no unrelated transaction can interleave after the pre-hook, and a post-hook revert would roll back both the effect and the lockdown | `test/daybreak/parser_executor/ParserExecutorDaybreak.t.sol`; `test/daybreak/stateful_hooks/InCallIncidentTransition.t.sol`; SPEC_V1 §14 |
| 24 | **AR-24 — The Safe refund window is an attacker-reachable callback that a FAILED transaction opens for free.** Safe v1.5.0 caches the guard, executes, calls `handlePayment` when `gasPrice > 0`, and only then calls the cached post-hook; the native refund is an unrestricted `receiver.call{value}("")`, not the 2300-gas `send` that 0x's SafeGuard relies on, and the ERC-20 branch hands control to an attacker-chosen `gasToken`. When the inner call reverts while `safeTxGas != 0`, Safe does not bubble: it still pays the refund, so the callback runs, and the post-hook then receives `success == false`, so INV-TIME-4 deliberately preserves the ticket. The attacker therefore obtains the callback without spending the authorisation, at the cost of one nonce. No escalation follows while the guards are installed: unscheduled, immature and module-ticketless nested calls are all refused inside the window, and a scheduled MultiSend with every refund field zero reaches the same end state | `test/poc/RefundPostHookReentrancy.t.sol`; `docs/PRE_TAG_REVIEW_DISPOSITIONS.md` refund-window campaign R1/R5/R10 |
| 25 | **AR-25 — A guard-slot disarm and its exploitation can be atomic, and `refundReceiver == address(0)` runs code that the signed hash does not name.** A scheduled `setGuard(0)` or `setModuleGuard(0)` followed by a nested call in the refund window leaves no block in which monitoring can interpose, and composing it with `triggerLockdown` produces a singleton reporting `LockedDown` while the uncovered owner path still executes (AR-20 composed with AR-23). Separately, `handlePayment` refunds `tx.origin` when `refundReceiver` is zero, so an EIP-7702-delegated or contract submitter receives control although the signed hash contains only `address(0)`; SPEC_V1 §7.2's instruction to review for `refundReceiver != 0` is inverted for exactly this case. The callback can also cancel the in-flight outer ticket, suppressing `TimelockConsumed` for a transaction that executed, with no replay because the nonce has advanced | `test/poc/RefundPostHookReentrancy.t.sol`; `docs/PRE_TAG_REVIEW_DISPOSITIONS.md` refund-window campaign R6/R8/R9/R11 |
| 26 | **AR-26 — Two fail-closed residuals in the decision predicates.** No predicate can be made to accept a payload the executor decodes into a different call, and the module blacklist is complete against Safe v1.5.0's nine `authorized` self-call functions. Two residuals remain, both fail-closed. (a) `Safe.setup()` also writes the fallback-handler slot and is NOT blacklisted: the guard accepts such a call and only Safe's own `GS200` stops it on a live Safe, so this one protection is a Safe-side invariant rather than ours and would need rechecking against any supported Safe upgrade. (b) `_isTimelockManagementCall` mixes one exact-length arm (`cancelTransaction`, `0x24`) with two minimum-length arms, so one trailing byte costs the timelock carve-out for the first and not the others; the strictness is kept deliberately because it is the direction mutant T6 protects, but the asymmetry may matter to signer-review tooling that normalises calldata | `test/poc/DecisionPredicateAgreement.t.sol`; `docs/PRE_TAG_REVIEW_DISPOSITIONS.md` decision-predicate campaign P2/P3 |

| 27 | **AR-27 — The timelock-exempt meta-call lane is a free Safe-nonce burner, and every owner ticket is bound to one exact nonce.** `scheduleTransaction` binds a ticket to a nonce and `_verifyOwnerTimelock` recomputes the hash at `nonce() - 1`, so a ticket is valid at exactly one position in the Safe's nonce sequence. `_isTimelockManagementCall` exempts three self-calls from the delay, and a SUCCEEDING one (`scheduleModuleTransaction`, or `cancelModuleTransaction` on a real ticket) consumes a nonce instantly. A coerced quorum can therefore strip a matured defensive queue that cost up to 30 days to prepare, for free and repeatably: the defenders must re-schedule and wait the FULL delay again. AR-16 describes the nonce burn only as the DEFENDER's tool; it is symmetrically the attacker's, and the exempt lane makes it delay-free. Two bounds, both executed. A FAILING meta-call is not a burner: `cancelTransaction` on an unknown hash reverts `TicketNotFound`, and because the lane forces `safeTxGas == 0` (INV-TIME-9) Safe bubbles the revert and the nonce rolls back. And no funds move: this is defensive-liveness loss under an attacker who already holds the quorum. No Solidity change: the nonce coupling is intrinsic to Safe's signature model. Operator obligations: re-schedule the ticket queue after ANY meta-call execution, and have monitoring alert on the gap between `Safe.nonce()` and the nonces of open tickets | `test/poc/MixBytesCrossAuditLeads.t.sol`; `docs/PRE_TAG_REVIEW_DISPOSITIONS.md` cross-audit campaign M1/M2 |
| 28 | **AR-28 — Scheduling applies no policy validation, so a ticket can be written for a call the guard will always refuse.** `scheduleModuleTransaction` checks only that the timelock is active and that no ticket exists; it never calls `_checkCall`. Under `Privilege.Module` execution refuses unconditionally any `to == singleton` (`ModuleCallToSingletonDenied`), any `DelegateCall` outside `MultiSendCallOnly` (`DelegateCallDenied`), and any guard-hook selector (`GuardHookSelfCallDenied`). An operator can therefore write a ticket, watch a healthy `ModuleTransactionScheduled` event, wait the full delay, and only then discover the call is structurally dead; the slot stays occupied (`TicketAlreadyExists`) until an explicit `cancelModuleTransaction` or the 90-day TTL. The owner path has the same shape, more weakly. No funds move and nothing is bypassed: this is a liveness and ergonomics defect, worst case 30 days lost. A Solidity fix is possible and is NOT taken in V1, because it would either duplicate policy at two sites (divergence risk) or cost EIP-170 margin on a contract with 6,986 B of headroom; the class is documented instead. Operator obligation: validate intent against the module policy before scheduling | `test/poc/MixBytesCrossAuditLeads.t.sol`; `docs/PRE_TAG_REVIEW_DISPOSITIONS.md` cross-audit campaign M3 |
| 29 | **AR-29 — An enabled module can escalate to owner (NM-1060 6.2).** The module-path denials (singleton, guard-disable self-calls) are direct-call guarantees, not authority guarantees: owner topology stays allowed on the module path (pre-init and Normal) because legitimate recovery, signer-gate and inheritance modules rotate owners, so a malicious module can `addOwnerWithThreshold(attacker, 1)` and the attacker then uses owner-path powers (remove the guard, administer the singleton). The class is four selectors: `addOwnerWithThreshold` and `removeOwner` both call `changeThreshold` internally (one call adds or removes an owner AND sets threshold 1), `changeThreshold` sets it directly, and `swapOwner` keeps owner count and threshold but repeated swaps to attacker keys still build a real quorum. Denying any subset short of all four does not close the class. With `timelockDelay > 0` the module call needs a quorum-scheduled ticket and the new owner a fresh full delay; at delay 0 and on base `Lockdown` there is no reaction window. Before initialize the owner path is fail-open, so the new owner can also `initialize` the Safe with its own config; no module-path rule is added for that window (H.28). Operator obligations: install atomically (`setGuard`, `setModuleGuard`, `setFallbackHandler`, `initialize` in one MultiSend) and never leave a Safe Uninitialised with a module enabled; enable only audited modules; prefer a non-zero timelock with owner-rotating modules; alert off-chain on `AddedOwner` / `RemovedOwner` / `ChangedThreshold` inside module transactions | `test/poc/ModuleTopologyEscalation.t.sol`; SPEC_V1 §7.2, §14, H.20, H.28 |
| 30 | **AR-30 — Recovery is a race between two quorums.** When the attacker holds a full owner quorum (stolen keys, not only a coerced person), the attacker can sign the same recovery whitelist as the defenders during Recovering. `_isRecoveryCall` validates only the NEW owner of a `swapOwner` (a pre-registered recovery owner that is not yet an owner), never the evicted one, so the attacker chooses whom to evict. Three attacker moves: (a) burn nonces to invalidate the defenders' pre-signed recovery; (b) swap honest owners for recovery owners, which leaves those keys on the defenders' side but consumes the allowlist (an address that became an owner is no longer a valid target, AR-11), so with enough swaps no target is left to evict the stolen keys and the attacker keeps the quorum after auto-resume; (c) `removeLockdownSigner` the defenders' panic identities. A re-trigger during Recovering also returns the Safe to LockedDown and closes the repair window mid-way (NM-1060 6.8 bound); a partially executed recovery is safe but incomplete. The defenders win with ONE transaction that evicts enough stolen keys to drop the attacker below threshold. Operator obligations: register more recovery owners than the number of owner keys that can be stolen together, held apart from them; size `lockdownDuration + resumeDelay` to cover access to the offline keys; sign the recovery during LockedDown and submit it through a private relay in the first block of Recovering; put every eviction (and the `removeLockdownSigner` of compromised panic identities) in ONE atomic MultiSend, never several transactions | `_isRecoveryCall` (`src/Lockdown.sol`); `poc/VerifierAndGriefing.t.sol::test_refuted_allSurvivingSignersCulledInOneRecoveryBatch`; AR-3, AR-11, AR-16 |

### Failure-mode matrix

The register above records *why* each residual is accepted; this table is the index into it: for each thing that can be compromised or lost, what the guard actually bounds and who must cooperate to get back to Normal. Outcomes are stated as time bounds rather than as "recoverable" or "bricked", because V1 has no unanimous unlock, no vote and no rescue hatch: the only exits are the clock and a Safe owner quorum. Shorthand: **D** = `lockdownDuration` (1h to 30d), **R** = `resumeDelay` (4h to 7d), **S** = live registered signers (at most 32).

| # | Failure | Count | Bounded outcome | Cooperation to restore | Evidence |
|---|---|---|---|---|---|
| 1 | Panic identity compromised (attacker holds it) | 1 | Attacker freezes for **D + R** (at most 30d + 7d). The identity self-burns on use | None, time only; quorum re-arms after resume | AR-2, AR-3, AR-14; INV-LIFE-2, INV-SIGN-1; `Lockdown.t.sol::test_triggerLockdownExtendsWhenAlreadyLockedDown` |
| 2 | Panic identities compromised | all S | Repeated re-lock at the last second of each Recovering: frozen **at most S × (D + R) − (S − 1)** s (32 × 37d ≈ 1,184d; stacking inside LockedDown reaches only S × D + R), each trigger burning one identity and closing the repair window again | Quorum `removeLockdownSigner` during Recovering (not LockedDown) breaks the chain | AR-3, AR-14; INV-LIFE-2/3; `Lockdown.t.sol::test_triggerLockdownReLocksDuringRecovering`, `::test_removeLockdownSignerAllowedDuringRecovery` |
| 3 | Panic identity lost, inert rather than stolen | 1 of S | No freeze from it; others unaffected. Silent, because registration never calls the verifier | Quorum rotates in Normal; the pre-incident off-chain drill (`script/DrillSigner.s.sol`) is mandatory | AR-17, AR-5; `poc/ArmedButInert.t.sol::test_confirmed_codeless20ByteIdentityRegistersButCannotTrigger`, `poc/VerifierAndGriefing.t.sol::test_confirmed_registrationNeverCallsTheVerifier` |
| 4 | Panic identities lost, zero registered (dormant) | all | **No lockdown is possible at all.** The guard degrades to a Normal-mode timelock; `SafeDormant` is emitted | Quorum `addLockdownSigner` in Normal, deliberately NOT recovery-whitelisted | AR-4, AR-17; H.8/H.15; `Lockdown.t.sol::test_initializeWithEmptyOptionalsIsDormant`, `poc/ArmedButInert.t.sol::test_limitation_fullyGreenSafeCanHaveNoWorkingTrigger` |
| 5 | Safe owner key compromised | < quorum | **The guard makes no claim here.** The Safe threshold governs; accepted Normal-mode residual | Quorum `swapOwner` in Normal (timelocked) | Threat model, out of scope. Unevidenced by design, no PoC |
| 6 | Safe owner keys compromised or coerced, quorum live | ≥ quorum | Disarm costs **at least `timelockDelay`** on every path (INV-LIVE-3 floor `D ≥ timelockDelay`); that wait is the window for an off-site trigger, which then freezes for at least D. Once signers are exhausted, in-recovery disarm is free, so unprotected at **D + R** | Off-site panic trigger. No on-chain remedy after that | AR-8, AR-14; INV-LIVE-1, INV-LIVE-3, T-LIVE-2; `test_liveness_timelockGatesGuardRemoval_INV_LIVE_1`, `echidna_lockdownCoversTimelock` |
| 7 | Same, with `timelockDelay == 0` | ≥ quorum | **No bound at all**: instant disarm, no intervention window. Configuration, not code | Runbook must require `timelockDelay > 0`; the verify script only WARNs | AR-13; SPEC §7.1; `scripts/verify-install-v1.sh` |
| 8 | Safe owner keys lost | all | Safe unusable. **Recovery owners do not help**: they are `swapOwner` targets and still require a live quorum | None. Not a guard function | AR-11 (clarified 2026-08-28); `_isRecoveryCall` runs only inside `execTransaction` |
| 9 | Recovery owner compromised | 1 of N | No effect alone: the allowlist is immutable during LockedDown and Recovering, and pre-positioning `addRecoveryOwner` is timelocked | Quorum `removeRecoveryOwner` in Normal, now strict | AR-11; INV-REC-2, INV-LIVE-1, H.19; `poc/VerifierAndGriefing.t.sol::test_regression_removeRecoveryOwnerRevertsOnAnUnknownAddress` |
| 10 | Recovery owners unusable, all became current owners | all | Recovery `swapOwner` unavailable for that incident: it runs its full **D + R** with no owner swap | Normal-mode cleanup only, after auto-resume | AR-11; H.19; question 7 |
| 11 | Timelock bypasser (HSM) compromised | 1 | Removes the delay, **does not grant authority**: execution still needs quorum signatures. Combined with a coerced quorum it is a same-block disarm with a provably zero response window | Key management only | AR-8; A8/A9; `poc/TimelockAccounting.t.sol::test_confirmed_bypassCreatesTicketWithoutAnySchedule`, `::test_confirmed_bypassAndExecuteInSameBlock`; `poc/CancellationSemantics.t.sol` C1 |
| 12 | ERC-7913 verifier turns always-true, or an EOA is delegated under EIP-7702 | 1 verifier | Trigger becomes **permissionless**: anyone freezes for D + R, repeatable per identity under that verifier (row 2 bound) | Quorum culls affected signers; all 31 survivors fit in one recovery MultiSend | AR-5, AR-18, AR-21; `poc/VerifierAndGriefing.t.sol::test_confirmed_upgradedVerifierMakesTriggerPermissionless`, `::test_refuted_allSurvivingSignersCulledInOneRecoveryBatch` |
| 13 | ERC-7913 verifier turns always-false, OOG, or revert-bomb | 1 verifier | Liveness denial: every identity under it is inert. If it is the sole identity, **no freeze is ever available** | Quorum remove or rotate to fresh material; never reuse that verifier | AR-5; A1/A2/A3; `poc/VerifierAndGriefing.t.sol::test_confirmed_returnDataBombVerifierOutOfGassesTriggerAtEveryGasLimit`, `::test_limitation_verifierBecomingCodelessDisarmsTheIdentity` |
| 14 | Fallback handler removed or swapped | 1 slot | A hostile handler is **refused at every depth**, and the module path cannot touch the slot at all (H.20). Removal is reachable only after the execution guard is already gone; ERC-1271 is then unfrozen, and was always deferred rather than invalidated | Quorum re-install; recovery must `swapOwner` the affected owner or the old signature revives | AR-15, AR-19, AR-20; `poc/Erc1271IncidentSignature.t.sol::test_confirmed_incidentEra1271SignatureValidatesAfterAutoResume`, `poc/SafeIntegrationLifecycle.t.sol::test_limitation_setFallbackHandlerZeroRevertsWithoutInvalidFallbackHandlerSelector` |
| 15 | Enabled module compromised | 1 | **Fully blocked** in LockedDown and Recovering, and can never reach the singleton or the guard slots in any state. Before initialize and in Normal it keeps the Safe authority it already had, including escalating to owner through `addOwnerWithThreshold` (and, pre-init, then calling `initialize`): accepted residual AR-29, closed operationally by the atomic install | Recovery whitelist admits exact-length `disableModule` | AR-29, INV-REC-3, INV-LIFE-5, H.20, H.28; `poc/ModuleTopologyEscalation.t.sol`, `poc/SafeIntegrationLifecycle.t.sol::test_confirmed_moduleReturnDataPathGuardedIdentically`, `poc/CalldataEncoding.t.sol::test_refuted_zeroAddressAliasBlocksModuleGuardDisable` |
| 16 | Partial guard uninstall, one of the three slots | 1 slot | Views can report `LockedDown` while an uncovered path executes; with the refund window the disarm and its use are **atomic**, so no block exists in which monitoring can interpose. No new authority (dominance result) | Off-chain lifecycle UI must diff all slots while the Safe is cold | AR-20, AR-25, A6/A7; `poc/SafeIntegrationLifecycle.t.sol::test_limitation_moduleGuardRemovalSilentlyDefeatsLockdownOnModulePath`, `poc/RefundPostHookReentrancy.t.sol::test_confirmed_lockedDownViewWhileTheUncoveredOwnerPathStillExecutes`, `::test_refuted_dominanceNoRefundMultiSendReachesTheSame` |
| 17 | Safe `masterCopy` or canonical-address drift | 1 chain | All three Lockdown slots still look correct while the module freeze silently stops existing; a non-canonical `MultiSendCallOnly` is a full drain under a coerced MultiSend | Preflight and verify codehash pinning only, **no Solidity control** | AR-9, AR-20; T-DEPLOY-1/2, T-UPGRADE-1. **No Solidity PoC**. Off-chain the masterCopy pin now fails closed: while `manifest.json` `safeMasterCopyCodehash` is still `0xFILL` (and no `--safe-codehash` is given) preflight and verify FAIL, unless the dev/test `--allow-unpinned-codehash` flag downgrades it to WARN; `scripts/operator-e2e-anvil.sh` asserts that FAIL against real Safe v1.5.0 bytecode on anvil |
| 18 | False-positive lockdown: drill, panic, accidental trigger | 1 | Frozen **D + R**, no cancel, one identity burnt. A second panicking signer extends it (row 2) | None, time only. `addLockdownSigner` is deliberately not recovery-whitelisted | AR-3, AR-4, AR-14; `poc/TimelockAccounting.t.sol::test_confirmed_stateMachineExactSecondBoundaries` |
| 19 | Pre-incident authorisation outlives the incident: ERC-1271 signature or matured ticket | any | **Deferred, not killed.** A ticket can fire at the exact auto-resume second with no fresh delay, and `cancelTransaction` is not recovery-whitelisted. Durable invalidation costs `k+1` nonce burns | Recovery must swap the signing owner and burn through the signed nonce; for module tickets, only `disableModule` works, and only until the module is re-enabled within the TTL | AR-15, AR-16, AR-19; INV-TIME-8; `poc/TimelockAccounting.t.sol::test_confirmed_preIncidentTicketFiresAtTheAutoResumeSecond`, `::test_confirmed_cancelIsUnreachableDuringRecovering`, `poc/TicketRevival.t.sol`, `poc/CancellationSemantics.t.sol` C3 |

- Direct owner `approveHash(bytes32)` calls are not intercepted by guards.
- A single owner or extra lockdownSigner can grief-lockdown the Safe. This is accepted
  because the primary use case requires 1-of-N panic activation.
- There is no early cancel. A false positive waits `lockdownDuration +
  resumeDelay`; since PR #59 remaining signers can re-trigger to extend/re-lock
  (worst case `k × (lockdownDuration + resumeDelay) − (k − 1)` seconds for
  `k` remaining signers, INV-LIFE-2, AR-14).
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

- Foundry unit/fuzz tests: 601/601 passing by default (the 2026-08-28 campaigns added 43: refund window 17, decision-predicate agreement 13, cancellation semantics 13; the 2026-08-29 cross-audit mining campaign added 13; the external audit NM-1060 identity-binding fix added 5; the NM-1060 drill answer added 3 PoC tests and moved 1 out of `Lockdown.t.sol`; the single trigger-digest view `hashLockdownTrigger` added 4 to `Lockdown.t.sol`; post-audit re-trigger stacking added 2 to `Lockdown.t.sol`; the module-ticket pre-hook consumption change added 6; the NM-1060 6.2 module-topology pins added 6 PoC tests; the NM-1060 6.1 ERC-1271 opt-in gate added 16: 15 in `test/poc/Erc1271OptIn.t.sol`, 1 integration; the bypass-route matrix and the timelock-activation batch pin added 15 in `test/poc/Erc1271BypassRoutes.t.sol`).
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
  test strength is evidenced instead by the 601-test suite and the 16 Echidna
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
- Echidna: 16/16 stateful invariants passing (2026-10-26, `make echidna`:
  seed `8660645280590958346`, 50,255 calls, 15,683 unique instructions,
  corpus 41, zero falsifications; adds `moduleTicketSingleUse` and the
  `getStorageAt` / `LOCKDOWN` harness stubs `initialize` needs). Previous run, PR #69 refresh (2026-08-12):
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
5. Decision predicates and executor agreement: settled by execution, recorded
   here as a fact rather than a request. Every `_checkCall` predicate compares
   `bytes4(data)` before reading any argument and is consumed with the intended
   polarity, so the two defects 0x shipped fixes for after its own audit
   (`d3ba88d4b1` selector-before-argument, `35abfb5601` reversed
   address-canonicality polarity) are structurally absent.
   `test/poc/DecisionPredicateAgreement.t.sol`, `test/poc/CalldataEncoding.t.sol`
   and `test/poc/DecodeCalldataBytesAdversarial.t.sol` execute the family: dirty
   address high bits at top level AND at MultiSend depth, `address(0)` aliasing,
   trailing bytes, sub-selector zero-padding, parser bounds (A4/A5), and
   privilege propagation at every recursion depth. No predicate can be made to
   accept a payload the executor decodes into a different call. Two fail-closed
   residuals are recorded as AR-26.
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
14. Terminal cancellation: what is established, and the decision that remains
    ours. `cancelTransaction` and `sweepExpiredOwnerTicket` delete the ticket
    slot, and the same public `scheduleTransaction` calldata recreates it while
    the signed nonce has not been surpassed (AR-16). 0x instead writes a
    permanent per-hash sentinel. `test/poc/CancellationSemantics.t.sol` settles
    the mechanics: a per-hash tombstone would durably stop the PUBLIC REPLAYER,
    the keyless actor who resubmits published calldata and who is the actor
    AR-16 is about, and would do nothing against a QUORUM ATTACKER who re-signs
    at will. It would cost permanently unreclaimable storage and a
    `getTransactionExecutableAt` magic value, and it would be inert unless
    bypasser precedence is settled, since `bypassTimelock` writes
    `executableAt = now` with no existence or state check. Permissionless sweep
    additionally strips the quorum's own cancellation handle. A generation
    counter folded only into ticket-key derivation would NOT give terminal
    revocation, because the same public signatures schedule again under the new
    generation; the earlier phrasing of this entry assumed otherwise. No guard
    local tombstone survives guard removal, so the AR-16 nonce-burn rule remains
    the durable control at uninstall regardless. Adoption is a V1.1/V1.2 design
    decision for the operator, not a V1 change.
