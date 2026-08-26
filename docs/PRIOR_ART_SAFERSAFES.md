# Prior art: Optimism SaferSafes / TimelockGuard vs Lockdown V1

Deep technical comparison performed June 2026. Purpose: (a) borrow audited
design patterns, (b) let the auditor lean on the Spearbit SaferSafes review
for idioms the two codebases share, (c) record deliberate divergences.

Subject: Optimism's `SaferSafes` singleton
(`contract SaferSafes is LivenessModule2, TimelockGuard`), the only other
guard-based Safe timelock with an audit and a mainnet deployment.

## 1. Facts (verified on-chain and in-source, 2026-06-10)

- Source: optimism monorepo `packages/contracts-bedrock/src/safe/`
  (`TimelockGuard.sol` ~678 lines abstract, `LivenessModule2.sol` ~426 lines
  abstract, `SaferSafes.sol` ~70 lines glue). MIT licensed; the blog post
  explicitly invites forking.
- Spec: `specs/protocol/safer-safes.md` in ethereum-optimism/specs (merged via
  PR #914, status "Production"): 5 assumptions (aSAFE-001..005) and 14
  invariants (iSAFE-001..014).
- Audit: Spearbit/Cantina, Nov 2025, at release `op-safe-contracts/v1.0.0`.
  Findings: 0 Critical, 0 High, 1 Medium, 2 Low, 5 Informational. Fixes in
  `op-safe-contracts/v1.1.0`.
- Deployment: singleton `0xA8447329e52F64AED2bFc9E7a2506F7D369f483a` on
  Ethereum mainnet and Sepolia. As of 2026-06-10 it is enabled as a
  **liveness module only** on the two Optimism Foundation Safes
  (`livenessResponsePeriod = 30d`, fallback owner = Security Council). The
  timelock half (`configureTimelockGuard`) is **not yet activated on any
  production Safe**, so the timelock path has audited provenance but no
  production history yet.
- **Safe v1.4.1 only**: both config functions revert unless
  `VERSION() == "1.4.1"`. It cannot be installed on a Safe v1.5.0, and we
  cannot be installed on 1.4.1. SaferSafes and Lockdown are therefore not
  substitutes; they target disjoint Safe versions, and both consume the
  single guard slot on whatever Safe they protect.

## 2. Their timelock design in one paragraph

`scheduleTransaction(safe, nonce, fullParams, signatures)` is permissionless
to call but validates a full Safe quorum via `safe.checkSignatures()` over the
real `safeTxHash`; the **same signatures later execute the tx**. Full
`ExecTransactionParams` are stored on-chain per hash (enumerable pending set,
`pendingTransactions()` view for watchtowers). `checkTransaction` passes
through when `timelockDelay == 0` (anti-brick, same as our SPEC_V1 §7.1),
requires the executor to be a current owner (anti signature-theft), recomputes
the hash at `nonce() - 1`, requires state Pending and maturity, and marks the
tx Executed in the pre-hook. Cancellation uses sub-quorum
`checkNSignatures` over a synthetic self-call to a no-op `signCancellation`
function, against a **dynamic threshold**: starts at 1, +1 per consecutive
cancellation, capped at `min(quorum, owners - quorum + 1)`, reset on any
execution. `clearTimelockGuard()` (only after the guard is unset) bumps a
per-Safe config-generation nonce, orphaning all timelock state in O(1).
Delay bounds `(0, 365d]`, no floor, no ticket expiry, no bypass of any
kind ("a timelock bypass is a question for the Reactive Security Council
feature"), and **no module-path coverage** (iSAFE-014 declares module txs out
of scope; their 1.4.1 target has no module guard hook).

## 3. Shared audited idioms the auditor can lean on

| Idiom | Their audited form | Our form |
|---|---|---|
| Hash recomputation at `nonce - 1` in `checkTransaction` (Safe bumps nonce before invoking the guard) | TimelockGuard `checkTransaction`, no audit finding | `_verifyOwnerTimelock` |
| Unconfigured pass-through anti-brick | `timelockDelay == 0 => return`, plus "enable guard and configure atomically in one batch" install guidance | SPEC_V1 §7.1 uninitialised pass-through + preflight script |
| Guard removal exposes outstanding signatures | iSAFE-013 (severity Critical in their spec) + Medium 5.1.1 remediation: runbooks mandating Safe nonce bumps after cancellation and around uninstall | Recovery whitelist empty self-call nonce burn; see action item 6.3 |
| Re-scheduling stability | iSAFE-009: a hash can never be scheduled twice per generation (signature-replay would extend the delay) | `scheduleTransaction` reverts `TicketAlreadyExists` for an existing owner-path ticket. Scheduling verifies the full Safe signatures without consuming the Safe nonce. |
| Cross-parameter timing invariant | iSAFE-006: `livenessResponsePeriod >= 2 * timelockDelay`, enforced in-contract via `_checkCombinedConfig` after every config mutation | INV-LIVE-3: `lockdownDuration >= max(LOCKDOWN_DURATION_MIN, timelockDelay)`, enforced in both setters unconditionally |

## 4. Spearbit findings triaged against Lockdown

- **Medium 5.1.1 (same signatures schedule and execute).** Their schedule
  model reuses detached execution signatures, so guard uninstall makes every
  previously scheduled or cancelled tx instantly executable, and
  `clearTimelockGuard` allows re-scheduling cancelled txs with the same
  signatures. Risks 2-3 do not apply to us (our scheduled tickets require
  quorum-authorized Safe signatures, keyed per Safe). Risk 1 is inherent
  to every guard-based timelock including ours: signatures collected for an
  scheduled-but-unexecuted tx outlive guard removal. Their accepted
  remediation (runbook nonce bumps) independently validates our recovery
  nonce burn; see action item 6.3.
- **Low 5.2.1 (configure-while-disabled bypasses the FREI-PI invariant).**
  They could set `timelockDelay` while the guard was disabled, then re-enable
  via `setGuard` which performs no revalidation. Our INV-LIVE-3 checks run in
  the setters unconditionally (installed or not), so the class appears
  closed; see action item 6.2 for the explicit test.
- **Low 5.2.2 (unchecked `execTransactionFromModule` success).** Their
  liveness takeover can silently no-op. Not directly applicable (we execute
  nothing through the Safe), but it is the same Safe-execution-semantics
  class our success-gated post-hook (INV-TIME-4) closes more strictly.
- **Informational 5.3.1 + 5.3.5 (fallback owner edge cases: GS203/GS204).**
  Directly applicable to our recovery-owner allowlist; see action item 6.1.
- **Informational 5.3.2 (stale state across disable/re-enable).** Their
  answer is the config-generation bump (iSAFE-012). Our per-Safe config and
  tickets persist in the singleton across guard removal and re-install; see
  action item 6.4.
- **Informational 5.3.3 (executor-must-be-owner blocks relayers).** They
  require `isOwner(msgSender)` at execution (iSAFE-008, anti signature
  theft) and accept losing relayers/paymasters. We deliberately do not
  provide iSAFE-008; documented as an accepted divergence (our owner-path
  scheduling already verifies quorum signatures, and the panic layer does not depend on
  executor identity). Revisit only if operator practice always self-executes.

## 5. Borrowable patterns, ranked

1. **Nonce-burn runbook hygiene (zero code, adopt now).** If the current Safe nonce is `n`, invalidating a transaction signed at nonce `n+k` requires advancing `Safe.nonce()` to `n+k+1`: `k+1` nonce-consuming transactions from `n`. If `cancelTransaction` has already consumed nonce `n` and advanced the Safe to `n+1`, `k` additional nonce burns remain. Apply this rule after any cancellation where execution signatures may exist off-chain and immediately before/after `setGuard(address(0))` at uninstall. Cite iSAFE-013 and their Medium 5.1.1 remediation as audited provenance; `test/poc/TicketRevival.t.sol` pins the cancellation case.
2. **Config-generation nonce (cheap, evaluate for V1.2).** One `uint64
   generation` folded into the ticket-key derivation would orphan all stale
   tickets on uninstall/re-install (their iSAFE-012) for a few gas. Applies
   to the ticket mapping only: signer registrations and the recovery
   allowlist must survive generations.
3. **Dynamic cancellation threshold (document the decision, do not adopt
   yet).** Their best idea: sub-quorum cancellation starting at 1 signature
   with audited anti-griefing escalation (`min(quorum, owners - quorum + 1)`
   cap). In our model a single honest owner cannot cancel a malicious
   scheduled ticket; the compensating control is `triggerLockdown` (one panic
   signer freezes everything), which subsumes per-tx cancellation at higher
   collateral cost. SPEC_V1 should state this explicitly: "no sub-quorum
   cancel because lockdown subsumes it". If graceful sub-quorum cancellation
   is ever wanted, adopt their audited mechanism as-is.
4. **`signCancellation` dummy-payload pattern.** A non-view no-op function
   whose calldata exists purely so the Safe UI / hardware wallets can
   clear-sign a meaningful payload. Reusable for any future sub-quorum
   ceremony.
5. **`TransactionBuilder` test library.** Their 1095-line test file drives
   lifecycle tests (schedule -> warp -> execute -> retry -> cancel) through a
   chainable memory-struct builder. Port the idea into `LockdownTimelock.t.sol`
   to add their lifecycle matrix: re-execute after execute, cancel after
   execute, re-schedule after cancel, identical params at different nonces.
6. **Watchtower documentation.** Their full-params storage exists for
   monitoring (`pendingTransactions()`). Our hash-only model is deliberately
   more private (a wrench attacker cannot read what the victim queued), at
   the cost of off-chain indexing. Add a short spec section: watchtowers
   index `TransactionScheduled` / `TimelockBypassed` / `TicketCancelled`
   events; they can count and time owner tickets but not simulate payloads.

## 6. Action items surfaced, and their resolution

1. **Recovery-owner validation (from 5.3.1/5.3.5): FIXED as SPEC_V1 H.19.**
   `_validateRecoveryOwner` rejects zero / sentinel `0x1` / the Safe itself /
   current owners at registration (`initialize` and
   `addRecoveryOwner`); `_isRecoveryTransaction` re-checks
   `isOwner(newOwner)` at hook time for the dynamic case; removal stays
   unvalidated (it is the cleanup path). Covered by 7 unit tests.
2. **Configure-while-disabled class (from 5.2.1): closed by construction.**
   All setters enforce INV-LIVE-3 unconditionally, installed or not; the
   singleton never branches on installation state. Flagged to the auditor
   (AUDIT_BRIEF question 13).
3. **Uninstall/cancellation nonce hygiene (from 5.1.1/iSAFE-013): runbook rule.** From current nonce `n`, a transaction signed at `n+k` is durably invalid only once `Safe.nonce()` reaches `n+k+1`: `k+1` burns from `n`, or `k` additional burns after a `cancelTransaction` has already consumed `n`. Apply the same exact rule immediately before/after `setGuard(address(0))` at uninstall.
4. **Stale-state semantics across re-install (from 5.3.2/iSAFE-012): TESTED,
   epoch not adopted.** Pinned by 5 tests: past-nonce owner tickets are dead
   by hash construction (the safeTxHash binds the nonce and the
   uninstall/reinstall consumed nonces); future-nonce owner tickets and
   module tickets (no nonce binding) survive re-installation as
   quorum-authorized, single-use, TTL-bounded, cancellable tickets; an
   active incident and burnt keys are still enforced after re-install. A
   ticket-epoch (`invalidateTimelockTickets`) was evaluated and deferred:
   the surviving-ticket shapes are quorum-approved and TTL-bounded, and the
   epoch would touch every ticket-key derivation for a surface no test
   showed exploitable. Revisit only if the threat model changes.

## 7. Where the designs differ

Ours: module-path coverage - restricting module `DelegateCall` to canonical
`MultiSendCallOnly` and denying any module call to the singleton at every
recursion depth (which their Safe v1.4.1 target cannot express, and which their
spec declares out of scope); success-gated post-hook ticket consumption
(INV-TIME-4) vs their pre-hook burn; hash privacy under coercion;
`TICKET_TTL` expiry vs their immortal scheduled txs; the entire
lockdown/recovery incident layer; the bypass availability lane; 15 stateful
Echidna invariants on the guard.

Theirs: on-chain queue transparency for watchtowers; sub-quorum cancellation
with audited anti-griefing math; anti signature-theft executor check
(iSAFE-008); O(1) state wipe on uninstall (iSAFE-012); signature-compatible
scheduling UX (no extra quorum ceremony per scheduled transaction); normative spec in
the OP specs repo and a clean Spearbit review.

## 8. What we deliberately do NOT borrow

- Full-params on-chain storage (breaks intent privacy under coercion, our
  core threat model; module scheduled events already carry full params because
  that path has no signature-backed hash).
- Detached-signature scheduling (reintroduces their Medium 5.1.1 risks 2-3).
- Their delay bounds (no floor): in our model the delay IS the protection
  during the disarm window, so `TIMELOCK_DELAY_MIN = 1h` stays. Their floorless
  choice is safe for them only because cancellation, not delay, carries their
  security.
- The liveness/deadman module: different problem (absent keys, not coerced
  keys). Note for docs: a LivenessModule-style fallback takeover executes
  through `execTransactionFromModule`, which on a 1.5.0 Safe traverses the
  module guard, i.e. us. During lockdown/recovery we would block it, which is
  the correct anti-coercion behaviour but means any future deadman feature
  needs its own iSAFE-006-style timing floor against our lockdown window.
