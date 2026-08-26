# Pre-tag adversarial review: findings and dispositions

Before freezing the audit candidate, the codebase went through an adversarial review designed to find what the authors could no longer see. Two independent AI reviewers each ran two passes: a specification-underdetermination pass, looking for places where the specification permits more than one behaviour and the code silently picks one, and an executable blind-spot hunt that had to turn every divergence into a Foundry test rather than a paragraph.

The second pass and its follow-up produced `test/poc/`: 12 files, 137 tests. Every executed claim below is re-runnable. That is the point: a reviewer should not have to take this document's word for anything.

**This register exists so that nothing found is silently dropped.** Where a finding is
not fixed, the reason is written down. An auditor is welcome to disagree with any of
these dispositions, and the questions in `AUDIT_BRIEF.md` name the places where we
would most value that disagreement.

## How to read it

Test names carry their own disposition:

| Prefix | Meaning |
|---|---|
| `test_confirmed_` | Real and unfixed. Pinned deliberately, with a rationale in this file |
| `test_refuted_` | Killed by execution. Do not spend audit hours re-asking |
| `test_limitation_` | Real, accepted, documented |
| `test_regression_` | Was confirmed, now fixed |
| `test_control_` | Positive control proving a fix did not break the path it protects |

Dispositions used below:

- **FIXED** - changed in `src/`, with the PoC flipped to `test_regression_`.
- **ACCEPTED** - real, not fixed, reason recorded here and in the accepted-risk register.
- **OPEN** - real, and the fix is a design decision still being arbitrated. There are
  no OPEN Solidity findings at candidate freeze.
- **REFUTED** - proven not to be a problem, kept only so nobody pays to re-derive it.
- **DOC** - the code was right and a document was wrong. Corrected.

## Findings requiring a change in `src/`

These are the only findings that could reopen the frozen scope, so each one is
dispositioned explicitly.

### FIXED

| # | Finding | Test | Why it was fixed |
|---|---|---|---|
| A4 | `_decodeCalldataBytes` offset addition wraps; the decoder points `transactions` at the guard's own zero word and validates a fabricated empty batch. Only the downstream `MultiSendCallOnly` decoder stopped it, accidentally | `CalldataEncoding.t.sol::test_regression_decodeCalldataBytesOffsetWraparoundRejectedByGuard` | Unchecked arithmetic in a calldata parser is an automatic audit finding, the fix is bounded and testable, and a guard whose validation is decoupled from what actually executes is the exact shape that produces "guard sees benign, executor runs hostile" |
| A5 | The same wrap with `length = type(uint256).max` puts the bound below the end of the slice, producing a parse loop over roughly 2^250 records: gas exhaustion instead of a clean rejection | `CalldataEncoding.t.sol::test_regression_declaredLengthOverflowRejectedByGuard` | Same root cause, same fix. Rejection now costs 19k gas and carries an error selector instead of burning 5M and reverting bare |
| A11 | `removeRecoveryOwner` is a silent no-op on an address that was never on the allowlist: successful transaction, no event, and the backup still eligible for `swapOwner` | `VerifierAndGriefing.t.sol::test_regression_removeRecoveryOwnerRevertsOnAnUnknownAddress` | An operator culling a compromised recovery owner with a typo would believe the cull succeeded. One word, `strict: true`, and the failure mode is a revert instead of false confidence |
| A13 | `triggerLockdown` removed and burnt the identity before signature verification, exposing an intermediate state to the verifier STATICCALL | `DrillEvasionVerifier.t.sol` (six verify-before-burn regression/control tests) | Verification now runs first through the public `testSigner` source of truth; only after success does the trigger remove, permanently burn and lock. Hadrien accepted the reorder as hygiene without expanding the supported threat model beyond the repository's pinned verifiers |

### ACCEPTED - real, deliberately not fixed

| # | Finding | Test | Why we are not fixing it |
|---|---|---|---|
| A1 | An ERC-7913 identity whose verifier returns a returndata bomb can make `triggerLockdown` OOG because OZ's high-level 7913 branch copies the whole result | `VerifierAndGriefing.t.sol::test_confirmed_returnDataBombVerifierOutOfGassesTriggerAtEveryGasLimit` | Supported production identities use only the immutable, closed-world verifier bytecodes shipped and codehash-pinned by the repository. The identity is the indivisible trust unit; any OOG, revert or invalid return condemns it and requires remove/rotate to a different verifier. We do not fork `SignatureChecker` locally for unsupported verifier behaviour |
| A2 | The same unbounded-copy outcome can be delivered through revert data | `VerifierAndGriefing.t.sol::test_confirmed_revertBombVerifierOutOfGassesTrigger` | Same trust-boundary decision as A1. A drill OOG/revert is an identity failure, not a recoverable signature error |
| A3 | A verifier can consume nearly the whole forwarded gas budget before returning an invalid result | `VerifierAndGriefing.t.sol::test_confirmed_gasBurnerVerifierInflatesCostAndIsIndistinguishable` | No verifier gas ceiling: legitimate verification cost is open-ended and chain-dependent, including P256 without a precompile and possible future post-quantum schemes. A ceiling could disable an otherwise valid panic identity |
| A6 | The three install slots are verified only inside `initialize`, unreachable afterwards. Reinstalling `setGuard` alone leaves the module path unguarded, and an enabled module can then call configuration entry points on the singleton | `SafeIntegrationLifecycle.t.sol::test_limitation_reinstallNeverRechecksInstallSlots` | No runtime Solidity re-check and no incident-time event. `triggerLockdown` must freeze every path still available rather than refuse degraded protection, and an on-chain warning would disclose a possible escape route to the coercer. The lifecycle diagnostic and monitoring must check all three slots before an incident and propose repair while the Safe is cold |
| A7 | An owner-path `setModuleGuard(0)` after `initialize` silently defeats the module freeze: the module executes while `getState()` reports `LockedDown` | `SafeIntegrationLifecycle.t.sol::test_limitation_moduleGuardRemovalSilentlyDefeatsLockdownOnModulePath` | Same decision as A6. Installation integrity is a continuously re-checked operator/UI condition, not a trigger-time contract predicate; a valid trigger always blocks everything it still can |
| A12 | The cap of 32 bounds only the active set; `_burnt` is never cleaned. An add followed by a remove inside one MultiSend permanently poisons an arbitrary future identity | `VerifierAndGriefing.t.sol::test_confirmed_burntHistoryIsUnbounded` | Permanent burn is required for `PasswordVerifier`, whose verification ignores the digest, and keeps emergency signing independent of an RPC epoch read. Fresh ERC-7913 key generation is the recovery path. A registration epoch remains a V1.2 design candidate, not a V1 change |
| A8 | `bypassTimelock` writes `executableAt = now` with no `TicketAlreadyExists` guard, so it resurrects a ticket already dead past its TTL and refreshes it indefinitely. Three consecutive TTL windows were crossed in the test | `TimelockAccounting.t.sol::test_confirmed_bypasserRearmsTicketPastTtl`, `::test_confirmed_bypasserRefreshesTicketIndefinitely` | A live compromised bypasser already holds full owner-path bypass authority under accepted risk #8: it can pre-bypass any hash at any time. Refreshing an old ticket grants it nothing it does not already have, so a guard here would buy no security. The genuine defect was the register telling the operator the opposite, and that is corrected |
| A9 | The documented response, paginate the pending tickets and cancel them BEFORE revoking, describes a window that is literally zero: bypass and execution fit in the same block | `TimelockAccounting.t.sol::test_confirmed_bypassAndExecuteInSameBlock` | Imposing a minimum delay on a bypass would defeat the purpose of the bypass, which exists precisely to skip the delay. The honest correction is to stop promising a response window that cannot exist and to state that containment of a compromised bypasser is a key-management problem, not an on-chain one |
| A10 | No atomic A to B singleton migration exists: A requires `H_B.LOCKDOWN() == A` and B requires `== B`, which cannot both hold in one transaction. Two owner transactions minimum, with an unavoidable fail-open window between them | `SafeIntegrationLifecycle.t.sol::test_confirmed_atomicMigrationBundleReverts`, `::test_confirmed_noHandlerSatisfiesBothAAndBInOneTransaction`, `::test_limitation_migrationNeedsTwoTransactions` | Atomicity would require a handler that satisfies two singletons at once, which means loosening the binding that makes the handler trustworthy in the first place. We would be weakening a live control to smooth a rare operation. The mitigation is procedural: the published runbook was wrong and is corrected, signers are burnt before uninstall, and the handler is removed last |

## Findings fixable outside `src/`

| # | Executed finding | Verdict and disposition |
|---|---|---|
| B1 | The guard accepts non-zero `value` on the three recovery leaves other than nonce burn | **DOC — corrected.** INV-REC-1 had overstated the guard predicate |
| B2 | Value nevertheless cannot move through those leaves today | **REFUTED as exploit / DOC.** The non-payable callees stop it accidentally, not the guard |
| B3 | Recovery reaches a payable third party directly, through MultiSend, through `address(0)`, or by smuggling `addOwner` | **REFUTED.** Every leaf is rechecked under Recovery privilege |
| B4 | A top-level canonical MultiSend DELEGATECALL envelope, including nested envelopes, is accepted during Recovering | **DOC — corrected.** INV-REC-1 now distinguishes the envelope from CALL-only leaves |
| B5 | A nested DELEGATECALL leaf accepted by the guard executes | **REFUTED.** `MultiSendCallOnly` rejects packed operation 1; this is an executor dependency |
| B6 | T-BYPASS-7's refund gate also covers the inline bypasser lane | **DOC — corrected / ACCEPTED.** The inline CALL and DELEGATECALL lane skips that gate, including uncapped ERC-20 gas-token refund |
| B7 | The inline refund lane escalates beyond bypasser authority | **REFUTED.** Accepted risk #8 already grants full owner-path bypass authority |
| B8 | EIP-7702 can turn a registered EOA panic identity inert | **ACCEPTED / DOC.** AR-18 prohibits delegation and requires drilling |
| B9 | EIP-7702 or an upgraded verifier can make triggering permissionless | **ACCEPTED / DOC.** AR-18 records the accurate anyone-can-trigger impact |
| B10 | A fully green Safe can have no working trigger through several identity/verifier shapes | **ACCEPTED / DOC.** AR-17 records the executed cases |
| B11 | Those B8/B10 cases are undetectable before an incident | **REFUTED for those cases.** `testSigner` distinguishes the executed inert identities inside the supported verifier domain; A13's deterministic ordering discrepancy is fixed |
| B12 | ERC-1271 signatures produced during an incident validate after auto-resume if the owner remains | **ACCEPTED / DOC.** AR-15 and the handler commentary now say deferred, not invalidated |
| B13 | Swapping the compromised owner fails to kill those signatures | **REFUTED.** Safe validates against the current owner set; the runbook now requires the swap |
| B14 | A pre-incident ticket can execute at the exact auto-resume second with no fresh delay, while cancel is unavailable during Recovering | **ACCEPTED / DOC.** AR-19 records the exact boundary and nonce-burn response |
| B15 | The published guards-only migration keeps both execution paths protected | **DOC — corrected.** The two-transaction migration and fail-open window are explicit |
| B16 | The old handler can still freeze ERC-1271 after execution guards are removed | **DOC — corrected.** The migration runbook burns/removes old signers and removes the handler last |
| B17 | The parser's final equality and `InvalidOperation` branches independently enforce the claimed properties | **DOC — corrected.** Exact consumption is derived from earlier bounds; invalid enum bytes can reject before the named error |
| B18 | Every malformed `setFallbackHandler` self-call returns `InvalidFallbackHandler` | **DOC — corrected.** Zero/non-contract/short inputs can fail closed earlier with different revert data |
| B19 | A sub-four-byte payload currently forges a guarded selector through zero-padding | **REFUTED, with maintenance note.** No current guarded selector ends in `0x00`; future selectors must preserve that condition |
| B20 | Exact `0x24` length on owner-path `cancelTransaction(bytes32)` was covered by the historical suite | **TEST GAP CLOSED.** Two tests now fail if T6 relaxes the check to selector-only or accepts a trailing byte |

The two highest-value documentary corrections were not cosmetic. `SPEC_V1.md` had justified permissionless sweep by saying an expired ticket was already unreachable, but clearing its slot removes `TicketAlreadyExists` and permits the same public signed authorisation to be scheduled again; AR-16 now states the exact `k+1` nonce-burn rule. `AUDIT_BRIEF.md` had also claimed the prior-art detached-signature replay class did not apply, although the signatures are public in `scheduleTransaction` calldata; that claim has been removed.

## Mutation campaign record

The archived historical `campaign.out` records exactly 19 mutants executed, 12 killed and 7 survivors. The clean pre-arbitration rerun on commit `1bea0ba` killed 17 of those 19 mutants; only M1 and M7 survived, with zero `INVALID` or `TIMEOUT`. This replaces both the erroneous relayed count of 20/6 and the stale inference that the five newly pinned timelock mutants merely "should" be killed.

| Mutant | Historical result | Current disposition |
|---|---|---|
| M1 — remove the external initial-signer cap check | SURVIVED | The cap is still imposed inside `_addLockdownSigner`; the outer line is redundant and not independently pinned |
| M7 — remove the parser's final equality | SURVIVED | Exact consumption is derived from the preceding bounds; the documentation no longer calls this an independent enforcement line |
| T1 — make the exact TTL endpoint non-executable | KILLED on rerun | `TimelockAccounting.t.sol::test_confirmed_ttlBoundaryExactSecondIsExecutableAndUnsweepable` |
| T2 — allow sweep at the exact TTL endpoint | KILLED on rerun | The same exact-second test and its plus-one counterpart |
| T5 — remove the bypasser check on inline DELEGATECALL | KILLED on rerun | `TimelockBypassRefundLane.t.sol`; the lane is accepted and documented |
| T6 — relax exact cancel calldata length from `0x24` to selector-only | KILLED on rerun | The two owner-path malformed-cancel tests in `LockdownTimelock.t.sol` |
| T7 — remove `value == 0` on the recovery nonce-burn arm | KILLED on rerun | The recovery value envelope is executed and zero remains required specifically on nonce burn |

The rerun evidence is archived outside the repository with its JSONL and logs; the candidate campaign will still be rerun on the final tagged SHA after every decision is incorporated.

## Refuted

Twenty-one leads were killed by execution and are recorded so that no audit hours are
spent re-deriving them. Among them: the module ticket preimage binds every field
(10 tests); a failed trigger attempt does not burn the signer; `nonce() - 1` holds under
a nested `execTransaction`; the post-hook runs against the cached guard; threshold-N
behaves identically to 1-of-1; cross-Safe isolation holds; both module entry points are
guarded identically; and 31 surviving signers can be culled in a single recovery
MultiSend, which is the mitigation the register claims and which does depend on the cap.

## Limits of this exercise

Two AI reviewers agreeing does not make a finding true, and the two disagreed with each
other and with themselves several times. Everything above that is marked confirmed or
refuted is backed by an executed test; everything that is not is in the appendix of the
internal reports and was deliberately left for the auditor rather than resolved here.

This review is not an audit and is not offered as a substitute for one.
