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
| A13 | `triggerLockdown` removed and burnt the identity before signature verification, exposing an intermediate state to the verifier STATICCALL | `DrillEvasionVerifier.t.sol` (six verify-before-burn regression/control tests) | Verification now runs first through the public `testSigner` source of truth; only after success does the trigger remove, permanently burn and lock. Hadrien accepted the reorder as hygiene without expanding the supported threat model beyond the repository's pinned verifiers. [Later: `testSigner` was removed in favour of the off-chain drill `script/DrillSigner.s.sol`; verification is now inline in `triggerLockdown`, still before the burn.] |

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
| B11 | Those B8/B10 cases are undetectable before an incident | **REFUTED for those cases.** `testSigner` distinguishes the executed inert identities inside the supported verifier domain; A13's deterministic ordering discrepancy is fixed. [Later: `testSigner` was removed; the same check now runs off-chain via `script/DrillSigner.s.sol`.] |
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

## Refund-window campaign (2026-08-28)

This campaign was opened after the comparative review of 0x's `ZeroExSettlerDeployerSafeGuard`, where Bailsec classified the same call ordering as Medium and 0x shipped an on-chain gate against it. All 17 tests are in `test/poc/RefundPostHookReentrancy.t.sol`.

The load-bearing fact, verified in the pinned submodule rather than inferred. `Safe.execTransaction` caches the guard, executes, calls `handlePayment` when `gasPrice > 0`, and only then calls the cached post-hook. `handlePayment` refunds with an **unrestricted** call:

```solidity
address payable receiver = refundReceiver == address(0) ? payable(tx.origin) : refundReceiver;
(bool refundSuccess, ) = receiver.call{value: payment}("");   // native
if (!transferToken(gasToken, receiver, payment)) ...          // ERC-20
```

0x permits native gas sponsorship on the explicit ground that "the Safe uses `send`, which defuses reentrancy due to the 2300 gas rule". That was true of Safe 1.3.0. It is **not** true of Safe v1.5.0, which forwards essentially all remaining gas.

This is not only our reading. Bailsec's June 2026 public upgrade audit of `SafeGuard.sol` rated the same window **Medium (Issue 04, fixed)**, describing it as a real reentrancy interval before `checkAfterExecution` that permits temporary guard removal or module installation followed by cleanup. 0x's fix forbids ERC-20 sponsorship on direct or batched `setGuard` / `enableModule` / `setFallbackHandler`, and leaves native sponsorship enabled **only** because its supported Safe versions use the 2,300-gas `send` path. That report states explicitly that the assumption must be revisited for Safe v1.5.0 or newer. We pin Safe v1.5.0. That is why this campaign was run rather than the concern being closed by reasoning. Our exposure is therefore strictly larger than the one 0x reasoned about, and `SPEC_V1.md` §7.2 never examined this window. `test_control_refundCallbackHasEnoughGasForNestedExecTransaction` pins that the callback receives ample gas for a full nested `execTransaction`, so every negative result below is attributable to the guard and not to an out-of-gas.

### Verdict against the campaign's stop gates

**The candidate stays frozen.** No callback moved assets or changed protected state without the authority that already governs that action, no scheduled ticket authorised two executions, and no callback bypassed an incident without a prior guard-slot disarm. The decisive control is `test_refuted_dominanceNoRefundMultiSendReachesTheSame`: an owner-approved, scheduled MultiSend with **every refund field zero** reaches the identical end state. The refund window therefore adds no authority. What it changes is atomicity and observability.

| # | Executed finding | Test | Disposition |
|---|---|---|---|
| R1 | The refund callback really does run after the business call and before the cached post-hook, on both the native and ERC-20 branches, with the outer ticket still live | `test_confirmed_nativeRefundCallbackRunsBeforeCachedPostHook`, `test_confirmed_erc20GasTokenCallbackRunsBeforeCachedPostHook` | **CONFIRMED reachability**, not a defect on its own |
| R2 | While the guard is installed, an unscheduled, immature, or module-ticketless nested call is refused inside the window exactly as outside it | `test_refuted_unscheduledNestedOwnerTxIsRejectedInsideTheWindow`, `test_refuted_immatureNestedTicketIsNotAcceleratedByTheWindow`, `test_control_moduleGuardIntactRejectsUnscheduledModuleCallInsideTheWindow` | **REFUTED.** The timelock governs the window |
| R3 | A separately scheduled, matured nonce `n+1` ticket does execute from the window, consuming exactly two tickets and two nonces | `test_limitation_maturedNestedTicketExecutesOnceInsideTheWindow` | **LIMITATION.** Authorised nesting, single-use accounting intact |
| R4 | A reverting refund receiver rolls back the whole transaction, including nonce, effect and ticket | `test_control_revertingRefundReceiverRollsBackEverything` | **REFUTED.** No partial commit through the window |
| R5 | **A failed business call still opens the window and does NOT consume the ticket.** With `safeTxGas != 0` Safe does not bubble, still pays the refund, and calls the post-hook with `success == false`; INV-TIME-4 then preserves the ticket. The attacker obtains the window for free and the authorisation stays spendable | `test_confirmed_failedBusinessCallStillOpensTheWindowAndPreservesTheTicket` | **CONFIRMED, new.** Not covered by any existing register entry. Proposed as AR-24 |
| R6 | The callback can cancel the outer ticket while it is in flight, so `TimelockConsumed` is never emitted for a transaction that executed. No replay follows, because the Safe nonce has advanced past the signed nonce | `test_confirmed_callbackCancelsTheInFlightOuterTicketSuppressingTimelockConsumed` | **CONFIRMED as an observability limitation.** Watchtowers reconciling scheduled against consumed tickets will mis-account it |
| R7 | The callback can activate the incident, and while the guard is installed the freeze is real for any subsequent call | `test_limitation_callbackCanTriggerLockdownAndTheGuardStillBlocksNestedCalls` | **LIMITATION.** Restates AR-23 on a new entry point |
| R8 | After a scheduled `setGuard(0)` or `setModuleGuard(0)`, the callback executes an unscheduled owner or module transaction **in the same transaction as the removal** | `test_confirmed_guardRemovalThenUnscheduledNestedTxInsideTheWindow`, `test_confirmed_moduleGuardRemovalThenUnscheduledModuleCallInsideTheWindow` | **CONFIRMED atomicity, not new authority.** Dominated by R10 |
| R9 | Composed: after a scheduled `setGuard(0)` the callback triggers Lockdown, so the singleton reports `LockedDown` while the owner path is already uncovered and still executes | `test_confirmed_lockedDownViewWhileTheUncoveredOwnerPathStillExecutes` | **CONFIRMED.** AR-20 composed with AR-23, atomically. Proposed as AR-25 |
| R10 | The same end state is reached by a scheduled, owner-approved MultiSend with every refund field zero | `test_refuted_dominanceNoRefundMultiSendReachesTheSame` | **REFUTED as an escalation.** This is the dominance result that keeps the candidate frozen |
| R11 | **With `refundReceiver == address(0)` the Safe refunds `tx.origin`.** Code there, by EIP-7702 delegation or simply a contract submitter, runs in the refund window while the signed hash contains zero | `test_confirmed_zeroRefundReceiverExecutesCodeAtTxOriginNotBoundByTheSignedHash` | **CONFIRMED, new, and documentary.** See below |

### The one documentation defect this campaign found

`SPEC_V1.md` §7.2 rests the Normal-mode refund policy on off-chain signer review: "the off-chain review pipeline is what catches `gasToken != 0` / `refundReceiver != 0` configurations". R11 shows that instruction is **inverted for the zero case**. When `refundReceiver == address(0)` the dangerous value is zero, and the code that will receive control is `tx.origin`, which is not in the signed hash at all. A reviewer following §7.2 literally would clear exactly the transaction that carries an unbound callback.

This is the same shape as AR-18, where an EIP-7702 delegation silently changes what a registered 20-byte panic identity means. Here it silently changes what `refundReceiver == 0` means. Neither requires a Solidity change to state honestly, but §7.2's review instruction must be corrected. The guard itself remains intact in this case: the test asserts the nested call is still refused with `TicketNotFound`.

### What is escalated rather than fixed

R5, R6, R9 and R11 are escalated to the auditor and the operator, not fixed here, because the deliberate stop gate for this campaign is that atomicity, observability and misleading views after an owner-authorised disarm are threat-model decisions rather than defects. No Solidity changed in this task. If a mitigation is wanted, the candidates to compare are: propagating a `forbidRefund` property through the recursive parser for guard-slot-mutating selectors, an owner-path in-flight guard, or accepting the atomicity and strengthening the runbook. That comparison belongs to a separate plan.

## Decision-predicate agreement campaign (2026-08-28)

Provenance: 0x shipped two fixes to this exact construction AFTER its own audit. `d3ba88d4b1` read an argument word at a fixed offset without first proving the selector; `35abfb5601` reversed the polarity of an address-canonicality check. Our audit question 5 previously pointed only at parser arithmetic, which is where our own A4 and A5 were, and not at the predicates the parser feeds. 13 tests in `test/poc/DecisionPredicateAgreement.t.sol`.

The question, answered by execution: can any `_checkCall` predicate disagree with Solidity ABI decoding, Safe v1.5.0 or `MultiSendCallOnly` about the call that will actually execute?

**No class-(a) divergence exists.** Nothing makes a predicate accept a payload the executor decodes into a different call. Both 0x defects are structurally absent: every predicate compares `bytes4(data)` before reading any argument, and each is consumed with the intended polarity. The encoding family was already settled by `CalldataEncoding.t.sol` and `DecodeCalldataBytesAdversarial.t.sol` and was deliberately not re-derived; this campaign extended it to predicate completeness and to depth.

| # | Executed finding | Test | Disposition |
|---|---|---|---|
| P1 | The module blacklist is complete against Safe v1.5.0's real surface: of the nine `authorized` self-call functions, exactly the three that write a protection slot are denied and the other six cannot reach one. Removing any selector turns the test red | `test_refuted_moduleBlacklistCoversEverySlotWritingSafeFunction`, `test_refuted_moduleCannotClearModuleGuardSlotEndToEnd`, `test_control_moduleSelfCallsThatAreNotSlotWritesStillExecute` | **REFUTED.** Completeness is now pinned, not assumed |
| P2 | `Safe.setup()` also writes the fallback-handler slot and is NOT in the blacklist. The guard accepts it; `setupOwners` reverts `GS200` on any live Safe, on both owner and module paths | `test_refuted_setupCannotRewriteTheFallbackSlotOnALiveSafe`, `test_refuted_setupOnOwnerPathCannotRewriteTheFallbackSlot` | **REFUTED as an exploit, kept as an auditor question.** This is the one place the blacklist is incomplete *by name* and correct only *by executor behaviour*: the protection is a Safe-side invariant, not ours |
| P3 | `_isTimelockManagementCall` mixes one exact-length arm (`cancelTransaction`, `0x24`) with two minimum-length arms, so one trailing byte costs the carve-out for the first and not the others. The executor would have accepted the padded calldata | `test_limitation_paddedCancelTransactionLosesTheManagementCarveOut`, `test_control_executorAcceptsPaddedCancelTransactionCalldata`, `test_control_minimumLengthArmGrantsTheCarveOutWithTrailingBytes` | **LIMITATION, fail-closed.** Keep the strictness: it is the direction mutant T6 protects |
| P4 | A malformed payload that wins a minimum-length carve-out dies in the decoder and rolls the whole transaction back, including inside the recovery window, so the quorum does not burn a nonce | `test_refuted_malformedScheduleModuleTransactionGetsBypassButCannotExecute`, `test_limitation_malformedRemoveLockdownSignerIsWhitelistedThenRollsBack`, `test_control_recoveryRemoveSignerWithLiveSigner` | **REFUTED.** The incident-time liveness worry does not materialise |
| P5 | Dirty high bits in the `swapOwner` newOwner word agree between guard and executor at MultiSend depth under `Privilege.Recovery`, not only at top level | `test_refuted_dirtySwapOwnerWordAgreesAtMultiSendDepth`, `test_refuted_nestedSwapOwnerToUnregisteredAddressDeniedAtDepth` | **REFUTED.** Note the mechanism: Safe *masks* the same low 20 bytes rather than rejecting dirty bits, so agreement is by construction |

## Cancellation-semantics campaign (2026-08-28)

The auditor question about terminal cancellation rested on assertions. 13 tests in `test/poc/CancellationSemantics.t.sol` replace them with executed facts. The campaign's organising insight is that **two different attackers were being conflated**, and separating them changes the answer.

- The **public replayer** holds no key, no owner status and no fresh signature. They resubmit published `scheduleTransaction` calldata. This is the actor AR-16 is actually about.
- The **quorum attacker** still controls signing and can re-sign at will.

| # | Executed finding | Test | Disposition |
|---|---|---|---|
| C1 | `bypassTimelock` has no existence and no state check: it writes `executableAt = now` into an EMPTY slot, over a live immature ticket, and over one the quorum just cancelled. A bypasser authorises hashes nobody ever scheduled | `test_confirmed_bypasserCreatesAnExecutableTicketWithNoPriorSchedule`, `test_confirmed_bypasserResurrectsATicketTheQuorumJustCancelled`, `test_confirmed_bypasserOverwritesALiveImmatureTicketToImmediate` | **CONFIRMED, within accepted risk 8 but sharper than it was stated.** Any tombstone proposal must settle bypasser precedence explicitly or the tombstone is decorative. Bounded by `test_control_bypassAuthorityDoesNotExtendIntoAnIncident`: Normal state only |
| C2 | **Permissionless sweep strips the quorum's own cancellation handle.** A keyless third party deletes an expired ticket; the quorum's `cancelTransaction` then reverts `TicketNotFound` while the authorisation stays reschedulable | `test_confirmed_permissionlessSweepStripsTheQuorumCancellationHandle`, `test_control_sweepIsRefusedBeforeTtlSoTheStripNeedsTheFullWindow` | **CONFIRMED, new.** Cancellation and sweep are not two routes to the same place: sweep strictly weakens the defender. Slow, not instant, since it needs the full TTL |
| C3 | Cancellation is impossible for the ENTIRE incident (`LockedDown` then `RecoveryActive`, since cancel is not recovery-whitelisted) while a matured pre-incident ticket survives untouched and executes at the auto-resume second | `test_confirmed_cancellationIsImpossibleForTheWholeIncidentWhileTheTicketStaysLive` | **CONFIRMED.** AR-19's boundary shown end to end. This, not the TTL, is where a transaction outlives its cancellability |
| C4 | An EXPIRED ticket cannot execute but stays cancellable, and a matured one stays cancellable too | `test_refuted_anExpiredTicketRemainsCancellable`, `test_control_aMaturedTicketIsStillCancellable` | **REFUTED, and we are better than 0x here.** No `TimelockElapsed` state exists in our design: Bailsec Issue 05, acknowledged and unfixed by 0x, does not apply |
| C5 | The public replayer revives a cancelled future-nonce authorisation from published calldata alone. `k+1` nonce burns defeat them (cancel consumes one, `k` more reach `signedNonce+1`, then `StaleSafeNonce`). The quorum attacker is unaffected and simply re-signs | `test_confirmed_publicReplayerRecreatesTheTicketFromPublicCalldataAlone`, `test_refuted_nonceBurnPastTheSignedNonceDefeatsThePublicReplayer`, `test_confirmed_quorumAttackerIsUnaffectedByAnyGuardLocalRevocation` | **CONFIRMED, and it corrects our own framing.** A tombstone WOULD durably stop the keyless replayer. Dismissing exact-hash revocation because "the attacker re-signs at n+1" silently swaps in an attacker who still holds the quorum |
| C6 | `getTransactionExecutableAt` returns 0 for cancelled, never-scheduled and consumed alike | `test_limitation_theGetterCannotDistinguishCancelledFromNeverScheduledOrConsumed` | **LIMITATION.** A sentinel fixes exactly this, at the price of unreclaimable storage and a magic value every indexer must learn |

Tooling note for future suites: `TestEnvironment._burnNonce` cannot be used once a timelock is active, because it submits a plain owner transaction that needs its own matured ticket.

## Cross-audit mining campaign (2026-08-29)

Twenty-seven bug classes were extracted from five public MixBytes reports on contracts adjacent to ours (timelocked multisig governance, Safe-adjacent guards) and pointed at this codebase: 3 APPLICABLE, 12 already COVERED, 8 ACCEPTED, 4 NOT APPLICABLE. That distribution is itself a result: on the surfaces closest to ours, five senior audits found nothing in other people's code that this suite does not already handle. The three applicable leads are all low severity, none moves funds and none bypasses an active lockdown. 14 tests in `test/poc/MixBytesCrossAuditLeads.t.sol`.

One caveat on provenance: the audited Mantle contract's repository is no longer public, so the upstream mechanisms were re-derived from the report's technical description rather than from source.

| # | Executed finding | Test | Disposition |
|---|---|---|---|
| M1 | **The mined lead's own example does not work.** `cancelTransaction(bytes32(0))` was proposed as a free nonce burner. `_cancelTicket` reverts `TicketNotFound` on a hash with no ticket, and because the meta-call lane forces `safeTxGas == 0` (INV-TIME-9, the C1 refund gate) Safe bubbles the revert and the nonce rolls back | `test_refuted_cancelTransactionOnAnUnknownHashDoesNotBurnANonce` | **REFUTED.** The refund gate written for a different reason incidentally closes this variant |
| M2 | The lead's mechanism is nonetheless real with a SUCCEEDING meta-call. One `scheduleModuleTransaction` consumes a nonce instantly, and an owner ticket is valid at exactly one nonce, so a matured defensive countermeasure becomes unreachable and must be re-scheduled for a full fresh delay. Three free meta-calls strip a three-deep defensive queue | `test_control_schedulingMetaCallConsumesANonceWithNoDelay`, `test_confirmed_oneFreeMetaCallStripsAMaturedDefensiveTicket`, `test_confirmed_threeFreeMetaCallsStripAThreeDeepDefensiveQueue`, control `test_control_maturedDefensiveTicketExecutes` | **CONFIRMED, recorded as AR-27.** No Solidity change: the nonce coupling is intrinsic to Safe's signature model. Runbook and monitoring obligations instead |
| M3 | A module ticket can be scheduled for a call `_checkCall` refuses unconditionally, on both the singleton-target and non-canonical-DelegateCall arms. The full delay is paid before the failure surfaces, and the dead ticket keeps its slot until cancel or TTL | `test_confirmed_moduleTicketSchedulableForACallTheGuardAlwaysRefuses`, `test_confirmed_moduleTicketSchedulableForANonCanonicalDelegateCall`, `test_confirmed_theDeadModuleTicketBlocksItsOwnSlot`, control `test_control_policyLegalModuleTicketExecutesAfterItsDelay` | **CONFIRMED, recorded as AR-28.** A Solidity fix is available and deliberately not taken in V1: it duplicates policy at two sites or costs EIP-170 margin |
| M4 | **AR-19's incident defusal was wrong for the module path.** A nonce burn does not touch a module ticket, whose key contains no nonce: the ticket survives the burns and fires at the exact auto-resume second | `test_confirmed_nonceBurnDoesNotDefuseAPendingModuleTicket` | **CONFIRMED, and AR-19 is corrected.** This was a runbook defect, not a contract defect, and it would have shown up only in the one scenario the product exists for |
| M5 | The correct module-path defusal exists and IS recovery-whitelisted: exact-length `disableModule`. A disabled module can no longer call `execTransactionFromModule`, so the ticket is unreachable before the guard runs. The obvious alternative, `cancelModuleTransaction`, is NOT whitelisted and is unavailable exactly when wanted | `test_confirmed_disableModuleDefusesPendingModuleTicket`, `test_limitation_cancelModuleTransactionIsUnreachableDuringRecovering` | **CONFIRMED as the fix.** This is the test the mined lead said was missing; AR-19 now names it |
| M6 | **Operator trap found while writing M4.** The recovery whitelist accepts an empty self-call only when `to == safe`. A nonce burn addressed to `address(0)` is refused `RecoveryActive`, although Safe v1.5.0 aliases `address(0)` to itself at execution and the same transaction is valid in Normal mode: the guard reads the literal top-level `to`, and the alias rewrite applies only to inner MultiSend leaves. `TestEnvironment._burnNonce` uses `address(0)`, so the repository's own helper does not work inside a recovery window | `test_limitation_recoveryNonceBurnMustTargetTheSafeNotAddressZero` | **CONFIRMED, new, and not from the mined report.** AR-19 now specifies `to == safe` explicitly |

### The three areas worth more than the finding list

The mining exercise produced a better structural observation than its individual leads, and it is offered to the auditor as orientation rather than as a question.

**The module path is a second-class path.** M3 and M4 are both there, and that is not a coincidence: the owner path has three layers of protection (the Safe nonce, the quorum, and the Safe Transaction Service for observability) and the module path has none of them. Every INV-TIME and every AR deserves an explicit module-path variant, with the cases where the stated mitigation does not apply marked as such. M4 is exactly one of those cases, and it was found by asking that question rather than by reading the code.

**The timelock carve-outs are a cartesian product, not a list.** All four are analysed individually and analysed well. AR-27 is a composition: the exempt lane is harmless alone, and the nonce binding is sound alone, but together they make the defensive queue free to destroy. That is the work no tool does.

**The AR register's fidelity is now the risk.** The register is of unusual quality, which makes it dangerous: it will be used to classify findings as known. What matters is not the accuracy of each risk description, which is good, but the real executability of each stated mitigation. AR-19 is the proof: its description was accurate and its prescribed countermeasure was wrong for half the system. Each entry should carry either a PoC that pins its mitigation or an admission that the mitigation is untested.

Two areas are deliberately declared low-yield, so that effort is not burned there: the MultiSend recursion with its parameter bounds, and ERC-7913 verification, where OpenZeppelin does the work and the only interesting residual is already AR-18 with its PoC.

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
