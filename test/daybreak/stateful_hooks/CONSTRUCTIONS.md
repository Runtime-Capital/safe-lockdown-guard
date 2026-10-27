# Frozen construction ledger — stateful_hooks

Frozen during the blind phase on 2026-08-27, before reading prior PoCs, coverage, dispositions, assurance, specs, or existing test names.

## C1 — Owner ticket executes through an in-call lockdown transition (`KNOWN_OR_ACCEPTED`)

Prerequisites: A fully configured genuine Safe v1.5.0 with LockdownTimelock installed in all three slots, an active owner timelock, a scheduled owner transaction at its executable time, a registered EOA panic signer, and a callback-capable asset target holding a valid trigger signature.

Entry point: `Safe.execTransaction(token, 0, abi.encodeCall(HookedToken.transfer, (recipient, amount)), Call, 0, 0, 0, address(0), address(0), ownerSignature)`.

Exact state/calldata sequence: Normal → owner ticket scheduled for the exact Safe nonce and calldata → delay elapsed → Safe increments nonce and calls `checkTransaction` → hook verifies the owner ticket while Normal → Safe calls `token.transfer` → the token calls `LockdownTimelock.triggerLockdown(safe, reasonHash, abi.encodePacked(panicEOA), panicSignature)` before changing balances → token changes balances and returns success → Safe calls `checkAfterExecution(safeTxHash, true)`.

Expected guard interpretation: The pre-hook accepts the elapsed owner ticket in Normal; `triggerLockdown` changes the Safe to LockedDown; the post-hook consumes the owner ticket solely because `success == true`, without checking the new state.

Expected executor behavior: Genuine Safe commits the successful token call and then invokes the old guard’s post-hook.

Material effect sought: Assets leave the Safe after the Safe has entered LockedDown in the same call stack, and the authorization ticket is consumed.

Final disposition: The behavior is newly pinned but is an inherent entry-time/atomicity limitation, not an authorization escalation. The exact asset call was already owner-authorized and ticketed; omitting the nested trigger produces the same transfer, while reverting in the post-hook would atomically roll back both the transfer and the lockdown.

## C2 — Module ticket executes through an in-call lockdown transition (`KNOWN_OR_ACCEPTED`)

Prerequisites: A fully configured genuine Safe v1.5.0 with an enabled module, active timelock, an elapsed scheduled module ticket, a registered EOA panic signer, and a callback-capable asset target holding a valid trigger signature.

Entry point: From the enabled module, `Safe.execTransactionFromModule(token, 0, abi.encodeCall(HookedToken.transfer, (recipient, amount)), Call)`.

Exact state/calldata sequence: Normal → module ticket scheduled for `(safe,module,token,0,data,Call)` → delay elapsed → module pre-hook verifies and consumes the ticket → token calls `triggerLockdown` before changing balances → token changes balances and returns success → Safe calls `checkAfterModuleExecution(returnedHash, true)`.

Expected guard interpretation: The pre-hook accepts and consumes the ticket while Normal; the incident becomes LockedDown during execution; the successful post-hook leaves the ticket consumed without rechecking incident state.

Expected executor behavior: Genuine Safe reports module success and commits both the lockdown transition and token transfer.

Material effect sought: Module-authorized assets leave after the hard freeze begins, proving the pre-hook authorization spans an incident transition without rollback.

Final disposition: Same accepted atomicity boundary as C1. The exact module call was already scheduled and authorized, no unrelated transaction can interleave after the pre-hook, and the nested trigger grants no additional execution authority.

## C3 — Nested identical module call double-spends one ticket

Prerequisites: A fully configured genuine Safe v1.5.0, an active timelock, one elapsed module ticket, an enabled outer module, and a target that can invoke an enabled nested module before the outer post-hook.

Entry point: `Safe.execTransactionFromModule(target, 0, abi.encodeCall(ReentrantTarget.run, (...)), Call)` where `run` asks the nested enabled module to submit the exact same `(to,value,data,operation)` tuple to the same Safe before returning.

Exact state/calldata sequence: Outer pre-hook verifies and consumes ticket key K → outer target reenters `execTransactionFromModule` with the identical tuple → nested pre-hook computes K while the outer post-hook has not run → if accepted, both calls succeed from one ticket.

Expected guard interpretation: The nested pre-hook finds no ticket at K (already consumed by the outer pre-hook) and reverts `TicketNotFound`; if the target catches that revert, only the outer call can succeed. If the outer call fails, its post-hook re-creates K.

Expected executor behavior: Genuine Safe invokes pre-hook before each nested execution and cannot reach nested `execute` after the guard revert.

Material effect sought: Two asset transfers from one scheduled ticket; expected to be refuted by pre-hook consumption.

## C4 — Mid-flight post-hook injection clears or substitutes the module ticket

Prerequisites: A fully configured genuine Safe v1.5.0, active timelock, one elapsed module ticket, and an enabled module whose target attempts to make the Safe call the singleton during the outer execution.

Entry point: Outer `execTransactionFromModule(target,0,data,Call)` followed before its post-hook by a nested owner or module transaction with `to = address(guard)` and calldata `abi.encodeCall(LockdownTimelock.checkAfterModuleExecution, (attackerHash, false))`, then a second module execution using the original ticket.

Exact state/calldata sequence: Outer pre-hook stores K → nested Safe execution targets the singleton hook selector → attempted hook call would clear K regardless of `success` → attacker attempts a second module call before the original outer post-hook.

Expected guard interpretation: `_checkCall` recognizes all four guard-hook selectors for direct and MultiSend-nested calls and reverts `GuardHookSelfCallDenied` before execution; K remains set until the genuine post-hook.

Expected executor behavior: Genuine Safe cannot execute the nested singleton hook because its own guard pre-hook reverts the nested transaction.

Material effect sought: Clear K to evade reentrancy protection or substitute which ticket the genuine post-hook consumes; expected to be refuted.

## C5 — Cross-Safe hook confusion consumes another Safe’s ticket

Prerequisites: Two fully configured genuine Safe v1.5.0 proxies sharing the same LockdownTimelock singleton, each with an active timelock and an elapsed module ticket; Safe A’s target can trigger Safe B’s enabled module before Safe A’s post-hook.

Entry point: Module A calls `SafeA.execTransactionFromModule(targetA,0,dataA,Call)`; `targetA` calls module B, which calls `SafeB.execTransactionFromModule(targetB,0,dataB,Call)` before A returns.

Exact state/calldata sequence: Safe A pre-hook verifies and consumes KA in Safe A’s config → nested Safe B pre-hook verifies and consumes KB in Safe B’s config → B succeeds and its post-hook leaves KB consumed → A succeeds and its post-hook leaves KA consumed.

Expected guard interpretation: Ticket storage is keyed by Safe (`msg.sender`) and each hook receives its own relayed `moduleTxHash`; neither hook can read, consume or restore the other Safe’s ticket.

Expected executor behavior: Both genuine Safes complete independently in LIFO order.

Material effect sought: Consume Safe B’s authorization for an operation on Safe A; expected to be refuted by per-Safe ticket storage.

## C6 — Failed module execution preserves a ticket that a different execution later consumes

Prerequisites: A fully configured genuine Safe v1.5.0, active timelock, one elapsed module ticket for exact tuple T, and a target configurable to fail first and succeed later.

Entry point: The enabled module calls `Safe.execTransactionFromModule(to,value,data,operation)` twice with exact tuple T; the first target invocation reverts and the second succeeds.

Exact state/calldata sequence: First pre-hook verifies and consumes K → Safe catches inner failure → post-hook receives `success=false` and re-creates K with `executableAt = block.timestamp` → target behavior changes without changing T → second pre-hook verifies and consumes the same K → execution succeeds → third identical attempt is made.

Expected guard interpretation: Failure deliberately restores K for an exact-tuple retry; the successful retry consumes it; the third attempt reverts `TicketNotFound`. Module, Safe, target, value, data hash, and operation are all committed in K, preventing a different transaction from using it.

Expected executor behavior: Genuine Safe commits the first outer module call as a reported failure, then permits the exact retry, then cannot pass the third pre-hook.

Material effect sought: Reuse one ticket for two successes or consume it with a substituted operation; expected to be refuted except for the documented exact retry after failure.
