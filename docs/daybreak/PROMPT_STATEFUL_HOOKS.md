# Lane: stateful hooks and tickets

Read `docs/daybreak/PROMPT_COMMON.md` first and follow it as the controlling contract. Your assigned lane is `stateful_hooks`; write only under `test/daybreak/stateful_hooks/` and `/tmp/daybreak-lockdown/stateful_hooks/`.

Objective: Break authorization uniqueness, hook ordering, transient in-flight state, or per-Safe isolation across owner execution, module execution, callbacks, and incident transitions.

Prioritize these constructions:

- `checkTransaction` versus `checkAfterExecution` across inner success, inner failure, outer revert, post-hook failure, nonce movement, and retries.
- `checkModuleTransaction` versus `checkAfterModuleExecution`, including returned hash, computed ticket key, transient slot, success flag, and cleanup.
- Reentrant or nested module execution before the outer post-hook through a target, fallback handler, another module, another Safe, or nested Safe execution.
- Overwrite, clearing, substitution, or cross-Safe reuse of `_inFlightModuleTicket`.
- Owner/module ticket confusion, key-prefix collision, module substitution, Safe A/Safe B confusion, and shared-singleton callbacks.
- A ticket used twice, consumed by a different transaction, lost after failure, or made reachable by a state transition beyond an already documented cancel/sweep behavior.
- An operation validated in Normal or Recovering whose relevant state changes before the operation actually executes in the same atomic call.
- ERC-1271 freeze behavior when the incident state or handler context changes inside the same call stack.

Final proof requirements: connect every storage anomaly to asset movement, forbidden execution, authorization reuse, recovery bypass, ERC-1271 acceptance, or another material effect. Use genuine Safe v1.5.0 owner/module paths for final evidence.
