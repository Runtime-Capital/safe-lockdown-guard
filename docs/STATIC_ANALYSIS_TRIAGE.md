# Static Analysis Triage

> **Regenerated 2026-07-15 against the `chore/public-release-v1-readiness`
> candidate source tree.**
> Tooling: solc 0.8.35 / EVM `prague` / via-IR project profile;
> Slither 0.11.5, Aderyn 0.6.8, Semgrep 1.168.0. Re-runs with other tool
> versions may produce different finding sets - compare against these pins
> before treating drift as a regression.
> Static analysis is run locally and triaged here; CI runs
> build/lint/test/coverage only and does NOT re-run Slither/Aderyn/Semgrep.
> Slither and Semgrep report no high/medium findings. Aderyn 0.6.8 reports one
> high-severity detector class (three sites in one scheduler flow), triaged
> below as a false positive caused by `view` calls. There are **zero actionable
> high / medium findings** after triage.

This file is the audit-facing triage of static-analysis output. It exists so
reviewers do not spend time rediscovering known tool limitations or deliberate
design choices. It is not a substitute for manual review.

Regenerate with:

```bash
make slither
make aderyn
make semgrep
```

## Slither

Command:

```bash
slither . --compile-force-framework foundry \
  --filter-paths "test|script|lib" \
  --exclude timestamp,assembly,naming-convention \
  --fail-none
```

Current result: **7 low/informational results**, zero high/medium.

Slither also prints an internal IR-generation warning:

```text
Impossible to generate IR for LockdownTimelock._inFlightModuleTicket
(src/base/Timelock.sol#417-419): 'NoneType' object has no attribute 'parameters'
```

Triage: **tool limitation**. The affected helper derives an ERC-7201-style
transient-storage slot for the module timelock in-flight ticket. The behaviour
is covered by unit tests (`test_moduleHook_reentrantPreHookReverts_INV_TIME_11`,
`test_moduleHook_inFlightClearedOnFailure`, `test_postHook_crossSafeIsolation`)
and Echidna (`echidna_sweepClearsExpiredOwnerTicketSlot` / module-path invariants).

| Detector | Instances | Site | Triage |
|---|---:|---|---|
| `unused-return` | 2 | `LockdownFallbackHandler.isValidSignature` ignores the `secondsRemaining` half of `LOCKDOWN.getState(address(safe))`; `getModules` ignores the pagination cursor from `getModulesPaginated`. | **INTENTIONAL.** `isValidSignature` only needs the enum state to freeze ERC-1271 outside `Normal` / `Uninitialised`. `getModules()` preserves Safe v1.5.0 `CompatibilityFallbackHandler` behaviour and returns the first page of 10 modules. |
| `write-after-write` | 1 | `Lockdown._decodeCalldataBytes(bytes).output` in memory-safe assembly. | **FP.** The assembly writes the calldata pointer and length for a returned calldata slice. This is manual ABI decoding of `multiSend(bytes)` and is covered by decoder differential fuzz tests. |
| `calls-loop` | 1 | `_validateRecoveryOwner` calls `ISafe(safe).isOwner(owner)` inside the `initialize` recovery-owner loop. | **INTENTIONAL.** One-time per-Safe install, caller-bounded list, fail-fast atomicity desired. Prevents registering current Safe owners as recovery owners. |
| `redundant-statements` | 2 | `targetContract; calldataPayload;` inside `LockdownFallbackHandler.simulate`. | **INTENTIONAL / inherited.** Preserves Safe v1.5.0 `CompatibilityFallbackHandler` semantics and byte-shape except for the ERC-1271 lockdown gate. |
| `unused-state` | 1 | `Timelock.IN_FLIGHT_TICKET_BASE_SLOT`. | **FP.** The constant is used inside an internal transient-slot derivation pattern Slither fails to resolve after the IR warning above. |

## Aderyn

Command:

```bash
aderyn . -s src -o /tmp/safe-lockdown-aderyn.md
```

Current result: **1 high detector class (3 instances, false positive) and 8
low classes**.

### H-1 — State change after external call

Aderyn points to `safe_.nonce()`, `safe_.getTransactionHash(...)`, and
`safe_.checkSignatures(...)` before the scheduler writes
`ticketExecutableAt[ticketKey]`. All three functions are declared `external
view` in the pinned Safe v1.5.0 `ISafe` interface, so Solidity emits
`STATICCALL`. The static context also applies transitively to contract-owner
ERC-1271 signature checks: neither the Safe nor a signature verifier can mutate
state or re-enter the scheduler with a state-changing call. A revert aborts the
schedule before the ticket write.

The ordering is intentional: the scheduler must derive the Safe transaction
hash and validate the current quorum signatures before creating a ticket.
Duplicate-ticket rejection remains immediately before the write. The real-Safe
integration tests cover future nonces, multi-owner thresholds, pre-approved
hashes, and unchanged Safe nonce semantics.

**Triage: FALSE POSITIVE; no Solidity change.** Re-evaluate if any of these
interface methods becomes non-`view`, if scheduling accepts an arbitrary Safe
interface, or if signature validation leaves the static context.

| ID | Finding | Instances | Triage |
|---|---:|---:|---|
| L-1 | Costly operations inside loop | 2 | **INTENTIONAL.** `initialize` loops over initial recovery owners and signers. One-shot per Safe, caller-bounded, and atomic revert semantics are desired. |
| L-2 | Empty block | 3 | **INTENTIONAL.** Empty hook / uninitialised branch structure documents Safe guard lifecycle: fail-open before init, no-op base post-hook, no-op base module post-hook. `LockdownTimelock` adds timelock post-hook behaviour where needed. |
| L-3 | Literal instead of constant | 26 | **INTENTIONAL.** Most literals are wire-format offsets / exact calldata lengths for Safe storage slots, MultiSend packed items, recovery whitelist checks, and ABI selector lengths. Keeping them adjacent to parser comments is clearer than indirection. |
| L-4 | Modifier invoked only once | 2 | **INTENTIONAL.** State-gate modifiers name state-machine transitions and keep the code aligned with SPEC_V1 terminology. |
| L-5 | Redundant statement | 2 | **INTENTIONAL / inherited.** Same Safe handler `simulate` compatibility point as Slither. |
| L-6 | Loop contains `require`/`revert` | 3 | **INTENTIONAL.** Fail-fast install and MultiSend parser rejection are the security property. |
| L-7 | Unchecked return | 2 | **INTENTIONAL.** Both sites are low-level post-hook cleanup calls where failure must not corrupt Safe execution semantics; covered by post-hook tests. |
| L-8 | Public function not used internally | 4 | **INTENTIONAL.** Public getters / Safe handler API surface are external integration points. |

## Semgrep

Command:

```bash
make semgrep
```

Current result: **1 registry performance finding**, zero local Safe-guard
tripwire findings.

| Rule | Site | Triage |
|---|---|---|
| `solidity.performance.use-custom-error-not-require` | `src/handlers/LockdownFallbackHandler.sol:127` (`require(safe.signedMessages(messageHash) != 0, "Hash not approved")`) | **INTENTIONAL / inherited.** This is copied from Safe v1.5.0 `CompatibilityFallbackHandler`. Replacing it with a custom error would save gas but increase the diff from the canonical handler. The current V1 posture prefers a minimal, auditable delta: the lockdown gate at the top of `isValidSignature`. |

## Net Result

- No remaining static-analysis finding currently requires a Solidity change.
- Aderyn's raw report contains one high detector class; it must be reported as
  the triaged STATICCALL false positive above, not described as a clean raw run.
- The only Semgrep finding is a conscious Safe-compatibility trade-off.
- If `LockdownFallbackHandler` stops being treated as a near-verbatim Safe
  handler in a future version, revisit the string `require` and redundant
  `simulate` statements together.
