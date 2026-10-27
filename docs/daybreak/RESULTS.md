# Daybreak adversarial audit results

## Decision

Do not block `v1.0.0-audit-candidate.3` on this pass. The three focused workers found no new code-level exploit, parser/executor mismatch, authorization reuse, recovery bypass, or incident-time privilege escalation. The pass produced one new low-severity operational liveness hazard for a supported ERC-1271 configuration and confirmed one inherent transaction-atomicity limitation that does not grant an attacker additional authority.

## Baseline and execution

- Audit candidate: `v1.0.0-audit-candidate.3` at `6b85a4c2bae4c98bdf8a143bd4fdfa44d70498a7`.
- Review checkout: `1c0dd00651383b0332bafec54e39de0c083839e6`.
- Before worker writes, `src`, `lib`, `test`, `foundry.toml`, and `remappings.txt` were identical between the candidate tag and the review checkout.
- Three independent Daybreak Blue workers covered parser/executor behavior, stateful hooks/tickets, and supported verifier liveness. Each froze exactly six constructions and implemented at most two proofs.
- Full verification: `forge test` completed with 489 passed, 0 failed, and 0 skipped.

## Finding DB-01: correlated ERC-1271 Safe signer loses panic liveness

Severity: Low, operational configuration hazard.

Disposition: New and proved, but not a production-code exploit.

A fully installed Lockdown Safe can be registered as another Safe's supported 20-byte ERC-1271 lockdown identity and pass the exact `testSigner` preflight while both Safes are Normal. If the signer Safe then enters LockedDown or Recovering, its `LockdownFallbackHandler` intentionally freezes ERC-1271 validation. A signature created before that incident is rejected, so the target Safe cannot enter lockdown through that identity and remains Normal.

Prerequisites: the target uses a Lockdown-protected Safe as a native ERC-1271 panic identity; that signer Safe enters an incident; and the target has no independent working panic identity. No hostile verifier, partial installation, or compromised target quorum is required.

Impact: correlated incidents can remove the target's only panic path precisely when it may be needed. This is a dependency/configuration failure, not an authorization bypass, and follows from the intended ERC-1271 freeze on the signer Safe.

Recommendation: do not use a Lockdown-protected Safe as the sole lockdown identity of another Safe. Installation and drill tooling should warn on this topology and require at least one independent EOA or shipped WebAuthn identity in a different failure domain. The audit candidate need not change if this rule is made an explicit operator obligation.

Evidence: `test/daybreak/supported_liveness/SupportedLiveness.t.sol::test_limitation_nativeSafeSignerPassesNormalButCannotTriggerWhileSignerSafeIsLockedOrRecovering` passes on genuine Safe v1.5.0 proxies with the production singleton and fallback handler.

Reproduction: `forge test --match-path test/daybreak/supported_liveness/SupportedLiveness.t.sol -vv`.

## Observation DB-02: lockdown activated inside an approved execution does not stop later effects in the same transaction

Severity: Informational, inherent atomicity limitation.

Disposition: Proved behavior, rejected as an exploitable finding.

Both the genuine MultiSend and direct-call proofs show that the pre-hook can approve a transaction in Normal, after which a callback calls `triggerLockdown` and later instructions in the same EVM transaction move assets. Timelock post-hooks then consume a successful owner or module ticket without rechecking the incident state.

This does not add attacker authority: the exact transfer was already authorized by the Safe quorum or module and succeeds if the callback simply omits `triggerLockdown`. An independent panic transaction mined before the Safe execution still blocks it. No unrelated transaction can interleave after the pre-hook, and a post-hook revert would atomically roll back both the asset movement and the lockdown itself. The meaningful guarantee is therefore entry-time blocking, not retroactive interruption of an already executing EVM transaction.

Recommendation: document that LockedDown blocks new Safe executions whose hooks begin after the transition, but cannot interrupt a call tree already executing in the transaction that creates the transition. Do not add a post-hook state check solely for this case.

Evidence: the parser worker proved a real Safe v1.5.0 plus genuine `MultiSendCallOnly` lock-then-transfer sequence; the stateful worker independently proved the same root on elapsed owner and module tickets.

Reproduction: `forge test --match-path test/daybreak/parser_executor/ParserExecutorDaybreak.t.sol -vv` and `forge test --match-path test/daybreak/stateful_hooks/InCallIncidentTransition.t.sol -vv`.

## High-ROI negative results

- Parser/executor: zero-offset ABI aliasing decoded identically; near-`2^256` offsets and lengths were rejected by subtraction bounds; packed MultiSend overlap was rejected by remaining-length validation; nested operation 1 was already known and atomically rejected by genuine `MultiSendCallOnly`.
- Stateful hooks: the transient module lock rejected nested identical execution; guard-hook selector injection was denied; per-Safe transient/storage isolation held; failure/retry behavior matched the documented exact-retry semantics.
- Supported liveness: the shipped WebAuthn flat tuple passed direct verification, exact singleton preflight, and a real Safe trigger; arbitrary-hash preflight, PasswordVerifier reason substitution, the 20/21-byte identity split, and P-256 environment behavior were known, accepted, or refuted.

## Final action

Keep the candidate tag unchanged. Before release, add DB-01 and DB-02 to the operator-facing limitations/runbook and make independent panic-identity redundancy a deployment check. Archive the construction ledgers and executable tests as audit evidence.
