# Lockdown V1 Independent Review Brief

This document orients an independent reviewer of the V1 `Lockdown` Safe v1.5.0 guard. Read it alongside the V1 diff.

## Scope of the review

The objective is to find real bugs, divergences from the spec, paths that move value during lockdown/recovery, paths that let one Safe's state affect another, and EIP-7913 / EIP-712 integration mistakes.

Output format:

1. **Critical / High** - bugs that move funds or break a load-bearing invariant.
2. **Medium** - spec divergences, subtle griefing paths, missing checks.
3. **Low / Informational** - style, nit, doc fix.
4. **Verified** - properties you independently checked and believe to hold (one line each).
5. **Open questions** - anything you can't resolve.

Be specific about line numbers. If you can't reproduce a finding, say so.
Before reporting a missing mitigation, check `docs/V1_NON_GOALS.md`: it records
out-of-scope and deliberately rejected hardening options, including rejected
on-chain fallback-handler codehash pinning and full ABI parsing in guard hooks.

## Code under review

V1 commits on branch `main` (in order; the V1 audit-hardening round includes the timelock layer, C1 refund-gate and C4 burnt-keys / INV-SIGN-7 fixes, and the H.18 PasswordVerifier production framing):

Initial V1 baseline:

- `a897fa2` docs(v1): introduce singleton + EIP-7913 verifier design (SPEC_V1)
- `5a6d60d` feat(v1): add EIP-7913 verifier interface + ECDSA / Password verifiers
- `d2f1cfe` feat(v1): rewrite src/Lockdown.sol as EIP-7913 singleton
- `967d5f1` test(v1): full unit + fuzz suite for V1 Lockdown.sol
- `b0de9a2` test(v1): port Echidna stateful harness to V1 ABI
- `4a1507d` feat(v1): V1 ops scripts (preflight + verify)

Integrated V1 hardening layer (committed on `main`, see note below):

- schedule / cancel / bypass / sweep timelock layer with per-Safe `timelockDelay`, `timelockBypassers[caller]`, `ownerTickets`, `moduleTickets`, 90-day `TICKET_TTL`, permissionless sweep
- C1 refund-zero gate on the `_isTimelockBypassedSelfCall` short-circuit (`TimelockBypassRefundDenied`)
- C4 + review round 1 permanent burnt-keys set (INV-SIGN-7, `keyBurntPermanently` per-Safe, `KeyAlreadyBurntPermanently` revert on re-add, view `isKeyBurntPermanently`)
- H.18 reintroduces `PasswordVerifier` as tier-2 production with explicit threat model + operator obligations + post-revert-before-burn runbook
- review round 2 adds the T-BYPASS-8 (forced burn via bypass) and T-PWD-LEAK-BEFORE-BURN named threats and the SPEC §6.4 / §H.11 documentation of `getSignersByIdRange`
- Echidna invariants extended to 17 (added `bypassRejectedDuringIncident`, `sweepClearsExpiredOwnerTicketSlot`, `disarmGatedByTimelock` (INV-LIVE-1), `lockdownCoversTimelock` (INV-LIVE-3))
- later hardening rounds add H.19 recovery-owner validation (SaferSafes-derived, registration-time + hook-time `isOwner` checks), the OZ-backed `WebAuthnVerifier` tier-3 candidate, and the uninstall/reinstall stale-state persistence pins

**Note on the model (read before the changelog above)**: the chronological list above predates later changes that are ALSO on `main` and ARE in scope: (1) the 2026-06-25 ERC-7913 bytes-identity refactor, which removed the id model - so the historical bullets' `keyBurntPermanently` / `KeyAlreadyBurntPermanently` / `isKeyBurntPermanently` are now `signerBurntPermanently` / `LockdownSigners_BurntPermanently` / `isSignerBurntPermanently`, and `getSignerById` / `getSignersByIdRange` / the local `ECDSAVerifier` were removed (20-byte identities verify natively via OZ `SignatureChecker`); (2) the state-machine and transient-storage cleanups; and (3) the split into `Lockdown` (lockdown-only base) and `LockdownTimelock` (production singleton with timelock). The current Echidna harness has **15** stateful invariants, not 17. Review against `src/LockdownTimelock.sol`, `src/Lockdown.sol`, the component mixins, and the aligned `specs/SPEC_V1.md` §1-§13.

**Note on review target**: review only the exact release-candidate commit SHA
provided in the audit handoff. A floating branch, tag that can move, or
uncommitted working-tree state is never the audit target. Record the SHA in the
report and re-confirm it after remediation.

Primary files:

- `src/LockdownTimelock.sol` - the V1 production singleton contract.
- `src/Lockdown.sol` - concrete lockdown-only base inherited by
  `LockdownTimelock`.
- `src/base/LockdownSigners.sol` and
  `src/base/RecoveryOwners.sol` - signer and recovery-owner set mixins.
- `src/base/Erc1271Policy.sol` - per-Safe ERC-1271 opt-in flag (H.27).
- `@openzeppelin/contracts/interfaces/IERC7913.sol` - ERC-7913
  verifier interface; returns `bytes4` magic value `0x024ad318`.
- The secp256k1 panic identity is the native 20-byte EOA / ERC-1271 signer,
  validated by OZ `SignatureChecker`; there is no separate `ECDSAVerifier`
  contract (the local verifier was removed in the bytes-identity refactor).
- `src/verifiers/PasswordVerifier.sol` - cleartext-password verifier,
  tier-2 production with documented mempool-leak trade-offs (H.18).
- `src/verifiers/WebAuthnVerifier.sol` - passkey verifier, thin wrapper over
  OZ WebAuthn/P256; tier-3 candidate in audit scope, not yet
  production-approved.
- `test/mocks/MockSecretVerifier.sol` - test-only preimage-of-commitment
  verifier; production-forbidden; exercises the non-ECDSA dispatch path
  in unit and fuzz tests.
- `test/Lockdown.t.sol` - 203 core V1 unit + fuzz tests (incl. INV-SIGN-7 burnt-identity + replay-after-burn-and-reregister + F-M2-01 phantom-recovery closure + MultiSend parser/fallback-handler checks + H.19 recovery-owner validation + uninstall/reinstall persistence pins).
- `test/LockdownTimelock.t.sol` - 96 V1 timelock + bypasser + sweep + refund-gate + DELEGATE-bundle + post-hook-INV-TIME-4 + INV-TIME-11 reentrancy-guard + INV-LIVE-1 liveness + INV-LIVE-3 duration-floor + stale-ticket-reinstall tests.
- `test/fuzz/DecoderDifferentialTest.t.sol` - 5 focused tests for non-canonical `multiSend(bytes)` calldata decoding and hidden fallback-handler swaps.
- `test/integration/SafeIntegration.t.sol` - 32 real-Safe integration tests exercising the owner path, module path, timelock, scheduleTransaction future nonce + multi-owner threshold, and ERC-1271 fallback-handler freeze over a genuine Safe v1.5.0 deployment via `SafeProxyFactory`.
- `test/verifiers/` - 10 PasswordVerifier + 10 WebAuthnVerifier + 2 captured-device WebAuthn fixtures = 22 (no separate ECDSA-verifier suite; the secp256k1 path is the native EOA identity tested in `test/Lockdown.t.sol`).
- `test/mocks/MockAdversarialVerifiers.sol` - seven adversarial verifier mocks: `MockRevertingVerifier`, `MockWrongMagicVerifier`, `MockEmptyReturnVerifier`, `MockAlwaysMagicVerifier`, `MockSelectiveMagicVerifier`, `MockSelectiveRevertingVerifier`, `MockToggleVerifier` (stateful reject-then-accept toggle; pins that a failed trigger attempt leaves no burnt-signer state behind). They exercise the trigger-time STATICCALL revert normalisation and magic-value comparison: a misbehaving verifier registered for a Safe must normalise to `BadSignature()` at trigger time rather than authorise a lockdown.
- `test/echidna/EchidnaLockdown.sol` - stateful harness (16 invariants, `vm.warp`-driven time advancement; hardening includes `resumeDelayCannotReopenIncident` (INV-LIFE-1 / F-M2-01), `bypassRejectedDuringIncident`, `sweepClearsExpiredOwnerTicketSlot`, `disarmGatedByTimelock` (INV-LIVE-1), `lockdownCoversTimelock` (INV-LIVE-3), and `moduleTicketSingleUse` (INV-TIME-4 / NM-1060 6.6)).
- `docs/V1_USER_SCENARIOS.md` - operator-facing walk-through of every supported user scenario, organised by lifecycle phase. Read this before the spec if you want the "what" before the "why".
- `specs/SPEC_V1.md` - the spec the implementation must satisfy. Pay particular attention to the bottom **Hardening log** (§H.1-H.29): it lists every behavioural change made in response to prior reviews and is what should be matched against the code. H.18 covers the `PasswordVerifier` production framing; H.19 covers recovery-owner validation; H.20 covers the module-path handling correction; H.21 covers prospective `resumeDelay` updates and elapsed-incident cleanup; H.22 covers verify-before-burn ordering and the pinned-verifier trust boundary. The timelock layer, INV-TIME-1..11, INV-SIGN-7 burnt-keys set, and the T-BYPASS-1..8 / T-PWD-* threat models live in the timelock sub-section earlier in the spec.

Build: `forge build` (solc 0.8.35, evm prague, optimizer 200, via_ir), then
`scripts/contract-sizes.sh` for artifact-derived runtime sizes. In this build
setup, `forge build --sizes` can omit the production `Lockdown` /
`LockdownTimelock` artifacts.
Run tests: `forge test`. Expected: **601 passed** (203 Lockdown + 96 Timelock + 5 decoder differential fuzz + 32 real-Safe integration + 10 PasswordVerifier + 10 WebAuthnVerifier + 2 captured-device WebAuthn fixtures, generated, + 237 adversarial PoCs + 6 focused Daybreak proofs).

## Context in one paragraph

Lockdown authority is exclusively the explicit per-Safe `signers` set of ERC-7913 identity `bytes` (either a 20-byte EOA / ERC-1271 address, or `verifier || key`). Each signer is single-use: a successful `triggerLockdown` removes it from the set AND marks it permanently burnt (`signerBurntPermanently`, INV-SIGN-7), so it can never be re-registered. The signed message is bound via EIP-712 to `(safe, signer, reasonHash)`: the `signer` field stops a signature for one identity being replayed through another identity that wraps the same key (external audit NM-1060, SPEC_V1 §H.23), and replay across burn/re-register cycles is prevented by the permanent burnt-identity register, not by a counter in the message. Trust is attached to each registered identity: a lockdown is authorised iff that exact identity is a member of the Safe's `signers` set AND OZ `SignatureChecker.isValidSignatureNow(signer, hash, sig)` validates the signature. There is no verifier-class approval bit; registration is the only on-chain authorisation and is Safe-quorum-gated. Registration sanity (`_validateSigner`: length >= 20; a 20-byte identity != `address(0)`; for a longer identity the leading-20-byte verifier must have code and the trailing key must be <= `MAX_KEY_LENGTH`) is the only registration-time check. For an ERC-7913 identity the verifier dispatch is a STATICCALL inside `SignatureChecker` whose success criterion is the magic `0x024ad318`; a compromised verifier is handled by removing the affected identities via per-signer `removeLockdownSigner` (batchable via MultiSend); in-Recovering `removeLockdownSigner` is whitelisted to neutralise post-resume relock races; module-path calls to the singleton are rejected unconditionally. Signer enumeration is provided directly by the set via `getLockdownSigners(safe)`; there is no id-indexed reverse map.

## Spec (must read before code)

`specs/SPEC_V1.md` is the contract for the implementation. Pay close attention to:

- §2 (12 locked-in architectural decisions)
- §3 (state layout, including the per-Safe `signers` `EnumerableSet.BytesSet` and the `signerBurntPermanently` register)
- §5 (authorisation model + EIP-712 message hash + replay analysis table + `SignatureChecker` dispatch)
- §6.4 (views: `getLockdownSigners`, `isLockdownSigner`, `isSignerBurntPermanently`, `getConfigSnapshot`, `getState` semantics, and `hashLockdownTrigger`, the single source of the trigger digest)
- §7.4 (recovery whitelist with `removeLockdownSigner` carve-out, see Hardening §H.4)
- §11 (invariants: INV-ISO, INV-AUTH, INV-LIFE, INV-SIGN-1..3 + INV-SIGN-7 (INV-SIGN-4..6 are obsolete with the id model), INV-VER-1..3, INV-REC, INV-MS, INV-DOM)
- §H.1-H.29 (Hardening log: every behavioural change from prior reviews, with rationale and what to verify, including: H.12 pre-init module-path denial, H.13 off-chain key-shape preflight after removing the local validator extension, H.15 `SafeDormant` on every count→0 transition, H.16 `signer` identity in `SafeLockedDown`, H.17 `testSigner` drill view (since removed in favour of the off-chain `script/DrillSigner.s.sol`), H.18 `PasswordVerifier` reintroduced as tier-2 production, H.19 recovery-owner validation at registration and hook time, H.20 module-path handling, H.21 F-M2-01 elapsed-incident cleanup, H.22 verify-before-burn ordering, H.23 signer identity bound in the trigger message (external audit NM-1060), H.24 re-triggers stack on the active lockdown window, H.25 on-chain drill view removed in favour of off-chain drills (external audit NM-1060), H.26 module tickets consumed in the pre-hook and restored on failure (external audit NM-1060 6.6), H.28 module-to-owner escalation kept as a documented residual (external audit NM-1060 6.2), H.29 single trigger-digest source `hashLockdownTrigger` shared by the trigger and the off-chain drill)
- Timelock section preceding the hardening log: schedule/cancel/bypass/sweep, INV-TIME-1..11, INV-SIGN-7 burnt-keys, T-BYPASS-1..8, T-PWD-REPLAY / T-PWD-LEAK-BEFORE-BURN / T-PWD-MEMPOOL
- §14 (out of scope / accepted risks, including the post-resume cleanup window and the buggy-verifier grief surface)

## What to spend disproportionate time on

1. **Cross-key isolation (INV-ISO-1)** extended to V1 state: the per-Safe `signers` set, the `signerBurntPermanently` register, and the config scalars. Storage layout walk: confirm every write derives its slot from `msg.sender` (admin paths) or the `safe` parameter (lockdown / views).

2. **EIP-7913 verifier external dispatch** (Hardening §H.1, §H.9, L.3). For a `verifier || key` identity the trigger validates the signature through OZ `SignatureChecker.isValidSignatureNow`, which dispatches into attacker-controlled verifier bytecode via a **low-level STATICCALL** and compares the return against the magic `0x024ad318` (= `IERC7913SignatureVerifier.verify.selector`). Confirm:
   - Signature validation runs inline (`SignatureChecker.isValidSignatureNow`) BEFORE any signer mutation. After it succeeds, the burn (removal from `signers` + `signerBurntPermanently = true`, via `_removeLockdownSigner`) happens before the state change (`lockdownUntil` set); any later revert rolls the whole sequence back.
   - A verifier revert (with ANY data) is normalised to a `false` result (hence `BadSignature()`), NOT bubbled.
   - A short or zero-length return is `false` / `BadSignature()`.
   - A non-magic return (e.g. `bytes4(0)`, `0xDEADBEEF`) is `false` / `BadSignature()`.
   - The dispatch is STATICCALL, not CALL — a malicious verifier cannot mutate Lockdown state during the call.

3. **Single-use burn correctness (INV-SIGN-1 + INV-SIGN-7)**. Confirm `triggerLockdown` checks registration, verifies the signature inline, then removes the identity from `cfg.signers` AND sets `cfg.signerBurntPermanently[signer]` through the shared `_removeLockdownSigner` helper before `cfg.lockdownUntil` is set. Failed verification must perform no signer mutation; any later revert must roll the sequence back. Confirm `cfg.signers.length()` (the `EnumerableSet.BytesSet` count) is the only signer counter, so no separate counter can desync from the set. Confirm a burnt identity can never be re-registered (`LockdownSigners_BurntPermanently`).

4. **EIP-712 typehash and domain separator**. Confirm:
   - The typehash string is `"Lockdown(address safe,bytes signer,bytes32 reasonHash)"` (exact spacing), with `signer` encoded as `keccak256(signer)` per EIP-712. The `signer` field binds the signature to the submitted identity (no cross-identity replay); there is no counter field — replay safety across re-registrations comes from the single-use burn + the permanent burnt-identity register.
   - The domain separator is bound to name `"RuntimeLockdown"` and `block.chainid` (via OZ `EIP712`).
   - A fork of the chain breaks signatures (intentional anti-cross-chain replay).

5. **Signer registration sanity** (INV-VER-1..3). There is no verifier-class approval bit. The only registration-time check (in `initialize`, `addLockdownSigner`, `rotateLockdownSigner`) is `_validateSigner(signer)`:
   - `signer.length >= 20` (else `LockdownSigners_InvalidFormat`).
   - a 20-byte identity must not equal `address(0)` (else `LockdownSigners_ZeroAddress`).
   - a longer (`verifier || key`) identity: the leading-20-byte verifier must have code (else `LockdownSigners_VerifierNoCode`), and the trailing key must be `<= MAX_KEY_LENGTH` (else `LockdownSigners_KeyTooLong`).
   Confirm INV-VER-1: registration reverts for a too-short identity, a 20-byte `address(0)`, a zero-code verifier, or an over-length key. Note a plain 20-byte EOA / ERC-1271 identity (no key) is valid.
   Confirm INV-VER-2: the only on-chain authorisation for an identity is its membership in `_configs[safe].signers` (the bytes-identity set); there is no verifier-class approval bit.
   Confirm INV-VER-3: a successful `removeLockdownSigner` neutralises exactly one identity and marks it permanently burnt for that Safe (`signerBurntPermanently`).

6. **Recovery whitelist** (§7.4, INV-LIFE-3..4, INV-REC, Hardening §H.4, §H.5, §H.19). Confirm the only owner-path self-call to the singleton accepted during Recovering is `removeLockdownSigner(...)` (any-length data; the function re-validates). The only Safe-targeted transactions accepted are the empty self-call (nonce burn), the exact-length `swapOwner` to an allowlisted recovery owner that is not already a current owner (H.19 hook-time re-check), and the exact-length (`0x44`) `disableModule`. No `add`, `rotate`, or scalar setter may pass, and there is no resume call (return to Normal is time-based auto-resume). Module-path calls to the singleton are rejected in EVERY state by `ModuleCallToSingletonDenied` (H.5).

7. **`initialize` initial signers flow**. Confirm:
   - If any of the loops revert, the entire transaction reverts (atomic).
   - Registration sanity fires inside the initial-signers loop too — an initial signer with a zero-code or zero-address verifier, or an out-of-range key length, must revert the whole `initialize`.
   - `cfg.signers.length()` after init equals `initialSigners.length` (there is no separate `signersCount` or `nextSignerId`).
   - `SafeDormant(safe)` event fires iff `initialSigners.length == 0` (H.8).

8. **MultiSend parser**. Confirm `_checkCall` recurses into nested
   `MultiSendCallOnly` delegatecalls and that, at every depth, (a) no
   `DELEGATECALL` to a non-`MultiSendCallOnly` target passes and (b) every
   `setFallbackHandler` self-call binds a `LockdownFallbackHandler` whose
   `LOCKDOWN()` is this singleton. Inner `CALL`s to the Safe, singleton, or
   `address(0)` are intentionally allowed; the outer scheduled Safe
   transaction hash is the timelock review object.

## What is intentionally out of scope

- Direct owner `approveHash(bytes32)` calls outside `execTransaction` (Safe v1.5.0 limitation; watchers handle it off-chain).
- 1-of-N griefing lockdown by any registered signer. Accepted by design.
- Privacy: a one-line `eth_getLogs` over the singleton enumerates every protected Safe. Accepted in exchange for singleton UX.
- "Selectively malicious" verifier that returns non-magic on empty but magic on real input. There is no on-chain behavioural vetting that catches this class. Mitigation is per-signer `removeLockdownSigner` (batchable via MultiSend), allowed in-recovery via H.4. Documented as accepted risk in §14.
- WebAuthn production approval deferred. `src/verifiers/WebAuthnVerifier.sol` ships as a tier-3 candidate (thin wrapper over OZ WebAuthn/P256, in audit scope), but it is not production-approved until clientDataJSON parsing has been fuzzed against real multi-vendor assertions.
- No `cancelLockdown`. False positives wait `lockdownDuration + resumeDelay`.
- Post-resume zero-signer window: the Safe quorum is responsible for re-registering signers immediately after resume. The recovery whitelist does NOT include `addLockdownSigner` (to prevent pre-signed addition attacks during coercion). The brief unprotected window is documented and accepted.
- Hardware-wallet display quality for the more complex V1 calldata (4 params, two dynamic `bytes`; the EIP-712 message has 2 fields). `docs/V1_HARDWARE_WALLET_UX.md` and `docs/clear-signing/` are the operator-facing companions.

## Things you should NOT spend time on

- Style or naming nits in `specs/SPEC_V1.md`.
- Solidity stylistic preferences unless they hide a bug.
- Suggesting upgrades to OpenZeppelin's `Ownable`, `AccessControl`, etc. The contract is self-contained by design.
- Suggesting a proxy / upgradeability pattern. Rejected in §2 #9.
- Suggesting an emergency owner or pauser. Rejected in §14 and the project design notes.

## Specific red flags to grep for

If you find any of these, escalate:

- A write to `_configs[X]` where `X` is neither `msg.sender` nor the `safe` parameter of `triggerLockdown` / views.
- A path where a `gasPrice > 0` or non-zero `refundReceiver` reaches `handlePayment` from a recovery-whitelisted transaction.
- A path where `_checkCall` accepts an inner `DELEGATECALL` to anything except
  the canonical `MultiSendCallOnly`, or accepts a `setFallbackHandler` self-call
  whose handler is not bound back to this singleton.
- A `triggerLockdown` message hash that encodes anything other than `(safe, keccak256(signer), reasonHash)` under `LOCKDOWN_TYPEHASH` — `signer` must be the exact identity bytes passed to `triggerLockdown`, and no counter or other caller-supplied field belongs in the digest.
- A `triggerLockdown` path that mutates `cfg.lockdownUntil` BEFORE the identity is removed from `cfg.signers` / `cfg.signerBurntPermanently[signer]` is set (the burn must precede the state change).
- A burn path that removes from `cfg.signers` but fails to set `cfg.signerBurntPermanently[signer]` (or vice-versa), which would let a burnt identity be re-registered. (INV-SIGN-7.)
- A `triggerLockdown` path that bubbles arbitrary verifier revert data instead of normalising to `BadSignature()`. The dispatch must be the low-level STATICCALL inside OZ `SignatureChecker.isValidSignatureNow`; the success criterion is the magic value `0x024ad318`, not "any non-zero return".
- A registration path (`initialize`, `addLockdownSigner`, `rotateLockdownSigner`) that accepts a too-short identity, a 20-byte `address(0)`, a `verifier || key` identity whose verifier has no code, or a key `> MAX_KEY_LENGTH`. `_validateSigner` is the only registration-time sanity check (INV-VER-1); missing or weakened checks are the bug class.
- An admin setter that succeeds before `initialize` (it must revert `InvalidState` via `onlyNormal`, which excludes the Uninitialised state).
- A way for the recovery-owner allowlist (`getRecoveryOwners(safe).length`) to fall to zero post-init.
- A way to re-initialise a config after it has been initialised once.
- An `addLockdownSigner` (or the add half of `rotateLockdownSigner`) that does NOT reject an already-burnt identity with `LockdownSigners_BurntPermanently`; the burn flag is never cleared (INV-SIGN-7).
- A way for `cfg.signers.length()` to exceed `MAX_LOCKDOWN_SIGNERS = 32`.
- A remove path that does not revert `LockdownSigners_Unknown` when the identity is absent (the `EnumerableSet` length cannot underflow, but removal of a non-member must still revert).
- A path where `checkModuleTransaction` accepts a call with `to == address(this)` (the singleton) - the H.5 / H.12 hardening rejects all such calls with `ModuleCallToSingletonDenied`. **H.12 specifically**: the denial MUST precede the uninitialised fail-open `return`, so the rejection holds even before `initialize` has been called (otherwise an enabled malicious module on a pre-init Safe can call `initialize(...)` with attacker-chosen recovery owners / verifiers / signers).
- A `removeLockdownSigner` or burn-on-trigger path that empties `cfg.signers` to zero WITHOUT emitting `SafeDormant(safe)`. H.15 makes the dormancy signal mandatory on every transition; only the transient zero inside `rotateLockdownSigner` is intentionally silent.
- A `SafeLockedDown` emit that omits or zeros out the trailing `signer` identity (H.16). Must equal the burnt identity bytes, captured BEFORE the entry is removed from `cfg.signers`.
- Any on-chain path that verifies a trigger signature WITHOUT burning the signer (a drill / dry-run view or a backdoor trigger). There is deliberately none: a trigger signature is a bearer credential, so a public verification view would invite operators to expose valid signatures over RPC. Drills are off-chain (`script/DrillSigner.s.sol` on a local fork; the lifecycle UI's local verification).
- A `_isRecoveryCall` decision that accepts something other than: empty Safe self-call (nonce burn); exact-length `swapOwner` to an allowlisted recovery owner that is not already a current owner (H.19); exact-length (`0x44`) `disableModule` Safe self-call; `removeLockdownSigner(...)` self-call to the singleton.
- Inside the native ECDSA path (OZ `SignatureChecker` / `ECDSA`): any acceptance of `v` other than 27 or 28, or of high-s. OpenZeppelin rejects both, so a malformed signature must normalise to `BadSignature()`, never authorise a trigger.

## Tests

`forge test` runs 601 tests:

- 203 unit + fuzz tests in `test/Lockdown.t.sol`, organised by section: ERC-165 + VERSION, constructor + EIP-712 domain / LOCKDOWN_TYPEHASH, initialize (including install completeness, `SafeDormant`, and registration-sanity rejection), add/remove/rotate lockdown signer, trigger lockdown, `SafeDormant`, absence of an on-chain drill view + the off-chain drill script, native ECDSA / ERC-1271 / ERC-7913 identity paths, cross-key isolation, fail-open uninit, recovery whitelist tightening, admin during incident, automatic return to Normal (including F-M2-01 delay-update closure), normal-mode owner path, recursive MultiSend parser, state getter, uninitialised-config gates, `ModuleCallToSingletonDenied`, `swapOwner` exact-length, H.19 recovery-owner validation, signer enumeration / per-Safe isolation, adversarial verifier normalisation, and uninstall/reinstall persistence pins.
- 96 V1 tests in `test/LockdownTimelock.t.sol`: schedule / cancel / bypass / sweep, module schedule/cancel, refund gate, DELEGATE-bundle parsing, INV-TIME-4 success-gated ticket consumption, INV-TIME-11 module reentrancy guard, INV-LIVE-1 / INV-LIVE-3 liveness, stale-ticket semantics across guard uninstall/reinstall, and exact owner-cancel calldata length.
- 5 focused decoder differential tests in `test/fuzz/DecoderDifferentialTest.t.sol`.
- 32 real-Safe integration tests in `test/integration/SafeIntegration.t.sol`: owner-path install + execute, module-path guard hooks via a real enabled module, owner-path/module-path timelock, scheduleTransaction future nonce + multi-owner threshold, both HSM-bypass forms, and ERC-1271 fallback-handler freeze/unfreeze over a genuine Safe v1.5.0 deployment.
- 10 tests in `test/verifiers/PasswordVerifier.t.sol`, 10 tests in `test/verifiers/WebAuthnVerifier.t.sol` (OZ WebAuthn/P256 wrapper exercised with a real secp256r1 fixture), and 2 generated captured-device WebAuthn fixture tests in `test/verifiers/WebAuthnCapturedFixtures.generated.t.sol`. There is no separate ECDSA-verifier suite: the secp256k1 path is the native 20-byte EOA identity exercised through `test/Lockdown.t.sol`.
- 237 executable adversarial proofs across the 21 files in `test/poc/`, including owner-ticket revival, recovery-envelope boundaries, timelock accounting, verifier trust-boundary behaviour, verify-before-burn ordering and guard/executor calldata-decoder agreement.

The cross-key isolation section and the replay-after-burn-and-reregister test (`test_signatureCannotReplayAfterBurnAndReRegister`) are V1-specific and are the place to start when checking the singleton's central novelty.

The Echidna harness (`test/echidna/EchidnaLockdown.sol`) runs separately via:

```bash
make echidna
```

The Make target pins the container digest and the required `crytic-compile`
compatibility override.

It targets these invariants: `signersCountAtMost32`, `noOwnerPathDuringLockdown`, `noModulePathDuringRecovery`, `allowlistCountNeverZero` (recovery-owner allowlist), `safeBNeverLockedDown`, `safeBConfigUntouched`, `modulePathCannotReachSingleton`, `burntSignerNeverResurrects`, `removedSelectiveMagicSignerCannotTrigger` (using `MockSelectiveMagicVerifier`; an explicitly removed signer under a selective-magic verifier cannot trigger), `recoveryAdminSelectorsRejected`, `resumeDelayCannotReopenIncident` (INV-LIFE-1 / F-M2-01), `bypassRejectedDuringIncident` (INV-TIME-7), `sweepClearsExpiredOwnerTicketSlot` (INV-TIME-8), `disarmGatedByTimelock` (INV-LIVE-1), `lockdownCoversTimelock` (INV-LIVE-3), and `moduleTicketSingleUse` (INV-TIME-4 / NM-1060 6.6). Time advancement (`vm.warp`) is wired so the harness reaches Recovering and post-resume Normal during fuzz.

## Open questions surfaced by the spec for your input

§17 of the spec lists open questions; the signer-enumeration resolution (`getLockdownSigners`) is already shipped in V1. Treat the remainder as discussion fodder for the audit kickoff:

1. Post-resume window: V1 allows `removeLockdownSigner` during Recovering (H.4). The theoretical pre-signed-removal vector exists - is the trade-off correctly tuned, or should removal require a fresh post-trigger signature?
2. Compromised-verifier handling: V1 removes affected signer identities one at a time via `removeLockdownSigner` (batchable via MultiSend) rather than a bulk verifier-class kill-switch. Is per-identity removal the right granularity, or does the lack of a single-call mass revocation leave an unacceptable response-time gap?

ERC-7913 stability is no longer open: ERC-7913 is Final and the pinned
OpenZeppelin interface matches its `bytes4` magic-value ABI.

## Final ask

Report your findings in the format specified at the top. Be specific about line numbers. If you contradict the spec, state which section. If you confirm a property, write one line so the next reviewer can skip it.

Thank you.
