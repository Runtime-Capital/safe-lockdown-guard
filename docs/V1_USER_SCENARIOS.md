# Lockdown V1 — User Scenarios Catalogue

What this document is: a complete walk-through of every user-facing scenario
the V1 singleton currently supports, organised by lifecycle phase, with the
relevant code references and rationale for each. It is intentionally more
verbose than `SPEC_V1.md` because the spec is the contract and this is the
operator's mental model.

What this document is NOT: a list of open gaps. For known limitations and
deliberate non-features, see `AUDIT_BRIEF.md` §"Out of scope / accepted
risks" and `specs/SPEC_V1.md` §14.

Line references are orienting only after the split into `Lockdown`,
`LockdownTimelock`, and component mixins. Treat symbol names and sections as
source of truth when code moves during refactors.

---

## 0. Lifecycle overview

A Safe protected by V1 moves through four explicit states, surfaced by the
single public view `getState(safe) → (State, secondsRemaining)`
(`enum State { Uninitialised, Normal, LockedDown, Recovering }`):

```
Uninitialised ──initialize──▶ Normal ──triggerLockdown──▶ LockedDown
                                ▲                              │
                                │                              │ t ≥ lockdownUntil
   t ≥ lockdownUntil + resumeDelay (auto-resume)              ▼
                                │                          Recovering
                                └──────────────────────────────┘
```

- **Uninitialised**: the guard is wired (or not yet) but `initialize` has not
  run (`lockdownDuration == 0`). Owner-path hooks fail open (anti-brick);
  module-path → singleton is still rejected. See 1.3 / 1.4.
- **Normal**: regular Safe operation, owner-path and module-path execute
  freely subject to the same constraints as a stock Safe. Quorum can administer
  the singleton (add/remove/rotate signers, edit durations).
- **LockedDown**: owner-path and module-path are fully blocked. Only the
  passing of wall-clock time (`block.timestamp ≥ lockdownUntil`) lets the
  Safe escape this state.
- **Recovering**: a deliberately narrow whitelist of owner-path calls is
  permitted (nonce burn, `swapOwner` to a recovery owner, `disableModule`,
  `removeLockdownSigner`). Module-path remains blocked. The Safe quorum uses
  this window to swap owners, neutralise modules, and remove compromised
  signers (including a Safe-batched `removeLockdownSigner` sweep through native
  MultiSend when an entire verifier turns out compromised). Reached once
  `block.timestamp ≥ lockdownUntil`, and lasting for `resumeDelay`.
- **Return to Normal (auto-resume)**: there is no separate `Resumable` state
  and no resume call. Once `block.timestamp ≥ lockdownUntil + resumeDelay`,
  `getState` reports `Normal` again, purely on time - no transaction, no event.
  No storage is cleared at that transition. The raw incident fields linger
  until the next trigger or a later Normal-state `setResumeDelay`, which clears
  the elapsed incident before applying the new delay. Public getters normalise:
  `getLockdownUntil` returns `0` and `lastReasonHash` returns `bytes32(0)` once
  the window elapses, consistent with `getState`.

The three roles that show up across scenarios:

- **Safe quorum**: the Safe owners reaching threshold and executing through
  `Safe.execTransaction`. Authority to administer the singleton.
- **Lockdown signer**: an ERC-7913 `bytes` signer identity (a 20-byte
  EOA/ERC-1271 address, or `verifier || key`) explicitly registered on the
  Safe by its quorum. Verifier trust is attached to this exact identity; there
  is no separate verifier-approval step. Authority to fire `triggerLockdown`.
  Single-use: burnt on success.
- **Watcher / responder**: indexer, monitoring bot, oncall responder, or
  auditor reading on-chain state and events. No write authority.

---

## 1. Install phase

### 1.1 Deploy the singleton

**Actors**: deployer + watcher (records the deployment for clear-signing
manifest distribution).

**Why it matters**: the singleton is the trust root for every protected Safe
on this chain. Its `MULTI_SEND_CALL_ONLY` immutable address pins the only
DELEGATECALL target the guard will accept in Normal mode. Its
EIP-712 domain separator (OpenZeppelin `EIP712`, exposed via ERC-5267
`eip712Domain()`) is cached at deployment and recomputed whenever
`block.chainid` changes, so every trigger signature is bound to the chain it
is verified on, providing anti-cross-chain-replay by construction.

**Flow**: deploy `new LockdownTimelock(MULTI_SEND_CALL_ONLY)` with the
canonical MultiSendCallOnly address for the target chain. `LockdownTimelock`
is the production singleton; `Lockdown` is the inherited lockdown-only base.
Constructor reverts if the address is zero (`ZeroAddress`).

**Guarantees**:
- `MULTI_SEND_CALL_ONLY` is `immutable` and verifiable post-deploy.
- The EIP-712 domain separator (OZ `EIP712`) is cached at deployment and
  recomputed if `block.chainid` changes; it is built from the current chainid,
  contract address, and `RuntimeLockdown` / `1.0.0` strings, and read via
  ERC-5267 `eip712Domain()` (there is no `DOMAIN_SEPARATOR()` getter).
- One singleton serves an unbounded number of Safes.

**Multichain trust (T-DEPLOY-1 / T-DEPLOY-2, SPEC_V1 §14.1)**: the singleton
and its `MULTI_SEND_CALL_ONLY` are trusted by ADDRESS, but an address does not
authenticate bytecode. If you deploy the singleton at a recognisable address
across chains (CREATE2), the SAME `MULTI_SEND_CALL_ONLY` immutable is forced on
every chain (constructor args are in the initcode hash), so it cannot also be
each chain's canonical MultiSendCallOnly unless that address happens to match.
On any chain you MUST, before `setGuard`:
- verify `EXTCODEHASH(singleton)` equals the audited runtime for the deployed
  commit (defeats a same-address malicious singleton), and
- verify `MULTI_SEND_CALL_ONLY` has code AND its `EXTCODEHASH` equals the
  canonical Safe v1.5.0 `MultiSendCallOnly` (a codeless address silently
  no-ops the owner-path DELEGATECALL carveout; non-canonical code runs in the
  Safe's context and can drain it).
Both checks are wired into `scripts/preflight-install-v1.sh` and
`scripts/verify-install-v1.sh` via `--singleton-codehash` and
`--multi-send-codehash`. Distribute the expected hashes in the per-chain
deploy manifest.

**Code**: `Lockdown` / `LockdownTimelock` constructors.
**Tests**: `test_constructorRejectsZeroMultiSend`,
`test_constructorStoresMultiSend`, `test_eip712DomainIsCorrect`.

### 1.2 Install on a Safe

**Actors**: Safe quorum, atomic via a single MultiSend that combines
`Safe.setGuard(singleton)`, `Safe.setModuleGuard(singleton)`,
`Safe.setFallbackHandler(lockdownFallbackHandler)`, and
`Lockdown.initialize(...)`.

**Why it matters**: the moment the guard is wired but `initialize` has not
yet been called is the most fragile moment. The guard MUST fail-open on
owner-path during that window so the Safe is not bricked, and MUST fail-
closed on module-path → singleton so an enabled malicious module cannot
bootstrap attacker-chosen config (this is the H.12 hardening: the module-
path singleton denial precedes the uninit fail-open).

**Flow**: the install MultiSend first wires all required Safe slots, then
calls `initialize(lockdownDuration_, resumeDelay_, initialRecoveryOwners,
initialSigners)`:

1. `Safe.setGuard(singleton)`.
2. `Safe.setModuleGuard(singleton)`.
3. `Safe.setFallbackHandler(lockdownFallbackHandler)`.
4. `Lockdown.initialize(...)`, which re-checks the three slots and requires
   `lockdownFallbackHandler.LOCKDOWN() == singleton`.

`initialize(...)` receives:

- `lockdownDuration_`: how long owner-path is blocked after trigger. Bounded
  to `1 hours` ≤ d ≤ `30 days`.
- `resumeDelay_`: additional delay in Recovering before resume becomes
  callable. Bounded to `4h` ≤ d ≤ `7d`.
- `initialRecoveryOwners`: pre-registered cold backup addresses, the only
  ones `swapOwner` may swap to during Recovering. Must be non-empty.
- `initialSigners`: optional list of ERC-7913 `bytes` signer identities to
  register atomically. Each must be at least 20 bytes
  (`LockdownSigners_InvalidFormat`); a 20-byte EOA/ERC-1271 identity must be
  non-zero (`LockdownSigners_ZeroAddress`); a longer `verifier || key`
  identity must have a code-bearing leading-20-byte verifier
  (`LockdownSigners_VerifierNoCode`) and a total length within
  `20 + MAX_KEY_LENGTH` (`LockdownSigners_KeyTooLong`). There is no on-chain behavioural smoke test;
  verifier-specific key-shape checks live in off-chain preflight tooling
  (H.13).

**Guarantees**:
- Single-shot: a second `initialize(...)` call reverts `InvalidState` (the
  `onlyUninitialised` modifier).
- Atomicity: if any inner loop reverts (zero / codeless verifier, mis-encoded
  key, duplicate, oversized list), the whole `initialize` reverts. Either the
  Safe is fully armed or fully unconfigured; never half-armed.
- `SafeDormant(safe)` event fires iff `initialSigners.length == 0`, so
  monitoring catches a Safe that finished install with the guard wired but
  no panic capability.
- The singleton does not re-check all three Safe slots after initialization.
  The lifecycle diagnostic and private monitoring must therefore repeat the
  slot/binding check periodically and before relying on the panic path, and
  propose repair while the Safe is cold. During an incident a valid trigger
  blocks every path it still can; it does not reject partial protection or
  emit an on-chain hint about an uncovered path.

**Code**: `Lockdown.initialize`.
**Tests**: many under `test/Lockdown.t.sol` "initialize" section, including
`test_initializeRejectsZeroDuration`, `test_initializeRejectsNoCodeVerifier`,
`test_initializeOnceOnly`.

### 1.3 Anti-brick fail-open on uninitialised Safes (owner-path)

**Actors**: Safe quorum during the install window only.

**Why it matters**: if `setGuard(singleton)` lands one block before
`initialize` succeeds, every Safe owner transaction in between MUST still
execute. Otherwise the Safe is bricked between two install MultiSends.

**Flow**: `checkTransaction` returns silently when
`cfg.lockdownDuration == 0`. This is owner-path only. Module-path → singleton
is rejected unconditionally (see 1.4).

**Code**: `Lockdown.checkTransaction` early return on uninitialised configs.

### 1.4 Reject module-path calls to the singleton even pre-init (H.12)

**Actors**: an enabled module on a Safe whose owners have not yet called
`initialize`.

**Why it matters**: if `setModuleGuard(singleton)` is wired but `initialize`
is not yet executed, a previously enabled module could route through
`execTransactionFromModule(singleton, 0, initCalldata, 0)` and bootstrap
attacker-chosen recovery owners / signers (from the singleton's
view, `msg.sender == Safe`). The H.12 hardening hoists
`if (to == address(this)) revert ModuleCallToSingletonDenied()` to the very
first statement of `checkModuleTransaction`, before any uninit fail-open
read. The denial therefore holds in EVERY state, including pre-init.

**Code**: the first branch of `Lockdown.checkModuleTransaction`.
**Tests**: `test_moduleCallToSingleton_blockedEvenWhenUninit`,
`test_moduleCallToSingleton_blockedEvenWhenUninit_addSigner`.

### 1.5 State-modifier gate on every admin setter (H.2)

**Actors**: Safe quorum.

**Why it matters**: before H.2 a quorum could accidentally call
`setLockdownDuration` (etc.) on a Safe that never called `initialize`,
writing a non-zero duration into a config that has no recovery owners or
signers. The Safe would look armed but be in a malformed state. Every scalar /
signer setter now carries a state modifier, so a Safe still in `Uninitialised`
(`lockdownDuration == 0`) reverts `InvalidState` until `initialize` has run.

**Setters covered**: `setLockdownDuration`, `setResumeDelay`,
`addRecoveryOwner`, `removeRecoveryOwner`, `addLockdownSigner`,
`rotateLockdownSigner` (all `onlyNormal`), and `removeLockdownSigner`
(`onlyNotLockedDown`, i.e. Normal | Recovering). None of these
states is reachable before `initialize`.

**Code**: `onlyNormal` / `onlyNotLockedDown` state modifiers, each reverting
`InvalidState`.

---

## 2. Normal mode

### 2.1 Vet a candidate signer identity (off-chain preflight + `testSigner`)

**Actors**: Safe quorum candidate-vetting a new signer identity (ECDSA,
WebAuthn, MPC, exotic schemes) before registering it.

**Why it matters**: there is no on-chain verifier-approval step and no
on-chain behavioural smoke test. Verifier trust is attached to each explicit
`bytes` signer identity at registration time (see 2.2). Pre-use
vetting is therefore purely off-chain preflight tooling PLUS the on-chain
`testSigner` view. A quorum considering an identity can fully exercise it
with real key material and a real signature before registering anything. The
`testSigner(bytes signer, bytes32 hash, bytes signature) → bool ok` view does
exactly that without state mutation: it runs the same
`SignatureChecker.isValidSignatureNow(signer, hash, signature)` dispatch the
trigger path uses and returns the boolean result instead of reverting. It
does NOT consume a registered signer and requires no approval
step. Safe for ECDSA and WebAuthn (signature material is non-secret
post-production). NOT safe for password / commit-reveal verifiers (would
leak the secret to the RPC): since `PasswordVerifier` ships as tier-2
production, the §8.3.9 obligation applies - test it ONLY with a throwaway
password, never the real one.

**Code**: `Lockdown.testSigner`.
**Tests**: see `test_testSigner_*`.

### 2.2 Register a lockdown signer

**Actors**: Safe quorum.

**Why it matters**: a signer is an ERC-7913 `bytes` identity (a 20-byte
EOA/ERC-1271 address, or `verifier || key`). Registering it is
what attaches trust to that exact identity for this Safe; a lockdown is
authorised iff that exact identity is registered AND the signature
verifies. For a `verifier || key` identity the verifier must have code and
the key is whatever the verifier expects (e.g. 64-byte `qx || qy` P-256
public key for WebAuthn). H.13 no longer uses an on-chain verifier-specific
key-shape extension; registration tooling should preflight known verifier
encodings before submitting Safe calldata, and drills can use
`testSigner(...)` to prove that the registered identity/signature pair
verifies.

**Flow**: `addLockdownSigner(bytes signer)`:
- `onlyNormal` state gate (`InvalidState` unless the Safe is in Normal, which
  already implies initialised and `lockdownUntil == 0`).
- `_validateSigner`: `LockdownSigners_InvalidFormat` (`< 20` bytes); for a
  20-byte identity `LockdownSigners_ZeroAddress`; for a longer
  `verifier || key` identity `LockdownSigners_KeyTooLong`
  (`> 20 + MAX_KEY_LENGTH`) and `LockdownSigners_VerifierNoCode`
  (leading-20-byte verifier has no code).
- `LockdownSigners_MaxReached` if `signersCount == 32` (cap is on the active count,
  not cumulative; see 2.5 below).
- `LockdownSigners_BurntPermanently` if this exact identity was previously
  removed, rotated-away, or trigger-burnt (INV-SIGN-7).
- `LockdownSigners_AlreadyRegistered` if the same identity is already in the active set.
- Add to the `EnumerableSet.BytesSet signers`, emit
  `LockdownSignerAdded(safe, signer)`.

**Returns**: nothing. The signer identity is itself the handle; the device
that holds the panic key signs the EIP-712 `Lockdown(safe, reasonHash)`
message and presents the same `signer` bytes to `triggerLockdown` when the
day comes.

**Code**: `Lockdown.addLockdownSigner` and the internal signer-set helper.
**Tests**: "addLockdownSigner" suite + verifier-level malformed-input
regressions.

### 2.3 Remove or rotate a signer

**Actors**: Safe quorum.

**Why it matters**: standard hygiene. Remove a key whose device was lost.
Rotate from a draft password commitment to an ECDSA-on-Yubikey. Rotation
is atomic: the new entry is written before the old is deleted (functionally
remove-then-add but atomic in a single transaction so the Safe is never
mid-rotation with neither key valid). This per-signer remove is also how a
compromised verifier is handled: there is no bulk verifier kill-switch, so
the Safe removes every signer identity under the affected verifier, batching
them in one transaction through native MultiSend if several exist.

**Flow remove**: `removeLockdownSigner(bytes signer)`:
- `onlyNotLockedDown` state gate: allowed in Normal AND Recovering
  (the H.4 carve-out). Forbidden during LockedDown (and Uninitialised), which
  revert `InvalidState`.
- `LockdownSigners_Unknown` if the entry does not exist.
- Remove from the active set, mark the identity in `signerBurntPermanently`,
  emit `LockdownSignerRemoved(safe, signer)`.
- Emit `SafeDormant` if `signersCount` now equals 0 (H.15).

**Flow rotate**: `rotateLockdownSigner(bytes oldSigner, bytes newSigner)`:
- `onlyNormal` state gate (initialised + `lockdownUntil == 0`).
- Calls `_removeLockdownSigner` then `_addLockdownSigner`; emit
  `LockdownSignerRotated(safe, oldSigner, newSigner)`.

**V1 INV-SIGN-7 (C4 fix)**: any signer identity that has
been removed, rotated-away, or trigger-burnt is **permanently** marked as
burnt in `cfg.signerBurntPermanently`. Re-registering the same identity via
`addLockdownSigner` or `rotateLockdownSigner` reverts
`LockdownSigners_BurntPermanently`. The operator MUST rotate to a fresh identity
each time. For a 20-byte ECDSA identity: a fresh panic-EOA address per cycle.
For `PasswordVerifier`: a fresh password / commitment per cycle. The
off-chain view `isSignerBurntPermanently(safe, signer)` lets the
runbook check before submitting an add.

**Recovery hygiene = permanent identity loss (review round 2)**: the
H.4 carve-out lets the quorum call `removeLockdownSigner` DURING
Recovering, which is the right primitive to clean a compromised signer
before resume. But the burnt-identity mark fires there too. So the
Recovering window is both:

- the surgical "kill this compromised identity inside the recovery
  window so it cannot relock the Safe in the first block after the
  auto-resume to Normal" primitive (H.4 + INV-LIFE-4),
  AND
- a **one-way permanent identity loss** for every targeted
  signer identity.

Operator obligation post-resume: when a Recovering-time remove was
applied to a panic identity (legitimately or under coercion), the
post-resume runbook MUST register a FRESH signer identity for
that role - never the same one. The contract will revert
`LockdownSigners_BurntPermanently` on any attempt to re-add. This is the
intended single-use semantic; the SPEC and §8.3 runbook both flag it
as a hard obligation, not a soft hint.

**Code**: `Lockdown.removeLockdownSigner` and
`Lockdown.rotateLockdownSigner`.
**Tests**: "removeLockdownSigner" + "rotateLockdownSigner" suites,
`test_addLockdownSignerRejectsBurntKeyAfterTriggerBurn`,
`test_passwordPath_replayAfterReRegistrationBlocked`.

### 2.4 Edit lockdown duration, resume delay, recovery allowlist

**Actors**: Safe quorum, only in Normal.

**Why it matters**: these are tuning knobs, not emergency levers. Changing
them mid-incident would let a coerced quorum shorten the wait. They are all
gated by the `onlyNormal` modifier (`InvalidState` outside Normal).

**Code**: Lockdown scalar/admin setters.

### 2.5 The 32-signers cap is on the active count, not cumulative

**Actors**: any Safe running drills or rotating keys.

**Why it matters**: `MAX_LOCKDOWN_SIGNERS = 32` bounds `signersCount`
(`signers.length()`, the number of currently alive signer entries). Burning a
signer (via trigger) or removing one (via admin) shrinks the active set and
frees room for a new `addLockdownSigner` call. Drills are therefore
unlimited in count: one drill burns one signer identity, and a follow-up
`addLockdownSigner` registers a FRESH identity. The anti-replay defence is the
permanent burn, not a monotone id: every removed / rotated / trigger-burnt
identity is recorded in `signerBurntPermanently`, so the SAME identity can
never be re-registered (re-adding reverts `LockdownSigners_BurntPermanently`) and
an old EIP-712 signature over that identity can never be replayed because the
identity is gone for good. Re-arming always uses fresh signer bytes.

---

## 3. Incident path: trigger

### 3.1 Trigger lockdown with a registered signer

**Actors**: a single lockdown signer (a person, a hardware wallet, an
emergency relayer bot). The Safe quorum is NOT involved; the whole point
of the design is to bypass the quorum during coercion.

**Why it matters**: this is the hot path. Everything else exists to make
this call reliable, replay-resistant, and impossible to forge.

**Flow**:

1. The signer produces an EIP-712 signature over the message
   `Lockdown(address safe, bytes32 reasonHash)` (typehash
   `keccak256("Lockdown(address safe,bytes32 reasonHash)")`, no `signerId`).
   The `reasonHash` is whatever the runbook says (an opaque
   identifier; the semantic "kidnapping" / "drill" / "device lost" lives
   in an off-chain log indexed by `reasonHash`).
2. A relayer (or the signer's own RPC) calls
   `triggerLockdown(safe, reasonHash, signer, signature)`.
3. The singleton (`onlyInitialized(safe)`):
   - reverts `InvalidState` only if `safe` is uninitialised; in LockedDown or
     Recovering, another registered signer may extend/re-lock the incident.
   - BURN FIRST: `_removeLockdownSigner(safe, signer)` removes the identity
     from the active set and marks it in `signerBurntPermanently`. If the
     identity was never registered (or already burnt) this reverts
     `LockdownSigners_Unknown`. The burn precedes the signature check on purpose;
     a `BadSignature` revert below rolls the burn back, so the burn only
     persists on success (INV-SIGN-1).
   - VERIFY: `SignatureChecker.isValidSignatureNow(signer, digest,
     signature)` where
     `digest = _hashTypedDataV4(keccak256(abi.encode(LOCKDOWN_TYPEHASH,
     safe, reasonHash)))`. For a `verifier || key` identity this is a
     STATICCALL to `verifier.verify(key, digest, signature)` that must return
     the ERC-7913 magic `0x024ad318`; any other outcome (revert, short
     return, non-magic return) maps to `BadSignature()`. For a 20-byte
     identity it is ECDSA / ERC-1271.
   - WRITE: `lockdownUntil = block.timestamp + lockdownDuration`,
     `lastReasonHash = reasonHash`.
   - EMIT `SafeLockedDown(safe, lockdownUntil, reasonHash, signer)` (the
     trailing `signer` bytes are the forensic trail: a watcher who missed
     the original `LockdownSignerAdded` can resolve which exact identity
     fired from this single event).
   - EMIT `SafeDormant(safe)` if `signersCount` now equals 0 (H.15).

**Reentrancy stance**: verification dispatches via STATICCALL (ERC-1271 /
ERC-7913 paths), so a verifier cannot mutate state during the call. The
trigger verifies through `testSigner` before any signer mutation, then removes
and permanently burns the identity before locking. A successful trigger
persists exactly one burn and a failed verification persists none
(INV-SIGN-1); any later revert rolls the sequence back atomically.

**Anti-replay**: the burnt identity is recorded permanently in
`signerBurntPermanently`, so the same identity can never be re-registered and
its old EIP-712 signature can never be replayed. (The EIP-712 message no
longer carries a `signerId`; single-use burn of the exact identity is the
replay defence, INV-SIGN-7.)

**Code**: `Lockdown.triggerLockdown`.
**Tests**: "triggerLockdown" suite + the
`test_signatureCannotReplayAfterBurnAndReRegister` regression.

### 3.2 Ordinary verifier failures normalised to BadSignature (L.3)

**Actors**: trigger path and a supported, codehash-pinned identity.

**Why it matters**: OZ `SignatureChecker.isValidSignatureNow` normalises an
ordinary verifier revert, no/short return, non-magic return, callee OOG or
invalid opcode to `false`, which the trigger turns into `BadSignature()`.
This is not an unconditional bound on caller work: the high-level ERC-7913
branch copies returndata, so an unsupported identity that constructs a
returndata/revert-data bomb can make the caller itself OOG before
normalisation. V1 deliberately does not fork the OZ dispatch or cap verifier
gas. The supported product domain is the immutable, closed-world verifier
bytecodes shipped and codehash-pinned by this repository; any abnormal drill
result condemns the whole identity and requires remove/rotate to a different
verifier.

**Code**: `Lockdown.testSigner`, used as the verification source of truth by
`triggerLockdown`, and the trigger's `BadSignature()` branch.

### 3.3 Owner-path is fully blocked in LockedDown

**Actors**: the Safe quorum (or an attacker holding signed messages).

**Why it matters**: the attacker may have coerced enough off-chain
signatures to push transactions during the lockdown window. Those
transactions MUST not pass.

**Flow**: `checkTransaction` reverts `LockedDown()` for every owner-path
transaction while `block.timestamp < lockdownUntil`.

**Code**: `Lockdown.checkTransaction`.
**Tests**: "triggerLockdown blocks owner path" + cross-key isolation tests.

### 3.4 Module-path is fully blocked in LockedDown and Recovering

**Actors**: any enabled module on the Safe.

**Why it matters**: an attacker may have enabled a hostile module pre-
incident, or coerced the quorum into enabling one. Modules MUST NOT bypass
the lockdown. Furthermore, module-path → singleton is rejected
unconditionally (H.5) in EVERY state, including Normal: modules can never
administer the singleton, period.

**Code**: `Lockdown.checkModuleTransaction`.
**Tests**: "moduleCallToSingleton" + cross-key isolation module tests.

---

## 4. Recovery phase

### 4.1 Empty self-call (nonce burn)

**Actors**: Safe quorum.

**Why it matters**: signing a no-op transaction to the Safe itself burns
the next nonce. This invalidates any off-chain-signed transaction the
attacker may have collected for that nonce.

**Flow**: owner-path `checkTransaction`, `to == safe`, `value == 0`,
`data.length == 0`, `operation == CALL`. The hook accepts.

**Code**: `Lockdown._isRecoveryCall`.

### 4.2 Owner swap to a pre-registered cold backup

**Actors**: Safe quorum executing `Safe.swapOwner(prevOwner, oldOwner,
newOwner)` to migrate authority away from the compromised owner set onto
addresses that were registered in `recoveryOwnerAllowlist` at install
time.

**Why it matters**: the only `swapOwner` permitted during Recovering swaps
to an owner from the pre-registered cold backup set. The attacker cannot
swap to an attacker-controlled address (would not be in the allowlist).
Exact calldata length check (4 + 3 × 32 bytes) rejects trailing-bytes
shenanigans and keeps signer-review tooling unambiguous.

**Side effect on coerced signatures**: once `swapOwner` lands, the Safe's
owner set changes. Any owner-set signature collected during coercion is
no longer valid for the new threshold (the missing/swapped owner is no
longer counted), and the nonce has already advanced. The combination
makes off-chain-signed messages from the incident window unusable.

**Code**: `Lockdown._isRecoveryCall`,
`ISafe.swapOwner.selector` + length (`0x64`) / decode check.

### 4.3 `removeLockdownSigner` during Recovering (H.4)

**Actors**: Safe quorum, post-incident cleanup.

**Why it matters**: if the trigger burnt the specific signer that fired,
the attacker may still hold other registered keys. The quorum must be
able to remove them BEFORE the auto-resume to Normal re-opens the trigger
path, otherwise a relock race exists. The recovery whitelist includes
`removeLockdownSigner` precisely for this. (Since PR #59 `triggerLockdown`
is `onlyInitialized`, a surviving signer can also re-lock from WITHIN
Recovering, not only after the auto-resume, which makes this in-recovery
`removeLockdownSigner` cull more important; see SPEC §7.4 / H.4.)
`addLockdownSigner` does NOT
appear in the whitelist (intentional: pre-signed addition attacks would
let an attacker plant a fresh key during coercion).

**Code**: `Lockdown.removeLockdownSigner`,
selector accepted in `_isRecoveryCall`.

### 4.4 Sweeping a compromised verifier during Recovering

**Actors**: Safe quorum, post-incident cleanup when an entire verifier
class is compromised (e.g. a buggy WebAuthn verifier that accepts any
signature).

**Why it matters**: there is no bulk verifier kill-switch. The quorum
instead removes every signer identity under the affected verifier via
per-signer `removeLockdownSigner` (the H.4 recovery carve-out, see 4.3),
batching them into one transaction through native MultiSend if several
exist. Each removed signer identity is marked burnt permanently
(INV-SIGN-7), so the operator must re-arm with FRESH identities
post-resume. `addLockdownSigner` remains forbidden during Recovering, so
no new identity under any verifier can be planted mid-incident.

**Code**: `Lockdown.removeLockdownSigner`,
selector accepted in `_isRecoveryCall`.

### 4.5 Return to Normal (auto-resume)

**Actors**: none - the transition is automatic.

**Why it matters**: this is the single exit from the post-lockdown period,
and it is **purely time-based**. Once `block.timestamp ≥ lockdownUntil +
resumeDelay`, `getState` reports `Normal` again. There is no
`resumeAfterLockdownPeriodExpired()` call, no `Resumable` state, no
transaction and no event. The mandatory `resumeDelay` still guarantees the
quorum a window to swap owners and clean up signers before the trigger path
re-opens.

**Flow**: no state mutation happens at auto-resume. The raw `lockdownUntil` /
`lockdownReasonHash` fields therefore linger until the next `triggerLockdown`
or Normal-state `setResumeDelay`. The latter clears the elapsed incident before
writing the new delay, so a prospective configuration change cannot re-open the
old recovery window. Public getters normalise past the window: `getState`
returns Normal, `getLockdownUntil` returns `0`, and `lastReasonHash` returns
`bytes32(0)`. Monitoring computes the `Recovering → Normal` moment from
`lockdownUntil + resumeDelay` (no on-chain signal fires); post-incident
forensics uses the durable `SafeLockedDown` event.

**Code**: `StateMachine.getState` (the final `else` arm returns `Normal`);
`getLockdownUntil` / `lastReasonHash` normalise to zero past the window.

### 4.5b `disableModule` during Recovering

**Actors**: Safe quorum, inside the recovery window.

**Why it matters**: the recovery whitelist accepts an exact-length
`disableModule(prevModule, module)` Safe self-call so the quorum can
neutralise a module during recovery (before the auto-resume re-enables the
module path). `disableModule` cannot move value, so it is a safe cleanup
primitive. The compromised-module threat itself is out of scope: a module is
never acquired by accident, and a detected rogue module is disabled directly
in Normal without any lockdown - so this is opportunistic hardening, not a
load-bearing control.

**Code**: `IModuleManager.disableModule` selector accepted in `_isRecoveryCall`.

### 4.6 What is FORBIDDEN during Recovering

- Any non-zero refund field (`safeTxGas`, `baseGas`, `gasPrice`,
  `gasToken`, `refundReceiver`). The Safe pays no relayer during
  recovery (`RecoveryRefundDenied`).
- DELEGATECALL of any kind (no `MultiSendCallOnly` during recovery).
- Module-path execution (`RecoveryActive` revert from the module hook).
- Singleton self-calls that are NOT in the whitelist: `addLockdownSigner`,
  `rotateLockdownSigner`, `setLockdownDuration`, `setResumeDelay`,
  `addRecoveryOwner`, `removeRecoveryOwner`, `initialize`.
- Self-calls to the Safe other than nonce burn / allowlisted `swapOwner`
  (e.g. `addOwnerWithThreshold`, `removeOwner`, `changeThreshold` are all
  rejected during Recovering).
- ETH `value > 0` on any recovery transaction.

---

## 5. Multi-Safe and isolation properties

### 5.1 One singleton serves N Safes

**Actors**: any number of Safes pointing their transaction guard, module guard
and singleton-bound fallback handler to the same singleton.

**Why it matters**: cost (one deploy ever per chain), discoverability
(everyone watches one address), and a simpler operator model. Per-Safe
isolation must hold against active adversaries running other Safes on
the same singleton.

### 5.2 INV-ISO-1: writes are anchored on `msg.sender` or `safe` param

**The property**: every storage write into `_configs[X]` derives `X`
from either `msg.sender` (admin paths, hooks) or the explicit `safe`
parameter (only `triggerLockdown`). There is no path where a transaction
identifying Safe A can write into Safe B's slot.

**Why it matters**: this is the central novelty of V1 versus a per-Safe
contract. The cross-key isolation tests
(`test/Lockdown.t.sol` "cross-key" section) exercise this property; the
Echidna invariants `safeBNeverLockedDown` and `safeBConfigUntouched`
make it stateful.

---

## 6. Watcher / forensics path

### 6.1 Event stream

Every state-changing path emits at least one event indexed by `safe`.
Indexers can build a complete history without re-running calls. Key
events:

- `SafeInitialised(safe, duration, delay, recoveryOwnersCount,
  initialSignersCount)`
- `LockdownSignerAdded(safe, signer)`
- `LockdownSignerRemoved(safe, signer)`
- `LockdownSignerRotated(safe, oldSigner, newSigner)`
- `SafeLockedDown(safe, lockdownUntil, reasonHash, signer)` (the trailing
  `signer` bytes are the forensic trail: post-burn forensics can resolve the
  burnt identity from a single event, without historical-log replay).
- (No resume event: the return to Normal is time-based auto-resume, so
  monitoring computes the transition from `lockdownUntil + resumeDelay`.)
- `SafeDormant(safe)` (the H.15 extension: fires on EVERY transition to
  `signersCount == 0`, not only at init-with-empty-signers. Watchers can
  page oncall the moment a Safe loses its last panic capability,
  whether through admin removal, rotation, or trigger burn.)
- `LockdownDurationChanged`, `ResumeDelayChanged`,
  `RecoveryOwnerAdded`, `RecoveryOwnerRemoved`.

### 6.2 On-chain views

For monitoring and incident response without log replay:

- `getState(safe) → (State, secondsRemaining)`: current state and a
  countdown. This is the single source of truth for the lifecycle phase;
  derive any "locked down?" / "recovering?" boolean from it (the standalone
  `isLockedDown` / `isRecovering` views no longer exist).
- `getConfigSnapshot(safe) → (lockdownDuration, resumeDelay, lockdownUntil,
  signersCount, recoveryOwnerAllowlistCount)`: 5-field snapshot of the
  per-Safe config (`signersCount` / `recoveryOwnerAllowlistCount` are live
  set lengths; there is no monotone-counter field).
- `getLockdownSigners(safe) → bytes[]`: the full active signer-identity set,
  enumerated directly from the `EnumerableSet.BytesSet`. Replaces `eth_getLogs`
  replay for "list every signer this Safe currently has" without depending on
  indexer freshness. (There is no reverse-by-id reader; the identity bytes are
  the key.)
- `isLockdownSigner(safe, signer) → bool`: membership check for one identity.
- `isSignerBurntPermanently(safe, signer) → bool` (V1,
  INV-SIGN-7): pre-check whether a planned `addLockdownSigner`
  would revert `LockdownSigners_BurntPermanently`. The runbook MUST call
  this before re-arming a signer with a recovered backup identity.
- `getRecoveryOwners(safe) → address[]`,
  `isRecoveryOwner(safe, owner) → bool`.
- `lastReasonHash(safe) → bytes32`: the `reasonHash` of the current
  incident while LockedDown / Recovering; normalises to `bytes32(0)` once the
  recovery window elapses (auto-resumed to Normal). A later `setResumeDelay`
  may also clear the underlying elapsed value. For post-incident forensics use
  the `SafeLockedDown` event log (the durable record), not this view.
- `getLockdownUntil(safe) → uint64`: `lockdownUntil` while LockedDown /
  Recovering; normalises to `0` once the recovery window elapses.
- `testSigner(signer, hash, signature) → bool`:
  pure signer-identity sanity test without state mutation. Safe to call on
  candidate identities before registering them (subject to the password-leak
  caveat in §2.1 / §8.3.9).

### 6.3 Single-set storage + permanent burn (INV-SIGN-7)

Signer identities live in one `EnumerableSet.BytesSet signers` keyed by the
identity bytes (no `id` / reverse map), plus a `signerBurntPermanently`
register that records every identity ever removed, rotated-away, or
trigger-burnt. The Echidna invariant `echidna_burntSignerNeverResurrects`
makes the burn-then-resurrect class impossible to observe.

---

## 7. MultiSend / Normal-mode DELEGATECALL parser

### 7.1 The only DELEGATECALL the guard allows in Normal mode

**Actors**: Safe quorum batching multiple owner-path operations.

**Why it matters**: the Safe owner-path supports `DELEGATECALL`, which
is a powerful and dangerous primitive. V1 restricts it to the canonical
`MultiSendCallOnly` (immutable `MULTI_SEND_CALL_ONLY` constructor
parameter). The guard then walks the inner batch recursively and enforces,
at every depth:

- any inner `DELEGATECALL` is allowed **only** to `MultiSendCallOnly`
  (so the "CallOnly" / storage-context property holds inside too); the
  parser recurses into such nested batches. Any other inner
  `DELEGATECALL` target is rejected (`DelegateCallDenied`);
- any `setFallbackHandler(address)` self-call must install a
  `LockdownFallbackHandler` bound to this singleton, otherwise it is
  rejected (`InvalidFallbackHandler`) — this prevents a bundle from
  silently swapping out the ERC-1271 freeze handler.

### 7.2 What the parser does NOT do

- it does NOT reject inner `CALL`s to the calling Safe, the singleton, or
  `address(0)`. On the owner path the whole bundle is authorised by full
  Safe quorum (and, with the timelock active, scheduled + waited as a
  single `safeTxHash` binding the exact contents), so such inner calls are
  already quorum-gated and visible to the operator reviewing the scheduled
  hash — they are not a privilege escalation.
- it does not enforce a per-inner-tx allowlist (that is the application's
  job).

**Code**: `_checkCall` in `src/Lockdown.sol`.

---

## 8. ERC-7913 verifier extension surface

### 8.1 Dispatch via OZ `SignatureChecker.isValidSignatureNow(signer, hash, sig)`

Verification is delegated to OpenZeppelin `SignatureChecker`, which dispatches
on the identity shape:

- a **20-byte** identity needs no verifier contract: it routes to native ECDSA
  (with OZ's EIP-2 low-`s` / `v ∈ {27, 28}` checks) or, if the address has
  code, ERC-1271.
- a longer **`verifier || key`** identity routes to
  `IERC7913SignatureVerifier(verifier).verify(key, hash, sig)`, which must
  return the ERC-7913 magic value `0x024ad318` (=
  `IERC7913SignatureVerifier.verify.selector`) on success; any other 4-byte
  value (typically `0x00000000`), a revert, or a short return is normalised to
  a boolean `false` (the STATICCALL outcome the trigger turns into
  `BadSignature()`).

### 8.2 Key-shape preflight (H.13)

Lockdown does not implement a verifier-specific on-chain key validator.
Registration accepts any non-empty key up to `MAX_KEY_LENGTH` for a
non-zero verifier that has code. Operators and tooling are responsible for
validating known verifier encodings before submitting Safe calldata:

- ECDSA: 20-byte packed address, non-zero.
- Password: 32-byte non-zero commitment.
- WebAuthn: 64-byte `qx || qy` P-256 public key.

Malformed keys are rejected at trigger time (the verifier's `verify(...)`
for `verifier || key` identities, or native ECDSA/ERC-1271 for 20-byte
identities), which Lockdown normalises to `BadSignature()`. Runbooks
should therefore include a `testSigner(...)` drill for newly registered
signers.

### 8.3 Timelock V1: schedule / wait / execute (or HSM bypass)

The V1 release includes an optional per-Safe timelock. When
`timelockDelay > 0`, every owner-path AND module-path Safe transaction must
either (a) be scheduled first and wait the delay, or (b) for owner-path
only, be unlocked by an allowlisted HSM bypasser.

#### 8.3.1 Enable the timelock

`Safe.execTransaction(singleton, 0, abi.encodeCall(setTimelockDelay, (24
hours)), CALL, ...)`. The first activation is FREE (timelock check is
skipped because the current delay is still 0 at hook time). Subsequent
changes (including back to 0) require schedule + wait.

#### 8.3.2 Schedule and execute an owner-path tx

1. Owners sign the planned Safe transaction normally in the Safe UI / service.
2. A scheduler submits
   `scheduleTransaction(safe, nonce, params, signatures)`. This verifies the
   Safe signatures with `checkSignatures(address(0), safeTxHash, signatures)`,
   writes the ticket, and does NOT consume the Safe nonce.
3. Wait `timelockDelay`.
4. `Safe.execTransaction(to, value, data, op, ...)`. The pre-hook
   recomputes the safeTxHash and validates against the scheduled ticket. The
   ticket is deleted in the post-hook (`checkAfterExecution`) gated on
   the inner call succeeding (V1 review round 3, INV-TIME-4 hardening).

If other txs consume Safe nonces in between, the planned safeTxHash no longer
matches until the Safe reaches the scheduled nonce. The user must either (a)
submit filler txs to reach the planned nonce, or (b) cancel and re-schedule
with the new nonce's full signed transaction.

**Refund-field warning (operator obligation)**: the scheduled
`safeTxHash` binds every refund field of the planned tx (`safeTxGas`,
`baseGas`, `gasPrice`, `gasToken`, `refundReceiver`). The Normal-mode
timelock execution path INTENTIONALLY allows non-zero refund fields
because legitimate user bundles often need them (relayer sponsorship,
etc.). This is asymmetric with the Recovery path (which rejects all
refund fields, see §4) and the bypass-meta short-circuit (C1 /
INV-TIME-9). The on-chain guard cannot judge intent. The off-chain
signer review tooling MUST surface any non-zero `gasToken` /
`refundReceiver` to the quorum BEFORE signatures are collected. The protection
is review-before-sign, not on-chain rejection.

**Recommendation**: prefer `safeTxGas == 0 && gasPrice == 0` for
timelocked owner txs (independently recommended by Safe v1.4.0+
because the `safeTxGas` try/catch pattern is fragile). With
`safeTxGas == 0`, a failed inner call rolls back the entire outer tx
including the pre-hook verify, so the operator can retry at the same
nonce. With `safeTxGas > 0`, the nonce advances on inner failure and
the leftover ticket is stranded at the old nonce (operator cleans via
`cancelTransaction(oldHash)` or the 90-day sweep).

**Failed execution semantics (V1 review round 3, INV-TIME-4)**: the
post-hook deletes the ticket ONLY if `success == true`. If the inner
call reverts BUT Safe still commits (`safeTxGas > 0` case), the
ticket survives in storage. Same for the module path: a module
revert (Safe emits `ExecutionFromModuleFailure`, outer tx commits)
leaves the ticket consumable for retry of the SAME module tx.

#### 8.3.3 Cancel a ticket

`Safe.execTransaction(singleton, 0,
abi.encodeCall(cancelTransaction, (safeTxHash)), CALL, ...)`. Reclaims the
storage slot, emits `TicketCancelled`. Bypassed from the timelock
check itself (cancel is a meta-op).

#### 8.3.4 Module-path: schedule / execute, NO bypass

The module-path has its own scheduling function
`scheduleModuleTransaction(module, to, value, data, op)` which writes to
a distinct namespace key and emits full call details for monitoring. The module then submits its tx; the pre-hook only
verifies the ticket, and consumption happens in the post-hook, gated on
`success == true` (INV-TIME-4). A module call that reverts leaves the
ticket in storage, so the module can retry without re-scheduling. No
bypass exists for module-path (deliberate scope decision).

#### 8.3.5 HSM bypass (owner-path only)

The Safe quorum adds an HSM service via `setTimelockBypasser(hsmAddr,
true)`. The HSM holds a private key (typically in hardware). When the
bypasser service approves a Safe transaction under its off-chain
policy, the HSM calls `bypassTimelock(safe, safeTxHash)` directly,
which writes `executableAt = now` for that specific safeTxHash. The Safe
owners can then execute the transaction immediately.

**Equivalent form, no separate bypass call**: if the bypasser itself
submits the owner `execTransaction` (so it is the `msgSender` the Safe
forwards to the guard), `checkTransaction` skips the timelock inline - no
`bypassTimelock` call and no ticket. This is the natural HSM-as-relayer
flow: the bypasser service relays the approved tx directly. Owner
signatures are still required, and it is Normal-state + owner-path only
(it cannot accelerate a LockedDown / Recovering tx).

**Critical trust model**: the contract receives only the hash, so it
CANNOT enforce "what is bypassable" on-chain. The bypasser service must
refuse to issue bypasses for admin txs (setTimelockDelay, setTimelockBypasser,
setGuard, owner changes, etc.). HSM compromise = full bypass authority
including disabling the timelock. The operator accepts this SPOF.

Named threats (SPEC §V1 "Threat model: bypasser compromise"):

- **T-BYPASS-1 (timelock disable)**: compromised bypasser accelerates
  `setTimelockDelay(0)`. Off-chain bypasser policy MUST refuse bypasses
  for self-calls to the singleton.
- **T-BYPASS-2 (signer eviction via bypass)**: compromised bypasser
  accelerates `removeLockdownSigner(...)` on the legitimate panic
  identities under a given verifier (there is no bulk verifier kill-switch
  to abuse; eviction is per-signer). Same off-chain mitigation. See also
  T-BYPASS-3.
- **T-BYPASS-3 (signer eviction)**: compromised bypasser accelerates
  `removeLockdownSigner(...)` on a legitimate panic identity.
- **T-BYPASS-4 (adversarial bypasser addition)**: compromised bypasser
  accelerates `setTimelockBypasser(attacker, true)`. Revocation of the
  legitimate bypasser is the only way back, and goes through the timelock.
- **T-BYPASS-5 (recovery shielding holds)**: NOT a threat. While `getState` is
  LockedDown or Recovering, `bypassTimelock` itself reverts `InvalidState` (its
  `onlyNormal` gate) and the hook's recovery branch never reaches
  the timelock check (INV-TIME-6/7). The attacker who only holds the
  bypasser key cannot touch a Safe currently in LockedDown or Recovering.
- **T-BYPASS-6 (stale tickets survive revocation, C3)**: revoking
  a compromised bypasser only blocks NEW `bypassTimelock` calls. Tickets
  the bypasser already wrote remain valid until executed or cancelled.
  **They do NOT reliably expire (corrected 2026-08-25).** `bypassTimelock`
  writes `executableAt = now` unconditionally, with no TTL check and no
  already-exists guard, so a still-allowlisted bypasser can resurrect a
  ticket already dead past its TTL and refresh any ticket indefinitely.
  Waiting out the 90-day TTL is NOT a mitigation while the key is
  allowlisted - revocation is. Pinned by
  `test/poc/TimelockAccounting.t.sol`. **HSM compromise runbook**: (1) enumerate all
  `TimelockBypassed` events for the compromised bypasser from event log;
  (2) for each, call `cancelTransaction(safeTxHash)` from the Safe
  quorum (Normal only). **Do not rely on cancelling before it fires: that
  window is zero (corrected 2026-08-25).** `bypassTimelock` sets
  `executableAt = now` and the hook accepts `now >= executableAt`, so a
  bypass and its execution land in the SAME block; only tickets the
  attacker has not yet used are cancellable. Pinned by
  `test/poc/TimelockAccounting.t.sol::test_confirmed_bypassAndExecuteInSameBlock`; (3) call `setTimelockBypasser(badBypasser,
  false)`. The order matters: revoke the bypasser AFTER cleaning their
  tickets, otherwise an attacker can race-execute pre-written tickets
  during the cleanup window.
- **T-BYPASS-7 (refund-field drain, C1)**: ON-CHAIN FIXED **FOR THE
  META-CALL LANE ONLY (scope corrected 2026-08-25)**. The hook reverts
  `TimelockBypassRefundDenied` if a bypassed schedule / cancel meta-call
  carries any non-zero refund field. The separate INLINE bypasser lane
  (the bypasser relays the `execTransaction` itself, README assumption 5)
  deliberately does NOT re-check refund fields on either the CALL or the
  DELEGATECALL branch, and the ERC-20 `gasToken` refund is uncapped: a
  coerced quorum relayed by the bypasser CAN drain that way. This is not
  an escalation - an allowlisted bypasser can already pre-bypass a plain
  transfer with zero refund fields (accepted risk #8) - but the earlier
  unqualified wording was wrong. Pinned by
  `test/poc/TimelockBypassRefundLane.t.sol`.
- **T-BYPASS-8 (forced burn via bypass, review round 2)**: a compromised
  bypasser can accelerate `removeLockdownSigner` / `rotateLockdownSigner`
  on a legitimate panic identity (the eviction itself is T-BYPASS-3).
  V1 INV-SIGN-7 makes the eviction permanent: the targeted
  signer identity is marked burnt forever on this Safe and the
  operator cannot re-arm the SAME identity after restoring the bypasser.
  The bypasser cannot weaponise this beyond eviction (no new authority
  is created), but the storage damage to the panic-identity surface is
  permanent. **HSM compromise runbook addition**: after step (3) above
  and resuming Normal operations, audit `LockdownSignerRemoved` and
  `LockdownSignerRotated` events targeting `to == address(this)` during
  the bypass window; for every panic identity forcibly burnt, register
  a FRESH signer identity via `addLockdownSigner` - the same
  identity will revert `LockdownSigners_BurntPermanently`. Accepted residual.

If the HSM is unavailable, the approved tx simply waits the full delay. No
loss of safety, only loss of speed.

If the operator is unwilling to accept T-BYPASS-1..4 + T-BYPASS-6
+ T-BYPASS-8, the correct response is to leave `timelockDelay == 0`
(timelock disabled, bypasser surface inert) and rely on the
panic-signer + recovery whitelist alone.

#### 8.3.6 Recovery is NOT timelocked

The recovery whitelist runs in a separate branch of the hooks. Recovery
operations (nonce burn, swapOwner to allowlist, disableModule,
removeLockdownSigner) execute WITHOUT going
through the timelock check. Reason: layering a timelock on top of an
already-narrow recovery whitelist would either block recovery entirely
or require pre-announcing every possible recovery op.

**Exact code ordering (auditor cross-check)**: `checkTransaction` first calls
`getState(msg.sender)`. `LockedDown` reverts; `Recovering` enters the refund-zero
gate and narrow recovery whitelist; `Normal` enters the bypass-meta-call or
`_verifyOwnerTimelock` path. This remains true after auto-resume because
lifecycle decisions use `getState`, not a raw-scalar predicate; a later
`setResumeDelay` can clear the elapsed incident fields. Ticket consumption happens
in the success-gated post-hook (INV-TIME-4). `removeLockdownSigner` during
Recovering therefore executes independently of `cfg.timelockDelay`. The module
path during Recovering reverts unconditionally and never enters the timelock
check either. Codified as INV-TIME-6 in SPEC §11.

#### 8.3.7 TTL: 90 days + permissionless sweep

A ticket expires `executableAt + 90 days` after scheduling. Past this,
the hook reverts `TicketExpired`. The entry stays in storage
because the revert rolls back any in-function delete. Two ways to
reclaim the slot:

1. **Safe quorum** can `cancelTransaction(safeTxHash)` (owner-path) or
   `cancelModuleTransaction(...)` (module-path) at any time, including
   on still-fresh entries. Gated by `onlyInitialized`; Normal-only in
   practice because the incident-state hook whitelist never lets a
   cancel self-call through during LockedDown/Recovering.
2. **Anyone** can call `sweepExpiredOwnerTicket(safe, safeTxHash)`
   or `sweepExpiredModuleTicket(safe, moduleTxHash)` once the entry is
   past its 90-day TTL. No `msg.sender` gate, no
   state gate; reverts `TicketNotExpired` if still fresh, reverts
   `TicketNotFound` if no entry exists. Emits `TicketSwept` so
   indexers can tell sweeps from cancels.

The sweep is the long-term storage hygiene mechanism: any external
janitor / MEV bot / forensics tool can run it without coordination with
the Safe quorum. Cost is whatever gas the caller pays; benefit is a
freed storage slot on the singleton. The Safe never pays for sweeps.

#### 8.3.8 `PasswordVerifier` + timelock interaction

`triggerLockdown(...)` is called DIRECTLY on the singleton by the panic
holder (any EOA holding the password). It does NOT go through
`Safe.execTransaction`, so the Safe's guard hook is NOT involved and the
timelock layer never sees it. Concretely:

- **Trigger is never timelocked**, regardless of `cfg.timelockDelay`.
  The password verifier runs as soon as the EOA can land the tx
  on-chain. Mempool leak of the password preimage happens at trigger
  time exactly as on a no-timelock Safe.
- **Trigger is never bypassable either**, because the HSM bypasser
  only writes owner-path tickets. No bypasser interaction
  exists for the trigger path.

What the timelock DOES change for a password-armed Safe:

- **Quorum admin around the password identity** (registering /
  removing / rotating the signer) is owner-path and goes through the
  timelock once
  `timelockDelay > 0`. Plan registration BEFORE enabling the timelock
  (no waiting), or wait the delay on a per-registration basis.
- **Pending owner-path tickets freeze across a lockdown**. If
  the quorum had scheduled an unrelated tx and the lockdown trips
  before execution, the ticket stays in storage but is
  unreachable: INV-TIME-6 says the hook's recovery branch never
  consults the timelock. After resume, the ticket is consultable
  again if still within TTL; otherwise the quorum must
  `cancelTransaction` post-resume to reclaim the slot.
- **Post-incident re-arm is timelocked**. The quorum must schedule
  the new `addLockdownSigner(passwordVerifier || newCommitment)` call, wait
  `timelockDelay`, then execute. The Safe is dormant during the wait
  (SafeDormant event if it was the last signer). For Safes that
  expect frequent re-arms (drills + incidents), keep
  `timelockDelay` short or leave it at 0 for the panic-primitive-only
  deployment mode.

Quick mental model:

> The timelock is a **policy layer on owner-path admin**. The trigger
> sits BELOW that layer (direct singleton call). Recovery operations
> sit BESIDE that layer (separate hook branch). So an active timelock
> never delays a panic, never delays recovery, and only ever delays
> the Safe's general owner-path traffic.

#### 8.3.9 Signer-identity security ranking (V1)

V1 supports a native 20-byte ECDSA/ERC-1271 identity plus pluggable ERC-7913
verifier-based identities, and reserves room for more. They differ materially
in adversarial robustness. Operators MUST consult this ranking before
registering a signer identity, and the runbook MUST document which identity
type each registered signer uses.

#### Tier 1: 20-byte ECDSA / ERC-1271 identity (recommended default)

- **Signature material is non-secret** once produced. Mempool
  observation cost is zero.
- **Hash-bound**: native ECDSA (via `SignatureChecker`) checks
  `ecrecover(digest, v, r, s) == identityAddress` so the signature is bound
  to the exact EIP-712 message digest. Frontrunning the trigger does NOT let
  an attacker pick a different `reasonHash` (the legitimate signer's signature
  would be invalid against the attacker's digest).
- **Drillable safely**: a real drill burns the signer (as for any
  identity) but does not leak any secret. Re-arm with a fresh
  panic-EOA address; the old signature stays unusable because the
  burnt identity is permanently blocked.
- **No on-chain leakage** of the panic device's private key.
- **Operational ask**: a single hardware wallet (Ledger, Trezor) per
  panic signer. Even a printed paper-wallet EOA used once is
  acceptable; the burn semantics make rotation cheap.

Register signers of this type first. Reach for tier 2 only if a
hardware wallet is genuinely unavailable.

#### Tier 2: `PasswordVerifier` (least secure, conditional use only)

- **Signature material IS the cleartext password.** It appears in the
  calldata of every `triggerLockdown` call (mempool, RPC providers,
  block explorers all see it before inclusion).
- **NOT hash-bound**: the `hash` parameter is ignored. A leaked
  password lets a frontrunner submit a competing trigger with a
  different `reasonHash` for the same Safe in the same block. The
  functional outcome is identical (Safe locked, signer burnt) but the
  on-chain `reasonHash` may not be the legitimate one. Forensic /
  audit trails suffer.
- **Commitment is publicly indexable** via `LockdownSignerAdded`
  events (the emitted `signer` bytes are `passwordVerifier || commitment`).
  Low-entropy passwords can be brute-forced offline against
  the emitted commitment. Operator MUST use ≥ 80-bit entropy
  passwords (diceware 6-8 words, or 12+ char random alphanumeric).
- **No cross-Safe AND no cross-chain reuse**: the commitment leaks via
  events, so any password reused across Safes lets one compromise locate
  all of them. The same applies across CHAINS: `PasswordVerifier` ignores
  the EIP-712 digest, so the `DOMAIN_SEPARATOR` chainId does NOT block
  replaying an observed cleartext trigger onto the same-address Safe on
  another chain (T-PWD-CROSS-CHAIN, SPEC_V1 §14.1). A password commitment
  is unique per Safe and per chain, no exception.
- **Drills consume the password permanently** AND the on-chain
  `signerBurntPermanently` set (V1 INV-SIGN-7, C4) enforces this:
  re-registering the same commitment reverts
  `LockdownSigners_BurntPermanently`. Rotate to a fresh password every cycle,
  no exception. Operationally, the runbook MUST treat each cycle's
  password as one-shot.
- **CRITICAL hard obligation - revert-before-burn leak (C5,
  T-PWD-LEAK-BEFORE-BURN)**: any `triggerLockdown` that REVERTS after the
  preimage is already in mempool calldata but BEFORE the burn leaks the
  password without consuming the identity, so it can be replayed while the
  identity is still in `cfg.signers`. Since PR #59 (`triggerLockdown` is
  `onlyInitialized`), submitting during LockedDown / Recovering
  no longer reverts - it SUCCEEDS and burns the identity (extending/re-locking),
  so the old "already-in-incident" leak case is gone. The remaining
  revert-before-burn cases are: a preimage submitted with a wrong/mismatched
  `signature` (`BadSignature`, burn rolled back), an unregistered/already-burnt
  identity (`NotLockdownSigner`), or an uninitialised Safe (`InvalidState`; a
  moot case since no identity is registered). **Containment runbook**: if a
  password trigger reverts for ANY reason, treat the password as fully
  compromised; immediately call `removeLockdownSigner(passwordVerifier ||
  commitment)` during Recovering (allowed per H.4), or in Normal.
  The INV-SIGN-7 burnt-identity gate then prevents accidental re-use.
- **No safe `testSigner` calls**: invoking
  `Lockdown.testSigner(passwordVerifier || commitment, hash, password)`
  would leak the password to the RPC provider. Use ONLY with a
  throwaway test password, never the real one.

Register a `PasswordVerifier` signer ONLY when:

1. No hardware wallet is available AND
2. The operator has read this section in full AND
3. The runbook flags this signer as "weak / one-shot / rotate
   after any use" AND
4. The Safe quorum is comfortable with the audit-trail risk.

#### Tier 3: candidate verifiers (NOT YET PRODUCTION-APPROVED)

The following require independent audit before a Safe should
register signers that use them:

- **`WebAuthnVerifier`** (P-256 passkey, hash-bound). The code ships
  in-repo (`src/verifiers/WebAuthnVerifier.sol`, a thin wrapper over
  OZ WebAuthn/P256, 10 unit tests) and is in audit scope. It will
  rank with the native ECDSA identity once its clientDataJSON parsing has
  been fuzzed against real multi-vendor assertions (Apple, Google,
  Yubico) and the audit signs off.
- **Salted password verifier** (binds password to Safe `nonce` via
  enclave-mediated salt + hash). Not yet written. Replaces
  `PasswordVerifier` for serious operations; requires a TEE backend
  service.

Until then, the native 20-byte ECDSA identity remains the only "good" default.

#### Quick operational rule

> If you can carry one extra hardware wallet, use a 20-byte ECDSA identity.
> Use `PasswordVerifier` only as the absolute last-resort emergency
> identity, with a freshly generated high-entropy password
> per-incident.

---

## 9. Failure modes acknowledged in the design

These are mentioned for completeness. Each is intentional and
documented in `specs/SPEC_V1.md` §14.

- **Buggy / always-magic verifier**: a verifier that returns the magic
  value on inputs it should reject grants lockdown authority to whoever
  can call trigger against a registered signer under it. There is no
  on-chain verifier-approval step or smoke test to catch this; pre-use
  vetting is off-chain preflight plus the `testSigner` view. Once
  registered, the mitigation is to remove every affected signer identity
  via per-signer `removeLockdownSigner` (allowed in Normal and, via H.4,
  during Recovering), batched through native MultiSend.
- **Forked chain / cross-chain replay for hash-bound signers**: the EIP-712
  domain separator tracks the current `block.chainid` (OZ `EIP712` recomputes
  it on a fork), so pre-fork signatures fail to verify post-fork for native
  ECDSA / ERC-1271 and other hash-bound verifier identities. `PasswordVerifier`
  is the explicit exception: it ignores the digest and therefore has the
  separate cross-chain replay obligations described in §8.3.9.
- **1-of-N griefing trigger by any registered signer**: any single
  registered signer can lock the Safe. This is the design intent.
  Mitigated by registering only trusted parties.
- **Post-resume zero-signer window**: removing the last signer during
  Recovering is allowed by design. The quorum can resume into a
  "dormant" Safe with no panic capability until they re-arm.
  `SafeDormant(safe)` event fires on EVERY transition to `signersCount
  == 0` (H.15) so monitoring catches the state and can page oncall.
  The quorum re-arms by registering a fresh signer identity after
  resume.
- **Multi-Safe operations from one quorum**: cross-Safe signer reuse
  requires per-Safe registration. By design (INV-ISO-1).
- **Drills consume signers**: a real drill produces a real burn. Slots
  reclaim on remove/burn, so drills are unlimited in count but cost
  one cycle of `lockdownDuration + resumeDelay` per drill (and one
  fresh registration to re-arm). The `testSigner` view (H.17)
  exists to dry-run the signer-verification piece without the lockup.
- **No `cancelLockdown` / unilateral unlock**: a false-positive trigger
  costs `lockdownDuration + resumeDelay`; since PR #59 remaining signers
  can re-trigger to extend/re-lock (bounded by `≤ (remaining signers) ×
  lockdownDuration`, INV-LIFE-2). No "owner override".
- **No emergency owner / pauser / proxy / upgradeability**: no mutable
  code on the trust path. **Migration takes TWO owner transactions, not
  one, and has an unavoidable fail-open window (corrected 2026-08-25).**
  The earlier "single MultiSend to switch `setGuard` and `setModuleGuard`"
  is wrong twice over: it leaves the NEW singleton uninitialised, so both
  the owner and module paths fail open under it and a live incident on the
  old singleton no longer freezes execution; and no single transaction can
  do the complete job, because the old singleton's pre-hook requires any
  new fallback handler to be bound to ITSELF while the new singleton's
  `initialize` requires all three slots to point at the NEW one.
  The real procedure is:
  1. `MultiSend[setGuard(B), setModuleGuard(B)]` - checked by A. After
     this and until step 2 lands, owner-path and module-path execution are
     governed by nobody. Still enforced meanwhile: the ERC-1271 freeze
     (handler H_A is still installed and still reads A) and B's
     uninitialised module branch, which still denies a module reaching the
     singleton or touching the guard slots.
  2. `MultiSend[setFallbackHandler(H_B), B.initialize(...)]` - checked by
     B, and it only passes BECAUSE B is uninitialised. The transaction that
     restores protection is itself unguarded.
  Before step 1, remove the old singleton's lockdown signers: A keeps a
  live `Normal` config and a live burnable panic signer for the Safe
  forever otherwise. Pinned by `test/poc/SafeIntegrationLifecycle.t.sol`.
