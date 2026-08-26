# Lockdown V1 - Singleton + EIP-7913 Verifier Design Specification

Status: v1.0.0 Solidity audit candidate
Author: Runtime Capital
Reviewer: external security review (to be confirmed)
Supersedes earlier development iterations. Superseded drafts are not part of
the release tree; this specification and the supplied candidate commit are
authoritative.

> **2026-06-25 refactor note:** the implementation moved from
> `(verifier, key) + signerId` records to a single ERC-7913 signer identity
> `bytes` value. A signer is either a 20-byte EOA/ERC-1271 address or
> `verifier || key`; verification is delegated to OpenZeppelin
> `SignatureChecker.isValidSignatureNow(bytes,bytes32,bytes)`. The EIP-712
> trigger message is now `Lockdown(address safe,bytes32 reasonHash)`.
> `signerId`, `nextSignerId`, `idToLookupKey`, `getSignerById`,
> `getSignersByIdRange`, and the local `ECDSAVerifier` have been removed.
> The normative sections (§1-§13) below have been aligned with this model.
> The **Hardening log** retains its dated, historical entries (H.6 / H.11 /
> H.13 / H.16 / H.17 describe the now-superseded id model); they are kept as a
> record of past review decisions, not as a description of the current code.
> The production deployment target is `src/LockdownTimelock.sol:LockdownTimelock`.
> `src/Lockdown.sol:Lockdown` is the concrete lockdown-only base inherited by
> `LockdownTimelock` and kept testable as a smaller no-timelock guard.

## 1. Goal and scope

`Lockdown` V1 is a dual transaction-guard + module-guard for Safe v1.5.0 multi-sigs, providing an anti-coercion panic primitive. A single deployed contract (the **singleton**) serves an unbounded number of Safes. Each Safe registers a per-Safe list of **lockdown signers**, each of which is an ERC-7913 `bytes` identity: either a 20-byte EOA/ERC-1271 address, or `verifier || key` where `verifier` (the leading 20 bytes) is a contract implementing the ERC-7913 `IERC7913SignatureVerifier` interface (return type `bytes4`, magic value `0x024ad318`) and `key` (the remainder) is the public material (a P-256 public key, etc.).

The guard authority is **exclusively** the explicit list of signer identities the Safe quorum has registered. Safe owners who want lockdown authority must register their EOA as a 20-byte identity explicitly.

The shipped V1 release verifies identities via OpenZeppelin `SignatureChecker`: a 20-byte identity routes natively to ECDSA / ERC-1271 (there is no local `ECDSAVerifier` contract), while a `verifier || key` identity routes to its verifier. `PasswordVerifier` and `WebAuthnVerifier` are the bundled ERC-7913 verifier contracts, each with its own threat model. Future verifiers plug in through the same per-Safe registration flow without re-deploying the singleton.

Threat model: physical coercion, kidnapping, wrench attacks; any registered lockdown signer can trigger lockdown (1-of-N over registered signers); recovery rotates the compromised owners before resume.

V1 introduces **single-use signer semantics**: every successful `triggerLockdown()` deletes the signer entry that authorised the call (burn-on-success). The Safe quorum re-registers signers between incidents (always doable in Normal state). This eliminates replay across the lifecycle and across re-registrations, regardless of verifier type.

This document is the contract for the V1 implementation. Subsequent commits to
`src/Lockdown.sol`, `src/LockdownTimelock.sol`, or their component mixins must
reference the relevant section number from this spec.

## 2. Architectural decisions (locked in)

| # | Decision | Rationale |
|---|---|---|
| 1 | **Singleton multi-Safe** with `mapping(address safe => SafeConfig)` | One audited bytecode protects N Safes while keeping per-Safe storage isolation explicit. |
| 2 | **No equivalence**: lockdown authority is exclusively the explicit `signers` set. Safe owners must register their identity if they want it. | Separates Safe-asset-quorum from lockdown-emergency authority. |
| 3 | **ERC-7913 identity dispatch**: every signer is a `bytes` identity (a 20-byte EOA/ERC-1271 address, or `verifier \|\| key`). Verification is delegated to OpenZeppelin `SignatureChecker.isValidSignatureNow(signer, hash, signature)`, which routes 20-byte identities to ECDSA/ERC-1271 and longer identities to `IERC7913SignatureVerifier(verifier).verify(key, hash, signature)` (checking the `bytes4` magic value 0x024ad318). | Multi-scheme extensibility (ECDSA, WebAuthn, BLS, post-quantum, threshold...) without re-deploying the singleton. EIP-7913 is the emerging Ethereum standard for non-EOA signer abstractions. The magic-value pattern (like ERC-1271) prevents accidental "every-signature-valid" verifiers. |
| 4 | **No verifier-class allowlist**: verifier trust is attached to each explicit signer identity. | Removes a second authorization plane and its bulk kill-switch semantics. A compromised verifier is cleaned up by removing the affected signer identities, which the Safe can batch through MultiSend. |
| 5 | **Single-use signer semantics**: every successful `triggerLockdown()` burns (removes + permanently blocks) the signer identity that authorised the call. | Eliminates mempool replay (the exact identity is burnt on success) and cross-registration replay (a re-registered identity is permanently blocked, INV-SIGN-7). Matches the operational use case "rare panic event, rotate after each". |
| 6 | **EIP-712 typed-data binding**: the signed message is `Lockdown(address safe, bytes32 reasonHash)`, bound to the verifying contract and chain id via the OZ EIP-712 domain. | Cross-Safe replay-safe: a signature for Safe A is a different digest from Safe B. Replay across re-registrations of the same key material is prevented instead by single-use burn + the permanent burnt-identity register (INV-SIGN-7), not by a counter in the message. Clear-signing friendly on modern wallets. |
| 7 | **Slot installation + baseline initialization are atomic; policy configuration is staged**: `initialize(...)` still accepts optional `initialSigners[]`, but the recommended v1.0.0 flow leaves them empty and provisions signers, timelock, and bypassers in later, independently reviewed Safe transactions. | The three Safe slots must never be observably half-wired. Separate policy transactions produce a deliberate dormant setup window, so operators must not resume normal use or call the Safe armed until signer/timelock verification is complete. The optional atomic signer path remains available when a deployment policy explicitly prefers zero dormant window. |
| 8 | **State unified**: `getState(safe)` derives the lifecycle state from `lockdownDuration`, `lockdownUntil`, and `resumeDelay` (single source of truth). | `lockdownDuration == 0` ⟹ Uninitialised; `lockdownUntil == 0` ⟹ Normal; `< lockdownUntil` ⟹ LockedDown; `< lockdownUntil + resumeDelay` ⟹ Recovering; else Normal (auto-resume once the recovery window elapses). No redundant state field to keep in sync. Auto-resume itself performs no storage write, so the elapsed incident fields can linger. A later Normal-state `setResumeDelay` clears them before writing the new delay, preventing a configuration change from resurrecting the old recovery window. Public getters always normalise an elapsed incident to `Normal` / `0` / `bytes32(0)`. |
| 9 | **No upgradeability**, no admin, no pauser, no emergency owner. Each version is its own immutable singleton. Migration = new singleton + per-Safe `setGuard`. **It cannot be atomic (correction, pre-tag review 2026-08-25): it takes exactly TWO owner transactions with an unavoidable fail-open window between them** - the old singleton's pre-hook requires any new fallback handler to be bound to ITSELF, while the new singleton's `initialize` requires all three slots to point at the NEW one, a contradiction inside one transaction. See §8 and `test/poc/SafeIntegrationLifecycle.t.sol`. | Audit corpus stays small and self-contained. |
| 10 | **Vendor strategy**: Safe v1.5.0 surfaces (`ISafe`, `Enum`, `ITransactionGuard`, `IModuleGuard`, `IFallbackManager`, `MultiSendCallOnly`) are imported from the pinned `safe-smart-account` submodule; ERC-165 and EIP-7913 come from OpenZeppelin. | Standard interfaces come from their canonical audited sources rather than hand-inlined copies. The production fallback handler is deliberately Safe-derived and remains `LGPL-3.0-only`; Runtime Capital original sources remain MIT (see §16 and `LICENSING.md`). |
| 11 | **Hard caps**: `MAX_LOCKDOWN_SIGNERS = 32`, `MAX_KEY_LENGTH = 256` bytes. | Bounded storage. Bounded calldata. Prevents grief-by-registration-spam and bounds the cross-key isolation proof. Raised from 16 to 32 in V1 because operator feedback flagged 16 as tight for multi-device + drill rotation. |
| 12 | `safe` indexed in **every** event. `SafeLockedDown` includes the raw `signer` identity bytes that were burnt and the `reasonHash`. | Off-chain watchers can attribute every lockdown to a specific identity; the event carries the full identity, so forensics needs no reverse map. |

### 2.1 Component decomposition

The production singleton `LockdownTimelock` is assembled from small,
single-responsibility mixins so each storage domain and its invariants can
be reviewed in isolation. Inheritance graph:

```
LockdownTimelock              src/LockdownTimelock.sol      concrete V1 singleton
  is Lockdown, Timelock
   |
   +-- Lockdown               src/Lockdown.sol              lockdown-only base (concrete)
   |     is ITransactionGuard, IModuleGuard, EIP712,
   |        LockdownSigners, RecoveryOwners, StateMachine
   |         |
   |         +-- StateMachine      src/base/StateMachine.sol
   |         +-- LockdownSigners   src/base/LockdownSigners.sol
   |         +-- RecoveryOwners    src/base/RecoveryOwners.sol
   |
   +-- Timelock                src/base/Timelock.sol
```

Each component owns its own `mapping(address safe => ...)` and reads or
writes only `msg.sender`'s slot, never another Safe's (the decision #1
singleton-multi-Safe isolation):

| Component | Kind | Owns (per-Safe storage) | Responsibility |
|---|---|---|---|
| `StateMachine` | abstract | `SafeConfig` (`resumeDelay`, `lockdownDuration`, `lockdownUntil`, `lockdownReasonHash`) in `_configs` | Derives the 4 lifecycle states (`getState`, decision #8) and exposes the `onlyUninitialised` / `onlyInitialized` / `onlyNormal` / `onlyNotLockedDown` gates. Single source of truth for the lifecycle scalars. |
| `LockdownSigners` | abstract | `_signers` (`EnumerableSet.BytesSet`) + `_burnt` register | ERC-7913 signer registration / removal / rotation, single-use burn-on-trigger, and the permanent burnt-identity block (INV-SIGN-7). |
| `RecoveryOwners` | abstract | `_owners` (`EnumerableSet.AddressSet`) | The recovery-owner allowlist and the exact-length `swapOwner` target validation used by the recovery whitelist (H.19). |
| `Lockdown` | concrete base | composes the three components + `EIP712` | Both guard hooks (owner-path `checkTransaction`, module-path `checkModuleTransaction`), the EIP-712 `triggerLockdown`, MultiSend-batch parsing, and the recovery whitelist. A complete, deployable lockdown primitive with NO timelock. |
| `Timelock` | mixin | `_timelockConfigs` (`SafeTimelockConfig`) | Per-Safe timelock: owner-path `scheduleTransaction`, module-path `scheduleModuleTransaction`, `cancel*`, `bypassTimelock`, tickets (`executableAt`), TTL `sweep`, and the bypasser allowlist. Self-contained; holds no lockdown state. |
| `LockdownTimelock` | concrete singleton | composes `Lockdown` + `Timelock` | The V1 deployment target. Overrides the guard hooks to fold the timelock schedule / wait / bypass checks into the Normal state, and re-applies the lifecycle gates as overrides. |

The split keeps the lockdown core (`Lockdown` plus its three components) a
complete deployable contract that can be reviewed on its own, with the
timelock layered on top only in `LockdownTimelock`.

## 3. State layout

### 3.1 Singleton-level (immutable / constant)

```solidity
string  public constant VERSION              = "1.0.0";
address public immutable MULTI_SEND_CALL_ONLY;          // canonical per chain

uint64  public constant LOCKDOWN_DURATION_MIN = 1 hours;
uint64  public constant LOCKDOWN_DURATION_MAX = 30 days;
uint64  public constant RESUME_DELAY_MIN      = 4 hours;
uint64  public constant RESUME_DELAY_MAX      = 7 days;

uint256 public constant MAX_LOCKDOWN_SIGNERS  = 32;
uint256 public constant MAX_KEY_LENGTH        = 256;

bytes32 public constant LOCKDOWN_TYPEHASH =
    keccak256("Lockdown(address safe,bytes32 reasonHash)");
```

The whitelist selectors are NOT public constants in the implementation: the
code compares against `IOwnerManager.swapOwner.selector`,
`IModuleManager.disableModule.selector`, `this.removeLockdownSigner.selector`,
and `MultiSendCallOnly.multiSend.selector` (= `0x8d80ff0a`) inline at the check
sites. Same semantics, smaller public surface.

EIP-712 domain handling is inherited from OpenZeppelin `EIP712("RuntimeLockdown", VERSION)`.

The chainId is baked in at deployment; a fork of the chain breaks the domain separator (intentional, anti-replay across chains).

ERC-165 and Safe guard interface IDs are resolved via `type(I).interfaceId` at runtime, not hardcoded.

### 3.2 Per-Safe (`SafeConfig`)

The logical per-Safe state is presented below as one struct for readability.
The implementation splits it across four `private` per-component mappings,
each keyed by the Safe address: `StateMachine._configs` (the four lifecycle
scalars, with `lockdownReasonHash` as the field name for `lastReasonHash`),
`LockdownSigners._signers` / `_burnt`, `RecoveryOwners._owners`, and
`Timelock._timelockConfigs`. The INV-ISO-1 slot-derivation review must be
done against those four mappings, not against a single monolithic struct.

```solidity
struct SafeConfig {
    // Lifecycle
    uint64  lockdownDuration;     // 0 ⟹ Safe is uninitialised
    uint64  resumeDelay;
    uint64  lockdownUntil;        // 0 ⟹ Normal state
    bytes32 lastReasonHash;       // implementation name: lockdownReasonHash

    // Signer management: ERC-7913 signer identities stored as raw bytes.
    // An identity is either a 20-byte EOA/ERC-1271 address or a
    // `verifier || key` blob (verifier in the leading 20 bytes, key in the
    // remainder). No ids, no reverse map: the bytes identity is the key.
    EnumerableSet.BytesSet signers;

    // Recovery
    EnumerableSet.AddressSet recoveryOwnerAllowlist;

    // Timelock V1 (implemented in LockdownTimelock; full semantics in the
    // timelock sub-section)
    uint64  timelockDelay;        // 0 ⟹ disabled (default after initialize)
    mapping(bytes32 ticketKey => uint64 executableAt) ticketExecutableAt;
    mapping(address bypasser => bool) timelockBypassers;

    // Permanent burnt-identity register (INV-SIGN-7): every signer identity
    // ever removed (admin remove, rotate old-half, or successful trigger
    // burn). Re-registering a burnt identity reverts
    // `LockdownSigners_BurntPermanently`. Blocks replay for password-style
    // signers whose preimage becomes public in trigger calldata.
    mapping(bytes signer => bool) signerBurntPermanently;
}

mapping(address safe => SafeConfig) internal _configs;
```

Storage rationale:
- Signer identities are stored as raw `bytes` in an `EnumerableSet.BytesSet`, not as `(verifier, keyHash, id)` tuples. Verification dispatches on the identity shape via OpenZeppelin `SignatureChecker.isValidSignatureNow(signer, hash, signature)`: a 20-byte identity routes to ECDSA / ERC-1271, a longer `verifier || key` identity routes to the ERC-7913 verifier.
- No `id` / `nextSignerId` / `idToLookupKey`: the bytes identity itself is the storage key, and the set provides enumeration (`getLockdownSigners`), so off-chain forensic tooling resolves signers directly without a reverse map.
- `key` is never stored on its own: an ERC-7913 identity carries the (bounded, ≤ `MAX_KEY_LENGTH`) key inline in the `bytes`, and the set entry size is bounded by `MAX_KEY_LENGTH + 20`.
- `signerBurntPermanently[signer]`: permanent one-shot register keyed by the identity bytes. Single-use per identity (INV-SIGN-7); a burnt identity can never be re-registered.

`lockdownDuration > 0` is the "is initialised" sentinel. **Every admin function is state-gated by `onlyNormal`**, which reverts `InvalidState(state, 1 << Normal)` unless the Safe is in `Normal` (initialised AND not in an incident): a pre-`initialize` self-call to `setLockdownDuration` (rejected because the Safe is still `Uninitialised`) would otherwise set the sentinel and brick `initialize`. See Hardening log §H.2.

## 4. Lifecycle states (derived)

State is derived from `lockdownDuration`, `lockdownUntil`, `resumeDelay`, and
`block.timestamp`. `getState(address)` is the single public source of truth:
every guard hook and modifier branches on it.

```solidity
enum State { Uninitialised, Normal, LockedDown, Recovering }

function getState(address safe) public view returns (State state, uint64 secondsRemaining) {
    SafeConfig storage cfg = _configs[safe];
    if (cfg.lockdownDuration == 0)                              return (State.Uninitialised, 0);
    if (cfg.lockdownUntil == 0)                                 return (State.Normal, 0);
    if (block.timestamp < cfg.lockdownUntil)                    return (State.LockedDown, cfg.lockdownUntil - uint64(block.timestamp));
    if (block.timestamp < cfg.lockdownUntil + cfg.resumeDelay)  return (State.Recovering, 0);
    return (State.Normal, 0); // auto-resume once the recovery window elapses
}
```

`secondsRemaining` is the lockdown time left in `LockedDown`; it is 0 in every
other state. `Uninitialised` makes the anti-brick fail-open explicit (§7.1): an
unconfigured Safe is `Uninitialised` and the hooks pass through.

Transitions:

- `Uninitialised → Normal`: the Safe self-calls `initialize(...)` (sets `lockdownDuration > 0`).
- `Normal → LockedDown`: any registered signer produces a valid `triggerLockdown(...)` call (sets `lockdownUntil = now + lockdownDuration`).
- `LockedDown → Recovering`: time elapses; `block.timestamp >= lockdownUntil`.
- `Recovering → Normal`: time elapses; `block.timestamp >= lockdownUntil + resumeDelay`. This transition is **purely time-based (auto-resume)**: no transaction, no event, and therefore no storage write. The elapsed incident fields remain until a later `_lock` overwrites them or a Normal-state `setResumeDelay` clears them before applying a prospective delay. There is no explicit resume call.

The recovery whitelist (§7.4) applies only in `Recovering`. There is no way back
from any state other than via these transitions. No `cancelLockdown`. No emergency
owner. No explicit resume: the recovery window simply expires and the Safe is
`Normal` again.

Because auto-resume is event-less, off-chain monitoring MUST compute the
`Recovering → Normal` transition from `lockdownUntil + resumeDelay` rather than
wait for an on-chain signal. The public views are self-consistent - `getState`,
`getLockdownUntil` and `lastReasonHash` all normalise to the auto-resumed Normal
(`0` / `bytes32(0)`) once the window elapses - so reading any of them is safe.
Raw incident fields may linger until the next trigger or delay update.

## 5. Authorisation model

### 5.1 No equivalence

The view `isLockdownSigner(safe, signer)` returns true iff the ERC-7913 identity `signer` is currently registered for `safe`:

```solidity
function isLockdownSigner(address safe, bytes calldata signer)
    external view returns (bool)
{
    return _configs[safe].signers.contains(signer);
}
```

Safe owners are not implicit lockdown signers. Lockdown authority comes only
from the explicit per-Safe `signers` set. The contract does call
`ISafe(safe).isOwner(...)` in the recovery-owner validation path (registration
and hook-time `swapOwner` checks), but those calls only keep the recovery
allowlist disjoint from the active Safe owner set; they do not grant lockdown
authority to Safe owners.

### 5.2 The `triggerLockdown` predicate

```solidity
function triggerLockdown(
    address safe,
    bytes32 reasonHash,
    bytes calldata signer,
    bytes calldata signature
) external onlyInitialized(safe) {
    // Preserve the cheap Unknown rejection before verifier dispatch.
    require(isLockdownSigner(safe, signer), LockdownSigners_Unknown());

    // testSigner is the single verification path for drills and triggers.
    bytes32 digest =
        _hashTypedDataV4(keccak256(abi.encode(LOCKDOWN_TYPEHASH, safe, reasonHash)));
    require(testSigner(signer, digest, signature), BadSignature());

    // Verify first, then remove and permanently burn, then lock.
    _removeLockdownSigner(safe, signer);

    SafeConfig storage cfg = _configs[safe];
    uint64 until = uint64(block.timestamp) + cfg.lockdownDuration;
    cfg.lockdownUntil = until;
    cfg.lastReasonHash = reasonHash;
    emit SafeLockedDown(safe, until, reasonHash, signer);
    // If the burnt signer was the last one, the Safe enters Recovering (and
    // later Normal post-resume) with zero panic capability. Emit the dormancy
    // signal so monitoring catches it without diffing the signer count (H.15).
    if (cfg.signers.length() == 0) emit SafeDormant(safe);
}
```

`onlyInitialized(safe)` rejects only an uninitialised Safe. A registered signer
may trigger from Normal or extend/re-lock an active LockedDown/Recovering
incident (INV-LIFE-2). `SignatureChecker.isValidSignatureNow`
routes a 20-byte identity to ECDSA/ERC-1271 and a `verifier || key` identity to
the ERC-7913 verifier (STATICCALL, checking the 0x024ad318 magic value); any
revert / short / non-magic return maps to `BadSignature`.

Notes:

- There is no verifier-class allowlist. An identity is authorised only if it is currently registered in `signers`.
- Signature verification runs before any signer mutation and delegates to the public `testSigner` source of truth. A registered-identity pre-check preserves the cheap `LockdownSigners_Unknown` rejection. After successful verification, the shared removal helper removes and permanently burns the identity before `_lock`; any later revert rolls the whole sequence back atomically (INV-SIGN-1).
- The burn marks the identity permanently (`signerBurntPermanently[signer]`, INV-SIGN-7): it can never be re-registered, even after resume.
- `SignatureChecker` dispatches the verifier via STATICCALL, so a malicious verifier cannot reenter or mutate state.

### 5.3 Replay analysis

The table is written against a 20-byte ECDSA/ERC-1271 identity (verified directly by `SignatureChecker`). A `WebAuthnVerifier` (tier-3 candidate) identity is hash-bound and inherits the same rows. `PasswordVerifier` (tier 2, §H.18) ignores the digest and has its own replay surface: see T-PWD-REPLAY / T-PWD-MEMPOOL / T-PWD-CROSS-CHAIN.

| Scenario | Replay possible? | Why |
|---|---|---|
| Same signature submitted twice in the same block | No | First wins; second reverts `LockdownSigners_Unknown` because the identity is already burnt. |
| Signature relayed by attacker who intercepted it (mempool, channel) | No (same as above) | First successful submission burns the identity; replays revert. |
| Signature submitted for an uninitialised Safe (`InvalidState`), tried after initialization | Not applicable to a pre-registered identity | An uninitialised Safe cannot yet hold a registered identity. In every initialised lifecycle state, a valid registered signer is accepted and burnt on success. |
| Signer identity removed after signature created | No | `triggerLockdown` requires the exact registered identity; removal reverts `LockdownSigners_Unknown` at trigger time. |
| Re-registration of the same identity after burn | No | A burnt identity can never be re-registered (`LockdownSigners_BurntPermanently`, INV-SIGN-7); a fresh identity must be used. The old signature authorises an identity that no longer exists. |
| Cross-Safe replay (same signer key registered on a second Safe) | No | The EIP-712 `safe` field is in the typed-data digest, so a signature for Safe A is a different digest from the equivalent signature for Safe B. |

Note on verifiers that ignore the EIP-712 message hash (e.g. a preimage-of-commitment "password" verifier): such verifiers have no protection beyond the burn. A preimage revealed in a reverted-before-burn trigger, or a commitment registered on multiple Safes, becomes replayable. V1 ships `PasswordVerifier` as a tier-2 last-resort production primitive with hard operator obligations, not as the default signing path. See Hardening log §H.18 and the T-PWD-* risks.

## 6. External interface

### 6.1 Per-Safe configuration

All admin functions read `msg.sender` as the Safe address. They must be invoked via `execTransaction`. Calls from non-Safe addresses write into the caller's own `_configs` slot - dead state, harmless because the caller will never trigger guard hooks.

```solidity
// An ERC-7913 signer identity is raw bytes: a 20-byte EOA/ERC-1271 address,
// or `verifier || key` (verifier in the leading 20 bytes, key in the rest).

function initialize(
    uint64 lockdownDuration,
    uint64 resumeDelay,
    address[] calldata initialRecoveryOwners,
    bytes[]   calldata initialSigners
) external;

function setLockdownDuration(uint64 newDuration) external;
function setResumeDelay(uint64 newDelay) external;
function addRecoveryOwner(address owner) external;
function removeRecoveryOwner(address owner) external;

function addLockdownSigner(bytes calldata signer) external;
function removeLockdownSigner(bytes calldata signer) external;
function rotateLockdownSigner(bytes calldata oldSigner, bytes calldata newSigner) external;
```

There is no `resumeAfterLockdownPeriodExpired()`: the Safe auto-resumes to
`Normal` once the recovery window elapses (see §4 transitions).

#### Semantics

Scalar/config admin setters (`setLockdownDuration`, `setResumeDelay`, `addRecoveryOwner`, `removeRecoveryOwner`, `addLockdownSigner`, `rotateLockdownSigner`) are gated by `onlyNormal` and revert `InvalidState` unless `_configs[msg.sender]` is in the `Normal` state (in particular they revert when uninitialised, `lockdownDuration == 0`). `removeLockdownSigner` is intentionally broader (`onlyNotLockedDown`) so recovery can neutralise compromised panic identities. Admin setters cannot create the lifecycle sentinel; only `initialize` can. This prevents the pre-`initialize` self-call sequence (`setLockdownDuration(...) → initialize(...)`) that would otherwise brick the Safe, because `initialize`'s `onlyUninitialised` gate would then reject step 2 (the sentinel is already set).

**`initialize`**: one-shot, gated by `onlyUninitialised` (reverts `InvalidState` if `_configs[msg.sender].lockdownDuration != 0`). Enforces:
- `lockdownDuration ∈ [LOCKDOWN_DURATION_MIN, LOCKDOWN_DURATION_MAX]` (1 h floor, INV-LIVE-3 / T-LIVE-2)
- `resumeDelay ∈ [RESUME_DELAY_MIN, RESUME_DELAY_MAX]`
- `initialRecoveryOwners.length > 0` (no `RecoveryOwners_EmptyAllowlist` brick)
- No `address(0)` and no duplicates in `initialRecoveryOwners` (a duplicate reverts `RecoveryOwners_AlreadyRegistered`)
- Each `initialSigners[i]` passes `_validateSigner` (the shape checks listed under `addLockdownSigner` below)
- No duplicate identities in `initialSigners` (the set rejects a duplicate with `LockdownSigners_AlreadyRegistered`)
- `initialSigners.length ≤ MAX_LOCKDOWN_SIGNERS`

After validation, the function registers each identity in the `signers` set and emits one `LockdownSignerAdded(safe, signer)` per registered signer.

`initialSigners` may be empty: the Safe is then in a dormant state. An empty `signers` set means `triggerLockdown` is unreachable until at least one signer is added. When `initialSigners.length == 0` the contract also emits a dedicated `SafeDormant(safe)` event so off-chain watchers can surface this state as a high-severity warning.

**`addLockdownSigner(signer)`**: Safe-gated, `onlyNormal` (reverts `InvalidState` during incident). `_validateSigner` enforces the identity shape:
- `LockdownSigners_InvalidFormat` if `signer.length < 20`
- for a 20-byte identity (EOA/ERC-1271): `LockdownSigners_ZeroAddress` if the address is `address(0)`
- for a `verifier || key` identity (`> 20` bytes): `LockdownSigners_KeyTooLong` if `signer.length > 20 + MAX_KEY_LENGTH`, and `LockdownSigners_VerifierNoCode` if the leading-20-byte verifier has no code

then:
- `LockdownSigners_MaxReached` if the set already holds `MAX_LOCKDOWN_SIGNERS`
- `LockdownSigners_BurntPermanently` if the identity was previously burnt (INV-SIGN-7)
- `LockdownSigners_AlreadyRegistered` if the identity is already in the set

On success: adds the identity to `signers` and emits `LockdownSignerAdded(safe, signer)`.

**`removeLockdownSigner(signer)`**: Safe-gated, `onlyNotLockedDown` (allowed in **Normal and Recovering**; forbidden during LockedDown, when owner-path execution is fully blocked anyway). The Recovering availability is the relock-race mitigation: a quorum that has identified a surviving compromised signer can cull it inside the recovery window, before the auto-resume to Normal re-opens the trigger path. Reverts `LockdownSigners_Unknown` if no entry exists. On success: removes the entry, marks the identity permanently burnt (`signerBurntPermanently[signer] = true`, INV-SIGN-7), and emits `LockdownSignerRemoved(safe, signer)`.

**`rotateLockdownSigner(oldSigner, newSigner)`**: Safe-gated, `onlyNormal`. Atomic remove + add: removes (and burns) `oldSigner`, then adds `newSigner`. The two identities may be of different shapes (e.g. rotate from a `verifier || key` password identity to a 20-byte ECDSA identity in one tx). Reverts as for both component operations. Emits `LockdownSignerRemoved(safe, oldSigner)` + `LockdownSignerAdded(safe, newSigner)` + `LockdownSignerRotated(safe, oldSigner, newSigner)`. The `Rotated` event lets watchers correlate the two without parsing the full event stream.

**`setLockdownDuration` / `setResumeDelay`**: same bounds as `initialize`. Normal only.

**`addRecoveryOwner(owner)` / `removeRecoveryOwner(owner)`**: Normal only (rejected during incident: blocks the pre-signed "add attacker as recovery owner" attack). `removeRecoveryOwner` cannot drop the allowlist count to 0 (`RecoveryOwners_EmptyAllowlist` revert). `addRecoveryOwner` is deliberately idempotent (non-strict): re-adding an existing owner is a silent no-op (no event, no revert), and leaves the intended state. `removeRecoveryOwner` is STRICT since 2026-08-25: removing an address that is not on the allowlist reverts `RecoveryOwners_Unknown`. Rationale: a quorum culling a compromised backup with a mistyped address previously got a successful Safe transaction, an `ExecutionSuccess` and no `RecoveryOwnerRemoved` event, while the compromised backup stayed `swapOwner`-eligible during recovery. The cost is deliberate loss of removal idempotence: a MultiSend cleanup containing one already-absent address reverts atomically and rolls back every later genuine removal, so the operator MUST refresh the allowlist before signing a batched cull. Pinned by `test/poc/VerifierAndGriefing.t.sol::test_regression_removeRecoveryOwnerRevertsOnAnUnknownAddress` and `::test_limitation_strictRecoveryOwnerRemovalRollsBackStaleCleanupBatch`. The strict variants (`RecoveryOwners_AlreadyRegistered` on duplicates) apply only inside `initialize`, where a duplicated initial list indicates an operator error worth failing loudly.

**Return to Normal (auto-resume)**: there is no resume function. Once
`block.timestamp >= lockdownUntil + resumeDelay`, `getState` returns `Normal`
purely on time. No transaction runs at that transition, so the raw incident
fields can linger. The next `_lock` overwrites them; alternatively, a later
Normal-state `setResumeDelay` clears both fields before applying the new delay,
so the update is prospective and cannot resurrect the elapsed incident. Public
getters normalise past the window: `getLockdownUntil` returns `0` and
`lastReasonHash` returns `bytes32(0)`, matching `getState == Normal`. The
`SafeLockedDown` event log remains the durable forensic record, including after
storage cleanup. No `SafeLockdownResumed` event is emitted, so watchers derive
the `Recovering → Normal` moment from `lockdownUntil + resumeDelay`.

### 6.2 Lockdown trigger (already covered in §5.2)

```solidity
function triggerLockdown(
    address safe,
    bytes32 reasonHash,
    bytes calldata signer,
    bytes calldata signature
) external;
```

`signer` is the full ERC-7913 identity bytes; it must already be registered on `safe`. `msg.sender` is the relayer; the contract does not gate on it. Authority comes from the signature.

### 6.3 Guard hooks

```solidity
function checkTransaction(
    address to, uint256 value, bytes calldata data, uint8 operation,
    uint256 safeTxGas, uint256 baseGas, uint256 gasPrice,
    address gasToken, address payable refundReceiver,
    bytes calldata signatures, address msgSender
) external;

function checkAfterExecution(bytes32 txHash, bool success) external;

function checkModuleTransaction(
    address to, uint256 value, bytes calldata data,
    uint8 operation, address module
) external returns (bytes32 moduleTxHash);

function checkAfterModuleExecution(bytes32 txHash, bool success) external;

function supportsInterface(bytes4 interfaceId) external pure returns (bool);
```

All hooks read `_configs[msg.sender]` only. Behaviour detail in §7.

### 6.4 Views

```solidity
function isLockdownSigner(address safe, bytes calldata signer)
    external view returns (bool);
function getLockdownSigners(address safe)
    external view returns (bytes[] memory signers);
function testSigner(bytes calldata signer, bytes32 hash, bytes calldata signature)
    external view returns (bool ok);
function isSignerBurntPermanently(address safe, bytes calldata signer)
    external view returns (bool);
function getState(address safe)
    public view returns (State state, uint64 secondsRemaining);
function getConfigSnapshot(address safe) external view returns (
    uint64  lockdownDuration,
    uint64  resumeDelay,
    uint64  lockdownUntil,
    uint256 signersCount,
    uint256 recoveryOwnerAllowlistCount
);
function isRecoveryOwner(address safe, address owner) external view returns (bool);
function getRecoveryOwners(address safe) external view returns (address[] memory owners);
function lastReasonHash(address safe) external view returns (bytes32);
```

`getLockdownSigners(safe)` returns the full set of registered identity bytes (enumeration via `EnumerableSet.BytesSet`). It replaces the old id-indexed reverse-map readers: incident tooling reads the active set directly, and `LockdownSignerAdded` / `LockdownSignerRemoved` carry the raw `signer` bytes, so indexers need no on-chain reverse map. `isLockdownSigner(safe, signer)` reports set membership for one identity.

`testSigner(signer, hash, signature)` (H.17 view) runs the same `SignatureChecker.isValidSignatureNow` dispatch the trigger path uses, WITHOUT requiring registration and WITHOUT mutating state. It lets an operator dry-run a panic identity (e.g. confirm a freshly provisioned passkey or HSM key signs correctly) before registering it.

**`testSigner` is the ONLY observable that distinguishes an armed Safe from an inert one, and the drill is therefore runbook-mandatory rather than optional (pre-tag review, 2026-08-25).** Registration accepts strictly more than verification requires: `_validateSigner` demands verifier code only for identities longer than 20 bytes, never asks a verifier whether a key SHAPE is usable, and re-checks nothing after registration. A Safe can therefore be fully green on every cheap observable - three slots wired, config initialised, `getState` Normal, `getLockdownSignerCount > 0`, preflight passing - and have NO working trigger. Proven cases, each in `test/poc/ArmedButInert.t.sol`: a 20-byte identity holding non-ERC-1271 code; a codeless 20-byte identity; a key length the verifier rejects; a verifier that lost its code after registration; and an EOA delegated under EIP-7702 (§14.1). `test_limitation_fullyGreenSafeCanHaveNoWorkingTrigger` is the composite. In every one of them `testSigner` returns `false` before the incident, and nothing else does. The drill MUST use the exact EIP-712 trigger digest for that `(safe, reasonHash)`, not an arbitrary hash, or it proves nothing. Caveat unchanged: it is UNSAFE for password / commit-reveal verifiers, where the preimage would leak over RPC - drill those with throwaway material only.

`isSignerBurntPermanently(safe, signer)` (V1, INV-SIGN-7) reports whether the identity has ever been removed, rotated-away, or `triggerLockdown`-burnt on this Safe. It lets the post-resume runbook (§8.3) pre-check whether a planned `addLockdownSigner` would revert `LockdownSigners_BurntPermanently` and rotate to a fresh identity instead.

`getConfigSnapshot(safe)` returns the lifecycle scalars plus the live `signersCount` (= `signers.length()`) and the recovery-owner allowlist count. `getState(safe)` is the single source of truth for the lifecycle state (§4).

All helpers are read-only; none mutates state.

## 7. Guard hook behaviour

### 7.1 Uninitialised Safe (fail-open pass-through)

If `_configs[msg.sender].lockdownDuration == 0`, all hooks return immediately without reverting. Rationale: anti-brick on install-order mistakes. An uninit Safe cannot be triggered into lockdown (`triggerLockdown` is `onlyInitialized` (PR #59), so it still reverts `InvalidState` on an uninitialised Safe), so the pass-through cannot suppress a real lockdown.

### 7.2 Normal mode (`cfg.lockdownUntil == 0`)

- `operation == CALL`: pass.
- `operation == DELEGATECALL`: pass **iff** `to == MULTI_SEND_CALL_ONLY` and `_checkCall(data)` passes; else `DelegateCallDenied`.
- No third operation can reach the named `InvalidOperation` branch with the current two-member `Enum.Operation`: ABI decoding rejects an invalid top-level value and the parser's enum conversion rejects an invalid inner byte first (Panic 0x21). The branch is defensive, not an independently reachable error guarantee.

`_checkCall` is a single recursive routine shared by the top-level owner-path
check and the MultiSend walk. At each level it enforces:
- a `DELEGATECALL` is allowed **only** to `MULTI_SEND_CALL_ONLY` carrying a
  `multiSend(bytes)` payload, into which the routine recurses (nested batches
  are walked to arbitrary depth); any other `DELEGATECALL` target is
  `DelegateCallDenied`;
- a `CALL` is allowed to any target. Inner calls to the calling Safe, the
  singleton, or `address(0)` are NO LONGER rejected at parse time (see §11.7
  for why this is safe given owner-path quorum + scheduled Safe tx review). The
  one CALL the routine still inspects is a `setFallbackHandler(address)`
  self-call (`to == safe`), which must install a `LockdownFallbackHandler`
  bound to this singleton or it reverts `InvalidFallbackHandler` — this check
  applies at every recursion depth;
- the envelope is exactly consumed at each level as a consequence of the loop bounds. The final `offset == transactions.length` check is defence-in-depth: removing that line alone does not weaken the current parser, as demonstrated by historical mutation M7.

**Refund-field asymmetry vs Recovery and bypass-meta (V1, review round 3 documentation)**: the Normal-mode timelock execution path INTENTIONALLY does NOT reject non-zero Safe refund fields (`safeTxGas`, `baseGas`, `gasPrice`, `gasToken`, `refundReceiver`). Recovery rejects them all (`RecoveryRefundDenied`) and the bypass-meta short-circuit rejects them all (`TimelockBypassRefundDenied`, INV-TIME-9). The Normal-mode timelock allows them because:

- Legitimate user bundles routinely set refund fields (Safe relayers, sponsored execution).
- The `safeTxHash` THAT GETS SCHEDULED already binds every refund field via `Safe.getTransactionHash(...)`. A coerced quorum that schedules a draining tx with `gasToken == attackerToken, refundReceiver == attacker` cannot then execute a clean version; the hash would not match.
- The protection is the off-chain operator review of the scheduled safeTxHash: it represents the EXACT params that will execute. Refund fields are part of that hash.

**Operator obligation** (post-resume runbook §8.3 calls this out as a hard obligation, not soft): when the quorum reviews any `TransactionScheduled(safe, safeTxHash, executableAt)` event, the off-chain signer review tooling MUST resolve the hash to the underlying tx params and surface the refund fields. The off-chain review pipeline is what catches `gasToken != 0` / `refundReceiver != 0` configurations; the on-chain guard cannot judge intent. Same obligation Safe v1.5.0 operators carry independently for any non-trivial tx.

Recovery's all-zero gate is justified because recovery actions are a narrow whitelist of pre-defined operations (swapOwner, removeSigner, disableModule, nonce burn) that NEVER legitimately need refund fields. The Normal-mode path has no such whitelist - any user tx is allowed - so a blanket refund-field rejection would break legitimate use.

### 7.3 Locked-down (`0 < block.timestamp < lockdownUntil`)

Both `checkTransaction` and `checkModuleTransaction` revert with `LockedDown`.

### 7.4 Recovering (`lockdownUntil <= block.timestamp < lockdownUntil + resumeDelay`)

This branch covers the `Recovering` state (the hook's `getState`-driven `else`
arm, taken while `lockdownUntil != 0` and the recovery window has not yet
elapsed). Once `block.timestamp >= lockdownUntil + resumeDelay` the Safe is
`Normal` again (auto-resume, §4) and the ordinary Normal-mode policy applies;
there is no separate `Resumable` state and no explicit resume call.

`checkTransaction`:
- `_isRecoveryCall(safe, operation, to, value, data)` must return true; else `RecoveryActive`.
- Reject any non-zero Safe refund field (`safeTxGas`, `baseGas`, `gasPrice`, `gasToken`, `refundReceiver`) with `RecoveryRefundDenied`.

**Ordering with the V1 timelock (INV-TIME-6 restated locally)**: `checkTransaction` branches on `getState` before any Normal-mode `_verifyOwnerTimelock` / `_verifyTicket` call (with ticket consumption deferred to the post-hooks). A Recovering state therefore enters the recovery branch directly. Consequently, every recovery-whitelisted owner-path call (`removeLockdownSigner`, `swapOwner`, `disableModule`, nonce burn) executes immediately even when `cfg.timelockDelay != 0`. There is no second timelock to satisfy during Recovering. Rationale: the timelock is a Normal-mode policy layer; the relock-race mitigation (H.4) MUST be promptly executable inside the recovery window, so any timelock interaction there would defeat the whole point of carving it out. The module-path branch reverts unconditionally during Recovering (`RecoveryActive`) and never sees the timelock either. NOTE (SPEC follow-up): the whitelist is a narrow set of value-less recovery ops, so this carve-out cannot itself move funds; there is no resume call to bundle a normal operation onto (the earlier resume+reconfigure batch bypass therefore does not exist in this design).

The recovery whitelist (`_isRecoveryCall`):
- `operation == CALL` for every whitelisted LEAF. The top-level `operation` MAY also be
  a `DELEGATECALL` to canonical `MultiSendCallOnly`, whose every leaf is re-validated
  through `_isRecoveryCall` at every depth (`Privilege.Recovery` threads through the
  recursion). This is what makes the batched `removeLockdownSigner` cull described in
  the rationale below possible. Pinned by
  `test/poc/RecoveryWhitelistEnvelope.t.sol::test_confirmed_recoveryAcceptsMultiSendDelegateCallEnvelope`.
- `value == 0` is enforced by the guard ONLY on the empty-data nonce-burn arm. The
  `swapOwner`, `disableModule` and `removeLockdownSigner` arms do NOT read `value`.
  No value can nevertheless move, but that is a property of the CALLEES, not of the
  guard: `swapOwner` / `disableModule` are non-payable Safe functions and the singleton
  is non-payable, so such a transaction reverts with EMPTY return data (Solidity's
  non-payable check) rather than with a guard error. The whitelist admits no third-party
  `to`, so there is no payable target to reach. Treat this as an ACCIDENTAL protection:
  a future payable recovery target would silently make it false. Pinned by
  `test/poc/RecoveryWhitelistEnvelope.t.sol` (`test_confirmed_recoveryGuardAcceptsNonZeroValue_*`,
  `test_limitation_recoveryValueBlockedOnlyByNonPayable*`, `test_refuted_recoveryCannotReachPayableTargetDirectly`).
- Either `to == safe` and:
  - `data.length == 0` (nonce burn), or
  - `data` is `swapOwner(prevOwner, oldOwner, newOwner)` with `cfg.recoveryOwnerAllowlist.contains(newOwner) == true` AND `newOwner` is not already a Safe owner (`!ISafe(safe).isOwner(newOwner)`). **Exact** calldata length (`4 + 3*32 = 100` bytes, `0x64`) is required - trailing bytes are rejected to eliminate signer-review tooling ambiguity.
  - `data` is `disableModule(prevModule, module)` (selector + **exact** `4 + 2*32 = 68` bytes, `0x44`). Lets the quorum neutralise a module inside the recovery window; `disableModule` cannot move value, so it is a safe cleanup primitive (the Safe re-validates the arguments and reverts on a bad `prevModule`).
- Or `to == address(this)` (the singleton) and `data` is:
  - `removeLockdownSigner(bytes signer)` (selector + arbitrary ABI tail; the function itself re-validates contents).

`addLockdownSigner`, `rotateLockdownSigner`, `setLockdownDuration`, `setResumeDelay`, `addRecoveryOwner`, `removeRecoveryOwner` remain unreachable during Recovering: the quorum waits for Normal state for anything that creates new authorisation surface.

Rationale: V1 allows `removeLockdownSigner` during Recovering to mitigate the **relock race**. With a strict whitelist that allowed no signer removal, a compromised signer surviving in storage could relock the Safe in the very first block after the auto-resume, before the quorum could remove it. Recovering-time removal cleans up surviving compromised signers atomically inside the recovery window (still gated by owner-path `execTransaction`, so any signer removal requires full Safe quorum). A verifier-class bulk kill-switch is intentionally not present; the Safe can batch multiple per-identity removals via MultiSend. `disableModule` is on the whitelist for the same "regain control / shut a bypass path during recovery" reason and is value-less; the compromised-module threat itself is out of scope (a module is never acquired by accident, and a detected rogue module is disabled directly in Normal without any lockdown).

Selector checks compare `bytes4(data)`; the `swapOwner` `newOwner` argument
is read as the low 20 bytes of the third 32-byte word at a fixed calldata
offset (`_readAddressCalldata(data, 0x50)`), with the exact-length gate
(`0x64`) guaranteeing the offset is in-bounds. Non-zero padding in the upper
12 bytes is NOT rejected by the guard; such a transaction passes the guard
but the Safe itself later rejects it at ABI decoding, so it is a dead end,
not a bypass.

`checkModuleTransaction`:
- Pre-init (H.12) the hook rejects any call targeting the singleton itself (`to == address(this)`) with `ModuleCallToSingletonDenied`; during Normal mode the same denial is enforced inside `_checkCall` (see the next bullet), so a module can never reach the singleton in any state that a call could otherwise pass through.
- During Normal mode (and Uninitialised), the module path is routed through the shared `_checkCall` helper with `allowAdminCalls = false` (the owner path passes `true`; the flag threads through every recursion level). Consequences (normative):
  - a module `CALL` to a non-singleton target is allowed; a `CALL` whose `to` is the singleton reverts `ModuleCallToSingletonDenied`;
  - on EVERY path (owner and module), a `CALL` whose `to` is the singleton and whose selector is one of the four guard hooks (`checkTransaction` / `checkAfterExecution` / `checkModuleTransaction` / `checkAfterModuleExecution`) reverts `GuardHookSelfCallDenied` (H.20): the hooks are internal machinery the Safe invokes around execution and must never be reachable as a user-tx `to`. Otherwise a pre-scheduled owner-path call to `checkAfterModuleExecution(0, false)` could clear the module reentrancy in-flight slot mid-flight and replay a scheduled module ticket (breaks INV-TIME-11);
  - a module `DelegateCall` is allowed ONLY to canonical `MultiSendCallOnly` and is parsed recursively exactly like the owner path; any other `DelegateCall` reverts `DelegateCallDenied`, and a non-CALL/non-DelegateCall op reverts `InvalidOperation`;
  - because `allowAdminCalls = false` propagates into every recursion level, any inner call targeting the singleton inside a module MultiSend batch also reverts `ModuleCallToSingletonDenied` - there is no depth at which a module can administer the Lockdown singleton;
  - a `to == safe` self-call carrying a guard-DISABLE selector - `setGuard(address)` / `setModuleGuard(address)` / `setFallbackHandler(address)` - reverts `ModuleSafeSelfCallDenied` on the module path (H.20). These three are the ONLY Safe self-calls the module path is denied, and they are exactly the ones that could remove the lockdown protection itself: dropping the transaction/module guard, or swapping the fallback handler for a non-freezing ERC-1271 shim. Every OTHER Safe self-call stays ALLOWED on the module path - owner topology (`addOwnerWithThreshold` / `swapOwner` / `changeThreshold`), module management (`enableModule` / `disableModule`), arbitrary module calls. This is a DELIBERATE threat-model decision: in Safe's security model a coerced module in Normal mode already has arbitrary execution power, and as long as it cannot DISABLE the guard, a future lockdown still freezes everything, so the guarantee holds. Constraining that residual module power further is a conscious non-goal - over-constraining the module path would block legitimate module use-cases for no real security gain;
  - `setFallbackHandler` on the OWNER path must still bind a singleton-bound `LockdownFallbackHandler`, else `InvalidFallbackHandler`; on the module path it is denied outright (above). The untrusted module path can therefore never swap the ERC-1271 freeze, while the owner path keeps the flexible on-chain lockdown-awareness check plus off-chain codehash attestation (exact on-chain codehash pinning remains a rejected non-goal, see `V1_NON_GOALS.md`).
- Rationale for the singleton denial: without it, an enabled module could execute `Safe.execTransactionFromModule(lockdown, 0, addLockdownSigner_data, CALL)` (or nest that CALL inside a MultiSend delegatecall) and the singleton would see `msg.sender == safe` and accept the admin write - bypassing the owner-path execTransaction (and therefore the Safe quorum threshold). The singleton must only be administered via owner-path execTransaction.
- During LockedDown / Recovering, the hook reverts unconditionally (`LockedDown` or `RecoveryActive`). Modules are totally disabled until the recovery window elapses and the Safe auto-resumes to Normal. The module path is frozen during the incident because a module executes without signer consensus, so leaving it open would be an unfrozen drain path around the owner-path freeze - not because a compromised module is itself in the threat model (that case is out of scope; see §7.4).

## 8. Install procedure

### 8.1 Required ordering (operator)

Atomic batch via a `MultiSend` `delegatecall` from a single `execTransaction`:

```
1. safe.setGuard(singleton)
2. safe.setModuleGuard(singleton)
3. safe.setFallbackHandler(lockdownFallbackHandler)
4. singleton.initialize(
       duration, resumeDelay, recoveryOwners,
       [
           abi.encodePacked(panicEOA1),   // 20-byte EOA/ERC-1271 identity
           abi.encodePacked(panicEOA2)
           // or `abi.encodePacked(verifier, key)` for an ERC-7913 identity
       ]
   )
```

The initialize call atomically:
- Stores config
- Registers the initial signer identities (one per `bytes` entry)
- Verifies the Safe has already wired the transaction guard, module guard and
  fallback handler expected by this singleton (`LOCKDOWN() == singleton` for
  the handler)

Because the Safe reads the current guard before `checkTransaction`, the install
MultiSend itself is checked by the pre-existing guard (often zero). The three
slot writes and `initialize` then execute sequentially inside that one Safe
transaction, so no external observer can interact with a half-installed state.

### 8.2 Off-chain preflight (mandatory)

Before submitting the install `execTransaction`, the UI / CLI MUST verify by `eth_call`:

| Check | Why |
|---|---|
| `Safe.VERSION() == "1.5.0"` | Guard relies on v1.5.0 module-guard hook. |
| `EXTCODEHASH(singleton)` matches the audited runtime hash for the deployed commit | Anti-T-DEPLOY-1 (same-address, different-bytecode singleton; §14.1). Address alone does not authenticate bytecode. **The preflight/verify scripts FAIL by default if this hash is not supplied** (`--singleton-codehash`); a fake singleton can spoof `VERSION()` and `supportsInterface()`, so an unpinned "green" run is not trustworthy. `--allow-unpinned-codehash` downgrades to a warning for dev/test only. |
| `singleton.MULTI_SEND_CALL_ONLY()` matches canonical for chain | Anti-mis-config. |
| `MULTI_SEND_CALL_ONLY` has `.code.length > 0` AND `EXTCODEHASH` matches the canonical Safe v1.5.0 `MultiSendCallOnly` | Anti-T-DEPLOY-2 (§14.1). Codeless = silent no-op of the DELEGATECALL carveout; non-canonical code = drain in Safe context. **Codehash binding FAILs by default if unsupplied** (`--multi-send-codehash`), same secure-by-default policy as the singleton row. |
| `singleton.supportsInterface(...)` returns true for ERC-165 + ITransactionGuard + IModuleGuard | Fail-fast. |
| `singleton.eip712Domain()` reports the expected verifying contract and chain id | Anti-mis-deployment. |
| Planned `LockdownFallbackHandler` has code, `EXTCODEHASH` matches the audited runtime, and `LOCKDOWN() == singleton` | Anti-half-install and anti-fake-handler. `initialize` enforces the binding on-chain; scripts fail closed when the hash is not pinned. |
| `singleton.getConfigSnapshot(safe).lockdownDuration == 0` | Not yet init. |
| Each planned `initialSigners[i]` is opaque `bytes`: `length >= 20`. A 20-byte identity is an EOA / ERC-1271 address (`!= 0`); a longer identity is `verifier(20) || key`, with `verifier.code.length > 0` (matching an audited immutable verifier runtime hash) and `key.length <= MAX_KEY_LENGTH`. | Anti-malicious-verifier + bounds (`_validateSigner`). |

`scripts/preflight-install-v1.sh` and `scripts/verify-install-v1.sh` are the active pre/post-install verification scripts.

**Deploy manifest (`deploy/manifest.json`)**: the codehash binding is only as
trustworthy as the EXPECTED hash the operator supplies. To avoid hand-typing
32-byte hashes (itself error-prone) and to make the per-chain trust root
reviewable, both scripts accept `--manifest deploy/manifest.json`: they read
`.chains[<chainId>].singletonCodehash` / `.multiSendCodehash` for the live
chain and use them when the explicit `--*-codehash` flags are absent. A
placeholder or missing entry resolves to empty, so the secure-by-default gate
still FAILs (it never passes a bogus hash). `scripts/gen-manifest-codehashes.sh`
prints the chain-invariant build codehashes for the bundled verifiers (PasswordVerifier, WebAuthnVerifier) and, given `--rpc`,
the on-chain codehashes to paste into the per-chain entry. The Lockdown
singleton codehash is per-chain (it bakes the `MULTI_SEND_CALL_ONLY` immutable)
and is read post-deploy.

**Post-install anti-fat-finger checks (`verify-install-v1.sh`)**: beyond the
trust-root binding, verify surfaces two operator-error signals: it WARNs
loudly when `timelockDelay == 0` (the Safe then has NO coercion resistance on
guard removal / signer disarm, INV-LIVE-1 / §14.2), and it prints the
worst-case freeze a single trigger costs (`lockdownDuration + resumeDelay`, in
hours/days) so a transposed or over-sized value is caught before it bites
during a real incident.

### 8.3 Post-resume runbook

Once the recovery window elapses and the Safe auto-resumes to Normal, the Safe quorum MUST immediately:

1. Inspect the burnt signer (from the `SafeLockedDown` event's `signer` identity bytes).
2. Decide: was this a legitimate panic, or coercion? Was the burnt key compromised?
3. If legitimate: re-register an equivalent signer (e.g. a freshly-generated ECDSA burner key bound to the same role).
4. If compromised: do NOT re-register that key material. Register a replacement.

Between resume and step 3/4, the Safe is **unprotected from lockdown** if no other signers were registered. Two operational levers reduce this:

- **Multi-signer install**: register N≥2 signers up-front. Lockdown burns one; the others survive the cycle and are usable immediately after resume. Trade-off: each registered signer is an independent 1-of-N lockdown authoriser (more grief surface).
- **In-recovery cleanup**: if forensics during the recovery window identify a compromised signer, the quorum can call `removeLockdownSigner(...)` via owner-path execTransaction inside the recovery window (V1 hardening, §7.4). This shortens the post-resume "compromised signer still live" window from `lockdownDuration + resumeDelay` to whatever time the quorum needs to assemble inside the recovery window.

If neither lever is acceptable, the operator MUST monitor the auto-resume
boundary and submit `addLockdownSigner(...)` as the first transaction once
`getState` reports `Normal`. There is no resume transaction to bundle or order
ahead of it; the exposed window begins at the time boundary.

**Pre-signed-removal residual (accepted, §17).** Because `removeLockdownSigner` executes without timelock during Recovering, a quorum signature collected under coercion at an idle Safe nonce can be replayed to disarm at a future incident. This is an accepted residual (a fresh-signature requirement was considered and rejected, §17). Operator obligations that neutralise it:
- **Burn the nonce on any suspicion of coercion.** Any Normal-mode tx, or the recovery-whitelisted empty self-call, advances `Safe.nonce()` and permanently invalidates a held pre-signed tx at the old nonce. Treat "we may have signed something under duress" as a mandatory nonce-burn trigger.
- **Rotate the panic signers between incidents.** After each resume + re-register cycle, register a FRESH identity. A stale pre-signed removal then targets a no-longer-registered identity and reverts (`LockdownSigners_Unknown` / `LockdownSigners_BurntPermanently`).
- **Recoverability.** A removal is not a permanent loss: re-register an equivalent signer in Normal (timelocked) after the incident.

## 9. Events

All events carry `safe` as the first indexed parameter.

```solidity
event SafeInitialised(
    address indexed safe,
    uint64  lockdownDuration,
    uint64  resumeDelay,
    uint256 recoveryOwnersCount,
    uint256 initialSignersCount
);

event LockdownDurationChanged(address indexed safe, uint64 newDuration);
event ResumeDelayChanged(address indexed safe, uint64 newDelay);
event RecoveryOwnerAdded(address indexed safe, address indexed owner);
event RecoveryOwnerRemoved(address indexed safe, address indexed owner);

event LockdownSignerAdded(address indexed safe, bytes signer);
event LockdownSignerRemoved(address indexed safe, bytes signer);
event LockdownSignerRotated(address indexed safe, bytes oldSigner, bytes newSigner);

event SafeLockedDown(
    address indexed safe,
    uint64  lockdownUntil,
    bytes32 reasonHash,
    bytes   signer            // the burnt identity bytes; post-burn forensics (supersedes the H.16 keyHash field)
);
// No SafeLockdownResumed event: the return to Normal is purely time-based
// (auto-resume once lockdownUntil + resumeDelay elapses) and runs no transaction.
event SafeDormant(address indexed safe);
// SafeDormant: emitted by initialize when no initial signers AND on every
// subsequent transition to an empty signer set (H.15). See §H.15.
```

## 10. Errors

```solidity
// Registration / signer identity
error LockdownSigners_ZeroAddress();          // 20-byte identity is address(0)
error LockdownSigners_InvalidFormat();        // identity < 20 bytes
error LockdownSigners_VerifierNoCode();       // ERC-7913 verifier (leading 20 bytes) has no code
error LockdownSigners_KeyTooLong();           // identity > 20 + MAX_KEY_LENGTH
error LockdownSigners_AlreadyRegistered();    // identity already in the set
error LockdownSigners_MaxReached();           // set already holds MAX_LOCKDOWN_SIGNERS
error LockdownSigners_BurntPermanently();     // re-registering a burnt identity (INV-SIGN-7)
error LockdownSigners_Unknown();              // identity not registered
error BadSignature();                   // verification failed / short / non-magic / verifier revert
// initialize given > MAX_LOCKDOWN_SIGNERS reverts LockdownSigners_MaxReached()
error RecoveryOwners_ZeroAddress();           // recovery owner is zero
error RecoveryOwners_Invalid();               // recovery owner is sentinel / Safe itself / current owner
error RecoveryOwners_AlreadyRegistered();     // duplicate recovery owner in `initialize` only
                                              // (the public addRecoveryOwner is idempotent, §6.3)
error RecoveryOwners_Unknown();               // reachable since 2026-08-25: the public
                                              // removeRecoveryOwner is strict (§6.3)
error RecoveryOwners_EmptyAllowlist();        // would drop the recovery-owner allowlist to 0

// Lifecycle / state machine
error InvalidState(State state, uint256 expectedStates); // a state-gating modifier failed
error LockedDown();                     // owner/module hook hit during LockedDown
error RecoveryActive();                 // owner/module call not on the recovery whitelist
error LockdownDurationTooLow();
error LockdownDurationTooHigh();
error ResumeDelayTooLow();
error ResumeDelayTooHigh();

// Guard hooks / execution path
error InvalidOperation(uint8 operation);       // defensive branch; invalid enum input is rejected first
error DelegateCallDenied();
error BadMultiSendCallOnlyPayload();
error RecoveryRefundDenied();
error ModuleCallToSingletonDenied();    // module path attempting to administer the singleton

// Install completeness (initialize-time)
error GuardNotInstalled();              // tx-guard or module-guard slot not wired to the singleton
error InvalidFallbackHandler();         // decodable handler whose LOCKDOWN() != singleton
                                        // (a zero/non-contract handler or short calldata may
                                        // revert earlier without this selector, §7.2)
error ZeroAddress();                    // zero-address constructor / setter argument

// Timelock errors are declared in the timelock sub-section: TimelockDisabled,
// TimelockDelayTooLow, TimelockDelayTooHigh, TimelockExceedsLockdownDuration,
// TicketAlreadyExists, TicketNotFound, TimelockNotElapsed, TicketExpired,
// TicketNotExpired, NotTimelockBypasser, BypasserZeroAddress,
// TimelockBypassRefundDenied, ReentrantModuleTimelockExecution.
```

## 11. Invariants (auditor verification targets)

Per-Safe invariants must hold for **every** `safe` independently. Cross-key isolation is the central singleton property to verify.

### 11.1 Cross-key isolation

**INV-ISO-1**: For all `a ≠ b`, no external call with `msg.sender == a` or with any function parameter set to `a` results in a write to `_configs[b].*`.

Includes the V1-specific fields: `signers[b]` (the identity set), `signerBurntPermanently[b][_]`, `recoveryOwnerAllowlist[b]`, and the timelock mappings (`ticketExecutableAt[b][_]`, `timelockBypassers[b][_]`).

Proof technique: read every storage write, confirm the slot derivation includes `msg.sender` (admin), the `safe` parameter of `triggerLockdown` / views (lockdown / views), and never an "other" Safe's address.

### 11.2 Authorisation

**INV-AUTH-1**: `triggerLockdown(safe, reasonHash, signer, sig)` reverts unless ALL of:
- `_configs[safe].lockdownDuration > 0` AND `_configs[safe].lockdownUntil == 0` (enforced by `onlyNormal(safe)`; otherwise `InvalidState`)
- `signer` is currently a member of `_configs[safe].signers` (otherwise `LockdownSigners_Unknown`, raised by the burn helper)
- `SignatureChecker.isValidSignatureNow(signer, digest, sig)` returns true, where `digest = _hashTypedDataV4(keccak256(abi.encode(LOCKDOWN_TYPEHASH, safe, reasonHash)))`. For a `verifier || key` identity this is a STATICCALL to `verifier.verify(key, digest, sig)` that must return the ERC-7913 magic value `0x024ad318`; any other outcome (revert, short return, non-magic return) maps to `BadSignature()`. For a 20-byte identity it is ECDSA / ERC-1271.

**INV-AUTH-2**: Hooks `checkTransaction` / `checkModuleTransaction` only mutate or read `_configs[msg.sender]`.

**INV-AUTH-3**: All admin setters operate exclusively on `_configs[msg.sender]`.

### 11.3 Lifecycle

**INV-LIFE-1**: Auto-resume is purely time-based: `getState` reports `Normal` once `block.timestamp >= lockdownUntil + resumeDelay`, with no transition transaction or storage write. No call may clear an active incident. After the old window has elapsed, a successful Normal-state `setResumeDelay` clears `lockdownUntil` and `lockdownReasonHash` before writing the new delay; therefore a delay update can never resurrect the elapsed incident. Otherwise the raw fields remain until a subsequent `triggerLockdown` overwrites them. Consumers derive lifecycle state from `getState`, not from a raw `lockdownUntil != 0` predicate. Verified by `test_setResumeDelay_afterAutoResume_doesNotReopenRecovery` and `echidna_resumeDelayCannotReopenIncident`.

**INV-LIFE-2**: `triggerLockdown(safe, ...)` is gated by `onlyInitialized` (PR #59): it succeeds in any initialised state (Normal, LockedDown, Recovering) and reverts `InvalidState` only when the Safe is uninitialised. A re-trigger while the Safe is still LockedDown/Recovering re-runs `_lock`, setting `lockdownUntil = block.timestamp + lockdownDuration`. Because `block.timestamp` only advances and `lockdownDuration` is immutable during an incident (INV-LIFE-3), a re-trigger can only push `lockdownUntil` **forward** - it never shortens an active lockdown, and from Recovering it re-locks the Safe back into LockedDown. Once the recovery window has elapsed the Safe has already auto-resumed to `Normal` (no separate Resumable state), so a later trigger simply starts a fresh lockdown. Every trigger still burns one single-use signer (INV-SIGN-7), so the number of re-triggers is bounded by the count of registered signers, and no new signer can be added during an incident (INV-LIFE-3).

**INV-LIFE-3**: `lockdownDuration[safe]`, `resumeDelay[safe]`, `recoveryOwnerAllowlist[safe][_]`, **signer additions and rotations** cannot change while the Safe is in LockedDown or Recovering. Signer **removal** (`removeLockdownSigner`) is the explicit exception: forbidden during LockedDown, allowed during Recovering (and Normal) via `onlyNotLockedDown` (§7.4 rationale).

**INV-LIFE-4**: During Recovering, the only owner-path calls accepted by the hook are: `removeLockdownSigner(signer)` to `address(this)`, plus the documented Safe self-calls (nonce burn; allowlisted exact-length `swapOwner` to a non-owner recovery owner; exact-length `disableModule`).

**INV-LIFE-5**: The module-path hook rejects any call targeting `address(this)` (the singleton) in every state, with error `ModuleCallToSingletonDenied`. The singleton may only be administered via owner-path execTransaction.

**INV-LIFE-6**: Every admin setter is state-gated and reverts `InvalidState` when the Safe is not in the required state (e.g. `onlyNormal` setters reject an uninitialised or incident Safe). Only `initialize` (gated by `onlyUninitialised`) can write the `lockdownDuration > 0` lifecycle sentinel.

### 11.4 Signer single-use

**INV-SIGN-1**: `triggerLockdown(safe, _, signer, _)` verifies through `testSigner` before mutating signer state. On successful verification it removes `signer` from `_configs[safe].signers` and marks it permanently burnt via the shared remove helper before the lockdown state mutation. A failed verification therefore performs no burn, and any later revert rolls the removal back; the burn persists only on success. No other code path removes a signer except `removeLockdownSigner` and `rotateLockdownSigner` (both Safe-gated).

**INV-SIGN-2**: The active signer count is `signers[safe].length()` (an `EnumerableSet.BytesSet`); there is no separately-stored counter that could desync from the set.

**INV-SIGN-3**: `signers[safe].length() ≤ MAX_LOCKDOWN_SIGNERS = 32` at all times (enforced at every add path).

**INV-SIGN-4 / INV-SIGN-5 / INV-SIGN-6** *(obsolete — id model removed 2026-06-25)*: these covered `nextSignerId` monotonicity, per-Safe id uniqueness, and `idToLookupKey` reverse-map consistency. Under the bytes-identity model there are no ids: the identity bytes are themselves the set key, so these invariants no longer apply. Enumeration is provided directly by the set (`getLockdownSigners`).

### 11.5 Verifier/key identity registration

**INV-VER-1**: `addLockdownSigner(safe, signer)`, the add half of `rotateLockdownSigner`, and `initialize`'s initial-signers loop all run `_validateSigner(signer)`, which reverts for `signer.length < 20` (`LockdownSigners_InvalidFormat`), a 20-byte identity equal to `address(0)` (`LockdownSigners_ZeroAddress`), or a `> 20`-byte identity whose length exceeds `20 + MAX_KEY_LENGTH` (`LockdownSigners_KeyTooLong`) or whose leading-20-byte verifier has no code (`LockdownSigners_VerifierNoCode`).

**INV-VER-2**: There is no verifier-class approval bit. The only on-chain authorization check for an identity is its membership in `_configs[safe].signers` (the bytes identity set).

**INV-VER-3**: A successful `removeLockdownSigner` neutralises exactly one signer identity and marks it permanently burnt for that Safe (`signerBurntPermanently[signer]`).

### 11.6 Recovery whitelist

**INV-REC-1**: `checkTransaction` accepts an owner-path tx during Recovering only if every leaf is in the explicit whitelist (§7.4) AND the tx has zero refund fields. Two earlier clauses of this invariant were WRONG against the code and are corrected here (pre-tag review, 2026-08-25):
  - `operation == CALL` is false at the top level: a `DELEGATECALL` to canonical `MultiSendCallOnly` is accepted and every leaf re-validated with `Privilege.Recovery`, including a NESTED `MultiSendCallOnly` delegatecall at any depth (which the guard admits and `MultiSendCallOnly` itself then refuses to execute). Any other `DELEGATECALL` target reverts `DelegateCallDenied`.
  - `value == 0` is enforced only on the nonce-burn arm; see §7.4 for why no value moves anyway and why that protection is accidental rather than enforced.
  Pinned by `test/poc/RecoveryWhitelistEnvelope.t.sol` (16 tests).

**INV-REC-2**: the recovery-owner allowlist (`getRecoveryOwners(safe).length`) cannot fall to zero post-init.

**INV-REC-3**: `checkModuleTransaction` reverts during any non-Normal state.

### 11.7 MultiSend parser

**INV-MS-1**: A successful `_checkCall` over a MultiSend payload implies every inner op is either `CALL` (to any target) or `DELEGATECALL` to `MULTI_SEND_CALL_ONLY` (which is itself recursed into); any other encoded op is rejected by enum conversion before the defensive `InvalidOperation` branch. Every well-formed `setFallbackHandler` self-call at any depth installs a singleton-bound `LockdownFallbackHandler`, and the inner buffer is exactly consumed at every level as a consequence of the per-record bounds; the final equality check is redundant defence-in-depth.

**Scope of the parser (V1, recursive-parser redesign)**:
- The parser INTENTIONALLY does NOT inspect inner `value` fields. Legitimate batches frequently carry per-call `value` (ETH disbursements, treasury sweeps, multi-recipient sends). The outer Safe tx authorisation gate (the quorum signing the bundle) is what bounds value flows; the parser's job is to enforce only the lockdown-relevant rules (no delegatecall escape, fallback-handler binding integrity, envelope integrity).
- Inner non-empty CALLs to the calling Safe, the singleton, or `address(0)` are now ALLOWED. The earlier design rejected them (`SafeSelfCallInMultiSendDenied`) to prevent "admin-selector smuggling". That gate has been removed because, on the owner path, the entire MultiSend bundle is authorised by full Safe quorum (and, when the timelock is active, scheduled and waited as a single `safeTxHash` that binds the exact bundle contents). An inner self-call or singleton admin call is therefore something the quorum could have authorised directly and is fully visible in the scheduled Safe tx the operator reviews; it is not a privilege escalation. Note in particular that `address(0)` inner targets, which Safe's `MultiSendCallOnly` aliases to the calling Safe via `to := or(to, mul(iszero(to), address()))`, are simply treated as self-calls by the recursion (`innerTo == address(0) ? safe : innerTo`) and require no special rejection.
- The two protections that DO remain are the ones the quorum gate cannot reconstruct on its own: (1) no `DELEGATECALL` may escape to a non-`MultiSendCallOnly` target at any depth (`DelegateCallDenied`), preserving the storage-context guarantee; and (2) any `setFallbackHandler(address)` self-call must bind a `LockdownFallbackHandler` pointing at this singleton (`InvalidFallbackHandler`), so a bundle cannot silently swap out the ERC-1271 freeze handler. Both checks recurse, so nesting a hostile item inside a child MultiSend does not bypass them.
- Outer ABI-decode of the `multiSend(bytes)` argument is performed by `_decodeCalldataBytes`, a bounds-checked calldata-slice helper that returns `success = false` (→ `BadMultiSendCallOnlyPayload`) when the declared `bytes` length would overrun the calldata tail, rather than relying on the Solidity decoder to revert. Test `test_multiSendAbiDecodeOverrunReverts` covers this class.
- `bytes4(data)` zero-pads calldata shorter than four bytes. No currently guarded selector ends in `0x00`, so a sub-four-byte prefix cannot forge one; `test_refuted_subSelectorPayloadCannotForgeGuardedSelector` pins the current selector set. Any future guarded selector ending in zero bytes MUST add an explicit length check or a regression test before it is added.

### 11.8 Domain separator

**INV-DOM-1**: the EIP-712 domain is provided by OZ `EIP712`, including the current chain id and singleton address. Cross-chain replay is structurally rejected for hash-bound verifiers because the typed-data digest changes by chain.

## 12. Installation / migration

Lockdown accepts only a Safe that is already running Safe v1.5.0. A v1.4.x ->
v1.5.0 singleton migration is a separate product workflow, is never bundled
with Lockdown installation, and is outside this repository and Solidity audit.

The installation transaction is an atomic owner-path MultiSend that calls
`safe.setGuard(singleton)`, `safe.setModuleGuard(singleton)`,
`safe.setFallbackHandler(lockdownFallbackHandler)`, then
`singleton.initialize(...)`. `initialize` re-checks all three slots and reverts
if the Safe is only partially wired.

That three-slot check is intentionally an initialization predicate, not a
runtime predicate on configuration mutations or `triggerLockdown`. A later
partial removal or reinstallation can therefore degrade coverage while the
singleton's views still report its own state. The operator UI and private
monitoring MUST re-read all three slots periodically and before relying on the
panic path, and MUST propose repair before an incident. During an incident a
valid trigger freezes every path that remains covered: it never rejects merely
because protection is incomplete, and it emits no configuration-warning event
that would reveal a possible escape route to the coercer.

The recommended operational sequence deliberately separates installation from
policy configuration. Install and initialize first; then use distinct,
independently reviewed Safe transactions to provision additional lockdown
signers, activate the timelock, and configure any bypasser. The operator UI must
not describe the Safe as fully armed until the required follow-up transactions
have executed and their on-chain state has been verified.

Before installation, operators can snapshot the Safe's transaction guard,
module guard, and fallback handler slots plus their runtime codehashes. Slot
restoration is then possible in three transactions: (1) remove the Lockdown
module guard and transaction guard, with the transaction guard last; (2)
restore the previous fallback handler while both guards are zero; (3) restore
the previous module guard and then the previous transaction guard last. This
ordering prevents an unknown prior guard from blocking restoration. It is not a
global historical rollback: Safe nonce/events and the singleton's persistent
per-Safe config, burnt identities, incident data, and tickets cannot be erased.

## 13. Audit focus

The V1 review must spend disproportionate time on:

1. **Cross-key isolation (INV-ISO-1)** extended to the V1 mappings (`signers`, `signerBurntPermanently`, `recoveryOwnerAllowlist`, the timelock mappings). Storage layout walk, slot derivation proofs.

2. **ERC-7913 verifier external call surface**. For a `verifier || key` identity the trigger does an external `view` call (via `SignatureChecker` STATICCALL) to quorum-selected verifier code. Even though STATICCALL forbids state mutation, confirm ordinary verifier failure paths map to `BadSignature` and that verification precedes burn. OZ's high-level ERC-7913 branch can copy unbounded return/revert data and make the caller OOG; V1 accepts that behaviour outside the immutable, closed-world, codehash-pinned verifier runtimes shipped by this repository rather than forking `SignatureChecker` or imposing a gas ceiling.

3. **Single-use burn correctness (INV-SIGN-1)**. Confirm a successful trigger removes the identity from `signers` (so subsequent membership checks return false) and marks it in `signerBurntPermanently` (so re-registration reverts `LockdownSigners_BurntPermanently`). Confirm the removal is rolled back on a `BadSignature` revert.

4. **EIP-712 typehash and domain separator**. Confirm the typehash string is `Lockdown(address safe,bytes32 reasonHash)` and matches the function semantics. Confirm OZ EIP712 domain handling binds chain id and verifying contract correctly. Confirm replay safety across re-registrations comes from single-use burn + the permanent burnt-identity register (not from a counter in the message).

5. **Signer identity enforcement (INV-VER-1, INV-VER-2)**. Confirm `triggerLockdown` authorises only an exact registered identity and that per-identity removal fully and permanently neutralises it.

6. **Recovery whitelist tightening (§7.4)**. Confirm the only owner-path singleton self-call accepted during Recovering is `removeLockdownSigner(...)` (H.4). The only Safe-targeted calls are nonce burn, exact-length `swapOwner` to an allowlisted non-owner recovery owner, and exact-length `disableModule`. No `addLockdownSigner`, no `rotateLockdownSigner`, no scalar setters.

7. **Initial signers init flow**. Confirm `initialize` cannot leave a Safe in a partially-configured state if any of the loops revert (entire tx atomically reverts, fine for that).

8. **MultiSend parser**: confirm `_checkCall` recurses into nested `MultiSendCallOnly` delegatecalls and that, at every depth, (a) no `DELEGATECALL` to a non-`MultiSendCallOnly` target passes (`DelegateCallDenied`) and (b) every `setFallbackHandler` self-call binds a singleton-bound `LockdownFallbackHandler` (`InvalidFallbackHandler`). Inner CALLs to the calling Safe / singleton / `address(0)` are intentionally allowed (owner-path quorum + scheduled Safe tx review; §11.7).

## 14. Out of scope / accepted risks

- Direct owner `approveHash(bytes32)` calls outside `execTransaction`. Safe v1.5.0 limitation; watchers handle this off-chain.
- **ERC-1271 authorisations are deferred, not invalidated.** The `LockdownFallbackHandler` makes `isValidSignature` revert throughout LockedDown and Recovering, but a signature produced before OR during the incident validates again at auto-resume if the signing owner remains in the current owner set. Recovery must replace a compromised owner to kill its outstanding signatures; auto-resume without that swap restores them. Token approvals / Permit2 allowances remain directly spendable by the approved spender without touching the Safe's execution paths. Operator obligation: complete owner recovery and minimise standing approvals and open orders. Pinned by `test/poc/Erc1271IncidentSignature.t.sol`; see the handler header and AUDIT_BRIEF accepted-risk register #15.
- 1-of-N griefing lockdown: any single registered signer can trigger. Accepted by design (panic primitive). Recovery rotates the bad signer.
- **Post-resume zero-signer window**: between the auto-resume to Normal and the next `addLockdownSigner(...)`, the Safe has fewer registered signers (often zero) if the incident burnt them. During this window, no lockdown can fire. Mitigation: register multiple signers up-front, or re-register as the first tx once the recovery window has elapsed. Runbook critical.
- **Operational cost of single-use signers**: burn-on-success applies uniformly to every successful `triggerLockdown(...)`, including ECDSA and WebAuthn paths. Any real trigger - real incident, drill, false positive, or accidental click - consumes one signer entry. Re-arming is a Normal-mode quorum transaction (`addLockdownSigner` per identity, or `rotateLockdownSigner` to swap material in place); it cannot be done during Recovering and is not on the recovery whitelist. Operators must size `MAX_LOCKDOWN_SIGNERS`-bounded entries against their expected false-positive / drill rate and budget the quorum cost of re-registration. The contract makes no distinction between identity types here: a passkey entry burns the same way a one-shot password entry does.
- **Permanent administrative burn and identity poisoning**: `removeLockdownSigner` and the remove half of `rotateLockdownSigner` burn the exact identity forever for that Safe. A coerced quorum can therefore pre-burn enumerable future identities. V1 keeps this uniform rule because `PasswordVerifier` ignores the digest and depends on permanent burn for replay defence; a registration epoch would also add an RPC state dependency to emergency signing. The recovery path is fresh ERC-7913 key material. An epoch remains a V1.2 candidate.
- **Post-initialization installation drift**: Solidity does not continuously re-check the Safe's transaction-guard, module-guard and fallback-handler slots. Partial uninstall/reinstall can leave an execution surface uncovered while singleton views still report `LockedDown`. This is detected and repaired privately by the operator UI/monitoring before an incident. `triggerLockdown` deliberately blocks every path it still can and neither fails on incomplete installation nor emits an incident-time warning that would disclose a possible route to the coercer.
- Verifier malicious-by-design or buggy, and registered by the Safe quorum. Two failure modes:
  - **Always-true verifier**: gives anyone lockdown authority for any signer registered under it. Mitigation is operational: register only audited immutable verifier runtimes and treat each signer tuple as explicit authority.
  - **Always-false / selectively-broken verifier**: every legitimate `triggerLockdown` reverts `BadSignature`, so the signer cannot be burnt. The Safe is griefed until the quorum removes the affected signer entries. The contract enforces nothing about verifier correctness; the operator's runbook must include off-chain verifier drills and codehash pinning before registration.
  - **T-VERIFIER-UPGRADE (mutable verifier behaviour after registration, panic-liveness DoS, C3)**: any off-chain codehash check (§8) only observes the verifier at REGISTRATION time. A verifier whose behaviour can change after registration can be made to revert / OOG / return non-magic on a real panic signature. If it is the Safe's only panic identity, the freeze becomes unavailable until the quorum removes and re-registers. The contract cannot detect this. Two distinct mutation vectors, BOTH must be excluded:
    - **mutable code**: an upgradeable proxy (delegatecall to a mutable implementation, or an admin upgrade path). The proxy's own codehash is unchanged across the upgrade, so a pinned-codehash check does NOT catch it.
    - **mutable external state**: even a verifier with IMMUTABLE bytecode is unsafe if its `verify()` path reads mutable external state - e.g. `return IRegistry(REG).isValid(...)`, an oracle read, or a call into a contract whose owner can flip it. Its codehash is constant while its verdict is attacker-controlled (flip to always-false = liveness DoS; always-true = unauthorised freeze).
    Mitigation is operator policy, runbook-mandatory: the supported product domain is limited to the immutable, closed-world verifier runtimes shipped and codehash-pinned by this repository (self-contained: the `verify()` path makes no external calls and reads no mutable state). Third-party, upgradeable or external-state-dependent verifiers may be quorum-authorised by the generic contract, but receive no product behavioural guarantee. The native 20-byte ECDSA / ERC-1271 path is not unconditionally closed-world either: OZ `SignatureChecker` branches on `signer.code.length`, so an EIP-7702 authorisation silently moves a registered EOA identity to the ERC-1271 branch. A registered panic EOA MUST NOT be delegated. Any OOG, revert or invalid result condemns the entire identity; remove/rotate it and do not reuse that verifier.
- WebAuthn verifier is supplied as a verifier contract; production use still depends on audited immutable runtime codehash pinning.
- Privacy: a one-line `eth_getLogs` over the singleton enumerates every protected Safe. Accepted in exchange for singleton UX.
- No `cancelLockdown`. A single false-positive trigger costs `lockdownDuration + resumeDelay`; since PR #59 (`triggerLockdown` is `onlyInitialized`) remaining signers can re-trigger to extend/re-lock, so the worst case is bounded by `≤ (remaining signers) × lockdownDuration + resumeDelay` (INV-LIFE-2). No owner override.
- Hardware-wallet display quality remains operationally critical: `triggerLockdown` has 4 calldata params, including two dynamic `bytes` fields (`signer`, `signature`). The EIP-712 message itself has two fields (`safe`, `reasonHash`). Off-chain UX must clear-sign each field; see `docs/V1_HARDWARE_WALLET_UX.md` and `docs/clear-signing/`.

### 14.1 Deployment-trust threats (multichain same-address)

The on-chain logic trusts the singleton and its `MULTI_SEND_CALL_ONLY` by
**address**; an EVM address does not authenticate bytecode. These are not
state-machine bugs (the contract makes no claim it can audit code at an
address) but they are real failure modes that the deploy manifest, preflight
(`scripts/preflight-install-v1.sh`), and post-install verify
(`scripts/verify-install-v1.sh`) MUST close by binding `EXTCODEHASH`. They
become acute under the intended multichain pattern (one recognisable
singleton address across chains via CREATE2), because a single bad chain
breaks the address-equals-trust assumption operators carry between chains.

- **T-DEPLOY-1 (same-address, different-bytecode singleton)**: a Safe installs
  a guard at the expected singleton address on a chain where that address
  holds attacker-controlled (or simply non-audited) code. Worst case: total
  loss of protection (the fake guard never honours `triggerLockdown` and can
  brick or pass any tx). Mitigation: preflight/verify bind
  `EXTCODEHASH(singleton)` to the audited runtime hash for the deployed
  commit; never trust the address alone.

- **T-DEPLOY-2 (wrong / non-canonical `MULTI_SEND_CALL_ONLY`)**: the immutable
  is baked at singleton construction. Same-address-across-chains (CREATE2)
  forces the SAME immutable on every chain (constructor args are in the
  initcode hash). On a chain where that address is **codeless**, the
  owner-path DELEGATECALL carveout (§7.1) becomes a silent no-op (MultiSend
  bricks, not a drain). On a chain where it holds **non-canonical code**, the
  Safe DELEGATECALLs arbitrary logic in its own context - a full drain after
  coerced owners sign a MultiSend-shaped owner tx. Mitigation: preflight/verify
  require `MULTI_SEND_CALL_ONLY` to have code AND bind its `EXTCODEHASH` to the
  canonical Safe v1.5.0 `MultiSendCallOnly`. Note: same-address singleton
  multichain is fundamentally incompatible with a chain-specific
  `MultiSendCallOnly`; pick one (per-chain singleton address, or a
  cross-chain-canonical MultiSendCallOnly) and verify codehash per chain
  regardless. An on-chain constructor codehash check was considered and
  rejected for V1: it would bake a maintained magic constant into the frozen
  audited contract and brick deployment on any chain whose canonical
  MultiSendCallOnly runtime differs, for marginal benefit over the preflight
  gate (the codeless case is already a no-op, not a drain).

- **T-PWD-CROSS-CHAIN (hash-ignoring verifier reuse across chains)**: EIP-712
  domain separation (chainId + verifyingContract) blocks cross-chain replay
  for verifiers that actually bind the supplied digest (ECDSA). It does NOT
  help `PasswordVerifier`, which ignores the hash (§H.18): the same password
  commitment registered on the same-address Safe on chains X and Y lets an
  attacker who observes the cleartext trigger on X replay a freeze on Y. This
  is the cross-chain extension of the existing no-cross-Safe-reuse obligation
  (see T-PWD-MEMPOOL, §11). Operator obligation: hash-ignoring verifier
  credentials are unique **per Safe AND per chain**; never reuse a password
  commitment across chains. Severity is unauthorised lockdown / DoS (the
  target-chain signer burns), not direct asset loss.

### 14.2 Install / upgrade / removal lifecycle threats

The installed state machine protects both paths, but the windows BEFORE,
DURING, and the act of UNDOING that installation are operator-lifecycle
surfaces, not contract bugs. The shared precondition of the drain variants is
**an already-enabled module**: until the module guard slot is set, a module
call is not intercepted. `scripts/preflight-install-v1.sh` enumerates enabled
modules so the operator vets them first.

- **T-INSTALL-1 (non-atomic / asymmetric install, uninitialised live guard)**:
  if `setGuard(singleton)` is set while `setModuleGuard(singleton)`,
  `setFallbackHandler(lockdownFallbackHandler)` and/or `initialize(...)` have
  NOT run, an enabled module can (a) drain the
  unguarded module path, or (b) call `initialize(...)` on the singleton with
  attacker-chosen recovery owners / verifiers / signers (`msg.sender == Safe`),
  pinning hostile config that the legitimate later `initialize` can no longer
  overwrite (its `onlyUninitialised` gate reverts `InvalidState`). The module-path singleton denial (§H.12)
  only fires once the module guard is installed, so it does not cover the
  setGuard-only window. Mitigation: install atomically in ONE MultiSend -
  `setGuard` + `setModuleGuard` + `setFallbackHandler` + `initialize` (§8.1) -
  so no intermediate
  state is externally observable; `verify-install-v1.sh` FAILs any post-install
  state where the two guard slots disagree, the fallback handler is missing /
  mis-bound, or the config is uninitialised.

- **T-UPGRADE-1 (v1.4.1 module-path gap and upgrade seam)**: Safe v1.4.1 has
  no module-guard hook, so a Lockdown installed there as transaction guard
  leaves the module path structurally unguarded. During an in-place
  v1.4.1 -> v1.5.0 migration (a DELEGATECALL that rewrites the singleton
  slot), module-path protection begins only once the v1.5.0 code path is
  active AND `setModuleGuard(singleton)` has run. Mitigation: do not treat a
  transaction-guard-only v1.4.1 Safe as module-path protected; perform the
  upgrade and `setModuleGuard` atomically before relying on the guarantees.

- **INV-LIVE-1 (timelock protects the liveness of protection itself)**: this
  IS contract-enforced when `timelockDelay > 0`. Every owner-path operation
  that NEUTRALISES protection - removing the guard (`setGuard(0)`, an
  owner-path self-call to the Safe), disarming a panic signer
  (`removeLockdownSigner`), rotating it out (`rotateLockdownSigner`, which
  burns the old identity and invalidates an already-signed trigger for it -
  C2 path 2), or disabling the timelock itself (`setTimelockDelay(0)`), adding an attacker
  bypasser (`setTimelockBypasser`, the meta-disarm), or pre-positioning an
  attacker recovery owner (`addRecoveryOwner`) - is NOT a bypassed
  schedule/cancel meta-call (§7), so it must be scheduled and waited
  `timelockDelay` like any other owner-path tx. In particular `setTimelockDelay`
  is self-protecting: once the timelock is active, turning it off takes a full
  `timelockDelay`, so a coerced quorum cannot first disable the timelock to
  then disarm instantly (only the very first `0 -> N` activation is free,
  because no timelock is yet in force). Adding a signer (`addLockdownSigner`)
  does NOT invalidate an in-flight trigger for an existing identity: it only
  registers a new identity and leaves existing ones untouched (C2 non-working path).
  In Normal mode a coerced quorum therefore cannot instantly strip a Safe of
  its anti-coercion guarantees; the mandatory wait is the window in which the
  off-site party calls `triggerLockdown`, which is NOT an owner-path tx and
  never needs a ticket. With `timelockDelay == 0` this protection is absent
  by design (Normal owner quorum has full Safe authority), so the runbook MUST
  require `timelockDelay > 0` to treat a Safe as coercion-resistant.

  **SCOPE - the timelock does NOT gate the Recovering branch (T-LIVE-2).** The
  guarantee above holds only while the Safe is in Normal mode. The Recovering
  branch (§7.4) deliberately admits `removeLockdownSigner` WITHOUT a timelock
  (so legitimate owners can evict a compromised signer during the recovery
  window). A coerced quorum can abuse
  this to bypass the Normal-mode wait entirely: once ANY lockdown is active -
  whether the attacker self-triggers with a held signer, OR the off-site
  defender triggers in response to the coercion - remaining signers can extend
  or re-lock the incident, but each successful trigger permanently burns one
  identity. Once the finite signer set is exhausted and `lockdownDuration`
  elapses, the coerced quorum can disarm surviving signers during Recovering
  with NO wait; the Safe then auto-resumes to an unprotected Normal state after
  `resumeDelay`. The panic identities are permanently gone before the off-site
  party gets a usable Normal-mode window.

  **INV-LIVE-3 (contract-enforced floor closing the shortcut).** The shortcut's
  cost is `lockdownDuration + resumeDelay` (the time to reach Recovering and
  auto-resume), which must not be cheaper than the `timelockDelay` it bypasses. V1
  enforces `lockdownDuration >= max(LOCKDOWN_DURATION_MIN, timelockDelay)` at
  every mutation point: `initialize` requires `lockdownDuration >=
  LOCKDOWN_DURATION_MIN` (1h); `setLockdownDuration` requires `>=
  max(LOCKDOWN_DURATION_MIN, timelockDelay)`; and `setTimelockDelay(N)` reverts
  `TimelockExceedsLockdownDuration` if `N > lockdownDuration` (to raise the
  timelock above the freeze you must raise `lockdownDuration` first, an explicit
  separately-timelocked decision, not a silent bump). `resumeDelay` is
  deliberately NOT counted - the relation uses `lockdownDuration` alone, the
  conservative choice. Result: the self-induced-lockdown disarm path now costs
  at least `lockdownDuration >= timelockDelay` before Recovering is even
  reached, so the attacker cannot disarm faster than `timelockDelay` on ANY
  path, and an operator can no longer silently configure less coercion
  resistance than the `timelockDelay` they set. Honest residual: this restores
  the wall-clock guarantee (disarm costs `>= timelockDelay`), but the off-site
  party still cannot intervene once a lockdown is active; that is acceptable
  because during the `>= timelockDelay` hard freeze the Safe is fully locked
  (the strongest protection), so the attacker gains no speed by self-triggering.
  Tests: `test_setTimelockDelay_revertsAboveLockdownDuration`,
  `test_setLockdownDuration_revertsBelowActiveTimelock`,
  `test_initialize_revertsBelowMinDuration` (+4 boundary tests), and Echidna
  `echidna_lockdownCoversTimelock`. The HSM bypass (`bypassTimelock`) can accelerate any of these txs;
  HSM off-chain policy MUST refuse bypasses for `setGuard`, `setModuleGuard`,
  `setTimelockDelay(0)`, singleton migration, and all signer mutation
  (`removeLockdownSigner`, `rotateLockdownSigner`)
  - accepted trust model, §5 / Q-Bypass-1. Tests:
  `test_liveness_timelockGatesGuardRemoval_INV_LIVE_1`,
  `test_liveness_timelockGatesSignerDisarm_INV_LIVE_1`,
  `test_liveness_timelockGatesSignerRotation_INV_LIVE_1`,
  `test_liveness_timelockGatesVerifierRevoke_INV_LIVE_1`,
  `test_liveness_timelockGatesTimelockDisable_INV_LIVE_1`,
  `test_liveness_timelockGatesAddBypasser_INV_LIVE_1`,
  `test_liveness_timelockGatesRecoveryOwnerAllowlist_INV_LIVE_1`,
  `test_liveness_panicTriggerStaysLiveDuringDisarmWait_INV_LIVE_1`.

## 15. Future work (V1.x+)

- **Explicit V1 non-goals**. See `docs/V1_NON_GOALS.md` for features that are
  intentionally outside the V1 audit target: minority timelock cancel,
  liveness/deadman recovery, irreversible config freeze, an on-chain
  non-bypassable admin floor, and a richer on-chain timelock queue.
- **WebAuthn verifier (canonical)**. Use OpenZeppelin's `P256` library when stable. Allows phone Passkeys as lockdown signers.
- **Threshold verifier**. M-of-N over an internal mini-quorum (BLS aggregated signature, or N independent ECDSA signatures). Allows "any 2 of 3 family members" to trigger lockdown.
- **Recovery quorum**. Alternative to recovery owner allowlist: M-of-N attestation that owner rotation is legitimate.
- **EIP-7913 chain-id edge cases**. OZ EIP712 handles chain-id changes by recomputing the domain separator. Chain forks during a lockdown remain outside the operational threat model for non-hash-bound verifiers such as passwords.

## 16. Vendor strategy

- ERC-165 (`IERC165`) comes from OpenZeppelin. Safe v1.5.0 surfaces - the guard interfaces (`ITransactionGuard`, `IModuleGuard`), `ISafe`, `Enum`, and `MultiSendCallOnly` - are imported from the pinned `safe-smart-account` submodule (LGPL-3.0), so selectors and the `Enum.Operation` type resolve against the canonical Safe sources at compile time rather than hand-inlined copies. No hardcoded magic numbers. `LockdownFallbackHandler` is the explicit production exception: it is Safe-handler-derived and therefore remains `LGPL-3.0-only`; Runtime Capital original sources remain MIT. See `LICENSING.md`.
- EIP-7913 types come from the pinned OpenZeppelin contracts dependency
  (`@openzeppelin/contracts/interfaces/IERC7913.sol`). The verifier interface
  is `verify(bytes,bytes32,bytes) returns (bytes4)` with magic value
  `0x024ad318`.
- There is no local `ECDSAVerifier` contract: 20-byte EOA / ERC-1271 identities are verified natively by OZ `SignatureChecker`, so the secp256k1 path needs no per-chain verifier deployment. Only `PasswordVerifier` / `WebAuthnVerifier` (and any future ERC-7913 verifier) are deployed alongside the singleton and pinned in the deploy manifest.
- `PasswordVerifier` moved from rejected draft semantics (§H.3) to tier-2 production verifier after the H.18 threat-model hardening. A `MockSecretVerifier` exists under `test/mocks/` for unit and fuzz exercise of the non-ECDSA dispatch path; it is clearly marked test-only and MUST NOT be approved by any production Safe.
- ERC-7913 is Final. The pinned OpenZeppelin interface matches the final
  `bytes4` magic-value interface, so interface-version parameterisation is not
  required for v1.0.0.

## 17. Open questions

These remain to be resolved by the external reviewer at audit kickoff or earlier:
- **§8.3 post-resume window vs in-recovery cleanup - RESOLVED (accepted trade-off, 2026-06-10).** V1 ships with `removeLockdownSigner` allowed during Recovering (§7.4). The pre-signed-removal vector exists (a quorum signature collected under coercion, at an idle Safe nonce, executes the disarm at the next incident's Recovering window with no timelock). **Decision: keep the current design, do NOT require a fresh post-trigger signature.** The vector is fenced by nonce burn, single-use semantics, and signer rotation between incidents.
- **T-LIVE-2: Recovering disarm bypasses the timelock-liveness window (internal review finding, V1) - RESOLVED in-contract (INV-LIVE-3).** The Recovering branch admits `removeLockdownSigner` with NO timelock, so a coerced quorum could convert "timelock active" into "panic identities disarmed" in `lockdownDuration + resumeDelay` rather than `timelockDelay`. The `LOCKDOWN_DURATION_MIN` plus setter guards enforce `lockdownDuration >= max(LOCKDOWN_DURATION_MIN, timelockDelay)`, so the attacker cannot disarm faster than `timelockDelay` on any path. (Since PR #59 `triggerLockdown` is `onlyInitialized` and may re-fire during an incident, but a re-trigger only pushes `lockdownUntil` further out - it delays reaching Recovering and can therefore only SLOW a disarm, never accelerate it, so INV-LIVE-3 is unaffected.)

*Resolved between draft and audit-ready: the earlier "`getSignerById` implementation" question was first closed by a storage-cached reverse map (`idToLookupKey`, Hardening §H.11), then made moot entirely by the 2026-06-25 bytes-identity refactor, which removed ids and the reverse map. Signer enumeration is now provided directly by the `EnumerableSet.BytesSet` via `getLockdownSigners`; see §3.2 and §6.4.*

## Hardening log (post pre-audit review, 2026-06-07)

Two independent reviews and a focused external review informed the following hardening pass. Each item is a concrete behavioural change in `src/Lockdown.sol` and the test suite.

### H.1 ERC-7913 interface: `bool` → `bytes4` magic value

The V1 draft mirrored the ERC-7913 interface returning `bool`. The official EIP returns `bytes4` with magic value `IERC7913SignatureVerifier.verify.selector` (= `0x024ad318`). The mismatch would have made every standard-conformant external verifier appear "always failing" to the singleton, silently breaking the entire panic path.

Changes:
- Historical note: earlier drafts used a local `src/interfaces/IERC7913SignatureVerifier.sol` mirror. Current V1 imports the interface from OpenZeppelin instead; return type is `bytes4`; success is the magic value `0x024ad318`.
- `src/verifiers/ECDSAVerifier.sol` returns `MAGIC` on success and `bytes4(0)` on failure; `MAGIC = IERC7913SignatureVerifier.verify.selector`.
- `Lockdown.sol` exposes `ERC7913_MAGIC_VALUE` (public constant) and compares the verifier return against it.
- Test fixtures updated; verifier-level tests assert `bytes4` magic comparison.

### H.2 Admin setters reject an uninitialised Safe

Earlier V1 drafts checked only `lockdownUntil != 0` (state gate), not `lockdownDuration != 0` (initialised gate). A pre-`initialize` self-call to `setLockdownDuration(...)` would set the lifecycle sentinel and cause `initialize` to revert `AlreadyInitialised`, bricking the Safe permanently.

Changes: every per-Safe admin function (`setLockdownDuration`, `setResumeDelay`, `addRecoveryOwner`, `removeRecoveryOwner`, `addLockdownSigner`, `removeLockdownSigner`, `rotateLockdownSigner`) rejects an uninitialised Safe. Only `initialize` can write the sentinel.

> **Current implementation (post state-machine refactor):** the dedicated `NotInitialised` / `AlreadyInitialised` errors were unified into `InvalidState(State, expectedStates)`. The admin setters above are now gated by `onlyNormal` (which subsumes the initialised check: `Normal` requires `lockdownDuration > 0` AND no active incident), and `initialize` by `onlyUninitialised`. The anti-brick property is unchanged.

### H.3 PasswordVerifier dropped from the release

The original V1 shipped a `PasswordVerifier` that returned magic iff `keccak256(signature) == key[:32]`, ignoring the EIP-712 message hash. This created three concrete replay paths:

1. **Cross-Safe replay**: two Safes with the same password commitment are both authorised by any one preimage broadcast.
2. **Revert-before-burn leakage**: a `triggerLockdown` that reverts after the password is in calldata but before the burn (e.g. an `InvalidState` revert on a duplicate trigger, gas, network) reveals the preimage publicly while leaving the registration live and replayable for any other unburnt entry with the same commitment.
3. **Cross-incident replay**: a password registration that survives a triggered incident on a sibling signer remains usable post-resume by anyone who saw a prior failed broadcast.

The single-use burn only protects the **specific entry** that completed; preimages, once broadcast in cleartext, leak globally.

Decision: drop `PasswordVerifier` from the production release. The `MockSecretVerifier` under `test/mocks/` mirrors the old semantics for unit/fuzz coverage of the non-ECDSA dispatch path but is documented as production-forbidden. The "fast emergency without hardware wallet" UX is recovered with an ECDSA burner EOA (key material the user can carry on a phone or print). Future verifiers (canonical WebAuthn, threshold) plug in via the same per-Safe allowlist when their security analysis is in.

### H.4 Recovery whitelist includes `removeLockdownSigner`

The pre-hardening V1 recovery whitelist allowed no singleton self-call that could cull a signer during recovery. Combined with single-use signer semantics and a multi-signer install, this created a **relock race**: any surviving compromised signer could fire `triggerLockdown` in the very first block after the auto-resume to Normal, before the quorum could schedule a `removeLockdownSigner` call. A patient attacker could iterate this up to the number of compromised signers, multiplying the freeze by `N * lockdownDuration`. The fix is to allow `removeLockdownSigner` throughout Recovering (and Normal), so the quorum can cull surviving signers inside the recovery window.

Decision: extend the recovery whitelist to also accept `Lockdown.removeLockdownSigner.selector` when `to == address(this)`. The function itself is updated to allow execution during Recovering (but not during LockedDown - owner-path execution is blocked entirely in that state). The quorum can now identify and cull compromised signers during the recovery window, before resume re-opens the trigger path. `add` and `rotate` remain Normal-only because their pre-signed forms would be the wrench-attack vector this design exists to neutralise.

**PR #59 update - `triggerLockdown` relaxed to `onlyInitialized`.** `triggerLockdown` is no longer `onlyNormal`; it succeeds in any initialised state (Normal, LockedDown, Recovering). Intended benefit: an operator can EXTEND an active incident on demand - a second panic signal re-locks/extends rather than being forced to pre-commit a long `lockdownDuration`. The canonical flow (runbook §8) is to re-trigger *before* the current window expires: `_lock` sets `lockdownUntil = now + lockdownDuration > now`, so the Safe stays LockedDown continuously and never enters Recovering. Re-triggering *during* Recovering is the safety net for a missed window: it re-locks back into LockedDown. Once the recovery window has fully elapsed the Safe has auto-resumed to Normal (no separate Resumable state), and a later trigger simply starts a fresh lockdown. Consequences for the relock model:

- The relock race is no longer strictly *post-resume*: a surviving/compromised signer can now re-lock from within Recovering too, without waiting for the auto-resume to Normal. During the re-locked hard-freeze the quorum cannot `removeLockdownSigner` (owner-path blocked in LockedDown); it can only cull once the window expires back to Recovering, and `triggerLockdown` is permissionless + single-signer while `removeLockdownSigner` needs quorum, so a determined griefer tends to win each race.
- The worst-case is still **bounded and self-limiting**: each trigger burns one single-use signer (INV-SIGN-7) and no signer can be added during an incident (INV-LIFE-3), so the maximum additional freeze is `≤ (remaining signers) × lockdownDuration`, after which the attacker is exhausted and recovery proceeds. This replaces the pre-#59 bound "a false positive costs exactly one `lockdownDuration + resumeDelay`".
- In the core coercion threat this is not an attacker advantage: a fund-seeking coercer wants the freeze to END, not to be extended, so re-triggering is a pro-victim primitive. The residual is narrow - a pure griefer holding compromised panic keys can impose a bounded recovery delay - and is accepted as the price of on-demand incident extension. Operators size `MAX_LOCKDOWN_SIGNERS` and `lockdownDuration` against this (a smaller `lockdownDuration` re-triggered on demand is preferable to a large fixed one).

### H.5 Module path cannot administer the singleton

In Normal mode, `checkModuleTransaction` accepted any module-initiated call. An enabled module could execute `Safe.execTransactionFromModule(lockdown, 0, addLockdownSigner_calldata, CALL)`; the singleton would see `msg.sender == safe` and apply the admin write, **bypassing the owner quorum threshold**. The spec text required admin via owner-path execTransaction; the implementation did not enforce it.

Decision: `checkModuleTransaction` now reverts `ModuleCallToSingletonDenied` whenever `to == address(this)`, regardless of state or selector. Module-initiated calls to any singleton function (admin, view, trigger) are rejected at the hook. The singleton is administered exclusively via owner-path execTransaction.

### H.6 Superseded verifier-allowlist hardening

Earlier V1 drafts carried a verifier-class approval flag with separate approval and revocation semantics. That design was removed: registration now directly validates only generic verifier address/code and key length bounds, and authority lives exclusively in explicit `(verifier, key)` signer entries.

### H.7 Recovery `swapOwner` exact-length check

`_isRecoveryTransaction` checked `data.length < 4 + 3*32` for the `swapOwner` self-call, rejecting truncated calldata but silently allowing trailing bytes. Signer-review tooling typically displays only the first ABI-decoded arguments; trailing bytes could hide. The fix enforces `data.length == 4 + 3*32` exactly.

### H.8 `SafeDormant` event on zero-signer initialize

`initialize` allows `initialSigners.length == 0` (the Safe quorum may wish to install the guard then provision signers in a follow-up tx). This state is operationally fragile: the guard is fully installed but no trigger can fire. The contract now emits a dedicated `SafeDormant(safe)` event in this case so off-chain watchers and dashboards can surface it as a high-severity warning.

### H.9 Other corrections

- `triggerLockdown` reentrancy comment rewritten: the primary defence is STATICCALL (the verifier is `external view`, so the EVM emits STATICCALL which forbids state mutation in any sub-frame). The pre-tag ordering hardening verifies before removing/burning, then locks; `testSigner` is the single verification source of truth.
- `nextSignerId` spec text aligned with the implementation: "last assigned id", not "next free id". Off-chain tooling computes the next id as `nextSignerId + 1`.
- `getSignerByLookupKey` NatSpec documents the existence convention (`verifier == address(0) ⇒ empty slot`) and explicitly defers the `keccak256(key) == keyHash` re-validation to the off-chain caller.
- Unused Echidna witness `_saw_revoked_trigger_success` either wired to a new invariant or removed.
- Superseded operational drafts are not part of the release tree; the active
  specification and runbooks are authoritative.

### H.10 Superseded on-chain verifier smoke test

The on-chain empty-input verifier smoke test belonged to the removed verifier-approval flow. Current V1 keeps `testSigner(...)` as the explicit drill primitive and leaves verifier-behaviour validation to off-chain tooling and audited codehash pinning.

### H.11 `getSignerById` + reverse map (resolves §17 Q2; adds `getSignersByIdRange`)

V1-draft exposed only `getSignerByLookupKey` and required off-chain incident tooling to replay every `LockdownSignerAdded` / `Removed` event to resolve an event-emitted `signerId` back to its `(verifier, keyHash)`. Under incident stress, that replay is brittle (indexer lag, partial logs, RPC limits).

Decision: introduce an on-chain reverse map `mapping(uint64 id => bytes32 lookupKey) idToLookupKey` in `SafeConfig` (§3.2), maintained alongside `signers` by every add/remove/rotate/burn path. Add the public view `getSignerById(safe, id) → (verifier, keyHash, exists)` (§6.4) that returns the entry in O(1). Cost: one extra SSTORE per `addLockdownSigner` and per `removeLockdownSigner` (and per burn / rotate component). The view cross-checks `signers[lookupKey].id == id` as defence in depth against the astronomically unlikely lookupKey hash collision. Consistency between the two mappings is invariant INV-SIGN-6.

**V1 extension** (forensics paginated reader, resolves "list all signers without `eth_getLogs`"): add the public view `getSignersByIdRange(safe, startId, endId) → SignerEntry[]` (§6.4), which iterates `idToLookupKey` over the requested range and returns one `(id, verifier, keyHash, exists)` per slot. The range is capped at `MAX_LOCKDOWN_SIGNERS = 32` (the active-set bound) so the call is gas-bounded regardless of `nextSignerId`. Reverts: `InvalidIdRange` (`endId < startId`), `IdRangeTooLarge` (`span > MAX_LOCKDOWN_SIGNERS`). Designed for incident dashboards that need a snapshot of the active panic-signer set without depending on indexer freshness. The `SignerEntry` struct and full signature are codified in §6.4.

### H.12 Module-path singleton denial precedes uninit fail-open (C1)

V1-draft `checkModuleTransaction` returned early on `cfg.lockdownDuration == 0` (anti-brick fail-open), and only then enforced `to == address(this) ⇒ revert ModuleCallToSingletonDenied`. Review C1 noted this opens a narrow pre-init bootstrap window: a Safe that has installed the singleton as module guard (`setModuleGuard(address)`) but has not yet been initialised by its owner quorum can have `initialize(...)` (or any other admin function) called from an enabled malicious module via `Safe.execTransactionFromModule(singleton, 0, initCalldata, 0)`. The fail-open returns before the singleton-denied check, the Safe proceeds, and from the singleton's view `msg.sender == Safe`, so the call writes `_configs[Safe]` with attacker-chosen recovery owners, verifiers and signers.

Decision: hoist `if (to == address(this)) revert ModuleCallToSingletonDenied()` to the very first statement of `checkModuleTransaction`, before any state read. The denial is now unconditional in EVERY state (Normal, LockedDown, Recovering, uninit). Anti-brick semantics on the owner path (`checkTransaction`) are unaffected: routine Safe owner traffic does not route through `to == singleton` and uninit owner-path traffic still passes through. This change closes pre-init bootstrap. The corresponding invariant strengthens to "the module path can never reach singleton admin in any state" (INV-LIFE-5 expanded).

### H.13 Removed `IERC7913KeyValidator` registration gate

V1-draft accepted any 1..256-byte key for any approved verifier, deferring shape validation to the verifier's `verify()` implementation at trigger time. Review C2 noted the resulting silent-dormancy footgun: a Safe quorum that registers a key in the wrong encoding for the chosen verifier (canonical example: `abi.encode(panicEOA)` 32 bytes instead of `abi.encodePacked(panicEOA)` 20 bytes for ECDSAVerifier) gets a signer that LOOKS armed (`signersCount > 0`, no `SafeDormant` event, indexer-visible `LockdownSignerAdded`) but reverts `BadSignature` every time the panic fires. The discovery window is the incident itself, which defeats the model.

Initial remediation introduced a local optional `IERC7913KeyValidator` sibling interface and a best-effort registration-time STATICCALL. That local extension has been removed after review: it is not part of ERC-7913, adds a second verifier interface, and duplicates responsibility that should live in registration tooling and verifier-specific tests.

Current decision: Lockdown only enforces generic key bounds (`1..MAX_KEY_LENGTH`) at registration. Key-shape correctness is an off-chain/operator-tooling obligation, and malformed keys fail at trigger time through the verifier's ERC-7913 `verify(...)` result, normalised by Lockdown to `BadSignature()`. Production registration tooling SHOULD validate known verifier wire formats before submitting Safe calldata:

- ECDSA: 20-byte packed address, non-zero.
- Password: 32-byte non-zero commitment.
- WebAuthn: 64-byte `qx || qy` P-256 public key, with verifier-specific fixture validation.

This deliberately removes the on-chain `InvalidKeyShape` path and the extra registration-time STATICCALL. The remaining mitigation for accidental inert signers is preflight tooling plus drills using `testSigner(...)` before and after signer registration.

### H.14 Superseded bulk verifier revoke

The earlier bulk verifier revoke was removed with the verifier allowlist. Recovery keeps only per-identity `removeLockdownSigner(...)`; a Safe can still remove every identity for a compromised verifier in one Safe transaction by batching the individual removals through MultiSend.

### H.15 `SafeDormant` emitted on every `signersCount == 0` transition (Gap 3 / C dormant)

V1-draft emitted `SafeDormant` only inside `initialize` when `initialSigners.length == 0`. A real-incident path that drove `signersCount` to zero (last signer removed during Recovering, last signer burnt at trigger time) emitted nothing, so monitoring had to diff `signersCount` across blocks to catch the dormant state. The "armed-looking but dead" Safe is exactly the failure mode the dormancy signal is meant to surface.

Decision: emit `SafeDormant(safe)` whenever `cfg.signersCount` reaches zero by ANY path:

- inside `initialize` when `nSigners == 0` (the original H.8 case);
- at the end of `removeLockdownSigner` (external wrapper, NOT the internal `_removeLockdownSigner` used by `rotateLockdownSigner` so the transient zero-state inside an atomic rotate is not surfaced as a false positive);
- at the end of `triggerLockdown`, after the burn and after `SafeLockedDown` (see the §5.2 snippet), so a watcher who only watches `SafeDormant` for paging gets the signal in the same transaction as the burn.

Cost: 3 extra conditional `emit` opcodes; ~50 B runtime.

### H.16 `keyHash` in `SafeLockedDown` (Gap 4, post-burn forensics)

V1-draft `SafeLockedDown` emitted `(safe, signerId, verifier, lockdownUntil, reasonHash)` only. Because the burn-on-trigger deletes both `signers[lookupKey]` and `idToLookupKey[signerId]`, a watcher (or incident-response indexer) that missed the original `LockdownSignerAdded` event could not resolve `(signerId, verifier)` back to the actual `keyHash` of the burnt entry without replaying the full historical log. Forensic / legal / insurance teams investigating "which device fired the panic?" lost the audit trail.

Decision: add a trailing `bytes32 keyHash` field (non-indexed; the event already has 3 indexed slots which is the topic cap). `triggerLockdown` captures `s.keyHash` into a local before `delete cfg.signers[sid]` and emits it. The `(signerId, verifier, keyHash)` triple is now derivable from this single event, with zero historical-log replay required.

Cost: 1 extra `MLOAD` + 32 bytes of log data per trigger. Off-chain consumers update their ABI subscription to the new event signature `SafeLockedDown(address,uint64,address,uint64,bytes32,bytes32)`.

### H.17 `testSigner` view (Gap 9, pre-approval drill primitive)

V1-draft offered only an empty-input private helper and no direct drill primitive. A quorum vetting a candidate verifier (e.g. a new WebAuthn implementation, a candidate MPC scheme) could not exercise the verifier with real `(key, hash, signature)` material. Drilling a registered signer end-to-end was also expensive: a real `triggerLockdown` burns the slot and locks the Safe for `lockdownDuration + resumeDelay`.

Decision: add the public view

```solidity
function testSigner(
    address verifier,
    bytes calldata key,
    bytes32 hash,
    bytes calldata signature
) external view returns (bool ok, bytes4 returnedMagic);
```

that replicates `_runVerifier` semantics (STATICCALL with revert normalisation) but returns `(ok, returnedMagic)` instead of reverting and never touches singleton state. It is safe for ECDSA-style and WebAuthn verifiers (signature material is non-secret once produced); UNSAFE for password / commit-reveal verifiers, where the secret would leak over RPC. `PasswordVerifier` (§H.18) ships with exactly this restriction documented: test it only with a throwaway password, never the real one (runbook §8.3.9 tier-2 obligations).

This is NOT a `simulateTriggerLockdown` (no burn skip, no `lockdownUntil` skip): it tests the verifier-only piece. A full drill remains a real `triggerLockdown` followed by a re-`addLockdownSigner` after the automatic return to Normal. Slot reuse makes drills unlimited in count (the cap is on `signersCount`, not `nextSignerId`).

Cost: ~200 B runtime, view-only, no state mutation.

### V1 Timelock (schedule tickets + HSM bypasser)

V1 includes an optional per-Safe timelock layer in the singleton, integrated rather than separate, because the design already occupies the Safe v1.5.0 `TransactionGuard` and `ModuleGuard` slots. A separate timelock contract would not be reachable.

#### Model in one sentence

Every owner-path AND module-path transaction is delayed by `timelockDelay` if non-zero, with two release paths: (a) schedule a ticket + wait, or (b) an allowlisted HSM-style bypasser. The bypasser has two equivalent forms: a direct `bypassTimelock(safe, safeTxHash)` call that sets `executableAt = now`, or submitting the owner `execTransaction` itself, in which case `checkTransaction` skips the delay inline (no ticket) because `msgSender` is the bypasser. Both bypasser forms are owner-path only (no module-path bypass).

#### Storage (added to `SafeConfig`)

```solidity
uint64 timelockDelay; // 0 = disabled (default after initialize)
mapping(bytes32 ticketKey => uint64 executableAt) ticketExecutableAt;
mapping(address bypasser => bool) timelockBypassers;
```

`ticketKey` is namespaced via two typehashes (owner vs module) so the same raw hash cannot collide between paths. Owner tickets wrap a Safe `safeTxHash`; module tickets wrap the canonical module transaction hash returned by `getModuleTransactionHash(safe, module, to, value, data, operation)`.

#### Constants

```solidity
uint64 public constant TIMELOCK_DELAY_MIN  = 1 hours;
uint64 public constant TIMELOCK_DELAY_MAX  = 30 days;
uint64 public constant TICKET_TTL    = 90 days;
bytes32 public constant OWNER_TX_TIMELOCK_TYPEHASH  = keccak256("OwnerTxTimelock(bytes32 safeTxHash)");
bytes32 public constant MODULE_TX_TIMELOCK_TYPEHASH = keccak256("ModuleTxTimelock(address module,address to,uint256 value,bytes32 dataHash,uint8 operation)");
```

`MODULE_TX_TIMELOCK_TYPEHASH` is now only a namespace tag for
`moduleTxHash.moduleTicketKey()`. Its string is historical and does not define
the module hash preimage anymore; the canonical module-call identifier is
`getModuleTransactionHash(safe, module, to, value, data, operation)`.

#### Public surface

```solidity
function setTimelockDelay(uint64 newDelay) external;
function setTimelockBypasser(address bypasser, bool allowed) external;
function scheduleTransaction(address safe, uint256 nonce, ExecTransactionParams calldata params, bytes calldata signatures) external;
function cancelTransaction(bytes32 safeTxHash) external;
function scheduleModuleTransaction(address module, address to, uint256 value, bytes calldata data, uint8 operation) external;
function cancelModuleTransaction(bytes32 moduleTxHash) external;
function bypassTimelock(address safe, bytes32 safeTxHash) external;
function sweepExpiredOwnerTicket(address safe, bytes32 safeTxHash) external;
function sweepExpiredModuleTicket(address safe, bytes32 moduleTxHash) external;
function getTimelockDelay(address safe) external view returns (uint64);
function isTimelockBypasser(address safe, address bypasser) external view returns (bool);
function getTransactionExecutableAt(address safe, bytes32 safeTxHash) external view returns (uint64);
function getModuleTransactionExecutableAt(address safe, bytes32 moduleTxHash) external view returns (uint64);
function getModuleTransactionHash(address safe, address module, address to, uint256 value, bytes calldata data, uint8 operation) external view returns (bytes32);
```

#### Hook integration

`checkTransaction` (Normal mode):
1. Recognise owner-path `cancelTransaction(bytes32)` and module-path `scheduleModuleTransaction(...)` / `cancelModuleTransaction(bytes32)` meta-calls as bypassed (no timelock check). Owner-path scheduling is performed out-of-band via `scheduleTransaction(...)` and is never itself a Safe self-call. The recogniser is strict for the fixed-length owner cancel self-call (`selector + 32 bytes`, `value == 0`, `to == address(this)`) and selector-only for the module meta-calls; malformed module calldata may pass the hook but reverts in the called function, which is accepted as nonce-grief-only.
2. If `cfg.timelockDelay != 0`, call `ISafe(msg.sender).getTransactionHash(...)` with `ISafe(msg.sender).nonce() - 1` (Safe v1.5.0 increments the nonce before calling the guard) and **verify** the ticket via `_verifyTicket` (existence + `executableAt` bounds, no delete). Actual deletion happens in `checkAfterExecution`.

`checkAfterExecution(safeTxHash, success)` (V1 review round 3 INV-TIME-4 hardening):
1. If `success == false`, return immediately (ticket survives for retry).
2. Recompute `ticketKey = _ownerTicketKey(safeTxHash)`.
3. If `cfg.ticketExecutableAt[ticketKey] == 0`, return immediately (bypass-meta self-calls, no-timelock paths, uninit Safes, and recovery-whitelisted calls all hit this no-op).
4. Else `delete cfg.ticketExecutableAt[ticketKey]` and emit `TimelockConsumed`.

`checkModuleTransaction` (Normal mode):
1. After the existing H.5/H.12 `to == address(this)` denial.
2. After the existing operation/recovery/lockdown gates.
3. If `cfg.timelockDelay != 0`:
   a. **Reentrancy guard (INV-TIME-11)**: revert `ReentrantModuleTimelockExecution` if the transient in-flight slot is set (`_inFlightModuleTicket(safe).tload() != 0`).
   b. Compute `moduleTxHash = getModuleTransactionHash(safe, module, to, value, data, operation)`, derive the module ticket key, **verify** via `_verifyTicket`.
   c. Arm the transient in-flight slot (`_inFlightModuleTicket(safe).tstore(ticketKey)`).
   d. Return the ticket key (Safe v1.5.0 stores and relays it verbatim to the post-hook).

`checkAfterModuleExecution(txHash, success)` (V1 review round 3 INV-TIME-4 + INV-TIME-11 hardening):
1. Read `pending = _inFlightModuleTicket(safe).tload()`. If 0, return immediately (no in-flight tx; covers no-timelock branch and uninit).
2. Clear the transient slot (`_inFlightModuleTicket(safe).tstore(0)`) regardless of `success` so the next module-path timelocked tx can begin (failure paths must not brick the path).
3. If `success == false`, return (Safe v1.5.0 `ExecutionFromModuleFailure` path; ticket survives for retry with identical params).
4. If `cfg.ticketExecutableAt[pending] == 0`, return (defence in depth against Safe v1.5.0 quirks).
5. Else `delete cfg.ticketExecutableAt[pending]` and emit `TimelockConsumed(safe, pending)`.

The in-flight slot lives in **transient storage** (EIP-1153), keyed per Safe via an ERC-7201 base slot (`IN_FLIGHT_TICKET_BASE_SLOT.deriveMapping(safe)`, see #18). It is scoped to the single transaction, so it needs no persistent cleanup beyond the post-hook clear and cannot leak across transactions.

The `txHash` parameter is part of the Safe v1.5.0 interface contract but is NOT used for the storage key - the transient in-flight slot is authoritative. This makes a malicious caller spoofing the post-hook with someone else's ticket key impossible to exploit cross-Safe: the spoofer's transient in-flight slot is 0 (they have no in-flight tx of their own) so the early return fires.

Post-hook consumption (Q-Bypass-6 / Q6, V1 review round 3): the ticket is deleted ONLY after the inner call completed successfully. This closes the Safe v1.5.0 execution-semantics gap flagged by the audit: with the previous pre-hook delete, a failed module call (Safe catches the revert and emits `ExecutionFromModuleFailure`, outer tx commits) burned the ticket and forced a full re-schedule + re-wait. Same gap for owner-path with `safeTxGas > 0`: Safe may commit the outer tx despite the inner revert.

**Residual operator surface (owner-path `safeTxGas > 0` only)**: when the operator's outer Safe tx commits with `safeTxGas > 0` but the inner call reverts, the post-hook fires with `success == false` and the ticket survives. The Safe nonce has advanced, so a same-params replay requires a NEW schedule at the new nonce. The leftover ticket is dead weight reclaimable via `cancelTransaction(oldHash)` or the 90-day TTL sweep. With `safeTxGas == 0` (and `gasPrice == 0`), an inner revert rolls back the entire outer tx including the pre-hook verify - the operator can simply retry at the same nonce. **Operators SHOULD prefer `safeTxGas == 0` for timelocked owner txs** (Safe v1.4.0+ recommendation independently).

#### Recovery interaction

**The timelock layer is structurally absent during LockedDown and Recovering.** The hooks branch on `getState`: LockedDown reverts, Recovering uses the narrow recovery path, and only Normal consults the timelock. This remains correct after auto-resume whether or not the raw elapsed incident fields have since been cleared. Therefore recovery-whitelisted operations (nonce burn, swapOwner to allowlist, `disableModule`, `removeLockdownSigner`) execute WITHOUT going through the timelock. This is intentional: the recovery whitelist already provides its own narrow set of operations; layering a timelock on top would either block recovery entirely (timelock not pre-scheduled) or require pre-scheduling every possible recovery op (operationally absurd). The cost is acknowledged: recovery ops bypass the timelock guarantees, but the recovery whitelist is already extremely narrow.

Concrete consequences for auditors and operators:

- Active tickets written before lockdown REMAIN in storage during LockedDown / Recovering. The PRE-hook never reaches the Normal-mode branch where `_verifyOwnerTimelock` lives, so neither delay nor TTL gates the recovery path. The POST-hook (`checkAfterExecution`) however runs in every state and consumes (deletes) a ticket whose `safeTxHash` matches a successfully executed transaction - so a pre-incident ticket whose exact hash is executed as a recovery-whitelisted call is consumed during Recovering, emitting `TimelockConsumed`. This is benign (the ticket was quorum-authorised and single-use either way) but it IS an in-recovery state mutation of the timelock namespace.
- At the exact auto-resume second, the lifecycle is Normal again and a pre-incident ticket whose original `executableAt`/TTL window still covers that timestamp may execute immediately, with no fresh `timelockDelay`. `cancelTransaction` is not recovery-whitelisted, so incident-time defusal is a Safe nonce burn; for a transaction signed at future nonce `n+k`, the operator must advance the Safe nonce through `n+k`. Pinned by `test/poc/TimelockAccounting.t.sol::test_confirmed_preIncidentTicketFiresAtTheAutoResumeSecond` and `::test_confirmed_cancelIsUnreachableDuringRecovering`.
- An attacker who controls the HSM bypasser cannot accelerate any recovery-time operation: `bypassTimelock` itself reverts `InvalidState` through the `onlyNormal` gate while `getState` is LockedDown or Recovering, and even if a ticket exists it is never consulted by those hook branches.
- Conversely, a legitimate post-resume cleanup of stale tickets is owner-path-only and must happen once the Safe is `Normal` again (after the recovery window elapses), since `cancelTransaction` (and `cancelModuleTransaction`) are not on the recovery whitelist.

#### Bypass model (Q-Bypass-1 = A, off-chain trust)

`bypassTimelock(safe, safeTxHash)` is called directly by an allowlisted `timelockBypassers[bypasser]` address (typically an operator-run HSM signing service). It writes `executableAt = now` for the owner ticket. No prior schedule is required: if no ticket exists for the hash, `bypassTimelock` CREATES one (it is a ticket-creation primitive, not merely an accelerator; the T-BYPASS scenarios below rely on this). A bypass-created ticket never appears in the `TransactionScheduled` stream, so monitoring MUST watch `TimelockBypassed` as well. The bypasser sees ONLY the hash; on-chain enforcement of "what is bypassable" is not possible. The operator's off-chain bypasser service is expected to apply policy (refuse to issue bypasses for admin self-calls, `setGuard`, etc.). HSM compromise = full bypass authority including disabling the timelock. The operator accepts this SPOF.

The bypasser has a second, equivalent release form that needs no `bypassTimelock` call at all: when the bypasser SUBMITS the owner `execTransaction` itself (so the Safe forwards `msgSender == bypasser` to the guard), `checkTransaction` skips the timelock verification inline, with no ticket written. This is the HSM-as-relayer flow (the bypasser service relays an approved tx directly rather than writing a ticket for a separate executor). It carries identical trust and authority: owner signatures are still enforced by the Safe, it is Normal-state + owner-path only, and it cannot accelerate a LockedDown / Recovering tx (those branches run before and around this check). Like a `bypassTimelock`-created ticket, this path bypasses WITHOUT re-checking the Safe refund fields, consistent with the bypasser's accepted full owner-path authority; the refund-field denial (`TimelockBypassRefundDenied`, C1) guards only the schedule/cancel meta-call carve-out, which any owner can reach, not the bypasser-gated paths.

Other Q decisions baked into the implementation:
- **Q-Bypass-2 (single bypasser)**: any allowlisted bypasser can bypass alone. No M-of-N.
- **Q-Bypass-3 (no init param)**: bypassers added post-init via `setTimelockBypasser`. Initial `setTimelockBypasser` may run "free" if `timelockDelay == 0` at that moment (first activation 0→N is free, Q5).
- **Q-Bypass-5 (no module bypass)**: only owner-path tx can be bypassed. Module-path always waits the delay.
- **Q-Bypass-6 (no cooling-off)**: a freshly added bypasser may call `bypassTimelock` immediately.
- **Q-Bypass-8 (prospective revocation)**: revoking a bypasser only prevents new bypasses; tickets they wrote prior remain valid until executed, cancelled, or TTL-expired.

#### TTL (90 days) + permissionless sweep

A ticket whose `executableAt + 90 days` has elapsed reverts `TicketExpired` at the hook. The revert rolls back any in-function `delete`, so the entry stays in storage until either the Safe quorum explicitly `cancelTransaction(...)`s it (or `cancelModuleTransaction(...)` for the module-path version) **or** any external caller invokes the permissionless sweep:

- `sweepExpiredOwnerTicket(safe, safeTxHash)`
- `sweepExpiredModuleTicket(safe, moduleTxHash)`

Both sweep functions are callable by anyone (no `msg.sender` gate, no incident-state gate; the production `LockdownTimelock` overrides them with `onlyInitialized(safe)`, which is unreachable in practice - an uninitialised Safe cannot hold tickets - but means the deployed functions are not literally modifier-free). They revert `TicketNotFound` if no entry exists, `TicketNotExpired` if the entry is still within its TTL window. The sweep does NOT depend on `cfg.timelockDelay != 0`: a Safe that has since disabled its timelock can still have its stale entries cleaned. Emits `TicketSwept(safe, ticketKey, sweeper)` to distinguish janitor-style cleanup from governance-driven `TicketCancelled`.

Why permissionless: the sweep is storage hygiene. Once the ticket is expired it cannot pass the hook, and allowing any caller to delete its slot offloads cleanup from the Safe quorum and bounds long-term storage growth on the singleton. The deletion is not a terminal revocation of the underlying Safe authorisation: for an owner ticket it removes the `TicketAlreadyExists` barrier, so the same public `scheduleTransaction` calldata and valid owner signatures can recreate the ticket while the signed nonce has not been surpassed; the caller must then wait the current `timelockDelay` again. This behaviour is pinned by `test/poc/TicketRevival.t.sol` and tracked as accepted risk AR-16 in `AUDIT_BRIEF.md`.

#### Setters and the timelock

All setters (the existing `setLockdownDuration`, `setResumeDelay`, `addRecoveryOwner`, `removeRecoveryOwner`, `addLockdownSigner`, `removeLockdownSigner`, `rotateLockdownSigner`, and the new `setTimelockDelay`, `setTimelockBypasser`) are owner-path self-calls. Once `timelockDelay > 0`, they all go through the timelock check in `checkTransaction`. The user must schedule + wait + execute each. The only "free" change is an activation `0 -> N` of `setTimelockDelay`, because the hook check is `if (cfg.timelockDelay != 0)` and `cfg.timelockDelay` is still 0 at the moment of the activation tx. Note this is mechanically EVERY `0 -> N` transition, not only the first: after a (timelocked) `N -> 0` disable, the next re-activation is free again.

This is enforced by hook position (no per-setter logic), making the design auditable in one place.

#### Errors and events

New errors: `TimelockDisabled`, `TimelockDelayTooLow`, `TimelockDelayTooHigh`, `TimelockExceedsLockdownDuration`, `TicketAlreadyExists`, `TicketNotFound`, `TimelockNotElapsed`, `TicketExpired`, `TicketNotExpired`, `NotTimelockBypasser`, `BypasserZeroAddress`, `TimelockBypassRefundDenied`, `LockdownSigners_BurntPermanently`.

New events: `TimelockDelayChanged`, `TimelockBypasserChanged`, `TransactionScheduled`, `ModuleTransactionScheduled`, `TicketCancelled`, `TicketSwept`, `TimelockBypassed`, `TimelockConsumed`.

#### Invariants (new)

- **INV-TIME-1**: a transaction reaches the Safe execution layer only if `cfg.timelockDelay == 0` OR a matching ticket existed with `block.timestamp >= executableAt && block.timestamp <= executableAt + TICKET_TTL`, where the matching ticket is `_ownerTicketKey(safeTxHash)` (owner-path) or `_moduleTicketKey(moduleTxHash)` (module-path) - with exactly four documented no-ticket carve-outs: (a) the cancel / module-schedule / module-cancel meta-call short-circuit (INV-TIME-3), (b) the inline bypasser-as-submitter form (README assumption 5), (c) recovery-whitelisted calls (INV-TIME-6: the timelock branch is not reached outside Normal), and (d) an explicit `bypassTimelock(hash)` which creates-then-satisfies the ticket.
- **INV-TIME-2**: `bypassTimelock` reverts `NotTimelockBypasser` for any caller not in `timelockBypassers[caller]`. The mapping is per-Safe (INV-ISO-1 extension).
- **INV-TIME-3**: `_isTimelockManagementCall` returns true only for owner-path self-calls to `address(this)` with `value == 0` and selectors equal to `cancelTransaction(bytes32)`, `scheduleModuleTransaction(...)`, or `cancelModuleTransaction(bytes32)`. Owner scheduling is out-of-band through `scheduleTransaction(...)`, not a Safe self-call. Strict length is enforced for owner cancel; module meta-calls are selector-only and malformed calldata reverts in the called function.
- **INV-TIME-4 (V1 review round 3 hardening, two-layer)**: ticket consumption is single-use AND success-gated AND reentrancy-protected. (a) Success-gating: a successful execution (`success == true` in the post-hook) deletes the entry; a failed execution leaves the entry consumable for retry. (b) Reentrancy-protection (module-path only, see INV-TIME-11): the in-flight slot blocks a same-Safe reentrant pre-hook from verifying the same ticket twice. Owner-path single-use is structurally enforced by Safe nonce ordering (distinct nonces produce distinct `safeTxHash` values, hence distinct ticket keys). Subsequent attempts after a successful delete revert `TicketNotFound`. The pre-hook (`checkTransaction` / `checkModuleTransaction`) only verifies; the actual `delete cfg.ticketExecutableAt[ticketKey]` lives in `checkAfterExecution` / `checkAfterModuleExecution`. Closes the Safe v1.5.0 execution-semantics gap: `execTransactionFromModule` catches inner reverts and commits the outer tx, and `execTransaction` with `safeTxGas > 0` may do the same. Owner-path residual when `safeTxGas > 0`: the nonce has advanced so a leftover ticket is unusable at the new nonce (operator cleans via `cancelTransaction` or 90-day TTL sweep). Verified by `test_moduleHook_postHookFailure_leavesTicketForRetry`, `test_moduleHook_postHookWithoutTicket_isNoOp`, `test_ownerHook_postHookFailure_leavesTicketForCleanup`, `test_ownerHook_postHookWithoutTicket_isNoOp`, `test_postHook_crossSafeIsolation`, `test_moduleHook_reentrantPreHookReverts_INV_TIME_11`, `test_moduleHook_inFlightClearedOnFailure`.
- **INV-TIME-5**: revocation of a bypasser is prospective. `bypassTimelock(safe, h)` calls made BEFORE revocation are not invalidated; the ticket stays until cancelled / executed / TTL-expired.
- **INV-TIME-6**: timelock PRE-checks do NOT apply during LockedDown or Recovering. The pre-hook branches on `getState` before the Normal-mode `_verifyOwnerTimelock` call. Recovery-whitelisted owner-path ops and the unconditional module-path revert both bypass the timelock verification entirely. Note the success-gated POST-hook consumption (`checkAfterExecution` → `_consumeTicket`) is NOT state-gated and can consume a matching pre-incident ticket during Recovering (see "Recovery interaction" above); the invariant covers verification, not post-hook cleanup.
- **INV-TIME-7**: `bypassTimelock` reverts `InvalidState` via `onlyNormal` whenever `getState(safe)` is LockedDown or Recovering. It is allowed again after time-based auto-resume even if raw elapsed incident fields still linger. Combined with INV-TIME-6, the bypasser cannot interact with Safe state during an active incident even if its key is compromised at that moment. Stateful Echidna invariant `echidna_bypassRejectedDuringIncident` verifies the live witness.
- **INV-TIME-8**: `sweepExpiredOwnerTicket` / `sweepExpiredModuleTicket` succeed only when `block.timestamp > executableAt + TICKET_TTL`. On success the ticket disappears: its storage slot is deleted and an immediate subsequent read returns 0. This property says nothing about terminal revocation of the underlying Safe authorisation. In particular, deleting an owner-ticket slot does not invalidate the owner signatures carried in the public `scheduleTransaction` calldata; while their signed nonce has not been surpassed, those signatures can recreate a new ticket that must wait `timelockDelay` again. The sweep remains state-gate free (Normal, LockedDown, Recovering) because the expired ticket itself cannot pass the hook. Echidna witness `echidna_sweepClearsExpiredOwnerTicketSlot` proves only the slot-clearing property; `test/poc/TicketRevival.t.sol` pins survival of the owner authorisation.
- **INV-TIME-9 (C1 fix)**: any owner-path tx that takes the `_isTimelockManagementCall` short-circuit MUST also have `safeTxGas == 0 && baseGas == 0 && gasPrice == 0 && gasToken == address(0) && refundReceiver == address(0)`. The hook reverts `TimelockBypassRefundDenied` otherwise. Prevents a coerced quorum from draining via Safe refund mechanics on the bypass path.
- **INV-TIME-10 (V1 review round 3)**: the post-hook delete is bound to the pre-hook verify via the `safeTxHash` (owner) or the transient in-flight slot (module). Both hooks read `_configs[msg.sender]` only (cross-Safe isolation preserved: a malicious Safe calling the post-hook with another Safe's ticket key cannot delete that ticket). The post-hook is idempotent: a second call with the same args is a no-op (existence guard).
- **INV-TIME-11 (V1 review round 3 Prompt-3 follow-up, reentrancy guard)**: a module-path timelocked execution that is in-flight on a Safe blocks any concurrent `checkModuleTransaction` on the same Safe. the transient in-flight slot (`_inFlightModuleTicket(safe)`) is armed by the pre-hook when the timelock branch verifies a ticket and cleared by the post-hook regardless of `success`. A reentrant `execTransactionFromModule(sameParams)` (target → module → Safe pattern) hits the non-zero in-flight slot in the inner pre-hook and reverts `ReentrantModuleTimelockExecution`. Closes the Safe v1.5.0 reentrancy double-spend window flagged by the Prompt-3 audit: without the guard, an outer module tx whose target reenters with identical params would verify the same ticket twice (verify-only pre-hook) and the inner post-hook would delete it - net result two executions from one ticket. Owner-path is structurally immune because Safe nonce ordering produces distinct `safeTxHash` values across nested `execTransaction` calls; the slot covers module-path only. Verified by `test_moduleHook_reentrantPreHookReverts_INV_TIME_11` and `test_moduleHook_inFlightClearedOnFailure`.

#### Burnt-identity set (INV-SIGN-7, C4 fix)

V1 includes a per-Safe `mapping(bytes signer => bool) signerBurntPermanently` in `SafeConfig`. A signer identity is marked permanently burnt:

- On any `removeLockdownSigner` call.
- On the old half of `rotateLockdownSigner(oldSigner, newSigner)`.
- On a successful `triggerLockdown` burn (which routes through the same remove helper).

`addLockdownSigner` and the add half of `rotateLockdownSigner` revert `LockdownSigners_BurntPermanently` if the identity was previously burnt. The off-chain view `isSignerBurntPermanently(safe, signer) view returns (bool)` lets the runbook pre-check before attempting a re-add.

Rationale: `PasswordVerifier` ignores `hash`, so a leaked preimage hashes to the same commitment forever. Allowing re-registration of an already-burnt identity would let any party who observed the prior trigger calldata re-trigger the Safe after resume (T-PWD-REPLAY). The same gate applies uniformly to ECDSA: rotation discipline is enforced on-chain rather than left to runbook hygiene.

- **INV-SIGN-7**: for any `(safe, signer)`, `cfg.signerBurntPermanently[signer] == true` implies any subsequent `addLockdownSigner(signer)` or `rotateLockdownSigner(..., signer)` reverts `LockdownSigners_BurntPermanently`. The flag is never cleared. Verified by `test_addLockdownSignerBurnsRemovedIdentity`, `test_addLockdownSignerRejectsBurntKeyAfterTriggerBurn`, `test_passwordPath_replayAfterReRegistrationBlocked`, and `test_signatureCannotReplayAfterBurnAndReRegister`.

**Recovery-hygiene trade-off (operator-facing)**: `removeLockdownSigner` is allowed during Recovering (H.4) AND marks the pair permanently burnt. The Recovering-time window is therefore both the "clean up a compromised signer atomically" primitive AND a one-way permanent identity loss for the targeted pair on this Safe. A quorum coerced into removing a legitimate panic identity during Recovering (e.g. a wrench attacker who can force the quorum to "rotate everything" before they resume) burns those identities forever - the operator must re-register fresh `(verifier, key)` pairs post-resume, not the same ones. This is the intended single-use semantic and the post-resume runbook §8.3 makes it a hard obligation, not a soft one. See also T-BYPASS-8 for the HSM-bypass variant of forced burn.

#### Threat model: bypasser compromise (named)

The HSM bypasser is a second trust root in addition to the registered lockdown signers. SPEC nails the following compromise scenarios so reviewers and operators reason from a shared list:

- **T-BYPASS-1 (timelock disable)**: a compromised bypasser can pre-bypass a `setTimelockDelay(0)` self-call, reducing the timelock to zero before the quorum notices. Mitigation: monitor `TimelockBypassed` events targeting the singleton (`to == address(this)`); off-chain bypasser policy must refuse bypasses for admin self-calls. Acknowledged residual: full off-chain trust per Q-Bypass-1.
- **T-BYPASS-2 (signer eviction)**: a compromised bypasser can pre-bypass `removeLockdownSigner(...)` on a legitimate signer. Same off-chain policy mitigation.
- **T-BYPASS-4 (adversarial bypasser addition)**: a compromised bypasser can pre-bypass `setTimelockBypasser(attackerAddress, true)`, expanding the bypasser allowlist. The new entry is then prospective (INV-TIME-5) and the operator must call `setTimelockBypasser(attackerAddress, false)` to revoke. The revocation itself goes through the timelock unless the legitimate bypasser still works.
- **T-BYPASS-5 (recovery shielding holds)**: explicitly NOT a threat. By INV-TIME-6 + INV-TIME-7, an attacker who only controls the bypasser cannot interact with a Safe currently in LockedDown or Recovering. The recovery whitelist still gates all execution.
- **T-BYPASS-6 (stale tickets survive revocation, C3)**: revoking a compromised bypasser via `setTimelockBypasser(_, false)` only blocks NEW `bypassTimelock` calls (INV-TIME-5). Tickets the bypasser already wrote remain valid until executed / cancelled / TTL-expired. **Operator obligation on HSM compromise**: enumerate every pending bypass ticket via `TimelockBypassed` event log and call `cancelTransaction(safeTxHash)` on each from the Safe quorum BEFORE / immediately after the revocation. The quorum is the only authority that can clean up mid-TTL bypass tickets (sweep only works post-TTL). **Correction (pre-tag review, 2026-08-25): "remain valid until executed / cancelled / TTL-expired" overstates the TTL as a bound.** `bypassTimelock` writes `executableAt = block.timestamp` UNCONDITIONALLY (`src/base/Timelock.sol:292-299`), with no TTL check and no `TicketAlreadyExists` guard, so a still-allowlisted bypasser can RESURRECT a ticket that is already dead past its TTL and can REFRESH any ticket indefinitely. Waiting out the TTL is therefore not a mitigation while the bypasser key remains allowlisted; revocation, not expiry, is the control. Pinned by `test/poc/TimelockAccounting.t.sol::test_confirmed_bypasserRearmsTicketPastTtl` and `::test_confirmed_bypasserRefreshesTicketIndefinitely`. Cancellation is not terminal if valid owner signatures for that hash remain available at a nonce that `Safe.nonce()` has not surpassed: the same public scheduling calldata can recreate the ticket, as pinned by `test/poc/TicketRevival.t.sol`. Apply the AR-16 nonce-burn rule in `AUDIT_BRIEF.md` to revoke that Safe authorisation durably. Accepted residual per Q-Bypass-8 / decision 2026-06-08.
- **T-BYPASS-7 (refund-field drain on bypassed meta-calls, C1)**: **fixed on-chain by `TimelockBypassRefundDenied`**. A bypassed schedule/cancel meta-call with non-zero `safeTxGas`/`baseGas`/`gasPrice`/`gasToken`/`refundReceiver` would let a coerced quorum drain via Safe refund mechanics while sidestepping the timelock. The hook reverts on any non-zero refund field in the META-CALL bypass path (Normal mode, CALL operation). Mirrors the recovery-time refund check in §7.4.
  **SCOPE CORRECTION (pre-tag review, 2026-08-25): the fix covers the management meta-call lane ONLY.** The separate INLINE bypasser lane - `msgSender` is an allowlisted bypasser, `src/LockdownTimelock.sol:201` (CALL) and `:212` (DELEGATECALL) - deliberately does NOT re-check refund fields, and the ERC-20 `gasToken` refund branch of `Safe.handlePayment` is not capped by `tx.gasprice`. A coerced quorum whose transaction is relayed by the bypasser CAN therefore drain via `gasToken`/`refundReceiver`. This is NOT an escalation: an allowlisted bypasser can already pre-bypass any hash, including a plain value transfer with all refund fields zero, per accepted risk #8. The register wording, not the contract, was wrong. Pinned by `test/poc/TimelockBypassRefundLane.t.sol` (7 tests, including the escalation refutation).
- **T-BYPASS-8 (forced burn via bypass, review round 2)**: a compromised bypasser can pre-bypass a `removeLockdownSigner(verifier, key)` or `rotateLockdownSigner(...)` self-call. Beyond the eviction itself (T-BYPASS-3), the V1 burnt-keys set (INV-SIGN-7) marks the targeted `(verifier, key)` pair as **permanently burnt for this Safe**. After recovery from HSM compromise the legitimate operator cannot re-arm the same identity - they MUST register a fresh `(verifier, key)` pair. The bypasser cannot weaponise this beyond eviction (no new authority is created and INV-SIGN-7 only ever shrinks the addable surface), but the storage damage is permanent per-Safe. Mitigation: monitor `LockdownSignerRemoved` / `LockdownSignerRotated` events targeting `to == address(this)` during the bypass window; the post-HSM-compromise runbook (§8.3) must include "re-register every forcibly burnt identity under a fresh `key`". Accepted residual per Q-Bypass-1 (off-chain trust).

These are properties of the off-chain-trust model V1 ships with; T-BYPASS-1..4, T-BYPASS-6 and T-BYPASS-8 are accepted off-chain trade-offs, T-BYPASS-7 is on-chain fixed FOR THE META-CALL LANE ONLY (see its entry: the inline bypasser lane is uncovered by design and dominated by accepted risk #8). Operators who reject T-BYPASS-1..4 + T-BYPASS-6 + T-BYPASS-8 must not enable the timelock (`timelockDelay == 0` makes the entire bypasser surface inert).

#### Threat model: PasswordVerifier exposure (named, C4/C5)

PasswordVerifier ships as tier-2 production (§H.18) with a publicly-known weakness profile. The following exposure paths are tracked explicitly:

- **T-PWD-REPLAY (re-registration replay, C4)**: **fixed on-chain by INV-SIGN-7** (per-Safe `signerBurntPermanently` set). Any identity that has been registered and subsequently removed / rotated-away / trigger-burnt is permanently blocked from re-registration on the same Safe (`LockdownSigners_BurntPermanently`). A PasswordVerifier preimage that has leaked publicly cannot be re-armed under the same identity - the operator MUST rotate to a fresh identity. Verified by unit tests `test_passwordPath_replayAfterReRegistrationBlocked` and `test_addLockdownSignerRejectsBurntKeyAfterTriggerBurn`.
- **T-PWD-LEAK-BEFORE-BURN (revert-before-burn leak, C5)**: **accepted operator risk, not on-chain fixed**. The `triggerLockdown` pre-verify checks can revert AFTER the preimage is publicly in calldata but BEFORE the verifier runs and the burn fires. Since PR #59 relaxed the gate from `onlyNormal` to `onlyInitialized`, a duplicate trigger during an active lockdown no longer reverts - it SUCCEEDS and burns the identity (extending the lockdown), so that formerly-most-realistic leak case is gone. The remaining revert-before-burn cases are: a wrong/mismatched `signature` (`BadSignature`, burn rolled back), an unregistered/already-burnt identity (`NotLockdownSigner`), or an uninitialised Safe (`InvalidState`; moot, no identity registered). **Operator obligation**: treat any reverted password trigger as a full leak and rotate to a fresh commitment IMMEDIATELY (via `removeLockdownSigner` during Recovering, or in Normal).
- **T-PWD-MEMPOOL (cleartext mempool observation)**: documented in `PasswordVerifier` NatSpec and runbook §8.3 tier-2 warning. Every successful trigger publishes the preimage. The on-chain burn + INV-SIGN-7 contain damage to the SAFE that was triggered; cross-Safe reuse leaks across all Safes that share the same commitment. Because `PasswordVerifier` ignores the EIP-712 digest, a password commitment is unique **per Safe AND per chain**.

### H.18 `PasswordVerifier` reintroduced as production verifier (V1)

Background: §H.3 documented rejecting the initial `PasswordVerifier` semantics because cleartext preimage verification against a `keccak256` commitment, without hash binding, failed under review on three fronts: mempool leakage of the secret, "revert-before-burn" replay window, and uncatchable cross-Safe replay if the same password was registered on multiple Safes.

Operator feedback for V1: a non-trivial fraction of cold-Safe owners do not carry a hardware wallet during travel / drills / coercion-response rehearsals and have asked for a no-hardware emergency path. The proposed remediation is to reintroduce `PasswordVerifier` with:

- the baseline V1 hardening (H.16 keyHash in `SafeLockedDown`, permanent burnt keys, and off-chain key-shape preflight per H.13);
- an EXTREMELY explicit threat model in the verifier NatSpec listing every adversarial property (cleartext mempool leak, frontrun-to-control-reasonHash, offline brute force of `keyHash`, drill exhaustion);
- a "verifier security ranking" section in `docs/V1_USER_SCENARIOS.md` §8.3.9 that flags it as the LEAST secure tier and instructs operators to prefer the native ECDSA / ERC-1271 path (a 20-byte identity);
- an explicit verifier-level rejection of empty / zero / wrong-length commitments at trigger time, plus operator tooling that should reject malformed commitments before registration.

What V1 does NOT fix: mempool frontrunning, hash-binding (the verifier ignores `hash` by design; binding would require a salted scheme as in the future "salted password verifier" roadmap). These remain accepted risks documented in the NatSpec and the runbook §8.3.

Result: `PasswordVerifier` ships as a tier-2 production verifier. H.18 supersedes the rejected draft status from H.3 while preserving the historical rationale as the audit trail.

### H.19 Recovery-owner validation at registration and hook time (V1, SaferSafes-derived)

Background: triaging the Spearbit SaferSafes review (Nov 2025) against this design surfaced two informational findings (5.3.1 fallback-owner-must-reject-Safe-address, 5.3.5 fallback-owner-already-an-owner) that transpose directly to the `recoveryOwnerAllowlist`. Safe's `OwnerManager.swapOwner` rejects `address(0)`, the sentinel `0x1`, and the Safe itself (GS203), and rejects a `newOwner` that is already a current owner (GS204). Before H.19 the singleton only rejected `address(0)` at registration, so a Safe could register a recovery owner that LOOKS armed but dead-ends with a Safe-level revert exactly at incident time.

Changes:

- New `_validateRecoveryOwner(address)` private helper: rejects `address(0)` (`RecoveryOwners_ZeroAddress`), the OwnerManager sentinel `address(0x1)`, the calling Safe itself, and any address for which `ISafe(msg.sender).isOwner(owner)` returns true (`RecoveryOwners_Invalid`). Called from `initialize` (per initial backup) and from `addRecoveryOwner(owner)`.
- Validation applies to ADDITIONS only. Removal of an entry that became invalid after registration (a backup later promoted to current owner) stays possible: removal is the cleanup for that situation.
- Dynamic hook-time re-check: the recovery whitelist in `_isRecoveryTransaction` now rejects a `swapOwner` whose allowlisted `newOwner` is a CURRENT Safe owner (`ISafe(safe).isOwner(newOwner)`, staticcall to the calling Safe). Safe would revert GS204 on the swap anyway; rejecting in the guard keeps the recovery whitelist from admitting a dead-end transaction and keeps signer-review tooling honest.
- `ISafe` gains `isOwner(address)`. Non-Safe callers of `initialize` that do not expose the owner interface now revert during recovery-owner validation instead of writing dead config state (initialize NatSpec updated).

Residual (accepted): the registration-time `isOwner` check is a snapshot; the hook-time re-check covers the dynamic case for the swap target. A Safe whose ENTIRE allowlist has become current owners has no recovery `swapOwner` path until it cleans up the allowlist in Normal mode; nonce burn, `removeLockdownSigner` and delayed resume remain available during Recovering. The preflight script and runbook must check allowlist-vs-owner-set disjointness before installation and periodically thereafter.

Tests: `test_initialize_rejectsRecoveryOwner{Sentinel,SafeItself,CurrentSafeOwner}`, `test_addRecoveryOwner_rejects{Sentinel,SafeItself,CurrentSafeOwner}`, `test_removeRecoveryOwner_allowsRemovingEntryThatBecameOwner`, `test_recoveryRejectsSwapOwnerWhenBackupBecameCurrentOwner`, plus uninstall/reinstall persistence pins (`test_incidentStatePersistsAcrossGuardReinstall`, `test_burntKeyPersistsAcrossResumeAndReinstall`, `test_staleOwnerTicket_pastNonce_deadAfterReinstall`, `test_staleOwnerTicket_futureNonce_survivesReinstall`, `test_staleModuleTicket_survivesReinstall_andIsCancellable`). The uninstall/reinstall pins resolve the SaferSafes iSAFE-012 mapping question: owner-path tickets at passed nonces are dead by hash construction; future-nonce owner tickets and module tickets (no nonce binding) survive re-installation as quorum-authorized, single-use, TTL-bounded tickets, with the runbook nonce-burn at uninstall as the operational backstop.

### H.20 Module guard-disable denial + guard-hook self-call denial (V1, final review round)

Background: two compiling PoCs against the H.12 module-path model. (1) An enabled module could, in one MultiSend, `setFallbackHandler(evilHandler)` where `evilHandler.LOCKDOWN() == singleton` passes the `InvalidFallbackHandler` interface check yet ships a malicious `fallback()`; combined with `addOwnerWithThreshold(evilHandler, 1)` it reaches owner-path `addLockdownSigner` via an ERC-1271 owner callback (timelock disabled), defeating the intended module→singleton denial and the ERC-1271 freeze integrity. (2) Because `checkAfterModuleExecution(bytes32,bool)` is a public guard hook and `scheduleTransaction` is permissionless, an attacker with a pre-signed owner-path tx to `checkAfterModuleExecution(0, false)` could execute it mid module execution, clear the transient in-flight slot, and replay one scheduled module ticket twice (INV-TIME-11 bypass).

Root cause: the pre-H.20 model ALLOWED module-path `setGuard`/`setModuleGuard`/`setFallbackHandler` self-calls, reasoning "a module is as strong as owner consensus". That holds for module power in general but NOT for DISABLING the guard: if a module can drop the guard or swap the freeze handler, a future lockdown no longer protects anything. And no path forbade routing the guard hooks themselves through a user tx.

Changes:

- `_isForbiddenModuleSafeSelfCall(data)` now denies exactly the three guard-DISABLE selectors on a module-path `to == safe` self-call: `setGuard`, `setModuleGuard`, `setFallbackHandler` (`ModuleSafeSelfCallDenied`). It no longer lists `enableModule` / `disableModule` / `execTransactionFromModule*` - those do not disable the guard and were needless over-blocking. Owner topology (`addOwnerWithThreshold` / `swapOwner` / `changeThreshold`) stays allowed on the module path (accepted residual, §7.2): a coerced module in Normal mode already has arbitrary execution power, so the fix targets ONLY guard-disable escape, not module power in general.
- New `_isGuardHookSelector(data)` + `GuardHookSelfCallDenied`: a `to == singleton` call whose selector is `checkTransaction` / `checkAfterExecution` / `checkModuleTransaction` / `checkAfterModuleExecution` is rejected on EVERY path (checked before the `allowAdminCalls` singleton gate). The hooks are Safe-invoked machinery, never a legitimate `execTransaction` target; blocking them closes the INV-TIME-11 in-flight-clear replay.
- The `allowSingletonCalls` flag is renamed `allowAdminCalls`: it now gates both singleton self-calls and the guard-disable Safe self-calls.
- `setFallbackHandler` denylisting is ordered BEFORE the `InvalidFallbackHandler` binding check, so the module path is uniformly denied (valid or foreign handler) and the `LOCKDOWN() == singleton` binding check is now an owner-path-only gate. Exact codehash pinning stays a rejected non-goal (`V1_NON_GOALS.md`): the module path is contained by denial, the owner path by the lockdown-awareness interface + off-chain attestation.

Both PoCs now revert. Regressions: `test_module_setFallbackHandler_deniedFor{Valid,Foreign}Handler`, `test_moduleHook_selfAdminSetFallbackHandlerDenied`, `test_ownerHook_guardHookSelectorsDeniedAsSingletonTarget`, `test_moduleHook_canStillAddOwner_acceptedNormalModePower` (plus the pre-existing `test_module_setGuardSelfCall_rejected` / `test_module_setModuleGuardSelfCall_rejected`).

Residual (accepted): a malicious enabled module in Normal mode retains full owner-equivalent power over the Safe (add owners/modules, move funds) - inherent to Safe's module model and out of scope. The Lockdown guarantee is that once a lockdown is triggered the guard freezes everything, and H.20 ensures a module cannot pre-emptively disable that guard.

### H.21 Prospective `resumeDelay` updates cannot resurrect an elapsed incident (F-M2-01)

Background: auto-resume performs no transaction, so `lockdownUntil` and
`lockdownReasonHash` can remain in raw storage after `getState` has returned to
Normal. Because the recovery boundary was computed live as `lockdownUntil +
resumeDelay`, increasing `resumeDelay` at that point could make the old window
true again. The Safe would re-enter a phantom Recovering state carrying the old
reason, and both hooks would enforce that state. The quorum could not undo the
delay in-band because `setResumeDelay` itself is Normal-only.

Change: `_setResumeDelay` reads the previous delay and, only when the previous
incident window has fully elapsed, clears `lockdownUntil` and
`lockdownReasonHash` before writing the new delay. The setter therefore applies
prospectively. Its elapsed-window predicate cannot clear a LockedDown or
Recovering incident; the public `onlyNormal` gate provides the primary check and
the internal predicate is defence in depth for future callers.

Consequence: a later delay update may erase the old reason from raw contract
storage. `SafeLockedDown`, which contains the Safe, deadline, reason, and signer
identity, is the durable forensic record. Auto-resume itself remains purely
time-based and event-less. Closure is pinned at the exact recovery boundary by
`test_setResumeDelay_afterAutoResume_doesNotReopenRecovery` and statefully by
`echidna_resumeDelayCannotReopenIncident` in both Echidna and Medusa.

### H.22 Verify before remove/burn in `triggerLockdown` (pre-tag arbitration)

`triggerLockdown` now preserves the cheap registered-identity check, verifies
through the public `testSigner` source of truth, then removes and permanently
burns the identity before `_lock`. Verification therefore observes no
singleton mutation introduced by the trigger. Failed verification performs no
burn; a later failure still rolls the successful verification, burn and lock
back atomically. `test/poc/DrillEvasionVerifier.t.sol` pins the ordering with a
read-only probe and confirms the ordinary ECDSA path remains unchanged.

This is ordering hygiene, not an expansion of the verifier threat model. The
supported ERC-7913 product domain remains the immutable, closed-world verifier
bytecodes shipped and codehash-pinned by this repository. The singleton has no
verifier allowlist; third-party verifiers remain quorum-authorised but outside
the supported behavioural guarantees. Any verifier OOG, revert or invalid
return condemns the whole identity and requires removal/rotation to a different
verifier. No verifier gas ceiling or local bounded-returndata fork of OZ
`SignatureChecker` is introduced for V1.

---

*This document is the contract for the V1 implementation. Subsequent commits to `src/Lockdown.sol`, `src/LockdownTimelock.sol`, or component mixins must reference the relevant section number from this spec.*
