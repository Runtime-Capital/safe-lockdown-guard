# Lockdown V1 - Hardware-Wallet UX & Clear-Signing Guide

Operational guide for Safe v1.5.0 owners signing Lockdown V1 transactions
on a Ledger, Trezor, or similar hardware wallet, especially under stress
(coercion, incident response, drills).

This file is the active hardware-wallet and clear-signing guide for the V1
singleton.

## 1. Why this matters

A Safe owner under physical coercion is going to confirm transactions on
the device screen with the attacker watching. If the wallet displays
"Unknown contract call" or 5 lines of hex, the signer cannot meaningfully
verify what they are about to sign and the whole anti-coercion model
falls apart.

V1 hardware-wallet UX is sensitive because:

- `triggerLockdown` has 4 parameters, two of which are dynamic `bytes`.
- `addLockdownSigner` and `removeLockdownSigner` take a single
  variable-length `bytes` signer identity. Hardware wallets will not
  natively decode `bytes` past their first 32 bytes. `addLockdownSigner`
  is also where a Safe quorum blesses an external ERC-7913 signer identity
  that controls future panic authority. This is governance, not "ops".
- `rotateLockdownSigner` takes two arguments, both dynamic `bytes`.

The companion ERC-7730 v2 templates under `docs/clear-signing/` are the
machine-readable side of this guide. Walletconnect-aware UIs, Safe
transaction builders, and wallet vendors should honour it.

## 2. The V1 contract surface in three groups

### Group A - Owner-path admin (every Safe owner sees these)

Routine Safe owner transactions during Normal mode. Signed via
`Safe.execTransaction`.

| Function | Selector | Sensitive args to display |
|---|---|---|
| `addLockdownSigner(bytes)` | `0xfb0dc216` | signer identity (hash on device, full bytes on host) |
| `removeLockdownSigner(bytes)` | `0xb63fb1cd` | signer identity (hash) |
| `rotateLockdownSigner(bytes,bytes)` | `0x914f7ab6` | old signer identity, new signer identity |
| `setLockdownDuration(uint64)` | `0x3211a5ce` | seconds (display as days/hours) |
| `setResumeDelay(uint64)` | `0xc962eb6f` | seconds |
| `addRecoveryOwner(address)` | `0x84ec720c` | owner address |
| `removeRecoveryOwner(address)` | `0x3cef8f33` | owner address |
| `initialize(uint64,uint64,address[],bytes[])` | `0x47bb0a97` | duration, delay, recovery owners, initial signers |

Selectors above were recomputed with `cast sig`. Recompute them from the frozen
ABI before registry submission and test every rendered action.

### Group B - Incident / recovery (rare, signed under stress)

| Function | When called | What the device must show |
|---|---|---|
| `removeLockdownSigner(...)` | during Recovering, post-trigger forensic cleanup | "Remove compromised signer identity" |
| `swapOwner(address,address,address)` | during Recovering, swap to allowlisted backup | "Swap owner X → Y on Safe Z" |
| `disableModule(address,address)` | during Recovering, neutralise a module | "Disable module M on Safe Z" |
| empty self-call (nonce burn) | during Recovering | "Burn next nonce on Safe X" |

There is no resume operation to sign: the Safe auto-resumes to Normal once the
recovery window elapses (time-based, no transaction).

`addLockdownSigner`, `rotateLockdownSigner`,
`setLockdownDuration`, `setResumeDelay`, `addRecoveryOwner`,
`removeRecoveryOwner`
**are never legitimate during an incident**. The hook reverts them; any
wallet UI that detects them mid-incident should warn loudly even before
broadcast.

### Group C - Off-chain witness / relayer (not signed by Safe owners)

`triggerLockdown(address,bytes32,bytes,bytes)` is the only V1
function called by the panic signer (or their relayer) rather than the
Safe quorum. The Safe owners do not sign it; they instead generate the
EIP-712 typed data and the panic signer (or their device) signs it
off-chain. The relayer broadcasts.

What the panic signer's device shows for the EIP-712 message:

```
Lockdown(
  address safe,
  bytes32 reasonHash
)
```

Two fields, both fixed-size. A clear-signing-aware wallet will display:

- `safe`: protected Safe address (verify chain, length, checksum)
- `reasonHash`: opaque identifier; the runbook says the signer types a
  short note and the UI hashes it. Show first 8 bytes on small devices.

The message does not carry the signer identity: replay safety comes from
single-use burn of the exact registered identity (`signerBurntPermanently`,
INV-SIGN-7), not from a counter in the message. The identity is supplied
as the separate `signer` calldata argument and must match a registered,
unburnt signer.

## 3. Field-by-field guidance

### `triggerLockdown` (4 params, signed via EIP-712 off-chain)

```solidity
triggerLockdown(
  address safe,           // protected Safe
  bytes32 reasonHash,     // forensic note hash
  bytes   signer,         // ERC-7913 signer identity (20-byte EOA/ERC-1271,
                          //   or verifier || key)
  bytes   signature       // signature payload checked against `signer`
)
```

The Safe owners do not sign this. The relayer broadcasts it. The
device-displayable thing is the EIP-712 message digest, not the
calldata. The relayer's UI should display:

- "Trigger lockdown on Safe `<address>`"
- "Reason: `<reasonHash[:8]>` (forensic note)"
- "Authorised by signer `<signer[:4]>…/<keccak256(signer)[:4]>`"
- After: "This panic identity is now burnt. The Safe is locked for
  `<duration>`, remains in recovery for `<delay>`, then returns to Normal
  automatically. No resume transaction exists."

If the user's wallet is not clear-signing-aware, the relayer's UI MUST
show the same information off-device and refuse to broadcast unless the
user explicitly confirms in the UI. Better an extra click than an
attacker mis-encoding the trigger.

For `PasswordVerifier`, the signature field is the cleartext one-time
password. The commitment is public and the cleartext is visible to the RPC
provider and mempool. Disclosure after successful execution is harmless
because the identity is permanently burnt; a failed or reverted attempt may
disclose the password while the identity remains live, and a mempool observer
may front-run the same lockdown. Registration and trigger screens MUST state
this explicitly, require unique high-entropy per-Safe/per-chain material, and
recommend private submission. Password material must never be reused.

### `addLockdownSigner(bytes signer)`

`signer` is an ERC-7913 signer identity: either a 20-byte EOA/ERC-1271
address, or `verifier || key` (the leading 20 bytes are the verifier
address, the remainder is the verifier-specific key). For a passkey via
the WebAuthnVerifier candidate the key is a 64-byte P-256 public key. The
hardware-wallet display SHOULD:

- When the identity is `verifier || key`, display the leading 20-byte
  verifier as a recognised name when it is a labelled verifier (e.g.
  "WebAuthnVerifier v1.0.0").
- Display `keccak256(signer)` in addition to the raw identity bytes. The
  hash is what indexers and audit logs will reference; the raw identity
  is what the user typed.
- Confirm post-tx that `getConfigSnapshot(safe).signersCount` increased by
  one (the live signer-set length; there is no per-signer id, see
  SPEC_V1 §3.2).

### `removeLockdownSigner(bytes signer)`

Same display rules as `addLockdownSigner`. CRITICAL: this function is
in the recovery whitelist (SPEC_V1 §7.4). If a Safe owner is asked to
sign it during a regular Normal-mode session and the device's UI shows
the Safe in Recovering state, that is a coerced cleanup attempt and
the signer should refuse.

There is no separate verifier-approval step. Trust is scoped to the exact
signer identity: a lockdown is authorised iff that identity is registered
via `addLockdownSigner` and the signature verifies. For a `verifier || key`
identity, `addLockdownSigner` only checks that the leading verifier is
non-zero and has deployed code, plus the key length bounds. A malicious or
buggy verifier is contained by removing the affected signers with
`removeLockdownSigner` (batchable via MultiSend). When registering a
`verifier || key` signer the UI should still:

- Display the verifier's code hash (compare against a known list).
- Show whether the verifier has been audited (off-chain registry).
- Warn loudly if the verifier was deployed in the same block as the
  registration - that pattern is associated with bait-and-switch attacks.

### `rotateLockdownSigner(bytes oldSigner, bytes newSigner)`

Two dynamic args. Display as two halves: "Remove signer
`keccak256(oldSigner)`" then "Register signer `keccak256(newSigner)`".
The atomicity matters - signers should understand that revert reverts
both halves.

### `initialize(...)`

4 args, two are arrays. Install-time only, typically batched with
`setGuard` and `setModuleGuard` in a single MultiSend. Hardware-wallet
display priorities (in order):

1. `lockdownDuration` (display in days)
2. `resumeDelay` (display in hours)
3. `initialRecoveryOwners.length` and each address
4. `initialSigners.length` and for each: the identity bytes and
   `keccak256(signer)`

`SafeDormant` event fires if `initialSigners.length == 0`. The
post-install verification script
(`scripts/verify-install-v1.sh`) FAILs on it unless `--allow-dormant` is
passed (for the intermediate check of a staged install only).

## 4. Stress drill checklist (for Safe owners)

Run this drill quarterly:

1. From a cold wallet, prepare an `addLockdownSigner(panicEOA)` tx (a
   20-byte EOA identity) via Safe Transaction Builder. Confirm device
   shows:
   - the identity bytes
   - `keccak256(signer)` matching what the indexer computes
   - `signersCount` incremented by one in the post-tx snapshot
2. From the panic signer device (separate device), produce an EIP-712
   signature for `Lockdown(safe, signer, reasonHash)`. Confirm device shows the
   EIP-712 fields cleanly, including the `signer` identity bytes.
3. Broadcast `triggerLockdown` via a relayer (test-only Safe, NOT the
   production Safe). Confirm `SafeLockedDown` event carries the
   expected `reasonHash` and `signer`.
4. Test `removeLockdownSigner` (and, if relevant, `disableModule` /
   `swapOwner`) during Recovering. Confirm the device shows the recovery
   context cleanly.
5. Wait through `lockdownDuration + resumeDelay`. Confirm the Safe
   auto-resumes to Normal (`getState` reports Normal) with no resume
   transaction to sign.

The drill is documented as part of the runbook; under-drilled signers
under stress fail.

## 5. Limitations and accepted gaps

- Ledger and Trezor do not natively render dynamic `bytes` past 32
  bytes. The clear-signing template hashes long fields on-host and
  shows the hash; the user must trust the host UI for the underlying
  bytes.
- The EIP-712 `reasonHash` is opaque on-chain by design. The semantic
  ("kidnapping", "device lost", "drill") lives in an off-chain log
  indexed by `reasonHash`.
- During an actual coercion event, the attacker sees what the device
  shows. The clear-signing UX cannot hide an admin operation from the
  attacker; it only prevents accidental signing of the wrong call.
- Walletconnect v2 still has gaps for EIP-7913 verifier displays. As
  the standard matures, the clear-signing template SHOULD be updated.
