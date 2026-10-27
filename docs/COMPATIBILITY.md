# Extension Compatibility Matrix

This file states which Safe extensions can coexist with Lockdown on the same
Safe v1.5.0. It is derived from what Lockdown occupies and what its guards
accept; it is not a certification of any third-party product. Rows marked
**(unverified in-repo)** rest on the third party's public design, not on a test
or source file in this repository, and must be re-checked against the exact
deployed version before an installation is declared compatible (D-03 in
`docs/DESIGN_DECISIONS.md`).

## What Lockdown occupies

Safe v1.5.0 has three single-occupancy extension slots. Lockdown takes all
three, and `initialize` reverts unless all three are wired:

| Slot | Occupant | Consequence |
| --- | --- | --- |
| Transaction guard (`setGuard`) | the Lockdown singleton | No other transaction guard can be installed |
| Module guard (`setModuleGuard`) | the Lockdown singleton | No other module guard can be installed |
| Fallback handler (`setFallbackHandler`) | a `LockdownFallbackHandler` whose `LOCKDOWN()` returns the singleton | No other fallback handler can be installed, on either path, at any MultiSend depth |

Modules are not a slot: any number can be enabled, but every module execution
passes through the module guard (`checkModuleTransaction`). In Normal a module
may CALL anything except the singleton, may not touch the three guard slots
(`ModuleSafeSelfCallDenied`), and is blocked entirely during LockedDown and
Recovering. On both paths the only `DELEGATECALL` accepted is to the pinned
canonical `MultiSendCallOnly`, whose batch is parsed recursively; any other
`DELEGATECALL` reverts `DelegateCallDenied`. With `timelockDelay > 0` every
module transaction additionally needs a ticket created by
`scheduleModuleTransaction` and matured for the full delay.

## Compatible

| Extension | Why it works | Conditions |
| --- | --- | --- |
| Any owner type: EOA, contract owner validated through ERC-1271, Safe passkey owner (`SafeWebAuthnSignerProxy`), MPC signer, an AI-agent cosigner holding an owner key | Owner signatures are checked by Safe itself; the guard sees only the resulting transaction, whatever produced the signatures | Owner-type behaviour is Safe's, not tested here; passkey and MPC rows are **(unverified in-repo)** |
| CALL-only modules: Safe Allowance module, Candide social recovery, Zodiac Delay and recovery modules | Their executions are plain `CALL`s accepted by the module guard in Normal | `timelockDelay == 0`, or every execution pre-scheduled (see below). Blocked during LockedDown and Recovering like any module. Module internals **(unverified in-repo)** |
| Zodiac modules that batch through MultiSend | Accepted when the batch `DELEGATECALL`s the exact pinned `MultiSendCallOnly` | A module configured with any other MultiSend (including the non-call-only `MultiSend`) is refused. Module configuration **(unverified in-repo)** |
| Token callbacks (ERC-721, ERC-1155, ERC-777) | `LockdownFallbackHandler` inherits Safe's `TokenCallbackHandler` | None |
| Classic CoW Protocol orders via `setPreSignature` | A plain owner-path `CALL` to the settlement contract | A pre-signature set before an incident is stored on the settlement contract and stays valid during it; cancel standing orders as part of recovery (AR-19). Settlement behaviour **(unverified in-repo)** |

## Incompatible

| Extension | Reason |
| --- | --- |
| Safe < 1.5.0 | No module guard, so the module path cannot be frozen (README, Compatibility item 1) |
| `Safe4337Module` | Must also be the Safe's fallback handler; that slot holds `LockdownFallbackHandler` **(unverified in-repo)** |
| Rhinestone `Safe7579` adapter | Same: requires the fallback-handler slot **(unverified in-repo)** |
| `ExtensibleFallbackHandler`, and therefore CoW `ComposableCoW` / TWAP orders | Requires the fallback-handler slot; `ComposableCoW` validates orders through it **(unverified in-repo)** |
| Any other transaction guard: Hypernative Guardian, an on-chain Safe Shield guard, Brahma, and the guards already listed in the README | The transaction-guard slot is taken. Product architectures **(unverified in-repo)** |
| On-chain message signing via `SignMessageLib` | It is a `DELEGATECALL` to a library other than `MultiSendCallOnly`, refused `DelegateCallDenied`. Off-chain ERC-1271 owner signatures still work in Normal |
| Gnosis Pay accounts | Their owner path is disabled by design and spending runs through modules, which Lockdown freezes and, with a timelock, gates per transaction **(unverified in-repo)** |

## Module automation and the timelock

With `timelockDelay > 0` there is no module-path bypass: each module
transaction must first be scheduled (`scheduleModuleTransaction` is called by
the Safe, so by the owner quorum) and then wait the full delay. A module that
reacts to external events cannot work under that rule, so module automation is
practical only with `timelockDelay == 0`, which in turn removes the
coerced-quorum response window (AR-13, failure-mode row 7). Operators must
choose between the two.

## Off-chain signatures (onboarding)

ERC-1271 is an explicit per-Safe opt-in (SPEC_V1 H.27, NM-1060 6.1). The
`LockdownFallbackHandler` refuses every ERC-1271 validation with
`Erc1271Disabled` until the Safe calls `setErc1271Allowed(true)` on the
singleton, and refuses it again with `SignaturesFrozenDuringLockdown` during
LockedDown / Recovering whatever the flag. The default after a plain install
is therefore **no off-chain signing at all**: no USDC / EURC / PYUSD gasless
transfers (`transferWithAuthorization`), no `permit`, no Permit2 signature
transfers, no CoW Protocol or Seaport orders, no Snapshot votes signed by the
Safe, no ERC-1271 owner signature for a nested Safe, and the Safe cannot serve
as a 20-byte ERC-1271 lockdown signer for another Safe (AR-22). An
uninitialised Safe reads the flag as `false` too, so the handler is not a
neutral drop-in before `initialize`.

The opt-in is an owner-path self-call, `onlyNormal`, and not a timelock
meta-call: with `timelockDelay > 0` it is scheduled and waits the delay (or a
registered bypasser releases it). Disabling it again goes through the same
path. Modules cannot reach it, and it is not on the recovery whitelist.

| Flag | Delay | Profile | ERC-1271 in Normal | ERC-1271 in LockedDown / Recovering |
|---|---|---|---|---|
| off (default) | any | Treasury Safe: nothing is signed off-chain | Refused (`Erc1271Disabled`) | Refused |
| on | `0` | Operational / DeFi Safe: Lockdown is a panic button | Accepted | Refused |
| on | `> 0` | Treasury Safe that still needs off-chain orders | Accepted; **re-opens NM-1060 6.1 by operator choice** | Refused |

Onboarding must state it in these words: **with ERC-1271 allowed, an
off-chain signature is settled by a third party without any
`execTransaction`, so the timelock gives it no reaction window; a coerced
quorum can move funds instantly through it even with `timelockDelay > 0`.**
The on-chain default is off (fail-closed). The lifecycle helper proposes the
opt-in at install, pre-ticked when no timelock is planned and unticked
otherwise; when the timelock is activated later, it builds one batch
`[setErc1271Allowed(choice), setTimelockDelay(N)]` with "off" as the default
and a warning to keep it on. The flag survives an incident: an opted-in Safe
auto-resumes with ERC-1271 on, so recovery must rotate every coerced owner
(AR-19). The preflight and verify scripts print the flag.

Two points the operator must act on:

- **Revoke standing allowances when relying on the timelock.** A spender that
  already holds an ERC-20 allowance, or a Permit2 AllowanceTransfer
  permission, pulls with `transferFrom` without touching the Safe: neither the
  guard nor the handler sees it, in any state.
- **Enabling the flag re-enables signatures, including ones signed earlier**,
  because validity is decided when the signature is checked, not when it is
  produced. The flag also survives an incident: after auto-resume an opted-in
  Safe validates again, so the post-recovery runbook reviews it and sets it
  back to `false` unless the open orders are still wanted.

With the flag on, allowance hygiene is the operator's job: approve the exact
amount, keep Permit2 `expiration` and signature deadlines (`deadline`,
`validBefore`) in hours rather than days, and revoke after use. Lockdown
protects what still has to go through the Safe after the trigger; anything
already delegated to a spender escapes it.

## Rejected: a generic forwarding fallback handler

A `LockdownFallbackHandler` that forwards unknown selectors to a second,
operator-chosen handler was evaluated and rejected. Fallback handlers identify
the Safe through `msg.sender` (plus Safe's appended original caller). Relaying
with `CALL` makes the forwarding handler the `msg.sender`, so the downstream
handler serves the wrong account. Relaying with `DELEGATECALL` runs the
downstream code in the handler's storage, and that one handler instance is
shared by every Safe bound to the singleton, so per-Safe handler state would
become cross-Safe state. Neither is acceptable.

The possible future path is a dedicated `LockdownExtensibleFallbackHandler`: a
fork of Safe's `ExtensibleFallbackHandler` with the same `LOCKDOWN()` binding
and incident-time ERC-1271 freeze. It is not in V1 and would need its own
review.
