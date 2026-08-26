# safe-lockdown-guard

[![CI](https://github.com/Runtime-Capital/safe-lockdown-guard/actions/workflows/ci.yml/badge.svg)](https://github.com/Runtime-Capital/safe-lockdown-guard/actions/workflows/ci.yml)

**An anti-coercion guard for Safe multisigs.** One MIT-licensed singleton that any
Safe v1.5.0 points at with two configuration transactions. No admin, no pauser, no
upgradeability, and no path for anyone, including us, to touch another party's Safe.
Each Safe keeps full custody, sets its own configuration, and can walk away at any
time.

> **Not audited yet.** An external audit is the only remaining step before v1.0.0.
> Do not install this on a Safe holding value until that audit is complete and
> published.

## The problem: the $5 wrench attack

Key management assumes the attacker cannot reach you. Cryptographically a 3-of-5
multisig is unbreakable. Physically it is a small number of findable people, and an
attacker only needs to hold one of them: a signer under duress is leverage over
everyone else who holds a key, and in practice keys sit far closer together than the
threshold suggests. The last two years have seen a steady stream of kidnappings, home
invasions and coercion aimed at people known to hold crypto keys.

Against a physical attacker, quorum is not a defence. If the attacker controls the
people, they control the threshold. Today the victim has no on-chain move at all: the
choice is between hoping the attacker is slow and handing over the funds. This guard
exists to give the victim one move.

## What it does

1. **Register one or more lockdown signers.** A passkey on a phone, a single-use
   password short enough to live behind something as ordinary as a physical panic
   button, a hardware wallet, a software wallet. Any of them can freeze the Safe.
   **None of them can spend from it.**

2. **Trigger the lockdown.** One signature locks the Safe for a chosen period, from a
   few hours to several days. Nothing moves value during that window, not even the
   full owner quorum, not through a module, and not through the ERC-1271 signature
   surface. The only transactions that still execute are a narrow recovery whitelist:
   replace a compromised owner with a pre-registered recovery owner, disable a module,
   burn a nonce.

3. **Show the attacker the lock.** The freeze is on-chain and verifiable by anyone on
   a block explorer. The victim can prove the funds cannot move before the window
   elapses, which is the point: it removes what the coercion is for, and buys time for
   the people involved and for law enforcement.

4. **The Safe resumes on its own.** Purely on elapsed time. No unlock transaction, no
   emergency admin, no pauser.

Well suited to an operational multisig signing many transactions: the guard stays
invisible until the day it is needed.

### The optional timelock

Every owner transaction can additionally be put behind a delay. Owners sign the
ordinary Safe transaction in the normal Safe frontend, anyone can schedule it on-chain
without consuming the Safe nonce, and it becomes executable once the configured delay
has passed. Full Safe frontend compatibility is retained, rather than pushing users
onto a separate governance paradigm.

The delay is also what makes the lockdown reliable: a stolen quorum can no longer move
funds instantly, so there is always a window in which someone can still trigger the
freeze.

## Why it is a public good

- **Open shared infrastructure.** One singleton contract, MIT-licensed, free to
  install and free to fork.
- **It makes self-custody survivable.** The honest answer to a wrench attack today is
  that self-custody has no answer. A credible freeze gives one, and removes an argument
  for moving assets back to custodians.
- **It should move people off single-key EOAs.** Many large holders still sit on one
  EOA because a multisig adds operational cost without addressing the risk they
  actually fear. Making the multisig the setup that survives coercion changes that
  trade-off.
- **It closes a gap Safe leaves open.** Safe v1.5.0 introduced the module guard, which
  is what finally makes a real freeze enforceable across every execution path. Very
  little has been built on it so far.

## Status

v1.0.0 audit candidate, scope-locked. Not deployed to mainnet.

| | |
|---|---|
| Solidity | 2,312 physical lines across 10 source files, 1,118 nSLOC |
| Tests | 483 Foundry unit, fuzz, integration and proof-of-behaviour tests |
| Fuzzing | 15 Echidna stateful properties, plus Medusa and sampled mutation testing |
| Integration | Real Safe v1.5.0 deployed through the canonical mainnet `SafeProxyFactory` |
| Static analysis | Slither, Aderyn and Semgrep, triaged in `docs/STATIC_ANALYSIS_TRIAGE.md` |

This repository is self-contained. It does not require any Runtime Capital private
repository to build, test, or review the contract.

## Where to go next

| You are | Start here |
|---|---|
| An auditor | `AUDIT_BRIEF.md`, then `specs/SPEC_V1.md` |
| Setting up a toolchain | `docs/DEV_ENVIRONMENT.md` |
| Evaluating the design | `docs/DESIGN_DECISIONS.md`, then `docs/PRIOR_ART_SAFERSAFES.md` |
| Assessing residual risk | `SECURITY_ASSURANCE.md` |
| Reporting a vulnerability | `SECURITY.md`. Please do not open a public issue. |

---

The rest of this README is written for reviewers and operators.

`LockdownTimelock` is the production dual-interface Safe guard. It inherits the
concrete `Lockdown` base, which provides the no-timelock lockdown/recovery
primitive and is tested directly.

- `ITransactionGuard` protects normal Safe owner transactions.
- `IModuleGuard` protects Safe module transactions introduced in Safe v1.5.0.

The goal is a credible anti-coercion primitive: if a lockdownSigner wallet triggers a
lockdown, funds cannot move through owner or module paths until the configured
lockdown period and recovery delay expire, after which the Safe auto-resumes to
normal operation (purely time-based; there is no explicit resume call and no
`Resumable` state).

## Compatibility and assumptions

These constraints are structural, not roadmap items. State them in any
serious conversation about the product:

1. **Safe v1.5.0 required.** The design depends on the module guard
   (`setModuleGuard`), introduced in Safe v1.5.0. On earlier versions the
   module path can bypass any transaction guard, so neither the lockdown
   freeze nor the timelock can be enforced. The contract cannot protect a
   v1.4.1 Safe.
2. **Launch networks are selected by capability, not by brand.** The
   Solidity contracts are chain-agnostic. A network is eligible for launch
   only when Safe publishes a canonical v1.5.0 deployment and Transaction
   Service support, and Runtime Capital has completed the per-chain manifest,
   bytecode/codehash, source-verification, and end-to-end operator checks.
   The final release manifest is the authoritative supported-network list.
3. **Lockdown installs only on an already-v1.5.0 Safe.** A Safe on v1.4.x
   must be migrated in a separate product flow before Lockdown installation.
   The v1.4.x -> v1.5.0 singleton upgrade is never bundled into the Lockdown
   installation transaction and is outside this repository and its Solidity
   audit scope.
4. **Three install slots per Safe.** Lockdown occupies the transaction-guard
   slot (`setGuard`), the module-guard slot (`setModuleGuard`), AND the
   fallback-handler slot (`setFallbackHandler`, a `LockdownFallbackHandler`
   bound to the singleton that freezes the Safe's ERC-1271 surface during an
   incident; signatures and approvals produced BEFORE the incident remain
   valid - see the accepted-risk register in `AUDIT_BRIEF.md`).
   `initialize` reverts unless all three are wired to the singleton
   / its handler. Lockdown is therefore mutually exclusive with any other guard
   (Safenet, Fiducia, Policy Engine, Kleidi, Optimism TimelockGuard, a future
   on-chain Safe Shield guard) and with any custom fallback handler.
5. **The timelock bypasser is a trusted fast lane.** `bypassTimelock` is
   restricted to a per-Safe allowlist. Any service using that authority must
   simulate and policy-check the full transaction off-chain before bypassing;
   such a service is separate from this open-source repository and outside the
   Solidity audit scope. The bypasser
   can fast-track either
   by calling `bypassTimelock` for a specific hash, or by submitting the
   `execTransaction` itself (the guard skips the delay inline when the submitter
   is an allowlisted bypasser); both require the per-Safe allowlist. On-chain,
   the bypasser sees only the hash: HSM compromise equals full owner-path bypass
   authority. The module path has no bypass in any state.

Installation and configuration are deliberately separate governance steps.
The first Safe transaction wires the three slots and calls `initialize`.
Signer provisioning, timelock activation, and bypasser policy are subsequent,
independently reviewed Safe transactions. An installed Safe must not be called
"armed" until the chosen follow-up configuration has executed and been
verified on-chain.

Prior-art comparison with Optimism's audited TimelockGuard/SaferSafes:
`docs/PRIOR_ART_SAFERSAFES.md`.

## Auditor Quick Start

```bash
cd safe-lockdown-guard
forge test          # deps are pinned submodules: OZ + safe-smart-account (src) + forge-std (tests)
scripts/contract-sizes.sh # artifact-derived runtime sizes; forge --sizes omits prod contracts here
```

For the standard local check (recommended before review):

```bash
make audit-check
```

For optional heavy tooling, if installed:

```bash
make audit-check-full
```

`make audit-check-full` runs Foundry tests/build/coverage, artifact-derived
runtime sizes, Sourcify rehearsal, Slither, Aderyn, Semgrep, Halmos, browser
smoke, Echidna, Medusa, and the mutation campaign. Current static analysis
output is triaged in `docs/STATIC_ANALYSIS_TRIAGE.md`: there are zero actionable
high/medium findings after triage. Aderyn's raw output contains one high
reentrancy detector class, documented as a false positive because all three
reported calls use the pinned Safe interface's `view`/`STATICCALL` surface.

The Safe integration suite (`test/integration/SafeIntegration.t.sol`, part of
`forge test`) deploys a real Safe v1.5.0 through the canonical Ethereum
mainnet `SafeProxyFactory`, installs `Lockdown` as both transaction guard and
module guard, then checks recovery refund denial and both Safe module entrypoints:
`execTransactionFromModule` and `execTransactionFromModuleReturnData`.

For optional targeted mutation testing:

```bash
make mutation-gambit
```

This requires a local Gambit install. See `docs/GAMBIT_MUTATION_PLAN.md`.

For build reproducibility:

```bash
make build-info
make sourcify-rehearsal
```

This is documented in `docs/BUILD_REPRODUCIBILITY.md`.

For optional Medusa and Semgrep passes:

```bash
make medusa
make semgrep
```

See `docs/MEDUSA.md` and `docs/SEMGREP.md`.

For lifecycle UI, open `deploy/lockdown-lifecycle.html` locally. The UI contains no private
defaults, diagnoses existing Safes, and exports Safe Transaction Builder JSON
for Safe{Wallet}.

## Tooling Requirements

Required:

- Foundry (`forge`, `cast`)

Optional:

- Slither (`slither`)
- Aderyn (`aderyn`)
- Gambit (`gambit`)
- Medusa (`medusa`)
- Semgrep (`semgrep`, or `uvx semgrep`)
- Docker (for Echidna via `trailofbits/echidna`)
- Node.js (for deployment HTML bytecode consistency checks)

No npm, pnpm, or yarn installation is required. The contract's external Solidity
dependencies are the pinned OpenZeppelin Contracts submodule (MIT) and the pinned
safe-smart-account submodule (LGPL-3.0, used for the Safe v1.5.0 interfaces,
`Enum`, `MultiSendCallOnly`, and the Safe-derived fallback-handler surface).
The test suite additionally uses `forge-std` (MIT OR Apache-2.0). All are
vendored as git submodules.

This repository uses a mixed-license model: Runtime Capital original code is MIT,
while `src/handlers/LockdownFallbackHandler.sol` is LGPL-3.0-only because it is
derived from Safe's LGPL fallback handler. See `LICENSING.md`.

The compiler profile is pinned in `foundry.toml`:

- Solidity `0.8.35`
- EVM `prague`
- optimizer enabled, `200` runs
- `via_ir = true`

## Design summary

- Lockdown is triggered by a 1-of-N registered ERC-7913 `bytes` lockdown signer
  (a 20-byte EOA/ERC-1271 address, or `verifier || key`).
- Lockdown duration is configured at deployment and can be changed later by Safe
  quorum only while the guard is in normal mode.
- Recovery stays active after expiry and for the configured `resumeDelay`,
  after which the Safe auto-resumes to normal (time-based; no resume call).
- Safe modules are blocked during lockdown and recovery.
- Module `DelegateCall` is allowed only to canonical `MultiSendCallOnly`,
  parsed with the same recursive check as the owner path but with
  guard-configuration calls disabled, so any call targeting the singleton is
  denied at every depth (a module can never administer the guard); any other
  `DelegateCall` is denied.
- Owner-path arbitrary `DelegateCall` is denied.
- Owner-path canonical `MultiSendCallOnly` is allowed in normal mode. The
  parser recurses into nested `MultiSendCallOnly` delegatecalls, rejects any
  delegatecall to a non-canonical target, and enforces the
  `setFallbackHandler` binding check at every depth. Inner `CALL`s to the
  Safe, the singleton, or `address(0)` (normalised to the Safe) are
  intentionally allowed; they remain Safe-quorum-gated and timelocked by the
  scheduled outer `safeTxHash`.
- During recovery, the owner path is intentionally narrow: empty Safe self-call
  nonce burns, `swapOwner` toward a pre-registered `recoveryOwnerAllowlist`
  address, `disableModule`, and `removeLockdownSigner`. `addOwner`,
  `removeOwner`, `changeThreshold`, and lockdown signer additions/rotations are
  rejected during recovery. Safe refund
  fields must also be zero during recovery, so value cannot leak through Safe
  gas refunds.

## Files

- `AUDIT_BRIEF.md` - start here for an external audit.
- `docs/DESIGN_DECISIONS.md` - concise record of deliberate choices and
  accepted v1.0.0 limitations.
- `SECURITY_ASSURANCE.md` - current assurance case, residual risks, and
  pre-production go/no-go gates.
- `src/LockdownTimelock.sol` - production candidate with optional timelock.
- `src/Lockdown.sol` - concrete lockdown-only base inherited by
  `LockdownTimelock`.
- `test/Lockdown.t.sol` - Foundry tests.
- `test/LockdownTimelock.t.sol` - V1 timelock, bypass, sweep, and stale-ticket
  tests.
- `test/verifiers/*.t.sol` - verifier unit tests for Password and WebAuthn;
  the native EOA / secp256k1 identity path is tested in `test/Lockdown.t.sol`.
- `test/echidna/EchidnaLockdown.sol` - Echidna stateful property harness.
- `specs/SPEC_V1.md` - current implementation brief and invariants.
- `docs/V1_REVIEW_PROMPT.md` - brief for an independent reviewer.
- `docs/STATIC_ANALYSIS_TRIAGE.md` - per-finding Slither/Aderyn triage.
- `docs/V1_HARDWARE_WALLET_UX.md` - recovery signing risks and operator
  verification checklist.
- `docs/V1_USER_SCENARIOS.md` - who-does-what during supported lifecycle
  scenarios.
- `docs/BUILD_REPRODUCIBILITY.md` - build-info and Sourcify verification gate.
- `docs/clear-signing/` - ERC-7730 v2 calldata and EIP-712 descriptor templates.
- `docs/GAMBIT_MUTATION_PLAN.md` - optional targeted mutation-testing plan.
- `docs/PRIOR_ART_SAFERSAFES.md` - deep comparison with Optimism's audited
  TimelockGuard/SaferSafes, borrowed patterns, and Spearbit-finding triage.
- `docs/MEDUSA.md` - optional Medusa fuzzing workflow.
- `docs/SEMGREP.md` - optional Semgrep registry + custom rules workflow.
- `config/wallet-addresses.template.json` - public schema for local deployment
  addresses. Real addresses belong in `config/wallet-addresses.local.json`,
  which is gitignored.
- `deploy/lockdown-lifecycle.html` - public static lifecycle helper.
- `scripts/audit-check.sh` - one-command local verification.
- `scripts/preflight-install-v1.sh` - read-only on-chain pre-install verifier;
  run before signing `setGuard + setModuleGuard + setFallbackHandler`.
- `scripts/verify-install-v1.sh` - read-only on-chain post-install verifier.
- `scripts/package-audit.sh` - optional utility to produce a clean source snapshot (excludes generated artifacts and local-only files).

Deployment helper frontends under `deploy/*.local.*` are intentionally ignored
because they can contain environment-specific wallet labels, Safe addresses,
salts, and calldata. `deploy/README.md` documents the convention.

The git repository itself is the audit handoff. A `scripts/package-audit.sh` utility
exists for anyone who wants a clean filesystem snapshot without the `.git` directory
or local ignored files; it is not required for review.
