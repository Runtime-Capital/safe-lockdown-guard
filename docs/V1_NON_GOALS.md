# V1 Non-Goals and Rejected Hardening Options

This file records deliberate scope decisions for the V1 audit target. These
features are useful design space, but they are intentionally outside V1 because
they would expand the audited Solidity surface before the first high-value
deployment.

It also records hardening ideas that were considered and deliberately rejected.
This is meant to save reviewer time: do not report these items as missing
mitigations unless the implementation contradicts the rationale below.

## Solidity Freeze

V1 Solidity production code is frozen except for clear bug fixes found during
review. Tests, documentation, tooling, runbooks, deployment manifests, and
the operator's off-chain bypasser policy may still change.

## Not In V1

### Minority Timelock Cancel

Inspired by Optimism Safer Safes, a minority of Safe owners could be allowed to
cancel a queued timelock transaction without full quorum.

Decision: not V1. Today, cancellation is a Safe-quorum action
(`cancelTransaction` / nonce consumption), and the adversarial response to a
coerced quorum is `triggerLockdown`. Minority cancel introduces a new signature
surface, threshold policy, replay domain, and griefing model. It belongs in
V1.x only with a dedicated spec and audit.

### Liveness / Deadman Recovery

Inspired by Optimism's Liveness Module, a fallback owner could recover a Safe
when too many owners are lost or unresponsive.

Decision: not V1. Lockdown addresses coercion / malicious quorum scenarios, not
key-loss deadlock. A liveness module is complementary but changes the product's
trust model and needs its own threat model, challenge-response window, and
interaction rules with the timelock.

### Irreversible Config Freeze

A Safe could permanently renounce the ability to uninstall or relax Lockdown
configuration.

Decision: not V1. This is attractive for an institutional "maximum assurance"
mode, but it is irreversible and raises real brick risk while the system is
young. V1 keeps full Safe-quorum control in Normal state; anti-coercion comes
from the panic path and timelock, not permanent governance capture.

### On-Chain Non-Bypassable Admin Floor

The contract could force certain high-impact admin operations
(`setGuard`, `setModuleGuard`, `setFallbackHandler`, timelock changes, signer
mutation, bypasser mutation) to wait the full timelock even if submitted or
pre-bypassed by an HSM bypasser.

Decision: not V1. The current model explicitly treats the bypasser as a trusted
fast lane: if it is compromised, it has broad owner-path bypass authority. V1
expects the operator's off-chain bypasser policy to refuse to auto-approve or
bypass these admin operations instead. Moving this on-chain would touch the
timelock core, require classifying Safe self-calls and MultiSend contents, and
would deserve a fresh audit.

### Rich On-Chain Timelock Queue

The contract could store full transaction parameters, not just ticket hashes,
to make queued transactions self-describing on-chain.

Decision: not V1. Current V1 keeps storage minimal and relies on off-chain
monitoring to reconstruct parameters from the Safe transaction / scheduled hash.
Richer queue observability is useful but not required for correctness, and it
increases storage and parser surface. A future version may add richer events or
storage if operator monitoring proves too fragile.

## Rejected Hardening Options

### Fallback Handler Exact Codehash Pinning On-Chain

Rejected on 2026-07-02 after review of PR #41.

The singleton checks that the installed fallback handler is lockdown-aware
(`LOCKDOWN() == singleton`). Deployment tooling and verify scripts pin the
canonical handler address / codehash off-chain. The contract deliberately does
not require a fixed runtime codehash on-chain.

Reasons:

- The fallback handler is new security code and may need to be upgraded without
  redeploying the Lockdown singleton or losing per-Safe config, signers,
  recovery owners, and in-flight timelock tickets.
- Exact on-chain codehash pinning turns a handler fix into a singleton migration.
  That is the wrong upgrade boundary.
- Codehash proves bytecode at one address, not future behaviour for proxies or
  handlers with mutable external dependencies. The operator still needs
  preflight / verify / runbook checks.
- The accepted model is: on-chain lockdown-awareness interface + off-chain
  deployment attestation for the canonical handler.

A later version can revisit a stricter registry or versioned handler policy if
operational evidence justifies the reduced flexibility.

### Full ABI Canonical Parsing in Guard Hooks

Rejected on 2026-07-02 after review of PR #41.

Guard hooks should validate the path and the lockdown-relevant selector, not
re-implement the ABI validation of every allowed target function.

Reasons:

- If a selector is allowed but calldata is malformed, the target function itself
  executes next and reverts. Re-validating the full ABI in the hook duplicates
  the callee's responsibility.
- Extra parsing increases the guard's attack surface and makes future Safe /
  ABI changes harder to reason about.
- Selector/path gating keeps the hook simple: the guard decides whether this
  kind of operation may proceed in this state; the function decides whether its
  own arguments are valid.
- Exact calldata checks are still appropriate where the guard itself must make a
  semantic decision from calldata before the target function runs, for example
  recovery `swapOwner` allowlist checks and MultiSend envelope parsing.

Review guidance: a finding that says "the hook admits malformed calldata that
the callee then reverts" is informational unless it consumes nonce/value in a
way that changes the threat model.

### Per-Safe Ticket Epoch Bumped on Trigger

Rejected for now on review of NM-1060 6.5.

A per-Safe epoch folded into every ticket key and incremented inside
`triggerLockdown` (one SSTORE) would invalidate every owner and module ticket
scheduled before the incident. It would close the residual that a pre-incident
module ticket survives nonce burns and owner swaps and fires at the first
second of Normal (AR-19).

Reasons:

- It also kills every legitimate ticket. A defensive queue that took up to 30
  days to mature must be rescheduled and waited again after every incident,
  drill or false positive, which is itself a liveness cost a single panic
  identity can impose.
- `disableModule` is already recovery-whitelisted and makes a pending module
  ticket unreachable; owner tickets are already handled by nonce burns. The
  residual is contained operationally (AR-19, D-18).
- It changes every ticket-key derivation on frozen Solidity, the same
  objection that deferred the uninstall ticket epoch
  (`docs/PRIOR_ART_SAFERSAFES.md` §6).

### Generic Forwarding Fallback Handler

Rejected during compatibility review (`docs/COMPATIBILITY.md`).

A `LockdownFallbackHandler` that forwards unknown selectors to a second
handler would let Lockdown coexist with `Safe4337Module`, `Safe7579` or
`ExtensibleFallbackHandler`. Handlers identify the Safe through `msg.sender`,
so a `CALL` relay presents the wrong account, and a `DELEGATECALL` relay runs
the second handler in storage shared by every Safe bound to the same handler
instance. A dedicated `LockdownExtensibleFallbackHandler` fork is the possible
future path.

## Principle

V1 is intentionally narrow: install completeness, owner-path lockdown,
module-path lockdown, ERC-1271 fallback-handler freeze, optional timelock, and
single-use panic signers. Anything that adds a second governance mechanism or a
new signature policy is deferred unless it fixes a concrete audit finding.
