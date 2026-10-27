# Runtime Lockdown Security Assurance

Status: living document, pre-production.

Last updated: 2026-08-27.

## Purpose

This file is the operator-facing assurance index for Runtime Lockdown.

It is deliberately not a second audit brief. Keep detailed test counts,
invariant mappings, residual-risk tables, and tool outputs in their canonical
files, then link to them from here. This avoids stale duplicated claims during
pre-audit churn.

Canonical sources:

- `AUDIT_BRIEF.md` - audit scope, current evidence, accepted residual risks,
  and reviewer questions.
- `specs/SPEC_V1.md` - normative protocol specification and invariants.
- `docs/STATIC_ANALYSIS_TRIAGE.md` - Slither / Aderyn / Semgrep triage.
- `docs/V1_USER_SCENARIOS.md` - lifecycle and incident runbooks.
- `docs/V1_NON_GOALS.md` - explicitly rejected V1 features.
- `docs/PRIOR_ART_SAFERSAFES.md` - comparison with Optimism SaferSafes and
  adopted / rejected lessons.
- `docs/daybreak/RESULTS.md` - focused three-worker adversarial campaign, executable evidence, lead triage, and final dispositions.

## Current Status

Runtime Lockdown is a **pre-audit v1.0.0 candidate**, not yet externally
audited or production-ready.

The current assurance case is sufficient to request comparable Solidity-audit
quotes and continue adversarial review and low-value deployment drills. Audit
start requires an exact frozen candidate commit and refreshed evidence for that
commit. This document is not a substitute for an external audit or a signed
operator runbook.

## Security Model Reminder

Runtime Lockdown is a Safe v1.5.0 guard system. A protected Safe must have:

1. transaction guard set to the Lockdown singleton;
2. module guard set to the same singleton;
3. fallback handler set to a Lockdown-aware handler bound to the same singleton;
4. per-Safe `initialize(...)` completed after those slots are wired.

Funds remain in the Safe. Runtime Lockdown is an admissibility layer, not a
custodian and not an executor contract.

Timelock mode is Safe-native:

- owners sign the ordinary Safe transaction;
- `scheduleTransaction(...)` records the signed Safe transaction hash without
  consuming the Safe nonce;
- after the delay, the original Safe transaction executes through Safe
  `execTransaction`;
- module transactions use `scheduleModuleTransaction(...)`;
- `bypassTimelock(...)` is an allowlisted owner-path fast lane intended for an
  HSM-backed off-chain reviewer.

## Go / No-Go Before Material Funds

Before putting material assets behind Runtime Lockdown, operators need a dated
go/no-go packet containing:

1. target commit hash and deployed singleton address;
2. `forge test` output for that exact commit;
3. refreshed static-analysis triage for that exact commit;
4. refreshed long-running Echidna or Medusa campaign for that exact commit;
5. Halmos focused checks for that exact commit;
6. browser/lifecycle helper smoke test for that exact commit;
7. verified mainnet bytecode and filled `deploy/manifest.json`;
8. successful `preflight` and `verify` scripts against the target Safe;
9. full low-value drill: install, schedule, execute, trigger lockdown, recover,
   resume, re-enrol panic signers;
10. live monitoring and paging for critical events;
11. written incident runbook signed off by Safe owners;
12. disclosure channel or capped bounty live before public promotion.

## Monitoring Minimum

Watch at least:

- lockdown lifecycle events;
- signer and recovery-owner changes;
- timelock delay / bypasser changes;
- `TransactionScheduled`;
- `ModuleTransactionScheduled`;
- `TicketCancelled`;
- `TicketSwept`;
- `TimelockBypassed`;
- `TimelockConsumed`.

For each owner-path `TransactionScheduled`, monitoring must resolve
`safeTxHash` back to full Safe transaction parameters through Safe Transaction
Service or another trusted indexer. `TimelockBypassed` should page immediately - but note the alert is
FORENSIC, not preventive: `bypassTimelock` sets `executableAt = now`, so a
bypass and its execution can land in the same block and no human or automated
response can cancel in between. Paging still matters for detecting a
compromised bypasser and for cancelling the tickets it wrote but has not yet
used. Pinned by `test/poc/TimelockAccounting.t.sol`.

## Runbook Minimum

Operators need rehearsed procedures for:

- install and verification;
- signer enrolment / rotation / removal;
- independent panic-identity failure domains, including the prohibition on a Lockdown-protected ERC-1271 Safe as the sole identity of another Safe;
- timelock schedule-and-execute flow;
- bypasser approval flow, if configured;
- NEVER_BYPASS admin/disarm policy in the off-chain reviewer;
- lockdown trigger;
- incident communications;
- recovery-owner swap;
- resume and post-resume signer re-enrolment;
- same-singleton reinstall state and pending-ticket reconciliation;
- fallback if Safe Transaction Service is unavailable;
- uninstall / migration.

## Next High-ROI Assurance Steps

1. Preserve and periodically rerun the completed Daybreak campaign's executable Foundry evidence; its lead-reviewed dispositions are in `docs/daybreak/RESULTS.md`.
2. Use this assurance index plus `AUDIT_BRIEF.md` to request a Safe Foundation
   audit/security grant.
3. Pursue audit subsidies and co-funding in parallel.
4. Open a capped disclosure / bounty program once the target commit is stable.
