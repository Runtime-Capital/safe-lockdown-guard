# Semgrep Safe-Guard Checks

This repository includes a lightweight Semgrep wrapper:

```bash
make semgrep
```

It runs:

- Semgrep Registry `p/smart-contracts`;
- local regression tripwires in `semgrep/safe-guard.yml`.
- the legacy Semgrep `--x-parmap` backend. Semgrep 1.168.0's default
  shared-memory/Eio backend can fail on this workstation with
  `io_uring_queue_init`; `--x-parmap` is slower but stable for this small
  Solidity scope.

The local rules are intentionally narrow and focused on Safe guard mistakes:

- no low-level `delegatecall`;
- no `selfdestruct` / `suicide`;
- no `tx.origin` authorization;
- no fund transfer to `refundReceiver`;
- flag owner-set degradation selector constants if they reappear in production
  code.

(Five rules total in `semgrep/safe-guard.yml`; keep this list in sync with the
rule ids in that file.)

Semgrep is a pattern scanner, not a proof system. Treat matches as manual-review
items. A clean Semgrep pass does not imply the contract is secure.

Current expected behavior:

- local `semgrep/safe-guard.yml`: zero findings;
- registry `p/smart-contracts`: most noisy gas/performance suggestions are
  filtered out by rule id so `make semgrep` remains a security/coherence
  tripwire. One inherited Safe-handler performance finding intentionally
  remains expected.
- expected result on the current codebase: one registry performance finding on
  the Safe-derived fallback handler's inherited string `require`. This is
  triaged in `docs/STATIC_ANALYSIS_TRIAGE.md`; local Safe-guard tripwires are
  clean.
