# V1 Adversarial Coverage - 2026-07-04

**Snapshot as of 2026-07-04. Counts and campaign results in this file are
point-in-time and are not updated; current figures live in `AUDIT_BRIEF.md`.**

Purpose: record adversarial and long-running assurance work already performed
against the current V1 audit target, so future reviewers do not repeat the same
campaigns without changing the scope, seed, harness, or parameters.

This file is an evidence index, not a security proof. Detailed invariants remain
in `AUDIT_BRIEF.md`, `specs/SPEC_V1.md`, and the test harnesses.

## Target

- Repository: `Runtime-Capital/safe-lockdown`
- Branch/snapshot: `main` after fast-forward to `origin/main` on 2026-07-04
- Packaging method: `scripts/package-audit.sh`
- Snapshot property: tracked files only, submodules included, no `.git`,
  local tooling/config directories, `.env*`, secrets, local caches, or generated
  build artifacts
- Remote workspace:
  `/home/<user>/safe-lockdown-longrun-20260704-1602`
- Cleanup command:
  `rm -rf /home/<user>/safe-lockdown-longrun-20260704-1602`

## Environment

- Host: `<internal-host>`
- OS/kernel observed: Linux x86_64, Ubuntu kernel 7.0.0-22-generic
- RAM observed before long runs: 30 GiB total, ~16 GiB available, 15 GiB swap
- Disk observed before long runs: ~2.3 TiB available under `/home`
- Isolation:
  - no system packages installed;
  - Node/npm installed locally under `tools/node`;
  - Foundry installed locally under `tools/foundry`;
  - long-running tools executed through Docker where practical;
  - all logs stored below the remote workspace.

## Long-Running Fuzz Campaigns

### Echidna Long Run

Status: **completed, no invariant failure observed**.

Command shape:

```sh
docker run --rm --memory 14g --memory-swap 14g \
  -v "$PWD":/src -w /src trailofbits/echidna \
  sh -lc "/venv/bin/pip install -q --upgrade crytic-compile && \
  echidna test/echidna/EchidnaLockdown.sol \
    --contract EchidnaLockdown \
    --config test/echidna/echidna.yaml \
    --test-limit 5000000 \
    --seq-len 120"
```

Observed result:

- Start: `2026-07-04T16:05:40+02:00`
- End: `2026-07-04T16:15:34+02:00`
- Total calls: `5,000,337`
- Target limit: `5,000,000`
- Unique instructions: `3744`
- Unique codehashes: `7`
- Corpus size: `25`
- Seed: `7634591781157125030`
- Result: 14/14 Echidna properties passing

Passing properties recorded in the log:

- `echidna_modulePathCannotReachSingleton`
- `echidna_disarmGatedByTimelock`
- `echidna_bypassRejectedDuringIncident`
- `echidna_removedSelectiveMagicSignerCannotTrigger`
- `echidna_safeBConfigUntouched`
- `echidna_sweepClearsExpiredOwnerTicketSlot`
- `echidna_allowlistCountNeverZero`
- `echidna_noModulePathDuringRecovery`
- `echidna_lockdownCoversTimelock`
- `echidna_signersCountAtMost32`
- `echidna_safeBNeverLockedDown`
- `echidna_recoveryAdminSelectorsRejected`
- `echidna_burntSignerNeverResurrects`
- `echidna_noOwnerPathDuringLockdown`

Remote log:

```text
/home/<user>/safe-lockdown-longrun-20260704-1602/safe-lockdown/longrun-logs/echidna-long.log
```

Do not repeat this exact run unless at least one of the following changes:

- audit target commit;
- `test/echidna/EchidnaLockdown.sol`;
- `test/echidna/echidna.yaml`;
- seed / test limit / sequence length;
- Echidna image or crytic-compile behavior.

### Medusa Long Run

Status: **completed, no failure observed**.

The Medusa run was scheduled to wait for Echidna completion, then started in a
separate tmux session.

Command shape:

```sh
docker run --rm --memory 14g --memory-swap 14g \
  -v "$RUN_DIR":/work -w /work/safe-lockdown \
  --entrypoint sh ghcr.io/crytic/medusa:latest \
  -lc "export PATH=/work/tools/foundry:/venv/bin:$PATH; \
  medusa fuzz \
    --config medusa.json \
    --compilation-target test/echidna/EchidnaLockdown.sol \
    --target-contracts EchidnaLockdown \
    --workers 4 \
    --test-limit 50000000 \
    --seq-len 120 \
    --corpus-dir medusa-corpus \
    --use-slither \
    --fail-fast"
```

Observed result:

- Docker image: `ghcr.io/crytic/medusa:latest`
- Start wait: `2026-07-04T16:13:03+02:00`
- End: `2026-07-04T16:51:27+02:00`
- Elapsed fuzzing time: `35m28s`
- Calls: `50,020,961`
- Target limit: `50,000,000`
- Branches: `628`
- Corpus: `64`
- Failures: `0/416838`
- Test summary: `53` tests passed, `0` tests failed
- Approx speed observed: ~23k-26k calls/sec
- HTML report: `medusa-corpus/coverage/coverage_report.html`
- LCOV report: `medusa-corpus/coverage/lcov.info`

Remote log:

```text
/home/<user>/safe-lockdown-longrun-20260704-1602/safe-lockdown/longrun-logs/medusa-long.log
```

Do not repeat this exact run unless at least one of the following changes:

- audit target commit;
- `medusa.json`;
- `test/echidna/EchidnaLockdown.sol`;
- Medusa image;
- Foundry version used for compilation;
- test limit / sequence length / workers / corpus seed.

### Medusa Deep-Sequence Run

Status: **completed, no failure observed**.

This second Medusa pass used the same harness but increased the sequence length
from `120` to `500`, targeting longer lifecycle combinations across scheduling,
module execution, lockdown, recovery, resume, stale-ticket cleanup, and
cross-Safe isolation.

Command shape:

```sh
docker run --rm --memory 14g --memory-swap 14g \
  -v "$RUN_DIR":/work -w /work/safe-lockdown \
  --entrypoint sh ghcr.io/crytic/medusa:latest \
  -lc "export PATH=/work/tools/foundry:/venv/bin:$PATH; \
  medusa fuzz \
    --config medusa.json \
    --compilation-target test/echidna/EchidnaLockdown.sol \
    --target-contracts EchidnaLockdown \
    --workers 4 \
    --test-limit 50000000 \
    --seq-len 500 \
    --corpus-dir medusa-corpus-seq500 \
    --use-slither \
    --fail-fast"
```

Observed result:

- Docker image: `ghcr.io/crytic/medusa:latest`
- End: `2026-07-04T17:49:03+02:00`
- Elapsed fuzzing time: `34m34s`
- Calls: `50,021,402`
- Target limit: `50,000,000`
- Branches: `628`
- Corpus: `64`
- Failures: `0/100041`
- Test summary: `53` tests passed, `0` tests failed
- HTML report: `medusa-corpus-seq500/coverage/coverage_report.html`
- LCOV report: `medusa-corpus-seq500/coverage/lcov.info`

Remote log:

```text
/home/<user>/safe-lockdown-longrun-20260704-1602/safe-lockdown/longrun-logs/medusa-seq500-long.log
```

Do not repeat this exact run unless at least one of the following changes:

- audit target commit;
- `medusa.json`;
- `test/echidna/EchidnaLockdown.sol`;
- Medusa image;
- test limit / sequence length / workers / corpus seed.

## Mutation Campaigns

### Gambit Sampled Mutation - Lockdown + LockdownTimelock

Status: **completed, no sampled survivor observed**.

This run used `scripts/mutation-gambit.sh` with `GAMBIT_SAMPLE_EVERY=10` over
the two production contracts most exposed to guard/timelock logic changes.
Gambit generated mutants with `--skip_validate`; each sampled mutant was killed
with the full `forge test` suite under the repository's normal via-IR Foundry
configuration.

Environment:

- `gambit`: `/home/<user>/safe-lockdown-longrun-20260704-1602/tools/gambit`
- `solc`: `0.8.35+commit.47b9dedd.Linux.g++`
- `forge`: `1.5.1-stable`
- Start: `2026-07-04T22:22:20+02:00`
- End: `2026-07-04T22:33:40+02:00`

Observed result:

| Target | Generated mutants | Sampled | Killed | Survived |
| --- | ---: | ---: | ---: | ---: |
| `src/Lockdown.sol` | `598` | `60` | `60` | `0` |
| `src/LockdownTimelock.sol` | `341` | `35` | `35` | `0` |

Remote artifacts:

```text
/home/<user>/safe-lockdown-longrun-20260704-1602/safe-lockdown/longrun-logs/mutation-gambit-sample10.log
/home/<user>/safe-lockdown-longrun-20260704-1602/safe-lockdown/mutation-work/kill-results-src-Lockdown-sample10.txt
/home/<user>/safe-lockdown-longrun-20260704-1602/safe-lockdown/mutation-work/kill-results-src-LockdownTimelock-sample10.txt
```

Do not repeat this exact sampled campaign unless at least one of the following
changes:

- audit target commit;
- `scripts/mutation-gambit.sh`;
- `src/Lockdown.sol`;
- `src/LockdownTimelock.sol`;
- sample rate;
- test suite / Foundry version.

A stricter follow-up would be `GAMBIT_SAMPLE_EVERY=1` on the same two targets,
but that is a multi-hour campaign and was not run in this pass.

## Remote Operations Cheat Sheet

Check status:

```sh
tmux list-sessions | grep lockdown
tail -f /home/<user>/safe-lockdown-longrun-20260704-1602/safe-lockdown/longrun-logs/medusa-long.log
```

Stop active sessions:

```sh
tmux kill-session -t lockdown-echidna
tmux kill-session -t lockdown-medusa
```

Delete the full workspace:

```sh
rm -rf /home/<user>/safe-lockdown-longrun-20260704-1602
```
