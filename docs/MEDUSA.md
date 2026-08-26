# Medusa Fuzzing

Medusa is optional, complementary fuzzing for the existing Echidna harness.

It is useful because it runs a Go-Ethereum based EVM and supports parallel,
coverage-guided fuzzing. It is not a replacement for Foundry unit/fuzz tests
or Echidna.

## Install

```bash
go install github.com/crytic/medusa@latest
```

## Run

Baseline:

```bash
make medusa
```

Longer campaign:

```bash
MEDUSA_TEST_LIMIT=5000000 MEDUSA_SEQ_LEN=120 make medusa
```

The wrapper targets the existing `EchidnaLockdown` property harness:

- target contract: `EchidnaLockdown`
- compilation target: `test/echidna/EchidnaLockdown.sol`
- corpus: `medusa-corpus/` (gitignored)

The wrapper prefers the self-contained Slither tool environment for
`crytic-compile`, avoiding broken or partially installed user-level Python
entrypoints.

## Pass / Fail

Pass:

- no property violation;
- no minimized failing sequence;
- corpus grows or plateaus without violations.

Fail:

- any Medusa property violation;
- any trace that reaches an impossible state according to `specs/SPEC_V1.md`.

If Medusa finds a violation, reduce it to a Foundry regression test before
changing production Solidity.
