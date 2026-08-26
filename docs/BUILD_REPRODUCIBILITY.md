# Build Reproducibility And Sourcify

This repository pins the production compiler profile in `foundry.toml`:

- Solidity: `0.8.35`
- EVM version: `prague`
- Optimizer: enabled
- Optimizer runs: `200`
- `via_ir`: enabled

These settings are part of the audited artifact. Changing any of them requires
re-running the audit check suite and treating the bytecode as a new candidate.

## Generate Build Info

```bash
make build-info
```

This runs:

```bash
forge build --build-info --sizes
```

Expected generated artifacts:

- `out/build-info/*.json`
- `reproducibility/forge-config.json`
- `reproducibility/README.md`

Generated artifacts are gitignored. The source of truth remains the audited Git
commit plus `foundry.toml`.

## Sourcify Rehearsal

Dry-run:

```bash
make sourcify-rehearsal
```

After deploying a candidate:

```bash
LOCKDOWN_DEPLOYED_ADDRESS=0x... \
LOCKDOWN_CONSTRUCTOR_ARGS=0x... \
CHAIN_ID=1 \
make sourcify-rehearsal
```

`LOCKDOWN_CONSTRUCTOR_ARGS` must be the ABI-encoded constructor arguments for
the production singleton `LockdownTimelock`:

```solidity
constructor(address multiSendCallOnly)
```

Verification failure is a release blocker: it means the deployed bytecode does
not match the audited source/compiler profile.
