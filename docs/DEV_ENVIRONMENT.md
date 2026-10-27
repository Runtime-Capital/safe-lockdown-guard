# Development Environment

Toolchain needed to reproduce the checks described in `AUDIT_BRIEF.md`. Only
the first section is required; everything else backs the optional
`make audit-check-full` chain.

Host provisioning (package manager, container runtime, browser install) is out
of scope for this document: it is machine-specific and is not tracked here.

## Required

| Tool | Version used for the v1.0.0 candidate | Install |
| --- | --- | --- |
| Foundry (`forge`, `cast`, `anvil`) | 1.7.1 | `curl -L https://foundry.paradigm.xyz \| bash && foundryup` |
| Git submodules | pinned in `foundry.lock` | `git submodule update --init --recursive` |

The build profile is pinned in `foundry.toml` and must not be overridden:
solc `0.8.35`, EVM `prague`, optimizer `200`, `via_ir = true`, `isolate =
false` (the module-timelock hook tests share transient storage between the
pre- and post-hook, as they do in production).

```bash
forge test          # 601 passing
forge build
forge fmt --check
make hooks          # optional: enables the tracked pre-commit fmt hook
```

## Optional (audit-check-full)

| Tool | Version | Install | Target |
| --- | --- | --- | --- |
| Slither | 0.11.6 | `pipx install slither-analyzer` | `make slither` |
| Aderyn | 0.6.8 | release binary from `Cyfrin/aderyn` | `make aderyn` |
| Semgrep | 1.172.0 | `pipx install semgrep` | `make semgrep` |
| Halmos | 0.3.3 | `pipx install halmos` | `make halmos` |
| Medusa | 1.5.1 | release binary from `crytic/medusa` | `make medusa` |
| Echidna | pinned image digest in `Makefile` | Docker | `make echidna` |
| Gambit | 1.0.6 | release binary from `Certora/gambit` | `make mutation-gambit` |
| `solc` | 0.8.35 | `pipx install solc-select && solc-select install 0.8.35 && solc-select use 0.8.35` | required by `make mutation-gambit` |
| Node.js + Playwright | Node 24.18.0 (CI pin) | `npm ci` | `make browser-smoke` |
| `zip` / `unzip` | any | system package | `make package`, `scripts/operator-check.sh` |

Aderyn, Semgrep, Medusa, and Gambit steps SKIP with a printed notice when the
tool is absent, so read the output rather than assuming a green run covered
them. Slither, Halmos, Docker, and Node/Playwright are hard prerequisites of
`make audit-check-full` and FAIL the chain when missing.

### Echidna and Docker

`make echidna` runs the digest-pinned `trailofbits/echidna` image. Both
rootful and rootless Docker work. Under rootful Docker the container writes
build artifacts back as `root`, so the target runs a cleanup `chown` in the
same pinned image; under rootless Docker the files already land with the
caller's UID and the target detects this and skips the cleanup entirely.

### Browser smoke test

`tests/browser/playwright.config.js` pins `channel: "chrome"`, which Playwright
resolves to a system Google Chrome install (`/opt/google/chrome/chrome` on
Linux) — not the Chromium that `npx playwright install` downloads. This is
deliberate: `deploy/lockdown-lifecycle.html` is an operator-facing incident UI,
so the smoke test should exercise the browser operators actually run, whose
WebCrypto and WebAuthn behaviour is what the helper depends on.

## Known caveats

- `forge coverage` cannot instrument `src/Lockdown.sol` or
  `src/LockdownTimelock.sol`: they compile only with via-ir, and Foundry's
  `--ir-minimum` mode silently drops them from the report. Expect no line
  coverage number for the singleton; test strength is evidenced by the
  601-test suite, the 16 Echidna invariants, and the Medusa campaign.
- `forge build --sizes` can omit the production artifacts in this via-ir
  setup. Use `scripts/contract-sizes.sh`, which reads the build artifacts
  directly.
- Slither prints an internal IR warning on the transient-slot helper and then
  completes normally. Its results and Aderyn's are triaged in
  `docs/STATIC_ANALYSIS_TRIAGE.md`.
- `deploy/manifest.json` ships with `0xFILL_` pre-deploy placeholders, so
  `scripts/operator-check.sh` warns about them until real codehashes are
  filled in.
