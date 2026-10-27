# Deployment Helpers

## Public helper

`lockdown-lifecycle.html` is a public static helper for the **v1.0.0 production
singleton** (`LockdownTimelock`, one deployed contract serves every Safe). It
contains no private default addresses. The panels follow the actual lifecycle
order, step by step:

0. Network, manifest load, and trust roots (codehash pins);
1. diagnose an existing Safe (version, masterCopy, both guard slots, per-Safe
   `getConfigSnapshot`, timelock delay, state);
2. deploy the singleton + bundled verifiers once per chain (only if the manifest
   has no deployed address);
3. build the baseline `initialize(...)` for a Safe;
4. capture/export the pre-install three-slot rollback snapshot, run preflight
   (secure-by-default `EXTCODEHASH` pinning, Safe masterCopy pin), and build the
   atomic `setGuard` + `setModuleGuard` + `setFallbackHandler` + `initialize`
   install batch, with an optional fifth call `setErc1271Allowed(true)`. The
   contract default is ERC-1271 off (SPEC_V1 H.27) and every trigger turns it
   off again; the helper pre-ticks the opt-in when no timelock is planned in
   step 3 (a normal Safe signs messages) and pre-unticks it when one is
   (an off-chain signature settles with no timelock window, NM-1060 6.1).
   The operator can override either way; the override with a timelock is
   flagged in the preview.
   The same panel builds the verified three-stage slot restore;
5. signer identities as a separate governance transaction
   (`addLockdownSigner`, remove/rotate, list; drills are off-chain, see 7);
6. timelock (`setTimelockDelay` with the 0->N one-way warning, built as one
   batch with the ERC-1271 choice: activating the timelock does not touch the
   flag on-chain, and once active changing it waits the delay, so the helper
   proposes `[setErc1271Allowed(false), setTimelockDelay(N)]`, which lands
   atomically and for free at delay 0. "Keep on" and "leave unchanged" are
   allowed and flagged (NM-1060 6.1); `verify-install-v1.sh` WARNs when the
   flag is on under a timelock. The contract enforces no policy here;
   `setTimelockBypasser`, owner/module schedule + cancel, HSM direct-call
   bypass artifact, state reads);
7. trigger lockdown via the full EIP-712 flow (build digest -> sign with burner
   key / typed-data wallet signing / passkey / pasted signature -> local
   in-browser verification (no RPC: ECDSA recover, WebAuthn P-256; other
   identities point to `script/DrillSigner.s.sol` on a local fork) -> submit
   `triggerLockdown`);
8. state and timers (including the effective coercion window);
9. recovery operations (nonce burn, `swapOwner` to allowlist,
   `disableModule`, `removeLockdownSigner`, and read-only auto-resume status);
10. ticket janitor (`sweepExpired*`) and burnt-signer check.

The helper exports Safe Transaction Builder JSON rather than posting directly
to the Safe Transaction Service. The HSM `bypassTimelock` path is the exception:
it exports a direct-call artifact that must be sent by an allowlisted bypasser,
not imported into Safe{Wallet}. The install preflight binds `EXTCODEHASH` and
FAILs by default if an expected hash is missing (mirrors
`scripts/verify-install-v1.sh`); load `deploy/manifest.json` to resolve the
pins by chain ID. Import the JSON into Safe{Wallet} for the normal signing
workflow. The trigger flow is the one place that issues a direct wallet call.

The Ethereum/Base dropdown entries are development conveniences only. v1.0.0
launches on Ethereum mainnet; Base is not supported unless and until a future
release adds a fully qualified Base entry to the manifest. The final filled
manifest is the support matrix: a chain is eligible only after canonical Safe
v1.5.0 + Transaction Service support and all per-chain codehash, source, and
operator-flow checks pass.

## CLI preflight and verify

`scripts/preflight-install-v1.sh` (before signing the install batch) and
`scripts/verify-install-v1.sh` (after it executes) are the read-only CLI
counterparts of panel 4. Typical production run:

```sh
scripts/preflight-install-v1.sh --safe S --singleton X --rpc R \
    --manifest deploy/manifest.json --snapshot-out preinstall-S.json
# ... sign and execute the atomic install batch ...
scripts/verify-install-v1.sh --safe S --singleton X --rpc R \
    --manifest deploy/manifest.json --snapshot preinstall-S.json
```

- **Codehash pins fail closed.** The singleton, `MultiSendCallOnly`,
  `LockdownFallbackHandler` **and the Safe masterCopy** (proxy slot 0,
  `--safe-codehash` / manifest `safeMasterCopyCodehash`) must all be pinned.
  A missing value or a `0xFILL...` manifest placeholder FAILs both scripts.
  `--allow-unpinned-codehash` downgrades every one of them to WARN, for
  dev/test only.
- **Owners, threshold and modules.** Preflight prints the Safe's owners,
  threshold and every enabled module (all `getModulesPaginated` pages, read at
  one block). `--snapshot-out <file>` saves them as JSON, only when preflight
  passed. `verify --snapshot <file>` FAILs if any of them changed, which
  catches an install batch that also slipped in `addOwnerWithThreshold`,
  `changeThreshold` or `enableModule`. Without `--snapshot`, verify prints them
  and WARNs that they were not compared. Take the snapshot immediately before
  the install and verify immediately after it: any intended owner or module
  change in between also shows up as a FAIL.
- **Dormant installs.** `signersCount == 0` is a valid contract state
  (SPEC_V1 H.15) but the Safe cannot be locked down, so verify FAILs it by
  default. For the staged flow of SPEC_V1 decision 7 (install with no signers,
  add them in a later reviewed transaction) run verify with `--allow-dormant`
  right after the install, then again **without** it once the signers are
  registered. Only the second run means "armed".

`make operator-e2e` (`scripts/operator-e2e-anvil.sh`) deploys
the canonical Safe v1.5.0 contracts and the Lockdown singleton + handler on a
throwaway anvil chain, then runs both scripts against that real bytecode:
full pins pass, a placeholder masterCopy pin fails, a staged install is
rejected as dormant until a signer is added, and an install batch that also
adds an owner and enables a module fails `verify --snapshot`.

## WebAuthn fixture recorder

`webauthn-fixture-recorder.html` is a public static capture harness for the
passkey verifier. It records real browser / OS assertions and exports JSON
fixtures that can be converted into Foundry tests:

```sh
node scripts/webauthn-fixture-to-sol.js
forge test --match-contract WebAuthnCapturedFixtures
```

Use it before approving WebAuthn for production to cover Chrome desktop,
Chrome Android, Safari iOS, Safari macOS, and external FIDO2 keys. See
`test/fixtures/webauthn/README.md` for the capture matrix and expected
semantics.

## Local helpers

Some deployment helper files are intentionally local-only in this repository.

The requested external-audit findings scope is Solidity only. Tests are review
evidence; HTML helpers and scripts are out of scope. Local copy/paste calldata
may contain private operational addresses, deployment salts, test Safe
addresses, and wallet labels, so it is ignored by Git.

Local convention:

- `guard-install.local.html`
- `safe-v15-test-deploy.local.html`
- `HANDOVER.local.md`
- `safe-v15-test-deploy-rabby.txt`

Use `config/wallet-addresses.template.json` as the public schema and copy it to
`config/wallet-addresses.local.json` for real deployment drills.
