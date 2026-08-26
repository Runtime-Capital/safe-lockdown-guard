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
   install batch. The same panel builds the verified three-stage slot restore;
5. signer identities as a separate governance transaction
   (`addLockdownSigner`, `testSigner` drill,
   remove/rotate, list);
6. timelock (`setTimelockDelay` with the 0->N one-way warning,
   `setTimelockBypasser`, owner/module schedule + cancel, HSM direct-call
   bypass artifact, state reads);
7. trigger lockdown via the full EIP-712 flow (build digest -> sign with burner
   key / typed-data wallet signing / passkey / pasted signature -> read-only `testSigner`
   drill for non-password schemes -> submit `triggerLockdown`);
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
