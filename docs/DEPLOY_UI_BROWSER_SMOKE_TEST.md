# deploy/lockdown-lifecycle.html browser smoke test

Goal: catch real browser regressions in `deploy/lockdown-lifecycle.html` that
static Node calldata checks cannot see: script load failure, DOM binding
breakage, wrong output panel, accidental `file://` assumptions, and builder
flows that throw after UI refactors.

Run:

```bash
make browser-smoke
```

The wrapper installs the pinned npm dev dependency on first use and runs the
Playwright spec against the system Chrome browser.

## Phase 1 - deterministic no-wallet smoke

Implemented in `tests/browser/lockdown-lifecycle.spec.js`.

Test steps:

1. Start a local static HTTP server from the test.
2. Open `/deploy/lockdown-lifecycle.html`.
3. Assert no page errors (uncaught exceptions via `pageerror`; console
   messages are not asserted).
4. Assert `window.ethers` exists and the caveat banner is visible.
5. Fill deterministic fields, click builders that do not need RPC/wallet:
   - `Build initialize() calldata`
   - `Build addLockdownSigner`
   - `Build removeLockdownSigner`
   - `Build rotateLockdownSigner`
   - `Build setTimelockDelay`
   - `Build setTimelockBypasser`
6. Parse `#previewOut` JSON after each click and assert:
   - transaction count;
   - `to`, `operation`, and `value`;
   - calldata selector;
   - dynamic `bytes signer` ABI shape for signer functions.

This phase is cheap and CI-friendly. It does not require a wallet, a live RPC,
or private keys.

## Phase 2 - mocked RPC preflight smoke

Implemented in `tests/browser/lockdown-lifecycle.spec.js`.

Route the read-only RPC URL to a local mock HTTP endpoint. The mock only needs
to support the JSON-RPC calls used by install/digest preflights:

- `eth_chainId`
- `eth_getCode`
- `eth_getStorageAt`
- `eth_call`
- `eth_getBlockByNumber`

Return canned values for:

- Safe `VERSION()`;
- Safe masterCopy storage slot;
- Lockdown `VERSION()`;
- `MULTI_SEND_CALL_ONLY()`;
- `eip712Domain()`;
- `supportsInterface(...)`;
- `getConfigSnapshot(...)`;
- Safe `getOwners()`, `getThreshold()`, and `nonce()`;
- Lockdown `getState(...)` and `isRecoveryOwner(...)`;
- `isLockdownSigner(...)`;
- `isSignerBurntPermanently(...)`.

Then smoke:

1. `Preflight & build install batch` with `include initialize`.
2. `Build digest / prepare` for Password.
3. `Build triggerLockdown JSON` from the produced context.
4. Build a recovery-whitelisted `disableModule(prevModule,module)` Safe
   self-call while the mocked state is `Recovering`.
5. Confirm the auto-resume control is read-only in both `Recovering` and
   normalized `Normal` states, and confirm the obsolete explicit-resume action
   is absent from the page.

This catches the exact class of bugs that already happened: stale
`DOMAIN_SEPARATOR()` assumptions, wrong singleton target, and UI/ABI drift.

## Phase 3 - wallet semantics smoke

Implemented in `tests/browser/lockdown-lifecycle.spec.js`.

Inject a minimal EIP-1193 provider with Playwright `addInitScript`:

- `eth_requestAccounts`
- `eth_chainId`
- `eth_signTypedData_v4`

Assert that `Sign with wallet (EIP-712)` calls `eth_signTypedData_v4`, never
`eth_sign` or `personal_sign`, and that the typed-data domain equals:

- `name = RuntimeLockdown`
- `version = 1.0.0`
- `chainId = form chainId`
- `verifyingContract = singleton input`

This is the most important wallet-specific regression check.

## What this smoke suite cannot prove

Be explicit about the residual gap when citing "browser smoke green":

- No live chain, no real wallet, no hardware-wallet rendering: everything
  on-chain is a canned mock, and the wallet is a minimal injected provider.
- The pinned-codehash preflight path is NOT exercised: phase 2 runs with
  `allow unpinned` checked and empty expected-hash fields, so the FAIL-on-
  mismatch / FAIL-on-missing-pin branches have no automated browser coverage.
- Phase 3 asserts the signing request (method + domain + types), not the
  downstream signature staging: the mock signature is not a valid secp256k1
  signature, so the flow after `eth_signTypedData_v4` returns is unverified.
- Console warnings are not asserted (only uncaught page errors fail the run).

A testnet dry-run before production use remains mandatory (see the banner in
the helper itself).

## CI policy

The lifecycle helper vendors the pinned `ethers` UMD file under
`deploy/vendor/`, so the smoke test does not depend on live CDN/network
availability. `LICENSING.md` records its npm source, version, SHA-256, and
preserved MIT notice.
