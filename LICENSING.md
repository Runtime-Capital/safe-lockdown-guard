# Licensing

This repository is published under a mixed-license model.

## Default license

Unless a file states otherwise through an SPDX header, Runtime Capital original
code and documentation are licensed under the MIT license in `LICENSE`.

The MIT copyright holder is:

```text
RUNTIME GUARD SASU
```

## LGPL Safe-derived fallback handler

`src/handlers/LockdownFallbackHandler.sol` is licensed under
`LGPL-3.0-only`. The complete license text is included at
`LICENSES/LGPL-3.0-only.txt`.

That file is intentionally derived from Safe v1.5.0's
`CompatibilityFallbackHandler.sol`, which is licensed under LGPL-3.0-only by
Safe. The Lockdown version keeps the Safe handler compatibility surface and
adds the incident-state gate around ERC-1271 signature validation.

Do not relabel that file as MIT unless the handler is rewritten without using
Safe LGPL implementation code.

## Dependencies

- OpenZeppelin Contracts: MIT.
- Safe Smart Account: LGPL-3.0-only.
- Forge Standard Library: MIT OR Apache-2.0.
- Playwright test tooling: Apache-2.0.
- ethers.js 6.13.5 browser bundle: MIT.

Safe interfaces, enums, and library types are imported from the pinned
`safe-smart-account` submodule so the build resolves selectors and types
against canonical Safe v1.5.0 sources. The fallback handler is the only
production source file in this repository that intentionally carries an LGPL
SPDX header.

The lifecycle helper vendors the unmodified npm distribution file
`ethers@6.13.5/dist/ethers.umd.min.js` as
`deploy/vendor/ethers-6.13.5.umd.min.js` so incident tooling does not depend on
a CDN. The pinned upstream archive is
`https://registry.npmjs.org/ethers/-/ethers-6.13.5.tgz`. The vendored file's
SHA-256 is
`c8550f9644492f2d1278467b301c615c768a0d61d5c22d5bcd107ec7c9cbd329`.
The upstream MIT notice is preserved in
`LICENSES/ethers-6.13.5-MIT.txt`.

## Project identity

Public-facing brand, package metadata, clear-signing descriptors, audit handoff
material, and security contact should use `Runtime Capital`, `runtime.capital`,
and `contact@runtime.capital`. `RUNTIME GUARD SASU` remains the legal copyright
holder where legally required. Product domains not yet announced must not be
published from this repository during the audit phase.
