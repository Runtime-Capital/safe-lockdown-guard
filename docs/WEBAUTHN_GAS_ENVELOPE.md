# WebAuthn gas measurements and no-cap decision

Input for issue #79 point A: what a passkey panic identity actually costs and
whether V1 can safely cap the gas forwarded to an ERC-7913 verifier.

**Decision: V1 has no verifier gas ceiling.** Legitimate verifier cost is
open-ended and chain-dependent; a ceiling calibrated to current P-256 could
silently disable a more expensive valid verifier, including future
post-quantum schemes. The measurements remain useful for transaction funding,
simulation and regression diagnosis, not for a production constant.

Reproduce with:

```bash
# Repository default: Prague execution, Solidity fallback.
forge script script/WebAuthnGasEnvelope.s.sol --sig 'measure()' -v

# Exact Prague-compiled verifier runtimes on the current Osaka/EIP-7951 EVM.
export WEBAUTHN_UV_PRAGUE_RUNTIME="$(forge inspect src/verifiers/WebAuthnVerifier.sol:WebAuthnVerifier deployedBytecode)"
export WEBAUTHN_NOUV_PRAGUE_RUNTIME="$(forge inspect src/verifiers/WebAuthnVerifier.sol:WebAuthnVerifierNoUV deployedBytecode)"
forge script script/WebAuthnGasEnvelope.s.sol --sig 'measurePragueVerifierOnCurrentEvm()' --evm-version osaka --out out-osaka -v
```

The harness is a `forge script`, deliberately not a test: a test file would
change the 483-test count that `AUDIT_BRIEF.md`, the scope sheet and the RFQ
answers all state, forcing a documentation round-trip for a measurement tool.
Nothing under `src/` is involved.

## Results

Measured on Foundry 1.7.1, solc 0.8.35 and `via_ir = true`. The fallback run uses
the repository's `evm_version = prague`. The current-mainnet run compiles the
measurement harness for Osaka but replaces both verifier contracts with the
exact runtimes produced by the default Prague build before measuring them.

### Prague fallback path

| Case | Gas |
|---|---:|
| `verify()`, UV-required verifier, UV assertion | 364,140 |
| `verify()`, UP-only verifier, UV assertion | 361,576 |
| `verify()`, UP-only verifier, UP assertion | 357,249 |
| `verify()`, captured Chrome + YubiKey fixture (long clientDataJSON) | 358,459 |
| `verify()`, captured Chrome + Google Password Manager fixture | 349,116 |
| **`verify()` range** | **349,116 - 364,140** |
| full `triggerLockdown`, UP-only verifier | 410,248 |
| full `triggerLockdown`, UV-required verifier | 416,925 |
| **full `triggerLockdown` range** | **410,248 - 416,925** |

### Current Ethereum mainnet path (Osaka / EIP-7951)

These direct calls execute the exact Prague-compiled verifier runtimes, not
Osaka recompilations of those contracts.

| Case | Gas |
|---|---:|
| `verify()`, UV-required verifier, UV assertion | 16,026 |
| `verify()`, UP-only verifier, UV assertion | 15,962 |
| `verify()`, UP-only verifier, UP assertion | 16,040 |
| `verify()`, captured Chrome + YubiKey fixture (long clientDataJSON) | 16,201 |
| `verify()`, captured Chrome + Google Password Manager fixture | 16,071 |
| **`verify()` range** | **15,962 - 16,201** |

### Rejecting paths

| Case | Prague fallback | Current EIP-7951 |
|---|---:|---:|
| UV-required verifier, UP-only assertion (policy rejection) | 7,332 | 7,378 |
| UV-required verifier, valid assertion over the wrong digest | 7,141 | 7,188 |
| Garbage signature blob | 1,488 | 1,503 |
| Empty signature | 1,485 | 1,501 |

Rejections are two orders of magnitude cheaper because they short-circuit before
the P-256 arithmetic. They do not provide an upper bound for legitimate
accepting paths.

## Reading these numbers

The direct-call measurement includes caller-side ABI and call overhead, so it
is a conservative observation rather than an exact minimum for callee work.

**Ethereum mainnet does have native P-256 verification.** Fusaka activated on
mainnet on 3 December 2025 and included EIP-7951 at `0x100`; EIP-7951 supersedes
RIP-7212. The Prague run deliberately characterises OZ's pure-Solidity fallback,
while the Osaka run characterises the current launch network. See the
[Ethereum Fusaka overview](https://ethereum.org/roadmap/fusaka/) and
[EIP-7951](https://eips.ethereum.org/EIPS/eip-7951).

The repository currently limits the v1 launch manifest to Ethereum mainnet.
Consequently, 16,201 is the observed current-mainnet maximum and 364,140 is the
observed no-precompile compatibility maximum. The difference demonstrates why
a chain-specific ceiling is brittle: the same audited verifier runtime has a
radically different legitimate cost depending on available precompiles.

**This is a measured range, not a proven worst case.** Cost tracks the
`clientDataJSON` length, which varies by vendor: origin string, extension fields,
JSON field ordering. The two captured fixtures are real Chrome blobs (Google
Password Manager on Android, and a cross-platform YubiKey), and the generated
assertions use a short origin. A vendor emitting a longer `clientDataJSON` than
anything measured here costs more. A tight ceiling would not degrade
gracefully: it would make the panic path unfireable for that identity. V1 avoids
that failure mode by forwarding the transaction's available gas.

**UV policy is not a cost argument.** Its observed effect is small relative to
the fallback path and negligible on EIP-7951. The choice between
`WebAuthnVerifier` and `WebAuthnVerifierNoUV` stays a threat-model decision: a
captor can force a biometric or PIN unlock, which is precisely the coercion this
primitive exists to survive.

## Operational consequence

The supported product domain is limited to immutable, closed-world verifier
bytecodes shipped and codehash-pinned by this repository. The identity is the
trust unit: any OOG, revert or invalid result means the identity must be removed
or rotated without reusing that verifier. V1 neither caps forwarded gas nor
forks OpenZeppelin's ERC-7913 dispatch to bound copied return data. The return
and revert bomb PoCs remain accepted evidence for behaviour outside the
supported verifier domain.
