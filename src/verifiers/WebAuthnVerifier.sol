// SPDX-License-Identifier: MIT
pragma solidity 0.8.35;

import {
    ERC7913WebAuthnVerifier
} from "@openzeppelin/contracts/utils/cryptography/verifiers/ERC7913WebAuthnVerifier.sol";

/// @title WebAuthnVerifier (V1 optional verifier candidate - UV-required policy)
/// @notice ERC-7913 verifier that authenticates a WebAuthn assertion signed by
///         a passkey (phone Secure Enclave / iCloud Keychain / Google Password
///         Manager / FIDO2 key) over a P-256 credential. The WebAuthn challenge
///         is bound to the Lockdown EIP-712 digest (`hash`), so a leaked
///         assertion cannot be replayed against a different
///         `(safe, reasonHash)` digest - the binding `PasswordVerifier` lacks
///         (it ignores `hash`).
///
/// @dev DESIGN: this is OZ's `ERC7913WebAuthnVerifier` with a single overridden
///      policy constant. Every load-bearing step is inherited unmodified from
///      audited OpenZeppelin code:
///        - `WebAuthn.verify(...)` (utils/cryptography/WebAuthn.sol): clientData
///          type + challenge binding, authenticatorData UP/UV/BE-BS flag checks,
///          `sha256(authData || sha256(clientData))` message construction, and
///          signature malleability handling;
///        - `P256.verify(...)`: secp256r1 verification via the RIP-7212
///          precompile when present, else the audited Solidity fallback.
///      Neither subclass in this file adds logic of its own - only the UV
///      policy each one pins.
///
///      UV (User Verification) policy: this contract requires UV. Its sibling
///      {WebAuthnVerifierNoUV} accepts UP-only assertions. UV is NOT
///      automatically safer for an anti-coercion primitive - a captor can force
///      a biometric / PIN unlock - so the UP-only variant is a deliberate
///      option, not a weakened default. Document the choice in the runbook.
///      UP (User Presence) is always required either way: `WebAuthn.verify`
///      validates the UP bit unconditionally.
///
///      The policy is fixed at COMPILE TIME, not chosen per deployment. OZ
///      declares `_requireUV` as `internal pure`, and Solidity forbids relaxing
///      an override from `pure` to `view`, so it cannot read a constructor-set
///      immutable. The two policies are therefore two distinct contracts with
///      two distinct runtime codehashes; an install must pin the codehash of
///      whichever one it actually deploys.
///
///      Closed-world (anti T-VERIFIER-UPGRADE, SPEC_V1 §14.1): no constructor,
///      no immutables, no storage, no external mutable state. P-256 is decided
///      either by a chain precompile or by OZ's embedded pure Solidity - both
///      deterministic, neither attacker-mutable.
///
///      AUDIT: even leaning on OZ, the canonical production path is to approve
///      either variant only after fuzzing clientDataJSON parsing against real
///      multi-vendor assertions (Apple, Google, Yubico differ in JSON field
///      ordering and extension data).
///
/// Wire format (identical for both variants):
///   key       : 64 bytes = `qx (32) || qy (32)` (the P-256 public key).
///   hash      : the Lockdown EIP-712 digest, bound as the WebAuthn challenge.
///   signature : flat tuple ABI encoding:
///               `abi.encode(r, s, challengeIndex, typeIndex,
///                 authenticatorData, clientDataJSON)`.
///               Do NOT encode the struct as a single top-level argument
///               (`abi.encode(auth)`). OZ `WebAuthn.tryDecodeAuth` expects the
///               six fields at the root of the calldata blob, with no outer
///               tuple offset.
/// @custom:security-contact contact@runtime.capital
contract WebAuthnVerifier is ERC7913WebAuthnVerifier {
    /// @dev Lockdown UV-required policy: the assertion MUST carry the UV flag.
    ///      This matches OZ's base default; it is restated here so the policy
    ///      is explicit at the deployed contract and gets its own build
    ///      artifact and pinned codehash. `pure` is mandated by the base
    ///      declaration - see the UV policy note above.
    function _requireUV() internal pure override returns (bool) {
        return true;
    }
}

/// @title WebAuthnVerifierNoUV (V1 optional verifier candidate - UP-only policy)
/// @notice UP-only counterpart of {WebAuthnVerifier}: same ERC-7913 WebAuthn
///         verification, same wire format, same digest binding, but it accepts
///         assertions that carry only the User Presence flag. Intended for
///         duress / panic credentials, where forcing a biometric or PIN unlock
///         is exactly the coercion the primitive defends against.
/// @dev See {WebAuthnVerifier} for the shared design, closed-world, audit, and
///      wire-format notes - all of them apply verbatim. The only difference is
///      the `_requireUV` constant below, and hence the runtime codehash.
/// @custom:security-contact contact@runtime.capital
contract WebAuthnVerifierNoUV is ERC7913WebAuthnVerifier {
    /// @dev Lockdown UP-only policy: the UV flag is not required. UP is still
    ///      enforced unconditionally by `WebAuthn.verify`. `pure` is mandated
    ///      by the base declaration.
    function _requireUV() internal pure override returns (bool) {
        return false;
    }
}
