// SPDX-License-Identifier: MIT
pragma solidity 0.8.35;

import {IERC7913SignatureVerifier} from "@openzeppelin/contracts/interfaces/IERC7913.sol";

/// @title PasswordVerifier (production, V1)
/// @notice WARNING: THIS IS THE LEAST SECURE OF THE V1 PRODUCTION VERIFIERS.
///         Prefer a 20-byte EOA / ERC-1271 signer before reaching for this
///         one. Use `PasswordVerifier` ONLY when the operator has no usable
///         signing device AND has internalised the trade-offs listed below.
///
///         ERC-7913 verifier whose `signature` is the cleartext preimage of
///         the commitment encoded in `key`. Designed for low-friction panic
///         scenarios where the lockdown signer is a human typing a password
///         into a browser, with no hardware wallet required.
/// @dev Threat model (READ BEFORE APPROVAL):
///
///   - The trigger transaction broadcasts the password IN CLEAR over the
///     public mempool. Anyone watching can read it BEFORE the transaction
///     lands. They cannot replay it on a different Safe (the verifier is
///     per-Safe and the signer entry is burnt on success), but they CAN
///     frontrun the original trigger by submitting their own
///     `triggerLockdown(...)` call with the same `verifier || key` identity and a
///     different `reasonHash`. The resulting `SafeLockedDown` event will
///     reference the attacker's `reasonHash`, polluting the on-chain
///     audit trail. The functional outcome (Safe locked, signer burnt)
///     is identical to the legitimate trigger.
///
///   - This verifier IGNORES `hash`. The password is not bound to the
///     EIP-712 message digest. The Lockdown singleton still permanently
///     burns the signer identity (`passwordVerifier || commitment`) on
///     removal, rotation, or successful trigger, so an old leaked password
///     cannot be re-armed with the same commitment. ANY in-flight cleartext
///     trigger can still be frontrun as described above.
///
///   - Operator obligations:
///       1. **Entropy floor 80 bits.** Diceware 6-8 words, or a 12-character
///          random alphanumeric. NEVER a reused or low-entropy password.
///          The 32-byte commitment hides the password against direct
///          lookup, but a low-entropy password can be brute-forced by
///          rainbow-table against the signer bytes once the registration
///          event becomes public.
///       2. **No cross-Safe reuse.** Each Safe must have its own
///          password. Otherwise a compromised password on one Safe
///          enables an attacker to locate every Safe that registered
///          the same commitment via event scraping (the commitment
///          `keccak256(password)` is publicly included in
///          `LockdownSignerAdded`).
///       3. **Single-use semantics.** Every successful trigger burns
///          the signer. Drilling this verifier permanently consumes
///          the password; rotation requires a fresh quorum
///          `addLockdownSigner(...)` call.
///       4. **Drill cost.** A real drill leaks the password to the
///          mempool AND burns the signer. Drilling more than once
///          with the same password is unsafe; rotate.
///       5. **No `testSigner` for drills.** Calling
///          `Lockdown.testSigner(passwordVerifier || key, hash,
///          cleartextPassword)` leaks the password via RPC. Use ONLY with
///          a throwaway password for pre-approval sanity check.
///
///   - For higher-security panic workflows, prefer:
///       - a 20-byte EOA / ERC-1271 signer (hardware wallet, no plaintext leak);
///       - the future salted-with-nonce passkey verifier (enclave-mediated;
///          binds to current Safe nonce so leaked credentials become
///          ineffective in the next block).
///
/// Wire format:
///   key       : 32 bytes, equal to `keccak256(passwordBytes)`. Computed
///               off-chain at registration time and registered via
///               `addLockdownSigner(passwordVerifier || commitment)`. Key
///               shape is the responsibility of the off-chain registration
///               tooling.
///   signature : the password bytes, non-empty. `verify` rejects an empty
///               signature, so the `keccak256("")` commitment (a publicly
///               known constant) can never be triggered. Otherwise hashed
///               via `keccak256` and compared to the stored commitment.
///   hash      : intentionally ignored. The singleton's EIP-712 binding
///               does not protect this verifier; the singleton's permanent
///               signer burn is the replay protection. Mempool-level
///               frontrunning is accepted per the threat model above.
/// @custom:security-contact contact@runtime.capital
contract PasswordVerifier is IERC7913SignatureVerifier {
    /// @inheritdoc IERC7913SignatureVerifier
    function verify(
        bytes calldata key,
        bytes32,
        /* hash */
        bytes calldata signature
    )
        external
        pure
        override
        returns (bytes4)
    {
        return key.length == 32 && signature.length != 0 && bytes32(key) == keccak256(signature)
            ? IERC7913SignatureVerifier.verify.selector
            : bytes4(0);
    }
}
