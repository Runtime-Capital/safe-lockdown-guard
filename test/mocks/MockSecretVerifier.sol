// SPDX-License-Identifier: MIT
pragma solidity 0.8.35;

import {IERC7913SignatureVerifier} from "@openzeppelin/contracts/interfaces/IERC7913.sol";

/// @title MockSecretVerifier (TEST-ONLY - DO NOT DEPLOY TO PRODUCTION)
/// @notice ERC-7913 verifier whose `signature` is a preimage of the
///         commitment encoded in `key`.
/// @dev    Intentionally ignores `hash`. This means the same `signature`
///         produces a valid result for any message hash, which makes the
///         path trivially replayable across Safes / across reverted txs /
///         after burn for any unburned matching registration. This verifier
///         is shipped ONLY in the test/mocks tree so that the singleton
///         can be exercised against a non-ECDSA verifier in unit and fuzz
///         tests. **Production deployments MUST NOT approve this verifier.**
///
///         key format       : 32 bytes (keccak256 commitment, packed).
///         signature format : arbitrary preimage bytes.
contract MockSecretVerifier is IERC7913SignatureVerifier {
    bytes4 private constant MAGIC = IERC7913SignatureVerifier.verify.selector;

    function verify(bytes calldata key, bytes32, bytes calldata signature) external pure override returns (bytes4) {
        if (key.length != 32) return bytes4(0);
        bytes32 commitment;
        assembly {
            commitment := calldataload(key.offset)
        }
        if (keccak256(signature) != commitment) return bytes4(0);
        return MAGIC;
    }
}
