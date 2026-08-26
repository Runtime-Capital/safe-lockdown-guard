// SPDX-License-Identifier: MIT
pragma solidity 0.8.35;

import {Enum} from "@safe-global/safe-smart-account/interfaces/ISafe.sol";

/// @title LockdownLib
/// @notice Library of common utilities
/// @custom:security-contact contact@runtime.capital
library LockdownLib {
    /// @notice Namespace prefix for owner-path timelock tickets. The actual
    ///         ticket key is `keccak256(abi.encode(typehash, safeTxHash))`,
    ///         so owner-path and module-path tickets cannot accidentally
    ///         collide (different prefixes) and the namespace is
    ///         observable on-chain via `getTransactionExecutableAt`.
    bytes32 internal constant OWNER_TX_TIMELOCK_TYPEHASH = keccak256("OwnerTxTimelock(bytes32 safeTxHash)");
    /// @notice Namespace prefix for module-path timelock tickets. The module
    ///         transaction hash is computed from (safe, module, to, value,
    ///         dataHash, operation) so identical module calls for the same Safe
    ///         produce identical tickets (one ticket = one execution,
    ///         single-use) while different Safes do not collide off-chain.
    bytes32 internal constant MODULE_TX_TIMELOCK_TYPEHASH =
        keccak256("ModuleTxTimelock(address module,address to,uint256 value,bytes32 dataHash,uint8 operation)");

    function ownerTicketKey(bytes32 safeTxHash) internal pure returns (bytes32 ticketKey) {
        // keccak256(abi.encode(OWNER_TX_TIMELOCK_TYPEHASH, safeTxHash))
        bytes32 typehash = OWNER_TX_TIMELOCK_TYPEHASH;
        assembly ("memory-safe") {
            mstore(0x00, typehash)
            mstore(0x20, safeTxHash)
            ticketKey := keccak256(0x00, 0x40)
        }
    }

    function moduleTicketKey(bytes32 moduleTxHash_) internal pure returns (bytes32 ticketKey) {
        // keccak256(abi.encode(MODULE_TX_TIMELOCK_TYPEHASH, moduleTxHash_))
        bytes32 typehash = MODULE_TX_TIMELOCK_TYPEHASH;
        assembly ("memory-safe") {
            mstore(0x00, typehash)
            mstore(0x20, moduleTxHash_)
            ticketKey := keccak256(0x00, 0x40)
        }
    }

    /// @notice Computes the module-path scheduling hash for a given transaction
    /// @dev Designed to diverge from the Safe's `getTransactionHash` to avoid collisions with Safe-path scheduled tickets.
    function moduleTxHash(
        address safe,
        address module,
        address to,
        uint256 value,
        bytes memory data,
        Enum.Operation operation
    ) internal pure returns (bytes32 hash) {
        // return keccak256(abi.encode(safe, module, to, value, keccak256(data), operation));
        assembly ("memory-safe") {
            let ptr := mload(0x40)
            mstore(add(ptr, 0x00), safe)
            mstore(add(ptr, 0x20), module)
            mstore(add(ptr, 0x40), to)
            mstore(add(ptr, 0x60), value)
            mstore(add(ptr, 0x80), keccak256(add(data, 0x20), mload(data)))
            mstore(add(ptr, 0xa0), operation)
            hash := keccak256(ptr, 0xc0)
        }
    }
}
