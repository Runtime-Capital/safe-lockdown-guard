// SPDX-License-Identifier: MIT
pragma solidity 0.8.35;

// Safe
import {ISafe} from "@safe-global/safe-smart-account/interfaces/ISafe.sol";
// OpenZeppelin
import {EnumerableSet} from "@openzeppelin/contracts/utils/structs/EnumerableSet.sol";

/// @custom:security-contact contact@runtime.capital
abstract contract RecoveryOwners {
    using EnumerableSet for EnumerableSet.AddressSet;

    /// @notice Safe OwnerManager sentinel (head of the owner linked list).
    ///         Never a valid recovery owner (H.19).
    address private constant SENTINEL_OWNERS = address(0x1);

    mapping(address safe => EnumerableSet.AddressSet) private _owners;

    event RecoveryOwnerAdded(address indexed safe, address indexed owner);
    event RecoveryOwnerRemoved(address indexed safe, address indexed owner);

    error RecoveryOwners_AlreadyRegistered();
    error RecoveryOwners_Unknown();
    error RecoveryOwners_ZeroAddress();
    error RecoveryOwners_Invalid();
    error RecoveryOwners_EmptyAllowlist();

    // -------------------------------------------------------------------
    // Accessors
    // -------------------------------------------------------------------

    function isRecoveryOwner(address safe, address owner) public view returns (bool) {
        return _owners[safe].contains(owner);
    }

    function getRecoveryOwnerCount(address safe) public view returns (uint256 count) {
        return _owners[safe].length();
    }

    function getRecoveryOwners(address safe) public view returns (address[] memory owners) {
        return _owners[safe].values();
    }

    // -------------------------------------------------------------------
    // Public mutators
    // -------------------------------------------------------------------

    function addRecoveryOwner(address owner) public virtual {
        _addRecoveryOwner(msg.sender, owner, false);
    }

    /// @notice Removes a pre-registered recovery owner from the allowlist.
    /// @dev    A Safe-quorum self-call setter, frozen during BOTH LockedDown
    ///         and Recovering (it is NOT part of the recovery whitelist). The
    ///         allowlist may shrink to a single entry but never to empty
    ///         (EmptyAllowlist). Validation is not re-run on removal, so an
    ///         owner that became invalid after registration can still be
    ///         culled (H.19). See SPEC_V1 §7.4.
    /// @dev Strict: removing an address that is not on the allowlist reverts
    ///      `RecoveryOwners_Unknown` rather than succeeding silently. A quorum culling a
    ///      compromised backup with a mistyped address would otherwise get a successful
    ///      Safe transaction, an `ExecutionSuccess`, and no `RecoveryOwnerRemoved` event,
    ///      while the compromised backup stayed `swapOwner`-eligible during recovery.
    ///      `addRecoveryOwner` stays non-strict: a redundant add is genuinely idempotent
    ///      and leaves the intended state.
    function removeRecoveryOwner(address owner) public virtual {
        _removeRecoveryOwner(msg.sender, owner, true);
        // Assert the non-empty invariant AFTER the mutation; a removal that
        // would empty the allowlist reverts and rolls back. `!= 0` (min 1),
        // not `> 1`: the allowlist may legitimately shrink to a single owner.
        require(getRecoveryOwnerCount(msg.sender) > 0, RecoveryOwners_EmptyAllowlist());
    }

    // -------------------------------------------------------------------
    // Internal mutators
    // -------------------------------------------------------------------

    function _addRecoveryOwner(address safe, address owner, bool strict) internal {
        _validateRecoveryOwner(safe, owner);
        if (_owners[safe].add(owner)) {
            emit RecoveryOwnerAdded(safe, owner);
        } else {
            require(!strict, RecoveryOwners_AlreadyRegistered());
        }
    }

    function _removeRecoveryOwner(address safe, address owner, bool strict) internal {
        if (_owners[safe].remove(owner)) {
            emit RecoveryOwnerRemoved(safe, owner);
        } else {
            require(!strict, RecoveryOwners_Unknown());
        }
    }

    function _validateRecoveryOwner(address safe, address owner) private view {
        require(owner != address(0), RecoveryOwners_ZeroAddress());
        require(owner != SENTINEL_OWNERS, RecoveryOwners_Invalid());
        require(owner != safe, RecoveryOwners_Invalid());
        require(!ISafe(payable(safe)).isOwner(owner), RecoveryOwners_Invalid());
    }
}
