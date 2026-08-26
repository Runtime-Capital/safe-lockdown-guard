// SPDX-License-Identifier: MIT
pragma solidity 0.8.35;

// OpenZeppelin
import {EnumerableSet} from "@openzeppelin/contracts/utils/structs/EnumerableSet.sol";

/// @custom:security-contact contact@runtime.capital
abstract contract LockdownSigners {
    using EnumerableSet for EnumerableSet.BytesSet;

    uint256 public constant MAX_LOCKDOWN_SIGNERS = 32;
    uint256 public constant MAX_KEY_LENGTH = 256;

    mapping(address safe => EnumerableSet.BytesSet) private _signers;

    /// @dev Permanent register of signer identity hashes
    ///      (`keccak256(signer)`) that have ever been removed - either
    ///      by `removeLockdownSigner`, `rotateLockdownSigner` (old half),
    ///      or by a successful `triggerLockdown` burn. Re-registering the
    ///      same identity is permanently rejected. This blocks replay for
    ///      password-style signers whose preimage becomes public during
    ///      trigger calldata. Strict one-shot per signer identity,
    ///      INV-SIGN-7.
    mapping(address safe => mapping(bytes signer => bool)) private _burnt;

    event LockdownSignerAdded(address indexed safe, bytes signer);
    event LockdownSignerRemoved(address indexed safe, bytes signer);
    event LockdownSignerRotated(address indexed safe, bytes oldSigner, bytes newSigner);
    /// @notice Emitted whenever a Safe's `signersCount` reaches 0 (H.15):
    ///         - on `initialize` with `initialSigners.length == 0`;
    ///         - on `removeLockdownSigner` / `rotateLockdownSigner` when the
    ///           last signer is removed without an atomic replacement;
    ///         - on `triggerLockdown` burn when the burnt signer was the last.
    ///         The guard is fully installed (or about to enter Recovering)
    ///         but cannot fire any panic until the quorum registers at least
    ///         one signer identity via `addLockdownSigner`. Off-chain
    ///         watchers MUST surface this state as a high-severity warning.
    event SafeDormant(address indexed safe);

    error LockdownSigners_MaxReached();
    error LockdownSigners_AlreadyRegistered();
    error LockdownSigners_BurntPermanently();
    error LockdownSigners_Unknown();
    error LockdownSigners_InvalidFormat();
    error LockdownSigners_KeyTooLong();
    error LockdownSigners_ZeroAddress();
    error LockdownSigners_VerifierNoCode();

    // -------------------------------------------------------------------
    // Accessors
    // -------------------------------------------------------------------

    function isLockdownSigner(address safe, bytes calldata signer) public view returns (bool) {
        return _signers[safe].contains(signer);
    }

    function getLockdownSignerCount(address safe) public view returns (uint256 count) {
        return _signers[safe].length();
    }

    function getLockdownSigners(address safe) public view returns (bytes[] memory signers) {
        return _signers[safe].values();
    }

    /// @notice Returns true if the signer identity has been
    ///         permanently retired on this Safe (via removal, rotation,
    ///         or a successful `triggerLockdown` burn). Re-registering
    ///         the same identity reverts `SignerAlreadyBurntPermanently`.
    ///         Off-chain runbook check before attempting a re-add.
    function isSignerBurntPermanently(address safe, bytes calldata signer) external view returns (bool) {
        return _burnt[safe][signer];
    }

    // -------------------------------------------------------------------
    // Public mutators
    // -------------------------------------------------------------------

    function addLockdownSigner(bytes calldata signer) public virtual {
        _addLockdownSigner(msg.sender, signer);
    }

    /// @notice Removes a registered lockdown signer.
    function removeLockdownSigner(bytes calldata signer) public virtual {
        _removeLockdownSigner(msg.sender, signer);
        // H.15: explicit dormancy signal when this removal empties the active
        // signer set. NOT emitted from `rotateLockdownSigner`, which immediately
        // re-adds a replacement in the same transaction (the transient zero
        // state would be noise for indexers).
        if (getLockdownSignerCount(msg.sender) == 0) emit SafeDormant(msg.sender);
    }

    /// @notice Atomic remove + add. Old and new signer schemes may differ.
    ///         Useful for password rotation and for migrating between
    ///         schemes (e.g. password → ECDSA).
    function rotateLockdownSigner(bytes calldata oldSigner, bytes calldata newSigner) public virtual {
        _removeLockdownSigner(msg.sender, oldSigner);
        _addLockdownSigner(msg.sender, newSigner);
        emit LockdownSignerRotated(msg.sender, oldSigner, newSigner);
    }

    // -------------------------------------------------------------------
    // Internal mutators
    // -------------------------------------------------------------------

    function _addLockdownSigner(address safe, bytes calldata signer) internal {
        _validateSigner(signer);
        require(_signers[safe].length() < MAX_LOCKDOWN_SIGNERS, LockdownSigners_MaxReached());
        require(!_burnt[safe][signer], LockdownSigners_BurntPermanently());
        require(_signers[safe].add(signer), LockdownSigners_AlreadyRegistered());
        emit LockdownSignerAdded(safe, signer);
    }

    function _removeLockdownSigner(address safe, bytes calldata signer) internal {
        require(_signers[safe].remove(signer), LockdownSigners_Unknown());
        // INV-SIGN-7: any removal marks the identity as permanently burnt so
        // it cannot be re-registered later.
        _burnt[safe][signer] = true;
        emit LockdownSignerRemoved(safe, signer);
    }

    function _validateSigner(bytes calldata signer) private view {
        if (signer.length < 20) {
            revert LockdownSigners_InvalidFormat();
        } else if (signer.length == 20) {
            // EOA / ERC-1271 case
            require(address(bytes20(signer)) != address(0), LockdownSigners_ZeroAddress());
        } else {
            // ERC-7913 verifier case: `verifier || key`
            require(signer.length <= 20 + MAX_KEY_LENGTH, LockdownSigners_KeyTooLong());
            require(address(bytes20(signer)).code.length > 0, LockdownSigners_VerifierNoCode());
        }
    }
}
