// SPDX-License-Identifier: MIT
pragma solidity 0.8.35;

/// @notice Per-Safe ERC-1271 opt-in read by `LockdownFallbackHandler`
///         (SPEC_V1 H.27, NM-1060 6.1). Independent of the lockdown lifecycle:
///         no incident transition reads or writes it.
/// @custom:security-contact contact@runtime.capital
abstract contract Erc1271Policy {
    /// @dev `false` (the storage default) ⟹ ERC-1271 DISABLED (fail-closed),
    ///      including for uninitialised Safes. Only `_setErc1271Allowed` writes it.
    mapping(address safe => bool) private _erc1271Allowed;

    /// @notice The Safe changed its ERC-1271 opt-in (SPEC_V1 H.27).
    event Erc1271AllowedChanged(address indexed safe, bool allowed);

    // -------------------------------------------------------------------
    // Accessors
    // -------------------------------------------------------------------

    /// @notice Whether `safe` opted into ERC-1271 signature validation through
    ///         its `LockdownFallbackHandler` (SPEC_V1 H.27). Defaults to
    ///         `false` (disabled), including for uninitialised Safes.
    function isErc1271Allowed(address safe) public view returns (bool) {
        return _erc1271Allowed[safe];
    }

    // -------------------------------------------------------------------
    // Setters
    // -------------------------------------------------------------------

    function setErc1271Allowed(bool allowed) public virtual {
        _setErc1271Allowed(msg.sender, allowed);
    }

    function _setErc1271Allowed(address safe, bool allowed) internal virtual {
        _erc1271Allowed[safe] = allowed;
        emit Erc1271AllowedChanged(safe, allowed);
    }
}
