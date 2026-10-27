// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity 0.8.35;

import {ISafe, Enum} from "@safe-global/safe-smart-account/interfaces/ISafe.sol";
import {ISignatureValidator} from "@safe-global/safe-smart-account/interfaces/ISignatureValidator.sol";
import {TokenCallbackHandler} from "@safe-global/safe-smart-account/handler/TokenCallbackHandler.sol";
import {StateMachine} from "../base/StateMachine.sol";
import {Erc1271Policy} from "../base/Erc1271Policy.sol";

/// @title Lockdown Fallback Handler
/// @notice A replacement for Safe's `CompatibilityFallbackHandler` whose
///         ERC-1271 signature surface is disabled unless the Safe opted in on
///         the Lockdown singleton, and frozen while the Safe is under an active
///         lockdown incident.
/// @dev ⚠️ This contract is only intended for being used as a fallback handler
///      for a {Safe}. Using it in other ways may cause undefined behavior. ⚠️
///
///      Rationale: the Safe transaction guard only runs inside `execTransaction`
///      (and the module guard inside `execTransactionFromModule`). It is NOT in
///      the call path of `isValidSignature`, which the Safe serves from its
///      fallback handler via `checkSignatures` against the current owner set.
///      During an incident, this handler makes ERC-1271 validation revert, so a
///      third party cannot settle an off-chain order through that surface while
///      the Safe is LockedDown or Recovering. It defers authorisations; it does
///      not invalidate them. A signature produced before or during the incident
///      validates again after auto-resume if the signing owner remains in the
///      current owner set. Recovery must replace a compromised owner to kill its
///      outstanding signatures. Operators must still minimise standing approvals
///      and open orders.
///
///      Opt-in gate (SPEC_V1 H.27, NM-1060 6.1): outside an incident,
///      ERC-1271 validates only if the Safe set `setErc1271Allowed(true)` on the
///      singleton (an owner-path, timelocked config call). The default is
///      disabled, also for uninitialised Safes, so this handler is not a neutral
///      drop-in on a Safe that never opted in. An off-chain signature (permit,
///      EIP-3009 `transferWithAuthorization`, Permit2, CoW, Seaport, ...) is
///      settled by a third party without any `execTransaction`, so the timelock
///      can never give it a reaction window. The gate covers both the inline
///      `checkSignatures` branch and the `signedMessages` branch (entries
///      written before the Lockdown install are permanent in Safe).
///
///      This file is a verbatim copy of Safe v1.5.0
///      `contracts/handler/CompatibilityFallbackHandler.sol` (LGPL-3.0) with
///      two additions, both at the top of `isValidSignature`: the lockdown
///      gate and the opt-in gate (plus their two errors). Diffing against the
///      canonical handler should show exactly that.
/// @custom:security-contact contact@runtime.capital
contract LockdownFallbackHandler is TokenCallbackHandler, ISignatureValidator {
    /// @notice The Lockdown singleton this handler reads incident state from.
    /// @dev MUST be the same singleton installed as the Safe's transaction /
    ///      module guard, otherwise the gate reads an unrelated Safe state.
    ///      The preflight / verify scripts bind this alongside the guard.
    StateMachine public immutable LOCKDOWN;

    /// @notice ERC-1271 validation is frozen while the Safe is under an active
    ///         lockdown incident (LockedDown / Recovering).
    error SignaturesFrozenDuringLockdown();

    /// @notice ERC-1271 validation is disabled for this Safe: it has not opted
    ///         in via `setErc1271Allowed(true)` on the singleton (SPEC_V1 H.27).
    error Erc1271Disabled();

    /**
     * @dev The precomputed EIP-712 type hash for the Safe message type.
     *      Precomputed value of: `keccak256("SafeMessage(bytes message)")`.
     */
    bytes32 private constant SAFE_MSG_TYPEHASH = 0x60b3cbf8b4a223d68d641b3b6ddf9a298e7f33710cf3d3a9d1146b5a6150fbca;

    /**
     * @dev The precomputed EIP-712 type hash for the Safe transaction type.
     *      Precomputed value of: `keccak256("SafeTx(address to,uint256 value,bytes data,uint8 operation,uint256 safeTxGas,uint256 baseGas,uint256 gasPrice,address gasToken,address refundReceiver,uint256 nonce)")`.
     */
    bytes32 private constant SAFE_TX_TYPEHASH = 0xbb8310d486368db6bd6f849402fdd73ad53d316b5a4b2644ad6efe0f941286d8;

    /**
     * @dev The sentinel module value in the {ModuleManager.modules} linked list.
     */
    address internal constant SENTINEL_MODULES = address(0x1);

    /// @param lockdown The Lockdown singleton (e.g. the LockdownTimelock) whose
    ///        per-Safe state gates this handler's ERC-1271 surface.
    constructor(StateMachine lockdown) {
        LOCKDOWN = lockdown;
    }

    /**
     * @notice Returns the hash of a message to be signed by owners.
     * @dev This function assumes that the caller is a Safe contract.
     * @param message Raw message bytes.
     * @return Message hash.
     */
    function getMessageHash(bytes memory message) public view returns (bytes32) {
        return getMessageHashForSafe(ISafe(payable(msg.sender)), message);
    }

    /**
     * @dev Returns the pre-image of the message hash (see {getMessageHashForSafe}).
     * @param safe Safe to which the message is targeted.
     * @param message Message that should be encoded.
     * @return Encoded message.
     */
    function encodeMessageDataForSafe(ISafe safe, bytes memory message) public view returns (bytes memory) {
        bytes32 safeMessageHash = keccak256(abi.encode(SAFE_MSG_TYPEHASH, keccak256(message)));
        return abi.encodePacked(bytes1(0x19), bytes1(0x01), safe.domainSeparator(), safeMessageHash);
    }

    /**
     * @dev Returns the hash of a message that can be signed by owners.
     * @param safe Safe to which the message is targeted.
     * @param message Message that should be hashed.
     * @return Message hash.
     */
    function getMessageHashForSafe(ISafe safe, bytes memory message) public view returns (bytes32) {
        return keccak256(encodeMessageDataForSafe(safe, message));
    }

    /**
     * @notice Implementation of the EIP-1271 signature validation method.
     * @dev This implementation verifies signatures for a `ISafe(msg.sender)`,
     *      refusing validation while that Safe is under an active lockdown
     *      or has not opted in to ERC-1271 on the Lockdown singleton.
     * @param _dataHash Hash of the data signed.
     * @param _signature Signature data.
     * @return The EIP-1271 magic value if the signature is valid, reverts otherwise.
     */
    function isValidSignature(bytes32 _dataHash, bytes calldata _signature) public view override returns (bytes4) {
        // Caller should be a Safe.
        ISafe safe = ISafe(payable(msg.sender));
        // --- Lockdown gate (addition vs CompatibilityFallbackHandler) ---
        // While this Safe is under an active incident, refuse ERC-1271 so an
        // off-chain signature cannot be used to drain the frozen Safe through a
        // third-party settlement that never calls execTransaction. This holds
        // regardless of the opt-in below.
        (StateMachine.State state,) = LOCKDOWN.getState(address(safe));
        require(
            state == StateMachine.State.Normal || state == StateMachine.State.Uninitialised,
            SignaturesFrozenDuringLockdown()
        );
        // --- Opt-in gate (addition, SPEC_V1 H.27, NM-1060 6.1) ---
        // ERC-1271 is an explicit per-Safe operator choice, disabled by default
        // (an uninitialised Safe reads `false` too). Runs before both branches
        // below, so pre-install `signedMessages` entries are gated as well.
        require(Erc1271Policy(address(LOCKDOWN)).isErc1271Allowed(address(safe)), Erc1271Disabled());
        // --- end additions ---
        bytes memory messageData = encodeMessageDataForSafe(safe, abi.encode(_dataHash));
        bytes32 messageHash = keccak256(messageData);
        if (_signature.length == 0) {
            require(safe.signedMessages(messageHash) != 0, "Hash not approved");
        } else {
            // We explicitly do not allow caller approved signatures for EIP-1271 to prevent unexpected behaviour. This
            // is done by setting the executor address to `0` which can never be an owner of the Safe.
            safe.checkSignatures(address(0), messageHash, _signature);
        }
        return EIP1271_MAGIC_VALUE;
    }

    /**
     * @dev Returns array of first 10 modules.
     * @return Array of modules.
     */
    function getModules() external view returns (address[] memory) {
        // Caller should be a Safe.
        ISafe safe = ISafe(payable(msg.sender));
        (address[] memory array,) = safe.getModulesPaginated(SENTINEL_MODULES, 10);
        return array;
    }

    /**
     * @notice Performs a `DELEGATECALL` to a `targetContract` in the context of self.
     * @dev Internally reverts execution to avoid side effects (making it effectively static).
     *      Catches the internal revert and returns encoded result as bytes.
     *      ⚠️ This function assumes the caller is a Safe contract and is only intended for being used as a fallback handler for a {Safe}. ⚠️
     * @param targetContract Address of the contract containing the code to execute.
     * @param calldataPayload Calldata that should be sent to the target contract (encoded method name and arguments).
     */
    function simulate(address targetContract, bytes calldata calldataPayload) external returns (bytes memory response) {
        // Suppress compiler warnings about not using parameters, while allowing
        // parameters to keep names for documentation purposes. This does not
        // generate code.
        targetContract;
        calldataPayload;

        /* solhint-disable no-inline-assembly */
        /// @solidity memory-safe-assembly
        assembly {
            let ptr := mload(0x40)
            // Store `simulateAndRevert.selector`.
            // String representation is used to force right padding.
            mstore(ptr, "\xb4\xfa\xba\x09")

            // Abuse the fact that both this and the internal methods have the
            // same signature, and differ only in symbol name (and therefore,
            // selector) and copy calldata directly. This saves us approximately
            // 250 bytes of code and 300 gas at runtime over the
            // `abi.encodeWithSelector` builtin.
            calldatacopy(add(ptr, 0x04), 0x04, sub(calldatasize(), 0x04))

            let success :=
                call(
                    gas(),
                    // `address()` has been changed to `caller()` to use the
                    // implementation of the calling Safe.
                    caller(),
                    0,
                    ptr,
                    calldatasize(),
                    // The `simulateAndRevert` call should always reverts, and
                    // instead encodes whether or not it was successful in the
                    // return data. The first 32-byte word of the return data
                    // contains the `success` value, and the second 32-byte word
                    // contains the response bytes length, so write them to memory
                    // address 0x00 (Solidity scratch which is OK to use).
                    0x00,
                    0x40
                )

            // Double check that the call reverted as expected, and that the
            // `returndata` is long enough to hold the encoded success boolean
            // and response bytes length (64 bytes total).
            if or(success, lt(returndatasize(), 0x40)) { revert(0, 0) }

            // Allocate and copy the response bytes, making sure to increment
            // the free memory pointer accordingly (in case this method is
            // called as an internal function).
            let responseEncodedSize := add(mload(0x20), 0x20)
            response := mload(0x40)
            mstore(0x40, add(response, responseEncodedSize))
            returndatacopy(response, 0x20, responseEncodedSize)

            if iszero(mload(0x00)) { revert(add(response, 0x20), responseEncodedSize) }
        }
        /* solhint-enable no-inline-assembly */
    }

    /**
     * @notice Returns the pre-image of the Safe transaction hash (see {Safe.getTransactionHash}).
     * @dev Added for backwards compatibility with previous versions of Safe.
     */
    function encodeTransactionData(
        address to,
        uint256 value,
        bytes calldata data,
        Enum.Operation operation,
        uint256 safeTxGas,
        uint256 baseGas,
        uint256 gasPrice,
        address gasToken,
        address refundReceiver,
        uint256 nonce
    ) public view returns (bytes memory) {
        // Caller should be a Safe.
        ISafe safe = ISafe(payable(msg.sender));
        bytes32 domainSeparator = safe.domainSeparator();
        bytes32 safeTxHash = keccak256(
            abi.encode(
                SAFE_TX_TYPEHASH,
                to,
                value,
                keccak256(data),
                operation,
                safeTxGas,
                baseGas,
                gasPrice,
                gasToken,
                refundReceiver,
                nonce
            )
        );
        return abi.encodePacked(bytes1(0x19), bytes1(0x01), domainSeparator, safeTxHash);
    }
}
