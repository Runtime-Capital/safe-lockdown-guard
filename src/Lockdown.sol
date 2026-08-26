// SPDX-License-Identifier: MIT
pragma solidity 0.8.35;

// Safe
import {ISafe, Enum} from "@safe-global/safe-smart-account/interfaces/ISafe.sol";
import {IFallbackManager} from "@safe-global/safe-smart-account/interfaces/IFallbackManager.sol";
import {IGuardManager} from "@safe-global/safe-smart-account/interfaces/IGuardManager.sol";
import {IModuleManager} from "@safe-global/safe-smart-account/interfaces/IModuleManager.sol";
import {IOwnerManager} from "@safe-global/safe-smart-account/interfaces/IOwnerManager.sol";
import {MultiSendCallOnly} from "@safe-global/safe-smart-account/libraries/MultiSendCallOnly.sol";
import {ITransactionGuard} from "@safe-global/safe-smart-account/base/GuardManager.sol";
import {IModuleGuard} from "@safe-global/safe-smart-account/base/ModuleManager.sol";
// OpenZeppelin
import {IERC165} from "@openzeppelin/contracts/interfaces/IERC165.sol";
import {EIP712} from "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import {SignatureChecker} from "@openzeppelin/contracts/utils/cryptography/SignatureChecker.sol";
// Lockdown
import {LockdownFallbackHandler} from "./handlers/LockdownFallbackHandler.sol";
import {LockdownSigners} from "./base/LockdownSigners.sol";
import {RecoveryOwners} from "./base/RecoveryOwners.sol";
import {StateMachine} from "./base/StateMachine.sol";
import {LockdownLib} from "./utils/LockdownLib.sol";

/// @title Lockdown
/// @notice Base version of LockdownFull, without the timelock.
/// @custom:security-contact contact@runtime.capital
contract Lockdown is ITransactionGuard, IModuleGuard, EIP712, LockdownSigners, RecoveryOwners, StateMachine {
    string public constant VERSION = "1.0.0";

    address public immutable MULTI_SEND_CALL_ONLY;

    // privilege level threaded through _checkCall()
    enum Privilege {
        Owners,
        Module,
        Recovery
    }

    // -------------------------------------------------------------------
    // Events
    // -------------------------------------------------------------------

    event SafeInitialised(
        address indexed safe,
        uint64 lockdownDuration,
        uint64 resumeDelay,
        uint256 recoveryOwnersCount,
        uint256 initialSignersCount
    );

    // -------------------------------------------------------------------
    // Errors
    // -------------------------------------------------------------------

    error GuardNotInstalled();
    error InvalidFallbackHandler();
    error BadSignature();
    error DelegateCallDenied();
    error InvalidOperation(Enum.Operation operation);
    error RecoveryActive();
    error RecoveryRefundDenied();
    error LockedDown();
    error ModuleCallToSingletonDenied();
    error ModuleSafeSelfCallDenied();
    error GuardHookSelfCallDenied();
    error BadMultiSendCallOnlyPayload();
    error ZeroAddress();

    // -------------------------------------------------------------------
    // Construction
    // -------------------------------------------------------------------

    constructor(address multiSendCallOnly) EIP712("RuntimeLockdown", VERSION) {
        require(multiSendCallOnly != address(0), ZeroAddress());
        MULTI_SEND_CALL_ONLY = multiSendCallOnly;
    }

    function supportsInterface(bytes4 interfaceId) public view virtual override returns (bool) {
        return interfaceId == type(IERC165).interfaceId // 0x01ffc9a7
            || interfaceId == type(ITransactionGuard).interfaceId // 0xe6d7a83a
            || interfaceId == type(IModuleGuard).interfaceId; // 0x58401ed8
    }

    // -------------------------------------------------------------------
    // Per-Safe configuration: initialize
    // -------------------------------------------------------------------

    /// @notice One-shot initialiser for the calling Safe's configuration.
    ///         msg.sender is the Safe. Reverts AlreadyInitialised if called
    ///         a second time.
    /// @dev Calls from non-Safe addresses are not blocked by the contract;
    ///      they just write into the caller's own `_configs` slot, which is
    ///      dead state. Since H.19 the recovery-owner validation staticcalls
    ///      `isOwner(address)` on the caller, so a caller that does not
    ///      expose the Safe owner interface reverts here instead of writing
    ///      dead state.
    function initialize(
        uint64 lockdownDuration_,
        uint64 resumeDelay_,
        address[] calldata initialRecoveryOwners,
        bytes[] calldata initialSigners
    ) public virtual onlyUninitialised(msg.sender) {
        // GUARD_STORAGE_SLOT: must be the Lockdown singleton, otherwise the Safe is not protected.
        require(
            _readAddress(
                ISafe(payable(msg.sender))
                    .getStorageAt(0x4a204f620c8c5ccdca3fd54d003badd85ba500436a431f0cbda4f558c93c34c8, 1),
                12
            ) == address(this),
            GuardNotInstalled()
        );
        // MODULE_GUARD_STORAGE_SLOT: must be the Lockdown singleton, otherwise the Safe is not protected.
        require(
            _readAddress(
                ISafe(payable(msg.sender))
                    .getStorageAt(0xb104e0b93118902c651344349b610029d694cfdec91c589c91ebafbcd0289947, 1),
                12
            ) == address(this),
            GuardNotInstalled()
        );
        // FALLBACK_HANDLER_STORAGE_SLOT: must be a LockdownFallbackHandler that points to the Lockdown singleton, otherwise the Safe is not protected.
        require(
            address(
                LockdownFallbackHandler(
                        _readAddress(
                            ISafe(payable(msg.sender))
                                .getStorageAt(0x6c9a6c4a39284e37ed1cf53d337577d14212a4870fb976a4366c693b939918d5, 1),
                            12
                        )
                    ).LOCKDOWN()
            ) == address(this),
            InvalidFallbackHandler()
        );

        require(initialRecoveryOwners.length > 0, RecoveryOwners_EmptyAllowlist());
        require(initialSigners.length <= MAX_LOCKDOWN_SIGNERS, LockdownSigners_MaxReached());

        _setLockdownDuration(msg.sender, lockdownDuration_);
        _setResumeDelay(msg.sender, resumeDelay_);
        for (uint256 i = 0; i < initialRecoveryOwners.length; ++i) {
            _addRecoveryOwner(msg.sender, initialRecoveryOwners[i], true);
        }
        for (uint256 i = 0; i < initialSigners.length; ++i) {
            _addLockdownSigner(msg.sender, initialSigners[i]);
        }

        emit SafeInitialised(
            msg.sender, lockdownDuration_, resumeDelay_, initialRecoveryOwners.length, initialSigners.length
        );
        if (initialSigners.length == 0) emit SafeDormant(msg.sender);
    }

    // -------------------------------------------------------------------
    // Per-Safe admin: override components setters with modifiers
    // -------------------------------------------------------------------

    function setLockdownDuration(uint64 newDuration) public virtual override onlyNormal(msg.sender) {
        super.setLockdownDuration(newDuration);
    }

    function setResumeDelay(uint64 newDelay) public virtual override onlyNormal(msg.sender) {
        super.setResumeDelay(newDelay);
    }

    function addRecoveryOwner(address owner) public virtual override onlyNormal(msg.sender) {
        super.addRecoveryOwner(owner);
    }

    /// @notice Removes a pre-registered recovery owner from the allowlist.
    /// @dev    A Safe-quorum self-call setter, frozen during BOTH LockedDown
    ///         and Recovering (it is NOT part of the recovery whitelist). The
    ///         allowlist may shrink to a single entry but never to empty
    ///         (EmptyAllowlist). Validation is not re-run on removal, so an
    ///         owner that became invalid after registration can still be
    ///         culled (H.19). See SPEC_V1 §7.4.
    function removeRecoveryOwner(address owner) public virtual override onlyNormal(msg.sender) {
        super.removeRecoveryOwner(owner);
    }

    function addLockdownSigner(bytes calldata signer) public virtual override onlyNormal(msg.sender) {
        super.addLockdownSigner(signer);
    }

    /// @dev    Allowed in Normal and Recovering. Forbidden only during
    ///         LockedDown (when owner-path execution is fully blocked). Its
    ///         availability across the whole recovery window (and into the
    ///         auto-resumed Normal state) is the relock-race cleanup primitive:
    ///         the quorum can race ahead of an attacker holding a surviving
    ///         compromised signer by removing it before the trigger path
    ///         re-opens. See SPEC_V1 §7.4.
    function removeLockdownSigner(bytes calldata signer) public virtual override onlyNotLockedDown(msg.sender) {
        super.removeLockdownSigner(signer);
    }

    /// @notice Atomic remove + add. Old and new signer schemes may differ.
    ///         Useful for password rotation and for migrating between
    ///         schemes (e.g. password → ECDSA).
    function rotateLockdownSigner(bytes calldata oldSigner, bytes calldata newSigner)
        public
        virtual
        override
        onlyNormal(msg.sender)
    {
        super.rotateLockdownSigner(oldSigner, newSigner);
    }

    // -------------------------------------------------------------------
    // Lockdown lifecycle: trigger and resume
    // -------------------------------------------------------------------

    /// @notice Locks down owner-path and module-path execution on `safe`
    ///         for `lockdownDuration[safe]`. Authority is the registered
    ///         ERC-7913 signer identity; authorisation is checked by OZ
    ///         `SignatureChecker` against the EIP-712 message hash.
    /// @dev Verify-then-burn (SPEC_V1 §5.2): signature verification observes
    ///      the same pre-burn state as `testSigner`. After verification, the
    ///      signer is removed and permanently burnt before the lockdown state
    ///      is set. The whole sequence remains atomic on revert.
    function triggerLockdown(address safe, bytes32 reasonHash, bytes calldata signer, bytes calldata signature)
        public
        virtual
        onlyInitialized(safe)
    {
        // Preserve the existing cheap `Unknown` rejection before dispatching
        // to the identity's verifier. `testSigner` is the single verification
        // path used by both drills and production triggers.
        require(isLockdownSigner(safe, signer), LockdownSigners_Unknown());
        bytes32 digest = _hashTypedDataV4(keccak256(abi.encode(LOCKDOWN_TYPEHASH, safe, reasonHash)));
        require(testSigner(signer, digest, signature), BadSignature());

        // Effects follow verification. The shared helper keeps the permanent
        // burn (INV-SIGN-7) and event semantics identical to admin removal;
        // any later revert still rolls the whole sequence back atomically.
        _removeLockdownSigner(safe, signer);
        _lock(safe, reasonHash, signer);

        // H.15: if the burnt signer was the last one, the Safe will enter
        // Recovering (and later Normal post-resume) with zero panic capability.
        // Emit the dormancy signal so off-chain monitoring catches it without
        // having to diff signersCount across blocks.
        if (getLockdownSignerCount(safe) == 0) emit SafeDormant(safe);
    }

    // -------------------------------------------------------------------
    // Views
    // -------------------------------------------------------------------

    /// @notice Pure signer sanity test and the verification source of truth
    ///         used by `triggerLockdown`. Returns the outcome instead of
    ///         reverting and never touches singleton state. Intended use: a
    ///         Safe quorum testing a candidate signer with real key material
    ///         and a real signature. Also useful as a drill primitive that
    ///         does NOT consume a registered signer.
    /// @dev    Safe-to-call for ECDSA / ERC-1271 / WebAuthn-style signatures.
    ///         UNSAFE for password / commit-reveal verifiers: the password
    ///         preimage would be leaked over RPC. Use throwaway passwords only.
    function testSigner(bytes calldata signer, bytes32 hash, bytes calldata signature) public view returns (bool ok) {
        return SignatureChecker.isValidSignatureNow(signer, hash, signature);
    }

    function getConfigSnapshot(address safe)
        public
        view
        returns (
            uint64 lockdownDuration_,
            uint64 resumeDelay_,
            uint64 lockdownUntil_,
            uint256 signersCount_,
            uint256 recoveryOwnerAllowlistCount_
        )
    {
        return (
            getLockdownDuration(safe),
            getResumeDelay(safe),
            getLockdownUntil(safe),
            getLockdownSignerCount(safe),
            getRecoveryOwnerCount(safe)
        );
    }

    // -------------------------------------------------------------------
    // Guard hooks - Transactions guard
    // -------------------------------------------------------------------

    function checkTransaction(
        address to,
        uint256 value,
        bytes calldata data,
        Enum.Operation operation,
        uint256 safeTxGas,
        uint256 baseGas,
        uint256 gasPrice,
        address gasToken,
        address payable refundReceiver,
        bytes calldata,
        address
    ) public virtual override {
        (State state,) = getState(msg.sender);
        if (state == State.Uninitialised) {
            // Fail-open for uninitialised configs (anti-brick on install order).
        } else if (state == State.Normal) {
            // Owner path: quorum may administer the singleton.
            _checkCall(msg.sender, to, value, data, operation, Privilege.Owners);
        } else if (state == State.LockedDown) {
            revert LockedDown();
        } else {
            // Recovering: the Recovery privilege routes every leaf through the
            // unconditional _isRecoveryCall gate (narrow whitelist), so the
            // Owners/Module admin branches are never consulted on this path.
            _checkCall(msg.sender, to, value, data, operation, Privilege.Recovery);
            require(
                safeTxGas == 0 && baseGas == 0 && gasPrice == 0 && gasToken == address(0)
                    && refundReceiver == address(0),
                RecoveryRefundDenied()
            );
        }
    }

    function checkAfterExecution(bytes32 safeTxHash, bool success) public virtual override {}

    // -------------------------------------------------------------------
    // Guard hooks - Module transactions guard
    // -------------------------------------------------------------------

    function checkModuleTransaction(
        address to,
        uint256 value,
        bytes calldata data,
        Enum.Operation operation,
        address module
    ) public virtual override returns (bytes32 moduleTxHash) {
        (State state,) = getState(msg.sender);
        if (state == State.Uninitialised) {
            // Anti-brick: legitimate module CALLs still pass before initialize,
            // but route through _checkCall (same policy as Normal) so a module
            // cannot reach the singleton - e.g. `initialize(...)` with
            // attacker-chosen params - directly OR nested inside a MultiSend
            // delegatecall while the config is uninitialised. The bare
            // `to != address(this)` check missed the MultiSend-wrapped inner
            // CALL to the singleton.
            _checkCall(msg.sender, to, value, data, operation, Privilege.Module);
        } else if (state == State.Normal) {
            // Module path: guard-disable self-calls and singleton admin calls denied.
            _checkCall(msg.sender, to, value, data, operation, Privilege.Module);
        } else if (state == State.LockedDown) {
            revert LockedDown();
        } else {
            // Recovering
            revert RecoveryActive();
        }
        return LockdownLib.moduleTxHash(msg.sender, module, to, value, data, operation);
    }

    function checkAfterModuleExecution(
        bytes32,
        /* txHash */
        bool success
    )
        public
        virtual
        override
    {}

    // -------------------------------------------------------------------
    // Transaction guard helpers
    // -------------------------------------------------------------------

    /// @dev The `privilege` level gates the two administrative surfaces a
    ///      module must never reach: singleton self-calls, and the Safe
    ///      self-calls that would disable the lockdown protection.
    ///        - Owner-path: `Privilege.Owners` (full admin),
    ///        - module-path: `Privilege.Module` (no admin),
    ///        - recovery-path: `Privilege.Recovery` (narrow whitelist only).
    ///        The singleton holds the anti-coercion roots of trust
    ///        (lockdown signers, recovery owners, initialize, timelock, bypassers)
    ///        and a module touching them is a silent, persistent hijack that is
    ///        NOT dominated by "a module can already drain".
    function _checkCall(
        address safe,
        address to,
        uint256 value,
        bytes calldata data,
        Enum.Operation operation,
        Privilege privilege
    ) private view {
        if (operation == Enum.Operation.Call) {
            if (privilege == Privilege.Recovery) {
                require(_isRecoveryCall(safe, operation, to, value, data), RecoveryActive());
            } else if (to == safe) {
                // Deny the module-path guard-disable self-calls (setGuard /
                // setModuleGuard / setFallbackHandler) first, so the module-path
                // can never touch the fallback-handler slot at all.
                require(
                    privilege == Privilege.Owners || !_isForbiddenModuleSafeSelfCall(data), ModuleSafeSelfCallDenied()
                );

                // Owner-path only (module-path setFallbackHandler denied above):
                // the fallback handler carries the ERC-1271 freeze, so the quorum
                // may only ever install a singleton-bound LockdownFallbackHandler,
                // never a non-freezing shim.
                require(
                    (bytes4(data) != IFallbackManager.setFallbackHandler.selector
                            || address(LockdownFallbackHandler(_readAddressCalldata(data, 0x10)).LOCKDOWN())
                                == address(this)),
                    InvalidFallbackHandler()
                );
            } else if (to == address(this)) {
                // The guard hooks are internal machinery the Safe invokes directly
                // around execution; they must never be reachable as the `to` of an
                // execTransaction. Otherwise an owner-path (or pre-scheduled) call to
                // `checkAfterModuleExecution` clears the module-reentrancy in-flight
                // slot mid-flight and lets one scheduled module ticket execute twice
                // (INV-TIME-11). Deny on every path, including owner-path admin.
                require(!_isGuardHookSelector(data), GuardHookSelfCallDenied());
                // Modules can NEVER administer the Lockdown singleton, in ANY
                // state including pre-initialisation, directly or nested inside a
                // MultiSend batch. The singleton holds the anti-coercion roots of
                // trust; unlike moving funds, touching them is a silent,
                // persistent hijack (register an attacker lockdown signer /
                // recovery owner, or `initialize(...)` a pre-init Safe with
                // attacker params) that must go through the owner-path quorum
                // (review C1, SPEC_V1 §H.12).
                require(privilege == Privilege.Owners, ModuleCallToSingletonDenied());
            }
        } else if (operation == Enum.Operation.DelegateCall) {
            require(to == MULTI_SEND_CALL_ONLY, DelegateCallDenied());

            bytes4 selector = bytes4(data);
            require(selector == MultiSendCallOnly.multiSend.selector, BadMultiSendCallOnlyPayload());

            (bool success, bytes calldata transactions) = _decodeCalldataBytes(data[4:]);
            require(success, BadMultiSendCallOnlyPayload());

            uint256 offset = 0;
            while (offset < transactions.length) {
                // The minimum length of a single transaction in the multi-send payload is 85 bytes:
                // - [0x00] 1 byte for operation
                // - [0x01] 20 bytes for to address
                // - [0x15] 32 bytes for value
                // - [0x35] 32 bytes for data length
                // - [0x55] <data length> bytes for data (can be empty)
                require(transactions.length - offset >= 0x55, BadMultiSendCallOnlyPayload());
                // Parse relevant items. The `require` above bounds `offset` so
                // every arithmetic term below is provably non-overflowing (the
                // calldata-slice reads keep their own bounds checks).
                Enum.Operation innerOperation = Enum.Operation(uint8(transactions[offset]));
                uint256 dataLength;
                address innerTo;
                uint256 innerValue;
                unchecked {
                    innerTo = _readAddressCalldata(transactions, offset + 0x1);
                    innerValue = _readUint256Calldata(transactions, offset + 0x15);
                    dataLength = _readUint256Calldata(transactions, offset + 0x35);
                    // Validated the data section fits within the payload length
                    require(transactions.length - offset - 0x55 >= dataLength, BadMultiSendCallOnlyPayload());
                }
                // Recursive check
                _checkCall(
                    safe,
                    innerTo == address(0) ? safe : innerTo,
                    innerValue,
                    transactions[offset + 0x55:offset + 0x55 + dataLength],
                    innerOperation,
                    privilege
                );
                // Move forward
                unchecked {
                    offset += 0x55 + dataLength;
                }
            }
            require(offset == transactions.length, BadMultiSendCallOnlyPayload());
        } else {
            revert InvalidOperation(operation);
        }
    }

    /// @dev The only module-path Safe self-calls that must be blocked are the
    ///      ones that DISABLE the lockdown protection itself: removing the
    ///      transaction guard (`setGuard`), removing the module guard
    ///      (`setModuleGuard`), or swapping the fallback handler
    ///      (`setFallbackHandler`) for a non-freezing shim. As long as the guard
    ///      stays installed and the fallback handler stays lockdown-bound, a
    ///      module may add owners/modules and make arbitrary module calls: a
    ///      future lockdown still freezes everything, so the guarantee holds.
    ///      Constraining those (owner topology, module management) is a
    ///      deliberate non-goal (SPEC_V1 §H.12): a coerced module in NORMAL mode
    ///      already has arbitrary execution power.
    function _isForbiddenModuleSafeSelfCall(bytes calldata data) private pure returns (bool) {
        if (data.length < 4) return false;

        bytes4 selector = bytes4(data);
        return selector == IGuardManager.setGuard.selector || selector == IModuleManager.setModuleGuard.selector
            || selector == IFallbackManager.setFallbackHandler.selector;
    }

    /// @dev The four guard-hook selectors. They are invoked by the Safe as part of
    ///      its own execution machinery; routing them through a user transaction
    ///      (`execTransaction` / a scheduled ticket) is never legitimate and would
    ///      corrupt the transient module-reentrancy state, so they are rejected as
    ///      a singleton `to` on every path (INV-TIME-11).
    function _isGuardHookSelector(bytes calldata data) private pure returns (bool) {
        if (data.length < 4) return false;

        bytes4 selector = bytes4(data);
        return selector == ITransactionGuard.checkTransaction.selector
            || selector == ITransactionGuard.checkAfterExecution.selector
            || selector == IModuleGuard.checkModuleTransaction.selector
            || selector == IModuleGuard.checkAfterModuleExecution.selector;
    }

    function _isRecoveryCall(address safe, Enum.Operation operation, address to, uint256 value, bytes calldata data)
        private
        view
        returns (bool)
    {
        // Operation must be a CALL and match one of the following:
        //   - Safe self-call with empty data and no value (nonce burn)
        //   - Safe self-call to `swapOwner` to a pre-registered recovery owner
        //   - Safe self-call to `disableModule` (neutralise a module during recovery)
        //   - Lockdown call to `removeLockdownSigner(signer)`
        return operation == Enum.Operation.Call
            && ((to == safe
                    && ((data.length == 0 && value == 0)
                        || (data.length == 0x44 && bytes4(data) == IModuleManager.disableModule.selector)
                        || (data.length == 0x64
                            && bytes4(data) == IOwnerManager.swapOwner.selector
                            && isRecoveryOwner(safe, _readAddressCalldata(data, 0x50)) // 0x44 + 0x0C (inner offset)
                            && !ISafe(payable(safe)).isOwner(_readAddressCalldata(data, 0x50))))) // 0x44 + 0x0C (inner offset)
                || (to == address(this) && data.length >= 0x04 && bytes4(data) == this.removeLockdownSigner.selector));
    }

    // -------------------------------------------------------------------
    // Internal helpers
    // -------------------------------------------------------------------

    /// @dev Both the ABI head `offset` and the declared `length` are attacker-controlled
    ///      full-width words, so every bound is checked by SUBTRACTION against
    ///      `input.length` before the value is ever added to `input.offset`. Adding first
    ///      and comparing afterwards wraps: an `offset` near `type(uint256).max` would
    ///      point the slice at unrelated calldata, and a `length` of `type(uint256).max`
    ///      would wrap the end bound below the slice end. Both then passed the check.
    ///      Ordering matters: each subtraction below is only reached once the preceding
    ///      comparison has proved it cannot underflow.
    function _decodeCalldataBytes(bytes calldata input) private pure returns (bool success, bytes calldata output) {
        assembly ("memory-safe") {
            output.offset := input.offset
            output.length := 0
            // The head word must itself be inside `input`.
            if iszero(lt(input.length, 0x20)) {
                let offset := calldataload(input.offset)
                // `offset + 0x20 <= input.length`, written so it cannot wrap.
                if iszero(gt(offset, sub(input.length, 0x20))) {
                    let length := calldataload(add(input.offset, offset))
                    // `offset + 0x20 + length <= input.length`, same treatment.
                    if iszero(gt(length, sub(sub(input.length, offset), 0x20))) {
                        output.offset := add(input.offset, add(offset, 0x20))
                        output.length := length
                        success := 1
                    }
                }
            }
        }
    }

    function _readAddress(bytes memory data, uint256 offset) private pure returns (address result) {
        require(data.length - offset >= 20, BadMultiSendCallOnlyPayload());
        assembly ("memory-safe") {
            result := shr(96, mload(add(add(data, 0x20), offset)))
        }
    }

    function _readAddressCalldata(bytes calldata data, uint256 offset) internal pure returns (address result) {
        return address(bytes20(data[offset:offset + 0x14]));
    }

    function _readUint256Calldata(bytes calldata data, uint256 offset) internal pure returns (uint256 result) {
        return uint256(bytes32(data[offset:offset + 0x20]));
    }
}
