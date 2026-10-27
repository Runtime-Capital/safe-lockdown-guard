// SPDX-License-Identifier: MIT
// NM-1060 6.2 (Medium): module-to-owner escalation (SPEC_V1 H.20, H.28, AR-29).
//
// An enabled module calls `addOwnerWithThreshold(attacker, 1)` through the module path,
// which only denies singleton calls and the three guard-DISABLE selectors. The new owner
// then uses `execTransaction` on the owner path, which may administer the singleton and the
// guard slots. While the Safe is Uninitialised the owner path is fail-open, so the new owner
// can also `initialize(...)` the Safe with its own config.
//
// Disposition: no Solidity change. The guard keeps fail-open-by-default before initialize
// and adds no edge-case module-path rule; the pre-init window is closed operationally by
// the atomic install. Owner topology stays allowed in Normal (legitimate social-recovery /
// signer-gate / inheritance modules). These tests pin that behaviour.
pragma solidity ^0.8.24;

import {TestEnvironment} from "../TestEnvironment.sol";

import {ISafe} from "@safe-global/safe-smart-account/interfaces/ISafe.sol";
import {Safe, Enum} from "@safe-global/safe-smart-account/Safe.sol";
import {MultiSendCallOnly} from "@safe-global/safe-smart-account/libraries/MultiSendCallOnly.sol";
import {IGuardManager} from "@safe-global/safe-smart-account/interfaces/IGuardManager.sol";
import {IModuleManager} from "@safe-global/safe-smart-account/interfaces/IModuleManager.sol";
import {IFallbackManager} from "@safe-global/safe-smart-account/interfaces/IFallbackManager.sol";
import {IOwnerManager} from "@safe-global/safe-smart-account/interfaces/IOwnerManager.sol";

import {Lockdown} from "../../src/Lockdown.sol";
import {LockdownTimelock} from "../../src/LockdownTimelock.sol";
import {StateMachine} from "../../src/base/StateMachine.sol";
import {Timelock} from "../../src/base/Timelock.sol";

/// @dev Candide-style social-recovery module: guardians rotate an owner through
///      `execTransactionFromModule(safe, swapOwner)`.
contract SocialRecoveryModuleMock {
    function recover(ISafe safe, address prevOwner, address oldOwner, address newOwner) external {
        require(
            safe.execTransactionFromModule(
                address(safe),
                0,
                abi.encodeCall(IOwnerManager.swapOwner, (prevOwner, oldOwner, newOwner)),
                Enum.Operation.Call
            )
        );
    }
}

contract Sink {
    receive() external payable {}
}

contract ModuleTopologyEscalationPoC is TestEnvironment {
    address private constant SENTINEL = address(0x1);
    uint64 private constant DELAY = 1 days;

    address private attacker = other;

    // -------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------

    function _addAttacker() private view returns (bytes memory) {
        return abi.encodeCall(IOwnerManager.addOwnerWithThreshold, (attacker, 1));
    }

    function _multiSend(bytes memory items) private view returns (bytes memory) {
        return abi.encodeCall(MultiSendCallOnly.multiSend, (items));
    }

    function _params(address to, bytes memory data, Enum.Operation op)
        private
        pure
        returns (Timelock.ExecTransactionParams memory)
    {
        return Timelock.ExecTransactionParams({
            to: to,
            value: 0,
            data: data,
            operation: op,
            safeTxGas: 0,
            baseGas: 0,
            gasPrice: 0,
            gasToken: address(0),
            refundReceiver: payable(address(0))
        });
    }

    function _sigFor(ISafe instance, uint256 pk, address to, bytes memory data, Enum.Operation op, uint256 nonce)
        private
        view
        returns (bytes memory)
    {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, _safeTxHash(instance, to, 0, data, op, nonce));
        return abi.encodePacked(r, s, v);
    }

    function _execAs(uint256 pk, ISafe instance, address to, bytes memory data, Enum.Operation op)
        private
        returns (bool)
    {
        bytes memory sig = _sigFor(instance, pk, to, data, op, instance.nonce());
        return instance.execTransaction(to, 0, data, op, 0, 0, 0, address(0), payable(address(0)), sig);
    }

    function _initData() private view returns (bytes memory) {
        return _initDataFor(recovery, panicKey);
    }

    function _initDataFor(address recoveryOwner, address signer) private pure returns (bytes memory) {
        address[] memory recoveryOwners = new address[](1);
        recoveryOwners[0] = recoveryOwner;
        bytes[] memory signers = new bytes[](1);
        signers[0] = abi.encodePacked(signer);
        return abi.encodeCall(Lockdown.initialize, (48 hours, 4 hours, recoveryOwners, signers));
    }

    function _state(ISafe instance) private view returns (StateMachine.State state) {
        (state,) = guard.getState(address(instance));
    }

    // -------------------------------------------------------------------
    // Uninitialised: fail-open by default, documented residual (H.28)
    // -------------------------------------------------------------------

    /// @dev NM-1060 6.2 exact pre-init sequence. Accepted residual: the module makes an
    ///      owner, which initializes the Safe with its own recovery owner and signer through
    ///      the fail-open owner path. Closed operationally by the atomic install below.
    function test_limitation_preInit_moduleOwnerInitializesWithOwnConfig() public {
        Safe safe = _createAndConfigure(620);
        assertEq(uint8(_state(safe)), uint8(StateMachine.State.Uninitialised));

        _moduleCall(module, safe, address(safe), 0, _addAttacker(), Enum.Operation.Call);
        assertTrue(safe.isOwner(attacker));
        assertEq(safe.getThreshold(), 1);

        assertTrue(
            _execAs(OTHER_PK, safe, address(guard), _initDataFor(address(0xBAD0), attacker), Enum.Operation.Call)
        );
        assertEq(uint8(_state(safe)), uint8(StateMachine.State.Normal));
        assertTrue(guard.isRecoveryOwner(address(safe), address(0xBAD0)));
    }

    /// @dev Control: the pre-init module path keeps its existing denial of direct calls to
    ///      the singleton (H.12), so the module cannot `initialize` without becoming owner.
    function test_control_preInit_moduleCannotInitializeDirectly() public {
        Safe safe = _createAndConfigure(621);
        _moduleCall_Revert(
            module,
            safe,
            address(guard),
            0,
            _initDataFor(attacker, attacker),
            Enum.Operation.Call,
            Lockdown.ModuleCallToSingletonDenied.selector
        );
        assertEq(uint8(_state(safe)), uint8(StateMachine.State.Uninitialised));
    }

    /// @dev The canonical fresh install is one owner-path MultiSend: setGuard,
    ///      setModuleGuard, setFallbackHandler, initialize. It leaves no Uninitialised window.
    function test_canonicalAtomicInstallStillWorks() public {
        Safe safe = _createSafe(625);
        bytes memory items = abi.encodePacked(
            _multiSendItem(
                Enum.Operation.Call, address(safe), 0, abi.encodeCall(IGuardManager.setGuard, (address(guard)))
            ),
            _multiSendItem(
                Enum.Operation.Call, address(safe), 0, abi.encodeCall(IModuleManager.setModuleGuard, (address(guard)))
            ),
            _multiSendItem(
                Enum.Operation.Call,
                address(safe),
                0,
                abi.encodeCall(IFallbackManager.setFallbackHandler, (address(handler)))
            ),
            _multiSendItem(Enum.Operation.Call, address(guard), 0, _initData())
        );
        assertTrue(_execAs(OWNER_PK, safe, address(multiSendCallOnly), _multiSend(items), Enum.Operation.DelegateCall));
        assertEq(uint8(_state(safe)), uint8(StateMachine.State.Normal));
        assertTrue(guard.isRecoveryOwner(address(safe), recovery));
    }

    // -------------------------------------------------------------------
    // Normal: documented residual
    // -------------------------------------------------------------------

    /// @dev Residual (SPEC_V1 §14, AR-29): at timelockDelay 0 a module can still make
    ///      an owner, which then holds owner powers - here it removes the guard.
    function test_normal_delayZero_escalationIsDocumentedResidual() public {
        Safe safe = _createConfigureAndInitialise(627);

        _moduleCall(module, safe, address(safe), 0, _addAttacker(), Enum.Operation.Call);
        assertTrue(safe.isOwner(attacker));
        assertEq(safe.getThreshold(), 1);

        assertTrue(
            _execAs(
                OTHER_PK, safe, address(safe), abi.encodeCall(IGuardManager.setGuard, (address(0))), Enum.Operation.Call
            )
        );
    }

    /// @dev At timelockDelay > 0: before the module acts, the attacker cannot even
    ///      schedule (signatures are checked against current owners). After a scheduled
    ///      module tx makes it an owner, its owner-path tx needs a fresh full delay.
    function test_normal_delayPositive_escalationNeedsFreshDelay() public {
        Safe safe = _createConfigureAndInitialise(628);
        _enableTimelock(safe, DELAY);

        bytes memory unguard = abi.encodeCall(IGuardManager.setGuard, (address(0)));
        Timelock.ExecTransactionParams memory p = _params(address(safe), unguard, Enum.Operation.Call);

        // Not yet an owner: scheduling with its signature fails.
        uint256 n = safe.nonce();
        bytes memory early = _sigFor(safe, OTHER_PK, address(safe), unguard, Enum.Operation.Call, n);
        vm.expectRevert(bytes("GS026"));
        guard.scheduleTransaction(address(safe), n, p, early);

        // The module tx itself must be scheduled by the quorum and wait.
        _execAsOwner(
            safe,
            address(guard),
            0,
            abi.encodeCall(
                Timelock.scheduleModuleTransaction, (module, address(safe), 0, _addAttacker(), Enum.Operation.Call)
            ),
            Enum.Operation.Call
        );
        vm.warp(block.timestamp + DELAY + 1);
        _moduleCall(module, safe, address(safe), 0, _addAttacker(), Enum.Operation.Call);
        assertTrue(safe.isOwner(attacker));

        // Owner now, but no ticket: direct execution reverts.
        n = safe.nonce();
        bytes memory sig = _sigFor(safe, OTHER_PK, address(safe), unguard, Enum.Operation.Call, n);
        vm.expectRevert(Timelock.TicketNotFound.selector);
        safe.execTransaction(address(safe), 0, unguard, Enum.Operation.Call, 0, 0, 0, address(0), payable(0), sig);

        // Scheduling works now, but the full delay starts afresh.
        guard.scheduleTransaction(address(safe), n, p, sig);
        vm.expectRevert(Timelock.TimelockNotElapsed.selector);
        safe.execTransaction(address(safe), 0, unguard, Enum.Operation.Call, 0, 0, 0, address(0), payable(0), sig);
        assertEq(_guardOf(safe), address(guard));
    }

    // -------------------------------------------------------------------
    // Normal: legitimate owner-rotating modules keep working
    // -------------------------------------------------------------------

    function test_normal_socialRecoveryModuleRotatesOwner() public {
        Safe safe = _createConfigureAndInitialise(629);
        SocialRecoveryModuleMock recoveryModule = new SocialRecoveryModuleMock();
        _enableModule(safe, address(recoveryModule));

        address newOwner = address(0xC0FFEE);
        recoveryModule.recover(safe, SENTINEL, owner, newOwner);

        assertTrue(safe.isOwner(newOwner));
        assertFalse(safe.isOwner(owner));
    }

    // keccak256("guard_manager.guard.address")
    uint256 private constant GUARD_SLOT = 0x4a204f620c8c5ccdca3fd54d003badd85ba500436a431f0cbda4f558c93c34c8;

    function _guardOf(Safe s) private view returns (address) {
        return address(uint160(uint256(bytes32(s.getStorageAt(GUARD_SLOT, 1)))));
    }
}
