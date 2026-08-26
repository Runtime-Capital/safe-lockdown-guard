// SPDX-License-Identifier: MIT
// Prompt C priority lead 4: does the module-path timelock ticket bind every field of
// the call it authorises?
//
// A ticket is keyed by `LockdownLib.moduleTxHash(safe, module, to, value, keccak(data),
// operation)` (src/utils/LockdownLib.sol:47-66), namespaced by `moduleTicketKey`. If any
// field of the executed call were absent from the preimage, one scheduled ticket could
// be consumed by a DIFFERENT call - a scheduled-vs-executed mismatch, which is the
// classic timelock break. These tests vary each field in turn and assert the ticket does
// not match.
//
// Note the "matching" property would stay green under a weakened preimage if it were
// only tested on the happy path, which is why every field gets its own negative test.
pragma solidity ^0.8.24;

import {TestEnvironment} from "../TestEnvironment.sol";

import {Safe, Enum} from "@safe-global/safe-smart-account/Safe.sol";

import {LockdownTimelock} from "../../src/LockdownTimelock.sol";
import {Timelock} from "../../src/base/Timelock.sol";

contract ModuleTicketPreimagePoC is TestEnvironment {
    uint64 private constant DELAY = 24 hours;

    address private constant TO = address(0x707);
    address private constant OTHER_TO = address(0x708);
    address private constant OTHER_MODULE = address(0x80D4);
    uint256 private constant VALUE = 1 ether;
    bytes private constant DATA = hex"deadbeef";
    bytes private constant OTHER_DATA = hex"deadbeff";

    Safe private safe;

    function setUp() public override {
        super.setUp();
        safe = _createConfigureAndInitialise(95);
        vm.deal(address(safe), 100 ether);
        _enableModule(safe, OTHER_MODULE);
        _enableTimelock(safe, DELAY);

        // Schedule exactly one module ticket, then make it executable.
        _execAsOwner(
            safe,
            address(guard),
            0,
            abi.encodeCall(LockdownTimelock.scheduleModuleTransaction, (module, TO, VALUE, DATA, Enum.Operation.Call)),
            Enum.Operation.Call
        );
        vm.warp(block.timestamp + DELAY + 1);
    }

    /// @dev Drives the module pre-hook exactly as Safe v1.5.0 would.
    function _preHook(address module_, address to, uint256 value, bytes memory data, Enum.Operation op) private {
        vm.prank(address(safe));
        guard.checkModuleTransaction(to, value, data, op, module_);
    }

    function _preHookExpectNoTicket(address module_, address to, uint256 value, bytes memory data, Enum.Operation op)
        private
    {
        vm.prank(address(safe));
        vm.expectRevert(Timelock.TicketNotFound.selector);
        guard.checkModuleTransaction(to, value, data, op, module_);
    }

    /// @dev Positive control: the exact scheduled call passes. Without this the
    ///      negative tests below could all be passing for the wrong reason.
    function test_control_exactScheduledModuleCallIsAccepted() public {
        _preHook(module, TO, VALUE, DATA, Enum.Operation.Call);
    }

    function test_refuted_preimageBinds_to() public {
        _preHookExpectNoTicket(module, OTHER_TO, VALUE, DATA, Enum.Operation.Call);
    }

    function test_refuted_preimageBinds_value() public {
        _preHookExpectNoTicket(module, TO, VALUE + 1, DATA, Enum.Operation.Call);
    }

    function test_refuted_preimageBinds_data() public {
        _preHookExpectNoTicket(module, TO, VALUE, OTHER_DATA, Enum.Operation.Call);
    }

    /// @dev Data is bound by its keccak hash, so a LENGTH change must also miss.
    function test_refuted_preimageBinds_dataLength() public {
        _preHookExpectNoTicket(module, TO, VALUE, hex"deadbeefee", Enum.Operation.Call);
    }

    /// @dev Empty data must not collide with the scheduled non-empty data.
    function test_refuted_preimageBinds_emptyDataDoesNotCollide() public {
        _preHookExpectNoTicket(module, TO, VALUE, hex"", Enum.Operation.Call);
    }

    /// @dev A DIFFERENT enabled module cannot spend another module's ticket.
    function test_refuted_preimageBinds_module() public {
        _preHookExpectNoTicket(OTHER_MODULE, TO, VALUE, DATA, Enum.Operation.Call);
    }

    /// @dev Operation is in the preimage. A DELEGATECALL variant of the scheduled call
    ///      must not match. (It is separately denied unless `to` is MultiSendCallOnly,
    ///      so this asserts the ticket lookup, using MultiSendCallOnly as `to` to get
    ///      past the operation policy and reach `_verifyTicket`.)
    function test_refuted_preimageBinds_operation() public {
        _execAsOwner(
            safe,
            address(guard),
            0,
            abi.encodeCall(
                LockdownTimelock.scheduleModuleTransaction,
                (module, address(multiSendCallOnly), 0, hex"", Enum.Operation.Call)
            ),
            Enum.Operation.Call
        );
        vm.warp(block.timestamp + DELAY + 1);

        // The CALL form matches its own ticket...
        _preHook(module, address(multiSendCallOnly), 0, hex"", Enum.Operation.Call);
        // ...then clear the INV-TIME-11 transient in-flight slot the way Safe would.
        // `success = false` clears the slot WITHOUT consuming the ticket, so the revert
        // below cannot be blamed on the ticket having been spent.
        vm.prank(address(safe));
        guard.checkAfterModuleExecution(bytes32(0), false);

        // ...the DELEGATECALL form of the same (to, value, data) does not. An empty
        // MultiSend payload is a valid, policy-accepted DELEGATECALL, so the revert
        // below comes from the ticket lookup and not from the operation policy.
        vm.prank(address(safe));
        vm.expectRevert(Timelock.TicketNotFound.selector);
        guard.checkModuleTransaction(
            address(multiSendCallOnly), 0, _emptyMultiSend(), Enum.Operation.DelegateCall, module
        );
    }

    /// @dev Cross-Safe: another Safe's identical module call must not match this
    ///      Safe's ticket (the preimage binds `safe`).
    function test_refuted_preimageBinds_safe() public {
        Safe otherSafe = _createConfigureAndInitialise(96);
        _execAsOwner(
            otherSafe,
            address(guard),
            0,
            abi.encodeCall(LockdownTimelock.setTimelockDelay, (DELAY)),
            Enum.Operation.Call
        );

        vm.prank(address(otherSafe));
        vm.expectRevert(Timelock.TicketNotFound.selector);
        guard.checkModuleTransaction(TO, VALUE, DATA, Enum.Operation.Call, module);
    }

    /// @dev And the hash helper agrees with the storage key: two calls differing in any
    ///      single field produce different hashes. Cheap belt-and-braces on the
    ///      library itself.
    function test_refuted_moduleTxHashIsInjectiveOverFields() public view {
        bytes32 base = guard.getModuleTransactionHash(address(safe), module, TO, VALUE, DATA, Enum.Operation.Call);
        assertTrue(
            base != guard.getModuleTransactionHash(address(safe), OTHER_MODULE, TO, VALUE, DATA, Enum.Operation.Call),
            "module"
        );
        assertTrue(
            base != guard.getModuleTransactionHash(address(safe), module, OTHER_TO, VALUE, DATA, Enum.Operation.Call),
            "to"
        );
        assertTrue(
            base != guard.getModuleTransactionHash(address(safe), module, TO, VALUE + 1, DATA, Enum.Operation.Call),
            "value"
        );
        assertTrue(
            base != guard.getModuleTransactionHash(address(safe), module, TO, VALUE, OTHER_DATA, Enum.Operation.Call),
            "data"
        );
        assertTrue(
            base != guard.getModuleTransactionHash(address(safe), module, TO, VALUE, DATA, Enum.Operation.DelegateCall),
            "operation"
        );
        assertTrue(
            base != guard.getModuleTransactionHash(address(this), module, TO, VALUE, DATA, Enum.Operation.Call), "safe"
        );
    }

    function _emptyMultiSend() private pure returns (bytes memory) {
        return abi.encodeWithSignature("multiSend(bytes)", hex"");
    }
}
