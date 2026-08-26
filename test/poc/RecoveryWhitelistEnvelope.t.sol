// SPDX-License-Identifier: MIT
// Prompt C priority leads 1 and 2: INV-REC-1's `value == 0` and `operation == CALL` clauses.
//
// SPEC_V1 §7.4 ("`operation == CALL`, `value == 0`"), SPEC_V1 §11.6 INV-REC-1 and
// AUDIT_BRIEF.md load-bearing invariant #4 all state that the Recovering owner-path
// whitelist enforces `value == 0` AND `operation == CALL`. These tests settle, by
// execution, what the guard actually enforces and - where the guard does not enforce
// it - WHICH line stops the attack instead, and whether that line is a deliberate
// protection or an accidental consequence of a non-payable callee.
pragma solidity ^0.8.24;

import {TestEnvironment} from "../TestEnvironment.sol";

import {Safe, Enum} from "@safe-global/safe-smart-account/Safe.sol";
import {IModuleManager} from "@safe-global/safe-smart-account/interfaces/IModuleManager.sol";
import {IOwnerManager} from "@safe-global/safe-smart-account/interfaces/IOwnerManager.sol";
import {MultiSendCallOnly} from "@safe-global/safe-smart-account/libraries/MultiSendCallOnly.sol";

import {Lockdown} from "../../src/Lockdown.sol";
import {StateMachine} from "../../src/base/StateMachine.sol";

/// @dev A payable sink. If any recovery-phase path could reach an arbitrary target,
///      this contract's balance would grow. It never does in any test below.
contract PayableSink {
    receive() external payable {}
}

contract RecoveryWhitelistEnvelopePoC is TestEnvironment {
    Safe private safe;
    PayableSink private sink;

    address private constant SENTINEL = address(0x1);
    uint256 private constant FUNDING = 10 ether;

    /// @dev Second lockdown signer, registered while Normal so that a
    ///      `removeLockdownSigner` recovery call has a live target after the
    ///      trigger burns the first one.
    bytes private spareSigner;

    function setUp() public override {
        super.setUp();

        safe = _createConfigureAndInitialise(91);
        sink = new PayableSink();
        vm.deal(address(safe), FUNDING);

        spareSigner = abi.encodePacked(other);
        _execAsOwner(
            safe, address(guard), 0, abi.encodeCall(Lockdown.addLockdownSigner, (spareSigner)), Enum.Operation.Call
        );

        // Enter Recovering: past lockdownDuration (48h), inside resumeDelay (4h).
        _triggerLockdown(safe, bytes32("wrench"));
        vm.warp(block.timestamp + 48 hours + 1);
        (StateMachine.State state,) = guard.getState(address(safe));
        assertEq(uint256(state), uint256(StateMachine.State.Recovering), "setUp must land in Recovering");
    }

    // -------------------------------------------------------------------
    // Lead 1 - INV-REC-1 `value == 0`
    // -------------------------------------------------------------------

    /// @dev Direct hook call: the guard is the ONLY thing under test here, with no
    ///      Safe execution behind it. A non-reverting call proves the guard admits
    ///      `value > 0`, i.e. INV-REC-1's `value == 0` clause is not enforced.
    function _guardAcceptsRecoveryCallWithValue(address to, bytes memory data) private {
        vm.prank(address(safe));
        guard.checkTransaction(
            to, 1 ether, data, Enum.Operation.Call, 0, 0, 0, address(0), payable(address(0)), hex"", address(0)
        );
    }

    function test_confirmed_recoveryGuardAcceptsNonZeroValue_disableModule() public {
        _guardAcceptsRecoveryCallWithValue(
            address(safe), abi.encodeCall(IModuleManager.disableModule, (SENTINEL, module))
        );
    }

    function test_confirmed_recoveryGuardAcceptsNonZeroValue_swapOwner() public {
        _guardAcceptsRecoveryCallWithValue(
            address(safe), abi.encodeCall(IOwnerManager.swapOwner, (SENTINEL, owner, recovery))
        );
    }

    function test_confirmed_recoveryGuardAcceptsNonZeroValue_removeLockdownSigner() public {
        _guardAcceptsRecoveryCallWithValue(address(guard), abi.encodeCall(Lockdown.removeLockdownSigner, (spareSigner)));
    }

    /// @dev The nonce-burn arm is the ONE disjunct that does read `value`
    ///      (`src/Lockdown.sol:525`), so it is the only one where the guard itself
    ///      rejects value. Contrast with the three tests above.
    function test_refuted_recoveryGuardRejectsNonZeroValue_onNonceBurnOnly() public {
        vm.prank(address(safe));
        vm.expectRevert(Lockdown.RecoveryActive.selector);
        guard.checkTransaction(
            address(safe),
            1 ether,
            hex"",
            Enum.Operation.Call,
            0,
            0,
            0,
            address(0),
            payable(address(0)),
            hex"",
            address(0)
        );
    }

    /// @dev End-to-end: value-bearing whitelisted calls do NOT move ETH. The revert
    ///      carries EMPTY return data, which is Solidity's non-payable-function check
    ///      in the CALLEE - not a guard error (every guard error has a 4-byte
    ///      selector). This is the proof that the protection here is ACCIDENTAL.
    function _executionRevertsEmptyAndKeepsBalance(address to, bytes memory data) private {
        uint256 before = address(safe).balance;
        bytes memory sig = _signTx(safe, OWNER_PK, to, 1 ether, data, Enum.Operation.Call);
        vm.expectRevert(bytes(""));
        safe.execTransaction(to, 1 ether, data, Enum.Operation.Call, 0, 0, 0, address(0), payable(address(0)), sig);
        assertEq(address(safe).balance, before, "no ETH left the Safe");
    }

    function test_limitation_recoveryValueBlockedOnlyByNonPayableCallee_disableModule() public {
        _executionRevertsEmptyAndKeepsBalance(
            address(safe), abi.encodeCall(IModuleManager.disableModule, (SENTINEL, module))
        );
    }

    function test_limitation_recoveryValueBlockedOnlyByNonPayableCallee_swapOwner() public {
        _executionRevertsEmptyAndKeepsBalance(
            address(safe), abi.encodeCall(IOwnerManager.swapOwner, (SENTINEL, owner, recovery))
        );
    }

    function test_limitation_recoveryValueBlockedOnlyByNonPayableSingleton_removeLockdownSigner() public {
        _executionRevertsEmptyAndKeepsBalance(
            address(guard), abi.encodeCall(Lockdown.removeLockdownSigner, (spareSigner))
        );
    }

    /// @dev The whitelist admits exactly three `to` values: the Safe itself, the
    ///      singleton, and (nonce burn) the Safe again. None is a third party, so
    ///      there is no whitelisted payable target to reach. Attempting an arbitrary
    ///      payable target is rejected BY THE GUARD.
    function test_refuted_recoveryCannotReachPayableTargetDirectly() public {
        vm.prank(address(safe));
        vm.expectRevert(Lockdown.RecoveryActive.selector);
        guard.checkTransaction(
            address(sink),
            1 ether,
            hex"",
            Enum.Operation.Call,
            0,
            0,
            0,
            address(0),
            payable(address(0)),
            hex"",
            address(0)
        );
        assertEq(address(sink).balance, 0, "sink never funded");
    }

    // -------------------------------------------------------------------
    // Lead 2 - INV-REC-1 `operation == CALL`
    // -------------------------------------------------------------------

    function _recoveryLeafRemoveSigner() private view returns (bytes memory) {
        return _multiSendItem(
            Enum.Operation.Call, address(guard), 0, abi.encodeCall(Lockdown.removeLockdownSigner, (spareSigner))
        );
    }

    /// @dev Spec says CALL only. The guard accepts a top-level DELEGATECALL envelope
    ///      to MultiSendCallOnly and re-validates each leaf with Privilege.Recovery.
    function test_confirmed_recoveryAcceptsMultiSendDelegateCallEnvelope() public {
        bytes memory batch = abi.encodePacked(
            _multiSendItem(Enum.Operation.Call, address(safe), 0, hex""), // nonce burn
            _recoveryLeafRemoveSigner()
        );
        vm.prank(address(safe));
        guard.checkTransaction(
            address(multiSendCallOnly),
            0,
            abi.encodeCall(MultiSendCallOnly.multiSend, (batch)),
            Enum.Operation.DelegateCall,
            0,
            0,
            0,
            address(0),
            payable(address(0)),
            hex"",
            address(0)
        );
    }

    function _expectEnvelopeRejected(bytes memory batch, bytes4 expected) private {
        vm.prank(address(safe));
        vm.expectRevert(expected);
        guard.checkTransaction(
            address(multiSendCallOnly),
            0,
            abi.encodeCall(MultiSendCallOnly.multiSend, (batch)),
            Enum.Operation.DelegateCall,
            0,
            0,
            0,
            address(0),
            payable(address(0)),
            hex"",
            address(0)
        );
    }

    /// @dev Every leaf is re-checked with Privilege.Recovery, so a non-whitelisted
    ///      leaf cannot be smuggled in beside legitimate ones.
    function test_refuted_recoveryEnvelopeCannotSmuggleNonWhitelistedLeaf() public {
        bytes memory batch = abi.encodePacked(
            _recoveryLeafRemoveSigner(),
            _multiSendItem(Enum.Operation.Call, address(sink), 1 ether, hex"") // value to a third party
        );
        _expectEnvelopeRejected(batch, Lockdown.RecoveryActive.selector);
        assertEq(address(sink).balance, 0, "sink never funded");
    }

    /// @dev `addOwnerWithThreshold` is the canonical forbidden recovery action.
    function test_refuted_recoveryEnvelopeCannotSmuggleAddOwner() public {
        bytes memory batch = abi.encodePacked(
            _recoveryLeafRemoveSigner(),
            _multiSendItem(
                Enum.Operation.Call,
                address(safe),
                0,
                abi.encodeCall(IOwnerManager.addOwnerWithThreshold, (address(0xBAD), 1))
            )
        );
        _expectEnvelopeRejected(batch, Lockdown.RecoveryActive.selector);
    }

    /// @dev Safe v1.5.0 aliases a leaf `to == address(0)` to the Safe itself
    ///      (MultiSendCallOnly line 43), and the guard mirrors that at
    ///      `src/Lockdown.sol:462`. A value-bearing aliased leaf is therefore judged
    ///      as a Safe self-call with empty data, where `value == 0` IS enforced.
    function test_refuted_recoveryEnvelopeAddressZeroAliasingCannotCarryValue() public {
        bytes memory batch = abi.encodePacked(_multiSendItem(Enum.Operation.Call, address(0), 1 ether, hex""));
        _expectEnvelopeRejected(batch, Lockdown.RecoveryActive.selector);
    }

    /// @dev A nested DELEGATECALL leaf pointing at MultiSendCallOnly is ACCEPTED by
    ///      the guard at depth: the Privilege.Recovery whitelist lives inside the
    ///      `Call` arm of `_checkCall` only (`src/Lockdown.sol:389-390`), so the
    ///      `DelegateCall` arm (`:427`) is reached at every depth regardless of
    ///      privilege. The guard is strictly more permissive than the spec.
    function test_confirmed_recoveryGuardAcceptsNestedDelegateCallAtDepth() public {
        bytes memory inner = abi.encodePacked(_recoveryLeafRemoveSigner());
        bytes memory outer = abi.encodePacked(
            _multiSendItem(
                Enum.Operation.DelegateCall,
                address(multiSendCallOnly),
                0,
                abi.encodeCall(MultiSendCallOnly.multiSend, (inner))
            )
        );
        vm.prank(address(safe));
        guard.checkTransaction(
            address(multiSendCallOnly),
            0,
            abi.encodeCall(MultiSendCallOnly.multiSend, (outer)),
            Enum.Operation.DelegateCall,
            0,
            0,
            0,
            address(0),
            payable(address(0)),
            hex"",
            address(0)
        );
    }

    /// @dev ...but it never executes: MultiSendCallOnly itself rejects operation == 1
    ///      with a bare `revert(0, 0)` (MultiSendCallOnly.sol case 1). The nested
    ///      delegatecall is stopped by the CALLEE, not by the guard - accidental,
    ///      though anchored on an immutable canonical library.
    function test_limitation_nestedDelegateCallStoppedByMultiSendCallOnlyNotGuard() public {
        bytes memory inner = abi.encodePacked(_recoveryLeafRemoveSigner());
        bytes memory outer = abi.encodePacked(
            _multiSendItem(
                Enum.Operation.DelegateCall,
                address(multiSendCallOnly),
                0,
                abi.encodeCall(MultiSendCallOnly.multiSend, (inner))
            )
        );
        bytes memory payload = abi.encodeCall(MultiSendCallOnly.multiSend, (outer));
        bytes memory sig = _signTx(safe, OWNER_PK, address(multiSendCallOnly), 0, payload, Enum.Operation.DelegateCall);
        vm.expectRevert(bytes(""));
        safe.execTransaction(
            address(multiSendCallOnly),
            0,
            payload,
            Enum.Operation.DelegateCall,
            0,
            0,
            0,
            address(0),
            payable(address(0)),
            sig
        );
    }

    /// @dev A DELEGATECALL to anything other than the canonical MultiSendCallOnly is
    ///      denied by the guard in Recovering, exactly as in Normal.
    function test_refuted_recoveryDelegateCallToArbitraryTargetDenied() public {
        vm.prank(address(safe));
        vm.expectRevert(Lockdown.DelegateCallDenied.selector);
        guard.checkTransaction(
            address(sink),
            0,
            hex"",
            Enum.Operation.DelegateCall,
            0,
            0,
            0,
            address(0),
            payable(address(0)),
            hex"",
            address(0)
        );
    }

    /// @dev The positive control for the whole file: a legitimate recovery batch
    ///      really does execute end-to-end, so the refutations above are not an
    ///      artefact of a broken fixture.
    function test_control_legitimateRecoveryBatchExecutes() public {
        bytes memory batch =
            abi.encodePacked(_multiSendItem(Enum.Operation.Call, address(safe), 0, hex""), _recoveryLeafRemoveSigner());
        uint256 before = address(safe).balance;
        _execAsOwner(
            safe,
            address(multiSendCallOnly),
            0,
            abi.encodeCall(MultiSendCallOnly.multiSend, (batch)),
            Enum.Operation.DelegateCall
        );
        assertFalse(guard.isLockdownSigner(address(safe), spareSigner), "spare signer removed");
        assertEq(address(safe).balance, before, "recovery moved no ETH");
    }
}
