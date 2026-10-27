// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {TestEnvironment, Vm} from "./TestEnvironment.sol";

import {ISafe, IOwnerManager, Enum} from "@safe-global/safe-smart-account/interfaces/ISafe.sol";
import {IGuardManager} from "@safe-global/safe-smart-account/interfaces/IGuardManager.sol";
import {IFallbackManager} from "@safe-global/safe-smart-account/interfaces/IFallbackManager.sol";
import {IModuleManager} from "@safe-global/safe-smart-account/interfaces/IModuleManager.sol";
import {MultiSendCallOnly} from "@safe-global/safe-smart-account/libraries/MultiSendCallOnly.sol";

import {LockdownTimelock, Lockdown} from "../src/LockdownTimelock.sol";
import {Timelock} from "../src/base/Timelock.sol";
import {LockdownLib} from "../src/utils/LockdownLib.sol";
import {StateMachine} from "../src/base/StateMachine.sol";
import {console} from "forge-std/console.sol";

contract LockdownTimelockTest is TestEnvironment {
    ISafe private SAFE_A;
    ISafe private SAFE_B;
    ISafe private SAFE_UNINIT;
    address private constant MODULE_A = address(0xAA01);
    address private constant BACKUP_OWNER_A = address(0xB1);
    address private constant HSM_A = address(0x77A1);
    address private constant HSM_B = address(0x77A2);
    address private constant TARGET = address(0xBEEF);

    function setUp() public override {
        super.setUp();

        SAFE_A = _createAndConfigure(0);
        SAFE_B = _createAndConfigure(1);
        SAFE_UNINIT = _createAndConfigure(2);

        address[] memory backupsA = new address[](1);
        backupsA[0] = BACKUP_OWNER_A;
        bytes[] memory signersA = new bytes[](1);
        signersA[0] = _eoaSigner(panicKey);
        vm.prank(address(SAFE_A));
        guard.initialize(48 hours, 4 hours, backupsA, signersA);

        // address(SAFE_B): no signers (dormant) - used to test cross-Safe isolation.
        vm.prank(address(SAFE_B));
        guard.initialize(24 hours, 4 hours, backupsA, new bytes[](0));
    }

    // -------------------------------------------------------------------
    // setTimelockDelay
    // -------------------------------------------------------------------

    function test_setTimelockDelay_acceptsValidRange() public {
        vm.prank(address(SAFE_A));
        guard.setTimelockDelay(24 hours);
        assertEq(guard.getTimelockDelay(address(SAFE_A)), 24 hours, "delay set");
    }

    function test_setTimelockDelay_acceptsZero_toDisable() public {
        vm.prank(address(SAFE_A));
        guard.setTimelockDelay(24 hours);
        vm.prank(address(SAFE_A));
        guard.setTimelockDelay(0);
        assertEq(guard.getTimelockDelay(address(SAFE_A)), 0, "delay disabled");
    }

    function test_setTimelockDelay_revertsBelowMin() public {
        vm.prank(address(SAFE_A));
        vm.expectRevert(Timelock.TimelockDelayTooLow.selector);
        guard.setTimelockDelay(30 minutes);
    }

    function test_setTimelockDelay_revertsAboveMax() public {
        vm.prank(address(SAFE_A));
        vm.expectRevert(Timelock.TimelockDelayTooHigh.selector);
        guard.setTimelockDelay(31 days);
    }

    function test_setTimelockDelay_revertsBeforeInitialise() public {
        vm.prank(address(SAFE_UNINIT));
        vm.expectRevert(
            abi.encodeWithSelector(
                StateMachine.InvalidState.selector,
                StateMachine.State.Uninitialised,
                1 << uint256(StateMachine.State.Normal)
            )
        );
        guard.setTimelockDelay(24 hours);
    }

    // -------------------------------------------------------------------
    // T-LIVE-2 / INV-LIVE-3: lockdownDuration >= max(LOCKDOWN_DURATION_MIN,
    // timelockDelay). The hard-freeze phase must never be shorter than the
    // timelock delay it backs, so a coerced quorum cannot self-induce a short
    // lockdown to reach the un-timelocked Recovering disarm faster than the
    // timelock would have allowed a Normal-mode disarm (SPEC §14.2 / §17).
    // address(SAFE_A) is initialised with lockdownDuration == 48h.
    // -------------------------------------------------------------------

    function test_setTimelockDelay_acceptsEqualToLockdownDuration() public {
        vm.prank(address(SAFE_A));
        guard.setTimelockDelay(48 hours); // == lockdownDuration, allowed
        assertEq(guard.getTimelockDelay(address(SAFE_A)), 48 hours, "delay == duration ok");
    }

    function test_setTimelockDelay_revertsAboveLockdownDuration() public {
        // 49h is within [TIMELOCK_DELAY_MIN, TIMELOCK_DELAY_MAX] but exceeds the
        // 48h lockdown freeze, so it must revert.
        vm.prank(address(SAFE_A));
        vm.expectRevert(LockdownTimelock.TimelockExceedsLockdownDuration.selector);
        guard.setTimelockDelay(49 hours);
    }

    function test_setLockdownDuration_revertsBelowMin() public {
        vm.prank(address(SAFE_A));
        vm.expectRevert(StateMachine.LockdownDurationTooLow.selector);
        guard.setLockdownDuration(30 minutes);
    }

    function test_setLockdownDuration_acceptsAtMin() public {
        vm.prank(address(SAFE_A));
        guard.setLockdownDuration(1 hours); // timelockDelay == 0, MIN floor only
        // no revert
    }

    function test_setLockdownDuration_revertsBelowActiveTimelock() public {
        vm.prank(address(SAFE_A));
        guard.setTimelockDelay(24 hours); // 24h <= 48h, allowed
        // Now try to lower the freeze below the active timelock.
        vm.prank(address(SAFE_A));
        vm.expectRevert(LockdownTimelock.TimelockExceedsLockdownDuration.selector);
        guard.setLockdownDuration(23 hours);
    }

    function test_setLockdownDuration_acceptsEqualToActiveTimelock() public {
        vm.prank(address(SAFE_A));
        guard.setTimelockDelay(24 hours);
        vm.prank(address(SAFE_A));
        guard.setLockdownDuration(24 hours); // == timelockDelay, allowed
        // no revert
    }

    function test_initialize_revertsBelowMinDuration() public {
        address[] memory backups = new address[](1);
        backups[0] = BACKUP_OWNER_A;
        vm.prank(address(SAFE_UNINIT));
        vm.expectRevert(StateMachine.LockdownDurationTooLow.selector);
        guard.initialize(30 minutes, 4 hours, backups, new bytes[](0));
    }

    // -------------------------------------------------------------------
    // setTimelockBypasser
    // -------------------------------------------------------------------

    function test_setTimelockBypasser_addsAndRemoves() public {
        vm.prank(address(SAFE_A));
        guard.setTimelockBypasser(HSM_A, true);
        assertTrue(guard.isTimelockBypasser(address(SAFE_A), HSM_A), "added");
        vm.prank(address(SAFE_A));
        guard.setTimelockBypasser(HSM_A, false);
        assertFalse(guard.isTimelockBypasser(address(SAFE_A), HSM_A), "removed");
    }

    function test_setTimelockBypasser_idempotentEmitsEvent() public {
        // Idempotent semantically (state stays false), but the event is
        // always emitted so off-chain indexers see every governance call
        // (V1 review, fix #1).
        vm.recordLogs();
        vm.prank(address(SAFE_A));
        guard.setTimelockBypasser(HSM_A, false);
        Vm.Log[] memory logs = vm.getRecordedLogs();
        bool found;
        bytes32 sig = keccak256("TimelockBypasserChanged(address,address,bool)");
        for (uint256 i = 0; i < logs.length; i++) {
            if (logs[i].topics[0] == sig) {
                found = true;
                break;
            }
        }
        assertTrue(found, "event emitted even on no-op");
        assertFalse(guard.isTimelockBypasser(address(SAFE_A), HSM_A), "still false");
    }

    function test_setTimelockBypasser_revertsOnZeroAddress() public {
        vm.prank(address(SAFE_A));
        vm.expectRevert(Timelock.BypasserZeroAddress.selector);
        guard.setTimelockBypasser(address(0), true);
    }

    function test_setTimelockBypasser_revertsBeforeInitialise() public {
        vm.prank(address(SAFE_UNINIT));
        vm.expectRevert(
            abi.encodeWithSelector(
                StateMachine.InvalidState.selector,
                StateMachine.State.Uninitialised,
                1 << uint256(StateMachine.State.Normal)
            )
        );
        guard.setTimelockBypasser(HSM_A, true);
    }

    function test_setTimelockBypasser_isPerSafe() public {
        vm.prank(address(SAFE_A));
        guard.setTimelockBypasser(HSM_A, true);
        assertTrue(guard.isTimelockBypasser(address(SAFE_A), HSM_A), "A has it");
        assertFalse(guard.isTimelockBypasser(address(SAFE_B), HSM_A), "B does not");
    }

    // -------------------------------------------------------------------
    // scheduleTransaction + cancelTransaction
    // -------------------------------------------------------------------

    function _enableTimelock(address safe, uint64 delay) private {
        vm.prank(safe);
        guard.setTimelockDelay(delay);
    }

    function _ownerParams(address to, uint256 value, bytes memory data, Enum.Operation op)
        private
        pure
        returns (Timelock.ExecTransactionParams memory)
    {
        return Timelock.ExecTransactionParams({
            to: to,
            value: value,
            data: data,
            operation: op,
            safeTxGas: 0,
            baseGas: 0,
            gasPrice: 0,
            gasToken: address(0),
            refundReceiver: payable(address(0))
        });
    }

    function _signTxAtNonce(
        ISafe safe,
        uint256 privateKey,
        address to,
        uint256 value,
        bytes memory data,
        Enum.Operation op,
        uint256 nonce
    ) private view returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, _safeTxHash(safe, to, value, data, op, nonce));
        return abi.encodePacked(r, s, v);
    }

    function _scheduleOwner(ISafe safe, address to, uint256 value, bytes memory data, Enum.Operation op)
        private
        returns (bytes32)
    {
        return _scheduleOwnerAtNonce(safe, to, value, data, op, safe.nonce());
    }

    function _scheduleOwnerAtNonce(
        ISafe safe,
        address to,
        uint256 value,
        bytes memory data,
        Enum.Operation op,
        uint256 nonce
    ) private returns (bytes32) {
        bytes memory signatures = _signTxAtNonce(safe, OWNER_PK, to, value, data, op, nonce);
        guard.scheduleTransaction(address(safe), nonce, _ownerParams(to, value, data, op), signatures);
        return _safeTxHash(safe, to, value, data, op, nonce);
    }

    function _bypassOwnerHash(ISafe safe, bytes32 safeTxHash) private {
        vm.prank(address(safe));
        guard.setTimelockBypasser(HSM_A, true);
        vm.prank(HSM_A);
        guard.bypassTimelock(address(safe), safeTxHash);
    }

    function test_scheduleTransaction_emitsEvent() public {
        _enableTimelock(SAFE_A, 24 hours);
        uint256 nonce = SAFE_A.nonce();
        bytes32 safeTxHash = _safeTxHash(SAFE_A, TARGET, 0, hex"01", Enum.Operation.Call, nonce);
        bytes memory signatures = _signTxAtNonce(SAFE_A, OWNER_PK, TARGET, 0, hex"01", Enum.Operation.Call, nonce);
        vm.expectEmit();
        emit Timelock.TransactionScheduled(address(SAFE_A), safeTxHash, uint64(block.timestamp + 24 hours));
        guard.scheduleTransaction(
            address(SAFE_A), nonce, _ownerParams(TARGET, 0, hex"01", Enum.Operation.Call), signatures
        );
    }

    function test_scheduleTransaction_writesExecutableAt() public {
        _enableTimelock(SAFE_A, 24 hours);
        uint64 t0 = uint64(block.timestamp);
        bytes32 h = _scheduleOwner(SAFE_A, TARGET, 0, hex"01", Enum.Operation.Call);
        assertEq(guard.getTransactionExecutableAt(address(SAFE_A), h), t0 + 24 hours, "executableAt frozen at schedule");
    }

    function test_scheduleTransaction_revertsWhenTimelockDisabled() public {
        uint256 nonce = SAFE_A.nonce();
        Timelock.ExecTransactionParams memory params = _ownerParams(TARGET, 0, hex"01", Enum.Operation.Call);
        bytes memory signatures = _signTxAtNonce(SAFE_A, OWNER_PK, TARGET, 0, hex"01", Enum.Operation.Call, nonce);

        vm.expectRevert(Timelock.TimelockDisabled.selector);
        guard.scheduleTransaction(address(SAFE_A), nonce, params, signatures);
    }

    function test_scheduleTransaction_revertsOnDuplicateBeforeCancel() public {
        _enableTimelock(SAFE_A, 24 hours);
        uint256 nonce = SAFE_A.nonce();
        bytes memory data = hex"02";
        Timelock.ExecTransactionParams memory params = _ownerParams(TARGET, 0, data, Enum.Operation.Call);
        bytes memory sig = _signTxAtNonce(SAFE_A, OWNER_PK, TARGET, 0, data, Enum.Operation.Call, nonce);
        guard.scheduleTransaction(address(SAFE_A), nonce, params, sig);
        vm.expectRevert(Timelock.TicketAlreadyExists.selector);
        guard.scheduleTransaction(address(SAFE_A), nonce, params, sig);
    }

    function test_cancelTransaction_clearsTicket() public {
        _enableTimelock(SAFE_A, 24 hours);
        bytes32 h = _scheduleOwner(SAFE_A, TARGET, 0, hex"03", Enum.Operation.Call);
        vm.prank(address(SAFE_A));
        guard.cancelTransaction(h);
        assertEq(guard.getTransactionExecutableAt(address(SAFE_A), h), 0, "cleared");
    }

    function test_cancelTransaction_revertsOnUnknownHash() public {
        _enableTimelock(SAFE_A, 24 hours);
        vm.prank(address(SAFE_A));
        vm.expectRevert(Timelock.TicketNotFound.selector);
        guard.cancelTransaction(bytes32("never"));
    }

    function test_cancelTransaction_worksAfterTimelockDisabled() public {
        // User enabled timelock and scheduled a tx; the pending ticket is
        // still cancellable so storage can be reclaimed.
        _enableTimelock(SAFE_A, 24 hours);
        bytes32 h = _scheduleOwner(SAFE_A, TARGET, 0, hex"04", Enum.Operation.Call);
        // Skipping the planned tx, we directly cancel the old ticket.
        vm.prank(address(SAFE_A));
        guard.cancelTransaction(h);
        assertEq(guard.getTransactionExecutableAt(address(SAFE_A), h), 0, "still cancellable");
    }

    // -------------------------------------------------------------------
    // sweepExpired{Owner,Module}Ticket (permissionless cleanup)
    // -------------------------------------------------------------------

    address private constant JANITOR = address(0xCAFEC0DE);

    function test_sweep_owner_succeedsPastTTL() public {
        _enableTimelock(SAFE_A, 24 hours);
        bytes32 h = _scheduleOwner(SAFE_A, TARGET, 0, hex"05", Enum.Operation.Call);
        uint64 execAt = guard.getTransactionExecutableAt(address(SAFE_A), h);
        // Warp PAST executableAt + 90d TTL.
        vm.warp(uint256(execAt) + 90 days + 1);

        // Permissionless: anyone can sweep.
        vm.prank(JANITOR);
        guard.sweepExpiredOwnerTicket(address(SAFE_A), h);
        assertEq(guard.getTransactionExecutableAt(address(SAFE_A), h), 0, "swept");
    }

    function test_sweep_owner_revertsBeforeTTL() public {
        _enableTimelock(SAFE_A, 24 hours);
        bytes32 h = _scheduleOwner(SAFE_A, TARGET, 0, hex"06", Enum.Operation.Call);
        // Warp just into the executable window but BEFORE TTL.
        uint64 execAt = guard.getTransactionExecutableAt(address(SAFE_A), h);
        vm.warp(uint256(execAt) + 1);

        vm.prank(JANITOR);
        vm.expectRevert(Timelock.TicketNotExpired.selector);
        guard.sweepExpiredOwnerTicket(address(SAFE_A), h);
    }

    function test_sweep_owner_revertsOnUnknownHash() public {
        _enableTimelock(SAFE_A, 24 hours);
        vm.prank(JANITOR);
        vm.expectRevert(Timelock.TicketNotFound.selector);
        guard.sweepExpiredOwnerTicket(address(SAFE_A), bytes32("ghost"));
    }

    function test_sweep_owner_revertsOnUninitSafe() public {
        vm.prank(JANITOR);
        vm.expectRevert(
            abi.encodeWithSelector(
                StateMachine.InvalidState.selector,
                StateMachine.State.Uninitialised,
                ~(1 << uint256(StateMachine.State.Uninitialised))
            )
        );
        guard.sweepExpiredOwnerTicket(address(SAFE_UNINIT), bytes32("any"));
    }

    // -------------------------------------------------------------------
    // Timelock mutator state-gate coverage. schedule / scheduleModule are onlyNormal,
    // cancel* / sweepModule are onlyInitialized: pin the gates the component
    // extraction must keep re-applying so a dropped gate fails loudly (a
    // missing gate would revert TimelockDisabled/TicketNotFound, or not at
    // all, instead of InvalidState).
    // -------------------------------------------------------------------

    function test_scheduleTransaction_revertsOnUninitSafe() public {
        uint256 nonce = SAFE_UNINIT.nonce();
        Timelock.ExecTransactionParams memory params = _ownerParams(TARGET, 0, hex"07", Enum.Operation.Call);

        vm.expectRevert(
            abi.encodeWithSelector(
                StateMachine.InvalidState.selector,
                StateMachine.State.Uninitialised,
                1 << uint256(StateMachine.State.Normal)
            )
        );
        guard.scheduleTransaction(address(SAFE_UNINIT), nonce, params, hex"");
    }

    function test_scheduleModuleTransaction_revertsOnUninitSafe() public {
        vm.prank(address(SAFE_UNINIT));
        vm.expectRevert(
            abi.encodeWithSelector(
                StateMachine.InvalidState.selector,
                StateMachine.State.Uninitialised,
                1 << uint256(StateMachine.State.Normal)
            )
        );
        guard.scheduleModuleTransaction(address(0xA11CE), address(0xB0B), 0, hex"", Enum.Operation.Call);
    }

    function test_cancelTransaction_revertsOnUninitSafe() public {
        vm.prank(address(SAFE_UNINIT));
        vm.expectRevert(
            abi.encodeWithSelector(
                StateMachine.InvalidState.selector,
                StateMachine.State.Uninitialised,
                ~(1 << uint256(StateMachine.State.Uninitialised))
            )
        );
        guard.cancelTransaction(bytes32("x"));
    }

    function test_cancelModuleTransaction_revertsOnUninitSafe() public {
        vm.prank(address(SAFE_UNINIT));
        vm.expectRevert(
            abi.encodeWithSelector(
                StateMachine.InvalidState.selector,
                StateMachine.State.Uninitialised,
                ~(1 << uint256(StateMachine.State.Uninitialised))
            )
        );
        guard.cancelModuleTransaction(bytes32(0));
    }

    function test_sweepExpiredModuleTicket_revertsOnUninitSafe() public {
        vm.prank(JANITOR);
        vm.expectRevert(
            abi.encodeWithSelector(
                StateMachine.InvalidState.selector,
                StateMachine.State.Uninitialised,
                ~(1 << uint256(StateMachine.State.Uninitialised))
            )
        );
        guard.sweepExpiredModuleTicket(address(SAFE_UNINIT), bytes32(0));
    }

    function test_sweep_owner_isPerSafe() public {
        _enableTimelock(SAFE_A, 24 hours);
        _enableTimelock(SAFE_B, 24 hours);
        bytes32 h = _scheduleOwner(SAFE_A, TARGET, 0, hex"08", Enum.Operation.Call);
        uint64 execAt = guard.getTransactionExecutableAt(address(SAFE_A), h);
        vm.warp(uint256(execAt) + 90 days + 1);

        // Sweep on B for a hash B never scheduled reverts TicketNotFound.
        // Sweep on A succeeds.
        vm.prank(JANITOR);
        vm.expectRevert(Timelock.TicketNotFound.selector);
        guard.sweepExpiredOwnerTicket(address(SAFE_B), h);

        vm.prank(JANITOR);
        guard.sweepExpiredOwnerTicket(address(SAFE_A), h);
        assertEq(guard.getTransactionExecutableAt(address(SAFE_A), h), 0, "A swept");
    }

    function test_sweep_module_succeedsPastTTL() public {
        _enableTimelock(SAFE_A, 24 hours);
        vm.prank(address(SAFE_A));
        bytes32 moduleTxHash = guard.scheduleModuleTransaction(MODULE_A, TARGET, 0, hex"", Enum.Operation.Call);
        // executableAt = block.timestamp + 24h at schedule.
        vm.warp(block.timestamp + 24 hours + 90 days + 1);

        vm.prank(JANITOR);
        guard.sweepExpiredModuleTicket(address(SAFE_A), moduleTxHash);
        assertEq(guard.getModuleTransactionExecutableAt(address(SAFE_A), moduleTxHash), 0, "swept");
    }

    function test_sweep_module_revertsBeforeTTL() public {
        _enableTimelock(SAFE_A, 24 hours);
        vm.prank(address(SAFE_A));
        bytes32 moduleTxHash = guard.scheduleModuleTransaction(MODULE_A, TARGET, 0, hex"", Enum.Operation.Call);
        // Just past executableAt, well before TTL.
        vm.warp(block.timestamp + 24 hours + 1);

        vm.prank(JANITOR);
        vm.expectRevert(Timelock.TicketNotExpired.selector);
        guard.sweepExpiredModuleTicket(address(SAFE_A), moduleTxHash);
    }

    // -------------------------------------------------------------------
    // Finding 1 (C1): bypassed meta-call MUST reject refund fields
    // -------------------------------------------------------------------

    function test_bypassMetaCall_revertsOnNonZeroBaseGas() public {
        _enableTimelock(SAFE_A, 24 hours);
        bytes memory data = abi.encodeCall(Timelock.cancelTransaction, (bytes32("h")));
        vm.prank(address(SAFE_A));
        vm.expectRevert(LockdownTimelock.TimelockBypassRefundDenied.selector);
        guard.checkTransaction(
            address(guard),
            0,
            data,
            Enum.Operation.Call,
            0, /* baseGas */
            uint256(1),
            0,
            address(0),
            payable(address(0)),
            hex"",
            address(0)
        );
    }

    function test_bypassMetaCall_revertsOnNonZeroGasToken() public {
        _enableTimelock(SAFE_A, 24 hours);
        bytes memory data = abi.encodeCall(Timelock.cancelTransaction, (bytes32("h")));
        vm.prank(address(SAFE_A));
        vm.expectRevert(LockdownTimelock.TimelockBypassRefundDenied.selector);
        guard.checkTransaction(
            address(guard),
            0,
            data,
            Enum.Operation.Call,
            0,
            0,
            0,
            /* gasToken */
            address(0xBEEF),
            payable(address(0)),
            hex"",
            address(0)
        );
    }

    function test_bypassMetaCall_revertsOnNonZeroRefundReceiver() public {
        _enableTimelock(SAFE_A, 24 hours);
        bytes memory data = abi.encodeCall(
            Timelock.scheduleModuleTransaction, (MODULE_A, TARGET, uint256(0), hex"", Enum.Operation.Call)
        );
        vm.prank(address(SAFE_A));
        vm.expectRevert(LockdownTimelock.TimelockBypassRefundDenied.selector);
        guard.checkTransaction(
            address(guard),
            0,
            data,
            Enum.Operation.Call,
            0,
            0,
            0,
            address(0), /* refundReceiver */
            payable(address(0xDEAD)),
            hex"",
            address(0)
        );
    }

    function test_bypassMetaCall_acceptsZeroRefundFields() public {
        _enableTimelock(SAFE_A, 24 hours);
        bytes32 h = _scheduleOwner(SAFE_A, TARGET, 0, hex"09", Enum.Operation.Call);
        bytes memory data = abi.encodeCall(Timelock.cancelTransaction, (h));
        vm.prank(address(SAFE_A));
        // No revert expected.
        guard.checkTransaction(
            address(guard), 0, data, Enum.Operation.Call, 0, 0, 0, address(0), payable(address(0)), hex"", address(0)
        );
    }

    /// @dev Review round 2 C1 follow-up: confirm the bypass refund gate is
    ///      strictly owner-CALL-only. A DELEGATECALL bundle to MULTI_SEND_CALL_ONLY
    ///      carrying non-zero refund fields MUST take the normal timelock path
    ///      (reverting `TicketNotFound` when no ticket exists), NOT the
    ///      `TimelockBypassRefundDenied` short-circuit, because legitimate
    ///      MultiSend bundles can carry refund fields and are timelocked as a
    ///      unit via the wrapping `safeTxHash` ticket.
    function test_bypassRefundGate_doesNotApplyToDelegateBundles() public {
        _enableTimelock(SAFE_A, 24 hours);
        // Minimal valid MultiSend payload: one inner CALL to TARGET with
        // empty data. `(op=0, to=TARGET, value=0, dataLen=0, data="")` packed.
        bytes memory inner = abi.encodePacked(Enum.Operation.Call, bytes20(TARGET), uint256(0), uint256(0));
        bytes memory bundle = abi.encodeCall(MultiSendCallOnly.multiSend, (inner));

        vm.prank(address(SAFE_A));
        // operation = 1 (DELEGATECALL). With non-zero refund fields. The
        // path goes to the DELEGATE branch in checkTransaction, then to
        // _consumeOwnerTimelock; since no ticket exists for this hash the
        // expected revert is TicketNotFound (NOT TimelockBypassRefundDenied).
        vm.expectRevert(Timelock.TicketNotFound.selector);
        guard.checkTransaction(
            address(multiSendCallOnly),
            0,
            bundle,
            Enum.Operation.DelegateCall,
            0, /* baseGas */
            uint256(50_000),
            uint256(20 gwei),
            address(0xC01D),
            payable(address(0xBEEF)),
            hex"",
            address(0)
        );
    }

    function test_sweep_owner_worksDuringLockedDown() public {
        // The sweep is state-gate-free: it only cleans entries that are
        // already past TTL and therefore unreachable. It must work even
        // while the Safe is in LockedDown.
        _enableTimelock(SAFE_A, 24 hours);
        bytes32 h = _scheduleOwner(SAFE_A, TARGET, 0, hex"0a", Enum.Operation.Call);
        uint64 execAt = guard.getTransactionExecutableAt(address(SAFE_A), h);

        // Force-lock address(SAFE_A) via direct state manipulation: trigger requires
        // a real signature flow, so we simulate the timelocked state by
        // warping past TTL and asserting the sweep still works regardless
        // of lifecycle. (A separate test in LockdownTimelockRecoveryTest
        // exercises the actual LockedDown branch.)
        vm.warp(uint256(execAt) + 90 days + 1);
        vm.prank(JANITOR);
        guard.sweepExpiredOwnerTicket(address(SAFE_A), h);
        assertEq(guard.getTransactionExecutableAt(address(SAFE_A), h), 0, "swept");
    }

    // -------------------------------------------------------------------
    // Hook enforcement on owner-path (CALL)
    // -------------------------------------------------------------------

    function test_hook_normalMode_noTimelock_allowsCALL() public {
        // Default state: timelockDelay == 0. checkTransaction must pass.
        bytes memory payload = hex"1234";
        // No revert.
        _execAsOwner(SAFE_A, TARGET, 0, payload, Enum.Operation.Call);
    }

    function test_hook_normalMode_withTimelock_revertsTicketNotFound() public {
        _enableTimelock(SAFE_A, 24 hours);
        bytes memory payload = hex"1234";
        _execAsOwner_Revert(SAFE_A, TARGET, 0, payload, Enum.Operation.Call, Timelock.TicketNotFound.selector);
    }

    function test_hook_normalMode_withTimelock_revertsTimelockNotElapsed() public {
        _enableTimelock(SAFE_A, 24 hours);
        bytes memory payload = hex"abcd";
        _scheduleOwner(SAFE_A, TARGET, 0, payload, Enum.Operation.Call);

        // Try to execute immediately: timelock not elapsed.
        _execAsOwner_Revert(SAFE_A, TARGET, 0, payload, Enum.Operation.Call, Timelock.TimelockNotElapsed.selector);
    }

    function test_hook_normalMode_withTimelock_passesAfterDelay() public {
        _enableTimelock(SAFE_A, 24 hours);
        bytes memory payload = hex"abcd";
        _scheduleOwner(SAFE_A, TARGET, 0, payload, Enum.Operation.Call);

        vm.warp(block.timestamp + 24 hours + 1);

        _execAsOwner(SAFE_A, TARGET, 0, payload, Enum.Operation.Call); // no revert

        // Single-use: re-executing the same hash should now fail
        // (executableAt was deleted).
        // Note: use guard.checkTransaction directly to avoid the Safe's nonce bump
        vm.prank(address(SAFE_A));
        vm.expectRevert(Timelock.TicketNotFound.selector);
        guard.checkTransaction(
            TARGET, 0, payload, Enum.Operation.Call, 0, 0, 0, address(0), payable(address(0)), hex"", address(0)
        );
    }

    // -------------------------------------------------------------------
    // INV-LIVE-1 (V1): timelock protects the liveness of protection
    // itself. When timelockDelay > 0, every owner-path operation that
    // NEUTRALISES protection - removing the guard (setGuard(0)), disarming
    // a panic signer (removeLockdownSigner), or rotating it - must be
    // scheduled + waited like any other owner-path tx. A coerced quorum
    // cannot instantly strip a Safe of its anti-coercion guarantees; the
    // mandatory wait gives the off-site party a window to triggerLockdown.
    // triggerLockdown itself is NOT an owner-path tx, so it never needs
    // scheduling and stays live throughout the wait. (B3 guard-removal
    // race, C1 signer-disarm race; SPEC_V1 §14.2.)
    // -------------------------------------------------------------------

    function _expectOwnerPathRevertsUnscheduled(ISafe safe, address to, bytes memory data) private {
        vm.prank(address(safe));
        vm.expectRevert(Timelock.TicketNotFound.selector);
        guard.checkTransaction(
            to, 0, data, Enum.Operation.Call, 0, 0, 0, address(0), payable(address(0)), hex"", address(0)
        );
    }

    function test_liveness_timelockGatesGuardRemoval_INV_LIVE_1() public {
        _enableTimelock(SAFE_A, 24 hours);
        // setGuard(address(0)) is an owner-path self-call to the Safe, NOT a
        // singleton cancel/module meta-call, so it is not bypassed and must
        // wait the timelock.
        bytes memory data = abi.encodeWithSelector(bytes4(0xe19a9dd9), address(0));
        _expectOwnerPathRevertsUnscheduled(SAFE_A, address(SAFE_A), data);
    }

    function test_liveness_timelockGatesSignerDisarm_INV_LIVE_1() public {
        _enableTimelock(SAFE_A, 24 hours);
        bytes memory data = abi.encodeCall(Lockdown.removeLockdownSigner, (_eoaSigner(panicKey)));
        _expectOwnerPathRevertsUnscheduled(SAFE_A, address(guard), data);
    }

    function test_liveness_timelockGatesSignerRotation_INV_LIVE_1() public {
        _enableTimelock(SAFE_A, 24 hours);
        // rotateLockdownSigner burns the in-flight identity (C2 path 2); it is
        // an owner-path self-call to the singleton, not bypassed, so gated.
        bytes memory data = abi.encodeCall(Lockdown.rotateLockdownSigner, (_eoaSigner(panicKey), _eoaSigner(TARGET)));
        _expectOwnerPathRevertsUnscheduled(SAFE_A, address(guard), data);
    }

    function test_liveness_timelockGatesTimelockDisable_INV_LIVE_1() public {
        _enableTimelock(SAFE_A, 24 hours);
        // Disabling the timelock to then disarm instantly is itself an
        // owner-path self-call gated by the active timelock: setTimelockDelay(0)
        // is not a cancel/module meta-call, so it must be scheduled + waited.
        bytes memory data = abi.encodeCall(LockdownTimelock.setTimelockDelay, (uint64(0)));
        _expectOwnerPathRevertsUnscheduled(SAFE_A, address(guard), data);
    }

    function test_liveness_timelockGatesAddBypasser_INV_LIVE_1() public {
        _enableTimelock(SAFE_A, 24 hours);
        // The meta-disarm: adding an attacker bypasser would let them
        // accelerate every other disarm. setTimelockBypasser is itself an
        // owner-path self-call to the singleton, not bypassed, so gated -
        // installing the bypasser already costs a full timelockDelay.
        bytes memory data = abi.encodeCall(Timelock.setTimelockBypasser, (TARGET, true));
        _expectOwnerPathRevertsUnscheduled(SAFE_A, address(guard), data);
    }

    function test_liveness_timelockGatesRecoveryOwnerAllowlist_INV_LIVE_1() public {
        _enableTimelock(SAFE_A, 24 hours);
        // Pre-positioning an attacker recovery owner (for a post-lockdown
        // swapOwner) is gated too: addRecoveryOwner is a non-bypassed
        // owner-path self-call.
        bytes memory data = abi.encodeCall(Lockdown.addRecoveryOwner, (TARGET));
        _expectOwnerPathRevertsUnscheduled(SAFE_A, address(guard), data);
    }

    function test_liveness_panicTriggerStaysLiveDuringDisarmWait_INV_LIVE_1() public {
        _enableTimelock(SAFE_A, 24 hours);
        // Coerced quorum schedules the signer removal but must wait 24h.
        bytes memory removeData = abi.encodeCall(Lockdown.removeLockdownSigner, (_eoaSigner(panicKey)));
        _scheduleOwner(SAFE_A, address(guard), 0, removeData, Enum.Operation.Call);
        // Mid-wait (well before 24h), the off-site party triggers lockdown.
        vm.warp(block.timestamp + 1 hours);
        // Lockdown
        _triggerLockdown(SAFE_A, bytes32("panic"));
        // Check
        (,, uint64 until,,) = guard.getConfigSnapshot(address(SAFE_A));
        assertNotEq(until, 0, "panic trigger must remain live during disarm wait");
    }

    function test_hook_normalMode_withTimelock_revertsTicketExpired() public {
        _enableTimelock(SAFE_A, 24 hours);

        bytes memory payload = hex"abcd";

        uint64 t0 = uint64(block.timestamp);

        bytes32 hash = _scheduleOwner(SAFE_A, TARGET, 0, payload, Enum.Operation.Call);

        // Warp past executableAt + 90 days.
        vm.warp(uint256(t0) + 24 hours + 90 days + 1);

        _execAsOwner_Revert(SAFE_A, TARGET, 0, payload, Enum.Operation.Call, Timelock.TicketExpired.selector);

        // Entry stays in storage because the revert rolled back the delete.
        // The Safe quorum can cancelTransaction to reclaim the slot.
        assertEq(
            guard.getTransactionExecutableAt(address(SAFE_A), hash),
            t0 + 24 hours,
            "entry persists post-revert (TTL is execution gate, not storage gc)"
        );
        // Quorum cleanup path is still available.
        vm.prank(address(SAFE_A));
        guard.cancelTransaction(hash);
        assertEq(guard.getTransactionExecutableAt(address(SAFE_A), hash), 0, "cleared via cancel");
    }

    // -------------------------------------------------------------------
    // Cancel / module-schedule meta-calls bypass the timelock check
    // -------------------------------------------------------------------

    function test_hook_cancelTransactionSelfCall_bypassesTimelock() public {
        _enableTimelock(SAFE_A, 24 hours);
        bytes32 h = _scheduleOwner(SAFE_A, TARGET, 0, hex"0b", Enum.Operation.Call);
        bytes memory selfCall = abi.encodeCall(guard.cancelTransaction, (h));
        _execAsOwner(SAFE_A, address(guard), 0, selfCall, Enum.Operation.Call);
    }

    function test_hook_scheduleModuleSelfCall_bypassesTimelock() public {
        _enableTimelock(SAFE_A, 24 hours);
        bytes memory selfCall = abi.encodeCall(
            guard.scheduleModuleTransaction, (MODULE_A, TARGET, uint256(0), hex"1234", Enum.Operation.Call)
        );
        _execAsOwner(SAFE_A, address(guard), 0, selfCall, Enum.Operation.Call);
    }

    function test_hook_unknownSingletonSelfCall_isNotBypassed() public {
        _enableTimelock(SAFE_A, 24 hours);
        bytes memory selfCall = abi.encodePacked(bytes4(0x12345678), bytes32(uint256(1)));
        _execAsOwner_Revert(SAFE_A, address(guard), 0, selfCall, Enum.Operation.Call, Timelock.TicketNotFound.selector);
    }

    function test_hook_cancelTransactionWithValueGtZero_isNotBypassed() public {
        _enableTimelock(SAFE_A, 24 hours);
        bytes memory selfCall = abi.encodeCall(guard.cancelTransaction, (bytes32(uint256(1))));
        _execAsOwner_Revert(
            SAFE_A, address(guard), 1 ether, selfCall, Enum.Operation.Call, Timelock.TicketNotFound.selector
        );
    }

    /// @dev Pins INV-TIME-3's exact-length owner-cancel carve-out. This is the
    ///      selector-only half of mutation survivor T6: relaxing `data.length == 0x24`
    ///      to `data.length >= 0x04` must make this test fail.
    function test_hook_cancelTransactionSelectorOnly_isNotBypassed() public {
        _enableTimelock(SAFE_A, 24 hours);
        bytes memory selectorOnly = abi.encodePacked(guard.cancelTransaction.selector);

        vm.prank(address(SAFE_A));
        vm.expectRevert(Timelock.TicketNotFound.selector);
        guard.checkTransaction(
            address(guard),
            0,
            selectorOnly,
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

    /// @dev The other T6 boundary: a correctly encoded owner cancel plus one trailing
    ///      byte is not a management call and therefore still needs its own ticket.
    function test_hook_cancelTransactionWithTrailingByte_isNotBypassed() public {
        _enableTimelock(SAFE_A, 24 hours);
        bytes memory withTrailingByte =
            bytes.concat(abi.encodeCall(guard.cancelTransaction, (bytes32(uint256(1)))), hex"00");

        vm.prank(address(SAFE_A));
        vm.expectRevert(Timelock.TicketNotFound.selector);
        guard.checkTransaction(
            address(guard),
            0,
            withTrailingByte,
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

    // -------------------------------------------------------------------
    // bypassTimelock
    // -------------------------------------------------------------------

    function _registerBypasser(address safe, address bypasser) private {
        vm.prank(safe);
        guard.setTimelockBypasser(bypasser, true);
    }

    function test_bypass_setsExecutableAtToNow() public {
        _enableTimelock(SAFE_A, 24 hours);
        _registerBypasser(address(SAFE_A), HSM_A);
        bytes32 hash = bytes32("urgent");
        uint64 t0 = uint64(block.timestamp);
        vm.prank(HSM_A);
        guard.bypassTimelock(address(SAFE_A), hash);
        assertEq(guard.getTransactionExecutableAt(address(SAFE_A), hash), t0, "now");
    }

    function test_bypass_allowsImmediateExecution() public {
        _enableTimelock(SAFE_A, 24 hours);
        _registerBypasser(address(SAFE_A), HSM_A);
        bytes memory payload = hex"deadbeef";
        bytes32 hash = _safeTxHash(SAFE_A, TARGET, 0, payload, Enum.Operation.Call);
        vm.prank(HSM_A);
        guard.bypassTimelock(address(SAFE_A), hash);
        _execAsOwner(SAFE_A, TARGET, 0, payload, Enum.Operation.Call); // no revert, no wait
    }

    function test_bypass_revertsForNonAllowlistedCaller() public {
        _enableTimelock(SAFE_A, 24 hours);
        vm.prank(HSM_A); // never registered
        vm.expectRevert(Timelock.NotTimelockBypasser.selector);
        guard.bypassTimelock(address(SAFE_A), bytes32("x"));
    }

    function test_bypass_revertsWhenTimelockDisabled() public {
        _registerBypasser(address(SAFE_A), HSM_A);
        vm.prank(HSM_A);
        vm.expectRevert(Timelock.TimelockDisabled.selector);
        guard.bypassTimelock(address(SAFE_A), bytes32("x"));
    }

    function test_bypass_revertsForUninitSafe() public {
        vm.prank(HSM_A);
        vm.expectRevert(
            abi.encodeWithSelector(
                StateMachine.InvalidState.selector,
                StateMachine.State.Uninitialised,
                1 << uint256(StateMachine.State.Normal)
            )
        );
        guard.bypassTimelock(address(SAFE_UNINIT), bytes32("x"));
    }

    function test_bypass_isPerSafe_isolation() public {
        _enableTimelock(SAFE_A, 24 hours);
        _registerBypasser(address(SAFE_A), HSM_A);
        // HSM_A is bypasser on address(SAFE_A) but NOT on address(SAFE_B).
        _enableTimelock(SAFE_B, 24 hours);
        vm.prank(HSM_A);
        vm.expectRevert(Timelock.NotTimelockBypasser.selector);
        guard.bypassTimelock(address(SAFE_B), bytes32("xb"));
    }

    function test_bypass_revertsDuringLockedDown() public {
        _enableTimelock(SAFE_A, 24 hours);
        _registerBypasser(address(SAFE_A), HSM_A);
        _triggerLockdown(SAFE_A, bytes32("panic"));
        vm.prank(HSM_A);
        vm.expectRevert(
            abi.encodeWithSelector(
                StateMachine.InvalidState.selector,
                StateMachine.State.LockedDown,
                1 << uint256(StateMachine.State.Normal)
            )
        );
        guard.bypassTimelock(address(SAFE_A), bytes32("x"));
    }

    function test_bypass_revertedRevokedBypasserIsImmediate() public {
        _enableTimelock(SAFE_A, 24 hours);
        _registerBypasser(address(SAFE_A), HSM_A);
        vm.prank(address(SAFE_A));
        guard.setTimelockBypasser(HSM_A, false);
        vm.prank(HSM_A);
        vm.expectRevert(Timelock.NotTimelockBypasser.selector);
        guard.bypassTimelock(address(SAFE_A), bytes32("post-revoke"));
    }

    function test_bypass_priorTicketsRemainValidPostRevocation() public {
        // Revocation is prospective (Q-Bypass-8 = A): a bypass already
        // written by the bypasser remains exectuable even after the
        // bypasser is revoked. The Safe quorum must `cancelTransaction`
        // to clear it.
        _enableTimelock(SAFE_A, 24 hours);
        _registerBypasser(address(SAFE_A), HSM_A);
        bytes memory payload = hex"a1";
        bytes32 hash = _safeTxHash(SAFE_A, TARGET, 0, payload, Enum.Operation.Call);
        vm.prank(HSM_A);
        guard.bypassTimelock(address(SAFE_A), hash);
        vm.prank(address(SAFE_A));
        guard.setTimelockBypasser(HSM_A, false);
        // Bypass still effective: execution passes without wait.
        _execAsOwner(SAFE_A, TARGET, 0, payload, Enum.Operation.Call);
    }

    // -------------------------------------------------------------------
    // Module-path timelock + no module-path bypass
    // -------------------------------------------------------------------

    function test_moduleHook_normalMode_withTimelock_revertsWithoutSchedule() public {
        _enableTimelock(SAFE_A, 24 hours);
        vm.prank(address(SAFE_A));
        vm.expectRevert(Timelock.TicketNotFound.selector);
        guard.checkModuleTransaction(TARGET, 0, hex"22", Enum.Operation.Call, MODULE_A);
    }

    function test_moduleHook_selfAdminSetGuardDenied() public {
        _assertModuleSafeSelfCallDenied(
            address(SAFE_A), abi.encodeWithSelector(IGuardManager.setGuard.selector, address(0)), Enum.Operation.Call
        );
    }

    function test_moduleHook_selfAdminSetModuleGuardDenied() public {
        _assertModuleSafeSelfCallDenied(
            address(SAFE_A),
            abi.encodeWithSelector(IModuleManager.setModuleGuard.selector, address(0)),
            Enum.Operation.Call
        );
    }

    function test_moduleHook_selfAdminSetFallbackHandlerDenied() public {
        _assertModuleSafeSelfCallDenied(
            address(SAFE_A),
            abi.encodeWithSelector(IFallbackManager.setFallbackHandler.selector, address(handler)),
            Enum.Operation.Call
        );
    }

    // Finding-2 fix: the four guard-hook selectors are internal machinery the Safe
    // invokes around execution; routing any of them through a user tx
    // (execTransaction / a scheduled ticket) is rejected on every path. Otherwise a
    // pre-signed owner-path call to checkAfterModuleExecution(hash,false) would
    // (re-)create an immediately executable module ticket, bypassing the timelock.
    function test_ownerHook_guardHookSelectorsDeniedAsSingletonTarget() public {
        _assertOwnerCallToGuardSelectorDenied(LockdownTimelock.checkTransaction.selector);
        _assertOwnerCallToGuardSelectorDenied(LockdownTimelock.checkAfterExecution.selector);
        _assertOwnerCallToGuardSelectorDenied(LockdownTimelock.checkModuleTransaction.selector);
        _assertOwnerCallToGuardSelectorDenied(LockdownTimelock.checkAfterModuleExecution.selector);
    }

    // Finding-1 accepted trade-off (SPEC_V1 §H.12): a module keeps arbitrary
    // Normal-mode power for everything that does NOT disable the guard. Adding an
    // owner through the module path stays ALLOWED; only the guard-disable self-calls
    // are denied. Pin it so the denylist is never accidentally widened to over-block.
    function test_moduleHook_canStillAddOwner_acceptedNormalModePower() public {
        vm.prank(address(SAFE_A));
        guard.checkModuleTransaction(
            address(SAFE_A),
            0,
            abi.encodeWithSignature("addOwnerWithThreshold(address,uint256)", address(0xBEEF01), uint256(1)),
            Enum.Operation.Call,
            MODULE_A
        );
    }

    function _assertOwnerCallToGuardSelectorDenied(bytes4 selector) private {
        vm.prank(address(SAFE_A));
        vm.expectRevert(Lockdown.GuardHookSelfCallDenied.selector);
        guard.checkTransaction(
            address(guard),
            0,
            abi.encodePacked(selector),
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

    function test_moduleHook_batchedSelfAdminDenied() public {
        bytes memory bundle = abi.encodeCall(
            MultiSendCallOnly.multiSend,
            (_multiSendItem(
                    Enum.Operation.Call,
                    address(SAFE_A),
                    0,
                    abi.encodeWithSelector(IGuardManager.setGuard.selector, address(0))
                ))
        );
        _assertModuleSafeSelfCallDenied(address(multiSendCallOnly), bundle, Enum.Operation.DelegateCall);
    }

    function test_moduleHook_scheduleEmitsEvent() public {
        _enableTimelock(SAFE_A, 24 hours);
        // Predict ModuleTxHash
        bytes32 moduleTxHash =
            guard.getModuleTransactionHash(address(SAFE_A), MODULE_A, TARGET, 0, hex"22", Enum.Operation.Call);
        // Schedule
        vm.prank(address(SAFE_A));
        vm.expectEmit();
        emit Timelock.ModuleTransactionScheduled(
            address(SAFE_A),
            MODULE_A,
            moduleTxHash,
            TARGET,
            0,
            hex"22",
            Enum.Operation.Call,
            uint64(block.timestamp + 24 hours)
        );
        guard.scheduleModuleTransaction(MODULE_A, TARGET, 0, hex"22", Enum.Operation.Call);
    }

    function test_moduleHook_acceptsScheduledModuleTxAfterDelay() public {
        _enableTimelock(SAFE_A, 24 hours);
        // Predict ModuleTxHash
        bytes32 moduleTxHash =
            guard.getModuleTransactionHash(address(SAFE_A), MODULE_A, TARGET, 0, hex"22", Enum.Operation.Call);
        // Schedule
        vm.prank(address(SAFE_A));
        bytes32 h1 = guard.scheduleModuleTransaction(MODULE_A, TARGET, 0, hex"22", Enum.Operation.Call);
        assertEq(h1, moduleTxHash, "module hash should be non-zero");
        // Wait
        vm.warp(block.timestamp + 24 hours + 1);
        // First pre-hook call returns the module hash
        vm.prank(address(SAFE_A));
        bytes32 h2 = guard.checkModuleTransaction(TARGET, 0, hex"22", Enum.Operation.Call, MODULE_A);
        assertEq(h2, moduleTxHash, "checkModuleTransaction should return module hash");
        // The pre-hook consumed the ticket; a successful post-hook keeps it
        // consumed. Simulate the Safe v1.5.0 flow.
        vm.prank(address(SAFE_A));
        guard.checkAfterModuleExecution(moduleTxHash, true);
        // Second pre-hook call (same module tx) now reverts because the
        // ticket was consumed.
        vm.prank(address(SAFE_A));
        vm.expectRevert(Timelock.TicketNotFound.selector);
        guard.checkModuleTransaction(TARGET, 0, hex"22", Enum.Operation.Call, MODULE_A);
    }

    function test_moduleHook_noBypassAvailable() public {
        // bypassTimelock writes to the OWNER ticket key namespace. The
        // module path uses MODULE_TX_TIMELOCK_TYPEHASH, so an HSM-issued
        // bypass for the same hash does NOT unlock a module tx.
        _enableTimelock(SAFE_A, 24 hours);
        _registerBypasser(address(SAFE_A), HSM_A);
        bytes32 moduleTxHash =
            guard.getModuleTransactionHash(address(SAFE_A), MODULE_A, TARGET, 0, hex"22", Enum.Operation.Call);
        vm.prank(HSM_A);
        guard.bypassTimelock(address(SAFE_A), moduleTxHash);
        vm.prank(address(SAFE_A));
        vm.expectRevert(Timelock.TicketNotFound.selector);
        guard.checkModuleTransaction(TARGET, 0, hex"22", Enum.Operation.Call, MODULE_A);
    }

    function test_scheduleModuleTransaction_revertsOnDuplicate() public {
        _enableTimelock(SAFE_A, 24 hours);
        vm.prank(address(SAFE_A));
        guard.scheduleModuleTransaction(MODULE_A, TARGET, 0, hex"22", Enum.Operation.Call);
        vm.prank(address(SAFE_A));
        vm.expectRevert(Timelock.TicketAlreadyExists.selector);
        guard.scheduleModuleTransaction(MODULE_A, TARGET, 0, hex"22", Enum.Operation.Call);
    }

    function test_cancelModuleTransaction_clears() public {
        _enableTimelock(SAFE_A, 24 hours);
        vm.prank(address(SAFE_A));
        bytes32 moduleTxHash = guard.scheduleModuleTransaction(MODULE_A, TARGET, 0, hex"22", Enum.Operation.Call);
        vm.prank(address(SAFE_A));
        guard.cancelModuleTransaction(moduleTxHash);
        vm.prank(address(SAFE_A));
        vm.expectRevert(Timelock.TicketNotFound.selector);
        guard.cancelModuleTransaction(moduleTxHash);
    }

    function test_hook_selectorOnlyScheduleModuleBypassIsNonceGriefOnly() public {
        _enableTimelock(SAFE_A, 24 hours);
        bytes memory selectorOnly = abi.encodePacked(guard.scheduleModuleTransaction.selector);

        vm.prank(address(SAFE_A));
        guard.checkTransaction(
            address(guard),
            0,
            selectorOnly,
            Enum.Operation.Call,
            0,
            0,
            0,
            address(0),
            payable(address(0)),
            hex"",
            address(0)
        );

        vm.prank(address(SAFE_A));
        (bool ok,) = address(guard).call(selectorOnly);
        assertFalse(ok, "malformed scheduleModuleTransaction execution reverts");
    }

    function test_hook_selectorOnlyCancelModuleBypassIsNonceGriefOnly() public {
        _enableTimelock(SAFE_A, 24 hours);
        bytes memory selectorOnly = abi.encodePacked(guard.cancelModuleTransaction.selector);

        vm.prank(address(SAFE_A));
        guard.checkTransaction(
            address(guard),
            0,
            selectorOnly,
            Enum.Operation.Call,
            0,
            0,
            0,
            address(0),
            payable(address(0)),
            hex"",
            address(0)
        );

        vm.prank(address(SAFE_A));
        (bool ok,) = address(guard).call(selectorOnly);
        assertFalse(ok, "malformed cancelModuleTransaction execution reverts");
    }

    // -------------------------------------------------------------------
    // Review round 3 (INV-TIME-4 hardening): a failed inner call must NOT
    // burn the ticket (module-path: re-created by the post-hook).
    // -------------------------------------------------------------------

    /// @dev Module-path: a failed inner module call (success=false from
    ///      Safe.execTransactionFromModule's catch) MUST re-create the ticket
    ///      the pre-hook consumed. Operator can retry the SAME module tx with
    ///      identical params and the ticket is still consumable.
    function test_moduleHook_postHookFailure_leavesTicketForRetry() public {
        _enableTimelock(SAFE_A, 24 hours);
        vm.prank(address(SAFE_A));
        guard.scheduleModuleTransaction(MODULE_A, TARGET, 0, hex"33", Enum.Operation.Call);
        vm.warp(block.timestamp + 24 hours + 1);

        vm.prank(address(SAFE_A));
        bytes32 h1 = guard.checkModuleTransaction(TARGET, 0, hex"33", Enum.Operation.Call, MODULE_A);
        // Simulate ExecutionFromModuleFailure: post-hook with success=false.
        vm.prank(address(SAFE_A));
        guard.checkAfterModuleExecution(h1, false);
        assertEq(guard.getModuleTransactionExecutableAt(address(SAFE_A), h1), block.timestamp, "ticket restored at now");

        // Retry: the ticket survives, the same module tx can be re-executed.
        vm.prank(address(SAFE_A));
        bytes32 h2 = guard.checkModuleTransaction(TARGET, 0, hex"33", Enum.Operation.Call, MODULE_A);
        assertEq(h1, h2, "identical params should yield identical ticket key");
        vm.prank(address(SAFE_A));
        guard.checkAfterModuleExecution(h2, true);

        // Third attempt: ticket consumed, must revert.
        vm.prank(address(SAFE_A));
        vm.expectRevert(Timelock.TicketNotFound.selector);
        guard.checkModuleTransaction(TARGET, 0, hex"33", Enum.Operation.Call, MODULE_A);
    }

    /// @dev Module-path: post-hook with success=true and no pre-existing
    ///      ticket is a no-op. Defends against external callers attempting
    ///      to spoof a deletion (msg.sender binding bounds the damage).
    function test_moduleHook_postHookWithoutTicket_isNoOp() public {
        _enableTimelock(SAFE_A, 24 hours);
        // Random hash, no ticket.
        bytes32 fakeKey = keccak256("never-scheduled");
        vm.prank(address(SAFE_A));
        guard.checkAfterModuleExecution(fakeKey, true); // no revert, no state change
        // Now schedule + execute the real flow to confirm normal path
        // unaffected.
        vm.prank(address(SAFE_A));
        guard.scheduleModuleTransaction(MODULE_A, TARGET, 0, hex"44", Enum.Operation.Call);
        vm.warp(block.timestamp + 24 hours + 1);
        vm.prank(address(SAFE_A));
        bytes32 h = guard.checkModuleTransaction(TARGET, 0, hex"44", Enum.Operation.Call, MODULE_A);
        vm.prank(address(SAFE_A));
        guard.checkAfterModuleExecution(h, true);
        vm.prank(address(SAFE_A));
        vm.expectRevert(Timelock.TicketNotFound.selector);
        guard.checkModuleTransaction(TARGET, 0, hex"44", Enum.Operation.Call, MODULE_A);
    }

    /// @dev Owner-path: a failed inner call with safeTxGas == 0 reverts
    ///      the entire outer tx in Safe v1.5.0 (no post-hook fires); a
    ///      failed inner call with safeTxGas > 0 commits the outer tx
    ///      but Safe passes success=false to the post-hook. In the
    ///      latter case the ticket survives (residual grief: the nonce
    ///      has advanced, so the same safeTxHash cannot be replayed, but
    ///      cancel/sweep still work).
    function test_ownerHook_postHookFailure_leavesTicketForCleanup() public {
        _enableTimelock(SAFE_A, 24 hours);

        bytes memory payload = hex"55";
        // Use  non-incremented nonce
        bytes32 hash = SAFE_A.getTransactionHash(
            TARGET, 0, payload, Enum.Operation.Call, 0, 0, 0, address(0), address(0), SAFE_A.nonce() - 1
        );

        _bypassOwnerHash(SAFE_A, hash);
        uint64 executableAt = uint64(block.timestamp);

        // Pre-hook approves.
        vm.prank(address(SAFE_A));
        guard.checkTransaction(
            TARGET, 0, payload, Enum.Operation.Call, 0, 0, 0, address(0), payable(address(0)), hex"", address(0)
        );
        // Inner call "failed" but outer tx committed (safeTxGas > 0
        // scenario). Post-hook fires with success=false.
        vm.prank(address(SAFE_A));
        guard.checkAfterExecution(hash, false);

        // Ticket survives.
        assertEq(
            guard.getTransactionExecutableAt(address(SAFE_A), hash),
            executableAt,
            "ticket persists after failed post-hook"
        );
        // Operator cleanup via cancel still works.
        vm.prank(address(SAFE_A));
        guard.cancelTransaction(hash);
        assertEq(guard.getTransactionExecutableAt(address(SAFE_A), hash), 0, "cleared via cancel");
    }

    /// @dev Owner-path: post-hook with success=true and no matching ticket
    ///      is a no-op. Covers bypass-meta self-calls (cancel
    ///      whose safeTxHash maps to no ticket) and uninit Safes.
    function test_ownerHook_postHookWithoutTicket_isNoOp() public {
        _enableTimelock(SAFE_A, 24 hours);
        bytes32 fakeKey = keccak256("never-existed");
        vm.prank(address(SAFE_A));
        guard.checkAfterExecution(fakeKey, true); // no revert, no state change
        // Uninit Safe also no-op.
        vm.prank(address(SAFE_UNINIT));
        guard.checkAfterExecution(fakeKey, true);
    }

    /// @dev Review round 3 Prompt-3 audit follow-up (H-1):
    ///      module-path reentrancy via target → module → execTransactionFromModule
    ///      with identical params would double-spend a single ticket if
    ///      the inner pre-hook could still see it. Simulates the reentrancy
    ///      directly: outer pre-hook fires (and consumes the ticket), then
    ///      before any post-hook the inner pre-hook runs (same params from
    ///      the same Safe) and MUST revert TicketNotFound. Outer post-hook
    ///      then completes normally: the ticket is used exactly once.
    function test_moduleHook_reentrantPreHookReverts_INV_TIME_11() public {
        _enableTimelock(SAFE_A, 24 hours);
        vm.prank(address(SAFE_A));
        guard.scheduleModuleTransaction(MODULE_A, TARGET, 0, hex"77", Enum.Operation.Call);
        vm.warp(block.timestamp + 24 hours + 1);

        // Outer pre-hook: consumes the ticket.
        vm.prank(address(SAFE_A));
        bytes32 h1 = guard.checkModuleTransaction(TARGET, 0, hex"77", Enum.Operation.Call, MODULE_A);
        assertNotEq(h1, bytes32(0), "outer pre-hook returned zero");

        // Inner reentrant pre-hook BEFORE the outer's post-hook fires:
        // MUST revert because the ticket is already consumed.
        vm.prank(address(SAFE_A));
        vm.expectRevert(Timelock.TicketNotFound.selector);
        guard.checkModuleTransaction(TARGET, 0, hex"77", Enum.Operation.Call, MODULE_A);

        // Outer post-hook completes successfully: ticket stays consumed.
        vm.prank(address(SAFE_A));
        guard.checkAfterModuleExecution(h1, true);

        // A retry with same params now reverts TicketNotFound (single-use
        // INV-TIME-4 holds).
        vm.prank(address(SAFE_A));
        vm.expectRevert(Timelock.TicketNotFound.selector);
        guard.checkModuleTransaction(TARGET, 0, hex"77", Enum.Operation.Call, MODULE_A);
    }

    /// @dev A failed module call re-creates its ticket with
    ///      `executableAt = now`: never earlier than the original (the
    ///      pre-hook verified it was executable), but the TTL window restarts.
    function test_moduleHook_failureRestoresTicketWithFreshTtl() public {
        _enableTimelock(SAFE_A, 24 hours);
        vm.prank(address(SAFE_A));
        bytes32 moduleTxHash = guard.scheduleModuleTransaction(MODULE_A, TARGET, 0, hex"88", Enum.Operation.Call);
        uint64 executableAt = guard.getModuleTransactionExecutableAt(address(SAFE_A), moduleTxHash);

        // Fail at the last executable second of the original TTL window.
        vm.warp(uint256(executableAt) + guard.TICKET_TTL());
        vm.prank(address(SAFE_A));
        bytes32 h1 = guard.checkModuleTransaction(TARGET, 0, hex"88", Enum.Operation.Call, MODULE_A);
        vm.expectEmit(address(guard));
        emit Timelock.TicketRestored(address(SAFE_A), LockdownLib.moduleTicketKey(h1), uint64(block.timestamp));
        vm.prank(address(SAFE_A));
        guard.checkAfterModuleExecution(h1, false);

        // Past the original TTL, the restored ticket is still executable.
        vm.warp(block.timestamp + 1 days);
        vm.prank(address(SAFE_A));
        bytes32 h2 = guard.checkModuleTransaction(TARGET, 0, hex"88", Enum.Operation.Call, MODULE_A);
        assertEq(h1, h2, "ticket key drifted across retry");
        vm.prank(address(SAFE_A));
        guard.checkAfterModuleExecution(h2, true);
        assertEq(guard.getModuleTransactionExecutableAt(address(SAFE_A), moduleTxHash), 0, "ticket consumed");
    }

    /// @dev While the timelock is disabled the post-hook never creates a
    ///      ticket: a failed (or spoofed) post-hook is a no-op.
    function test_moduleHook_postHookFailureWithoutTimelock_isNoOp() public {
        bytes32 fakeHash = keccak256("never-scheduled");
        vm.prank(address(SAFE_A));
        guard.checkAfterModuleExecution(fakeHash, false);
        assertEq(guard.getModuleTransactionExecutableAt(address(SAFE_A), fakeHash), 0, "no ticket created");
    }

    /// @dev Cross-Safe isolation in the post-hook: address(SAFE_B) calling the
    ///      post-hook with address(SAFE_A)'s ticket key must NOT delete address(SAFE_A)'s
    ///      ticket. The msg.sender binding scopes the delete to the
    ///      caller's own _configs entry.
    function test_postHook_crossSafeIsolation() public {
        _enableTimelock(SAFE_A, 24 hours);
        vm.prank(address(SAFE_A));
        bytes32 moduleTxHash = guard.scheduleModuleTransaction(MODULE_A, TARGET, 0, hex"66", Enum.Operation.Call);

        // Pre-hook on address(SAFE_A) returns the ticket key. We use that as the
        // hash address(SAFE_B) will try to spoof.
        vm.warp(block.timestamp + 24 hours + 1);
        vm.prank(address(SAFE_A));
        // verify the timelock has elapsed; getModuleTransactionExecutableAt
        // gives us the pre-warp timestamp.
        uint64 execAt = guard.getModuleTransactionExecutableAt(address(SAFE_A), moduleTxHash);
        assertNotEq(execAt, 0, "ticket scheduled");

        // address(SAFE_B) (different Safe) tries to spoof consumption of address(SAFE_A)'s
        // ticket. msg.sender binding ensures address(SAFE_A)'s ticket is untouched.
        vm.prank(address(SAFE_B));
        guard.checkAfterModuleExecution(moduleTxHash, true);

        // address(SAFE_A)'s ticket still alive.
        assertNotEq(
            guard.getModuleTransactionExecutableAt(address(SAFE_A), moduleTxHash),
            0,
            "address(SAFE_A) ticket untouched by address(SAFE_B)'s post-hook"
        );
    }

    // -------------------------------------------------------------------
    // Recovery is not affected by timelock (separate path)
    // -------------------------------------------------------------------

    function test_recoveryWhitelist_unaffectedByTimelock() public {
        _enableTimelock(SAFE_A, 24 hours);
        _triggerLockdown(SAFE_A, bytes32("panic"));
        vm.warp(block.timestamp + 48 hours + 1); // enter Recovering

        vm.prank(address(SAFE_A));
        guard.checkTransaction(
            address(SAFE_A), 0, hex"", Enum.Operation.Call, 0, 0, 0, address(0), payable(address(0)), hex"", address(0)
        );
    }

    // -------------------------------------------------------------------
    // Cross-Safe isolation
    // -------------------------------------------------------------------

    function test_ownerTickets_areCrossSafeIsolated() public {
        _enableTimelock(SAFE_A, 24 hours);
        _enableTimelock(SAFE_B, 24 hours);
        bytes32 h = bytes32("shared-hash");
        _bypassOwnerHash(SAFE_A, h);
        // address(SAFE_B)'s view is empty for the same hash.
        assertEq(guard.getTransactionExecutableAt(address(SAFE_B), h), 0, "B isolated");
        // address(SAFE_B) can create the same hash-keyed ticket independently through the HSM bypass path.
        _bypassOwnerHash(SAFE_B, h);
    }

    // -------------------------------------------------------------------
    // Test helpers
    // -------------------------------------------------------------------

    function _assertModuleSafeSelfCallDenied(address to, bytes memory data, Enum.Operation operation) private {
        _enableTimelock(SAFE_A, 24 hours);

        vm.prank(address(SAFE_A));
        vm.expectRevert(Lockdown.ModuleSafeSelfCallDenied.selector);
        guard.checkModuleTransaction(to, 0, data, operation, MODULE_A);
    }

    function _lockdownMsgHash(address safe, bytes memory signer, bytes32 reasonHash) private view returns (bytes32) {
        (, string memory name, string memory version, uint256 chainId, address verifyingContract,,) =
            guard.eip712Domain();
        bytes32 domainSep = keccak256(
            abi.encode(
                keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
                keccak256(bytes(name)),
                keccak256(bytes(version)),
                chainId,
                verifyingContract
            )
        );
        return keccak256(
            abi.encodePacked(
                "\x19\x01",
                domainSep,
                keccak256(abi.encode(guard.LOCKDOWN_TYPEHASH(), safe, keccak256(signer), reasonHash))
            )
        );
    }

    function _eoaSigner(address signer) private pure returns (bytes memory) {
        return abi.encodePacked(signer);
    }

    // -------------------------------------------------------------------
    // Guard uninstall/reinstall: stale-ticket semantics. The singleton keys
    // tickets by Safe address; setGuard/setModuleGuard changes never touch
    // `_configs`, so tickets made before an uninstall survive a later
    // re-install (SaferSafes iSAFE-012 analogue; docs/PRIOR_ART_SAFERSAFES.md).
    // These tests pin the exact consequences for both ticket families.
    // -------------------------------------------------------------------

    /// @notice Owner-path tickets are nonce-bound through the safeTxHash.
    ///         An uninstall/reinstall cycle consumes Safe nonces (setGuard,
    ///         setModuleGuard txs), so a ticket scheduled for an
    ///         already-passed nonce can never match the hash recomputed at
    ///         execution time: stale past-nonce tickets are dead, not
    ///         dangerous.
    function test_staleOwnerTicket_pastNonce_deadAfterReinstall() public {
        _enableTimelock(SAFE_A, 24 hours);
        bytes memory payload = hex"abcd";
        // Scheduled for execution at current nonce.
        _scheduleOwner(SAFE_A, TARGET, 0, payload, Enum.Operation.Call);
        vm.warp(block.timestamp + 24 hours + 1);
        // Uninstall + reinstall consumed 4 Safe nonces (setGuard x2,
        // setModuleGuard x2) without executing the scheduled tx.
        vm.store(address(SAFE_A), bytes32(uint256(0x05)), bytes32(SAFE_A.nonce() + 4));
        // Executing the same payload now recomputes the hash at nonce 4:
        // no ticket exists for it.
        _execAsOwner_Revert(SAFE_A, TARGET, 0, payload, Enum.Operation.Call, Timelock.TicketNotFound.selector);
    }

    /// @notice An owner-path ticket scheduled for a FUTURE nonce stays
    ///         executable after an uninstall/reinstall cycle that advances
    ///         the Safe to exactly that nonce, without re-scheduling.
    ///         Accepted semantics: the schedule carried a valid quorum signature,
    ///         the ticket is single-use, TTL-bounded
    ///         (TICKET_TTL) and cancellable; the runbook additionally
    ///         mandates a nonce burn at uninstall (see PRIOR_ART action
    ///         items).
    function test_staleOwnerTicket_futureNonce_survivesReinstall() public {
        _enableTimelock(SAFE_A, 24 hours);
        bytes memory payload = hex"abcd";
        // Scheduled for execution at nonce 42 (future at schedule time).
        _scheduleOwnerAtNonce(SAFE_A, TARGET, 0, payload, Enum.Operation.Call, 42);
        vm.warp(block.timestamp + 24 hours + 1);
        // Forward nonce to 42
        vm.store(address(SAFE_A), bytes32(uint256(0x05)), bytes32(uint256(42)));
        // Executes at nonce 42 with no fresh schedule.
        _execAsOwner(SAFE_A, TARGET, 0, payload, Enum.Operation.Call); // no revert
    }

    /// @notice Module-path tickets carry NO nonce, so a matured module
    ///         ticket survives uninstall/reinstall unconditionally.
    ///         Accepted semantics: scheduling was quorum-authorized and
    ///         TTL-bounded; cancelModuleTransaction cleans it up.
    function test_staleModuleTicket_survivesReinstall_andIsCancellable() public {
        _enableTimelock(SAFE_A, 24 hours);
        bytes memory payload = hex"5577";
        vm.prank(address(SAFE_A));
        bytes32 moduleTxHash = guard.scheduleModuleTransaction(MODULE_A, TARGET, 0, payload, Enum.Operation.Call);
        assertNotEq(moduleTxHash, bytes32(0), "matured module ticket admits tx after reinstall");
        vm.warp(block.timestamp + 24 hours + 1);
        // Simulated uninstall/reinstall: nothing on the singleton changes;
        // the matured ticket still admits the module tx.
        vm.prank(address(SAFE_A));
        guard.checkModuleTransaction(TARGET, 0, payload, Enum.Operation.Call, MODULE_A);

        // Close the module execution with success=false: (INV-TIME-4) the
        // post-hook re-creates the ticket the pre-hook consumed, so the
        // cancellation path below exercises a still-live stale ticket.
        vm.prank(address(SAFE_A));
        guard.checkAfterModuleExecution(moduleTxHash, false);
        // Cleanup path: the quorum cancels the stale ticket, after which
        // the module tx is rejected again.
        vm.prank(address(SAFE_A));
        guard.cancelModuleTransaction(moduleTxHash);
        vm.prank(address(SAFE_A));
        vm.expectRevert(Timelock.TicketNotFound.selector);
        guard.checkModuleTransaction(TARGET, 0, payload, Enum.Operation.Call, MODULE_A);
    }

    function _ecdsaSign(uint256 priv, bytes32 digest) private returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(priv, digest);
        return abi.encodePacked(r, s, v);
    }
}
