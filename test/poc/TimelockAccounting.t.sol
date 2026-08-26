// SPDX-License-Identifier: MIT
// Timelock ticket accounting + time/state boundary proofs (V1 audit prep).
// Scope: who can create / consume / cancel / sweep / resurrect a ticket, and
// every `block.timestamp` boundary in `src/base/Timelock.sol` and
// `src/base/StateMachine.sol`.
pragma solidity ^0.8.24;

import {TestEnvironment} from "../TestEnvironment.sol";

import {Safe, Enum} from "@safe-global/safe-smart-account/Safe.sol";

import {Lockdown} from "../../src/Lockdown.sol";
import {LockdownTimelock} from "../../src/LockdownTimelock.sol";
import {StateMachine} from "../../src/base/StateMachine.sol";
import {Timelock} from "../../src/base/Timelock.sol";

contract AccountingTarget {
    uint256 public calls;

    function mark() external {
        ++calls;
    }

    function boom() external pure {
        revert("boom");
    }
}

contract TimelockAccountingPoC is TestEnvironment {
    uint64 private constant DELAY = 24 hours;
    address private constant BYPASSER = address(0xB4551);
    address private constant RELAYER = address(0xE1A7);

    Safe private pocSafe; // timelock enabled
    Safe private stateSafe; // no timelock, used for pure state-machine boundaries
    AccountingTarget private target;

    function setUp() public override {
        super.setUp();
        target = new AccountingTarget();

        pocSafe = _createConfigureAndInitialise(101);
        // Register the bypasser BEFORE arming the timelock: the 0 -> N
        // activation is the only free setter call.
        _execAsOwner(
            pocSafe,
            address(guard),
            0,
            abi.encodeCall(LockdownTimelock.setTimelockBypasser, (BYPASSER, true)),
            Enum.Operation.Call
        );
        _enableTimelock(pocSafe, DELAY);

        stateSafe = _createConfigureAndInitialise(102);
    }

    // ------------------------------------------------------------------
    // Lead 1 - bypassTimelock has no TicketAlreadyExists guard
    // ------------------------------------------------------------------

    /// @notice A bypasser resurrects a ticket that is already PAST its TTL and
    ///         therefore unexecutable. `bypassTimelock` writes
    ///         `executableAt = now` unconditionally (Timelock.sol:297), with no
    ///         `TicketAlreadyExists` guard and no TTL check, so "the ticket dies
    ///         at TTL on its own" (T-BYPASS-6) is NOT true while the bypasser is
    ///         still allowlisted.
    function test_confirmed_bypasserRearmsTicketPastTtl() public {
        (bytes memory data, bytes memory sigs, bytes32 txHash) = _scheduleMark();
        uint64 executableAt = guard.getTransactionExecutableAt(address(pocSafe), txHash);

        // Past TTL: the hook refuses the ticket outright.
        vm.warp(uint256(executableAt) + guard.TICKET_TTL() + 1);
        _execAsOwner_Revert(pocSafe, address(target), 0, data, Enum.Operation.Call, Timelock.TicketExpired.selector);

        // A single bypass call brings the dead ticket back to life.
        vm.prank(BYPASSER);
        guard.bypassTimelock(address(pocSafe), txHash);
        assertEq(
            guard.getTransactionExecutableAt(address(pocSafe), txHash),
            uint64(vm.getBlockTimestamp()),
            "TTL-dead ticket re-armed to now"
        );

        assertTrue(_exec(data, sigs), "resurrected ticket executes");
        assertEq(target.calls(), 1, "target reached through a TTL-expired ticket");
    }

    /// @notice The same unconditional write lets a bypasser refresh a ticket
    ///         forever: three consecutive TTL windows are survived without any
    ///         quorum action, so a pre-signed transaction stays armed
    ///         indefinitely instead of decaying after 90 days.
    function test_confirmed_bypasserRefreshesTicketIndefinitely() public {
        (bytes memory data, bytes memory sigs, bytes32 txHash) = _scheduleMark();
        // Track time explicitly: the optimiser may CSE `block.timestamp` across
        // `vm.warp` inside a single call frame.
        uint256 start = vm.getBlockTimestamp();
        uint256 t = start;

        for (uint256 i = 0; i < 3; ++i) {
            t += uint256(guard.TICKET_TTL()) + 1 days;
            vm.warp(t);
            vm.prank(BYPASSER);
            guard.bypassTimelock(address(pocSafe), txHash);
            assertEq(guard.getTransactionExecutableAt(address(pocSafe), txHash), uint64(t), "ticket refreshed to now");
        }

        assertGt(t - start, 3 * uint256(guard.TICKET_TTL()), "outlived three TTL windows");
        assertTrue(_exec(data, sigs), "indefinitely refreshed ticket executes");
    }

    /// @notice A bypasser can move a not-yet-elapsed ticket's `executableAt`
    ///         strictly BACKWARD, to the current second. This is the intended
    ///         bypass primitive; the test pins the magnitude (the whole
    ///         remaining delay is erased in one call, no floor).
    function test_confirmed_bypassMovesExecutableAtBackward() public {
        (bytes memory data, bytes memory sigs, bytes32 txHash) = _scheduleMark();
        uint64 scheduledAt = guard.getTransactionExecutableAt(address(pocSafe), txHash);

        vm.warp(vm.getBlockTimestamp() + 1 hours);
        _execAsOwner_Revert(
            pocSafe, address(target), 0, data, Enum.Operation.Call, Timelock.TimelockNotElapsed.selector
        );

        vm.prank(BYPASSER);
        guard.bypassTimelock(address(pocSafe), txHash);
        uint64 movedTo = guard.getTransactionExecutableAt(address(pocSafe), txHash);
        assertLt(movedTo, scheduledAt, "executableAt moved backward");
        assertEq(movedTo, uint64(vm.getBlockTimestamp()), "moved exactly to now");
        assertTrue(_exec(data, sigs), "executes 23h early");
    }

    /// @notice A bypasser needs no prior ticket at all: `bypassTimelock` creates
    ///         the slot from nothing, with no signature check of its own
    ///         (`scheduleTransaction` at Timelock.sol:225 does `checkSignatures`,
    ///         `bypassTimelock` does not). Only the Safe quorum at execution time
    ///         bounds this, which is the documented off-chain trust model.
    function test_confirmed_bypassCreatesTicketWithoutAnySchedule() public {
        uint256 nonce = pocSafe.nonce();
        bytes memory data = abi.encodeCall(AccountingTarget.mark, ());
        bytes32 txHash = _safeTxHash(pocSafe, address(target), 0, data, Enum.Operation.Call, nonce);
        assertEq(guard.getTransactionExecutableAt(address(pocSafe), txHash), 0, "no ticket yet");

        vm.prank(BYPASSER);
        guard.bypassTimelock(address(pocSafe), txHash);
        assertEq(
            guard.getTransactionExecutableAt(address(pocSafe), txHash),
            uint64(vm.getBlockTimestamp()),
            "created ex nihilo"
        );

        bytes memory sigs = _signTxAtNonce(pocSafe, OWNER_PK, address(target), 0, data, Enum.Operation.Call, nonce);
        assertTrue(_exec(data, sigs), "unscheduled bypass ticket executes");
    }

    /// @notice REFUTED: the resurrection above is confined to Normal. The
    ///         `onlyNormal` override on `bypassTimelock`
    ///         (LockdownTimelock.sol) makes a bypasser powerless during the
    ///         incident itself.
    function test_refuted_bypassDuringRecoveringIsBlocked() public {
        (,, bytes32 txHash) = _scheduleMark();
        _triggerLockdown(pocSafe, keccak256("panic"));

        vm.warp(vm.getBlockTimestamp() + guard.getLockdownDuration(address(pocSafe))); // exactly lockdownUntil
        (StateMachine.State state,) = guard.getState(address(pocSafe));
        assertEq(uint256(state), uint256(StateMachine.State.Recovering), "recovering");

        vm.prank(BYPASSER);
        vm.expectRevert(
            abi.encodeWithSelector(
                StateMachine.InvalidState.selector,
                StateMachine.State.Recovering,
                uint256(1) << uint256(StateMachine.State.Normal)
            )
        );
        guard.bypassTimelock(address(pocSafe), txHash);
    }

    // ------------------------------------------------------------------
    // Lead 2 - no response window for a bypass
    // ------------------------------------------------------------------

    /// @notice The documented "TimelockBypassed should page immediately"
    ///         response (SECURITY_ASSURANCE.md) has ZERO on-chain window:
    ///         `bypassTimelock` writes `executableAt = block.timestamp` and
    ///         `_verifyTicket` accepts `block.timestamp >= executableAt`
    ///         (Timelock.sol:399), so bypass and execution land in the SAME
    ///         block at the SAME timestamp. Nothing can be cancelled in between.
    function test_confirmed_bypassAndExecuteInSameBlock() public {
        (bytes memory data, bytes memory sigs, bytes32 txHash) = _scheduleMark();
        uint256 ts = vm.getBlockTimestamp();
        uint256 bn = block.number;

        vm.prank(BYPASSER);
        guard.bypassTimelock(address(pocSafe), txHash);
        assertTrue(_exec(data, sigs), "same-block execution");

        assertEq(vm.getBlockTimestamp(), ts, "no time passed between bypass and execution");
        assertEq(block.number, bn, "same block");
        assertEq(target.calls(), 1, "drain landed");
    }

    // ------------------------------------------------------------------
    // Lead 3 - TTL boundary complementarity (mutation-flippable operators)
    // ------------------------------------------------------------------

    /// @notice At EXACTLY `executableAt + TICKET_TTL` the ticket is still
    ///         executable (`<=` at Timelock.sol:398) and NOT sweepable
    ///         (`>` at Timelock.sol:424). Pins both operators in one second.
    function test_confirmed_ttlBoundaryExactSecondIsExecutableAndUnsweepable() public {
        (bytes memory data, bytes memory sigs, bytes32 txHash) = _scheduleMark();
        uint64 executableAt = guard.getTransactionExecutableAt(address(pocSafe), txHash);

        vm.warp(uint256(executableAt) + guard.TICKET_TTL());

        vm.prank(RELAYER);
        vm.expectRevert(Timelock.TicketNotExpired.selector);
        guard.sweepExpiredOwnerTicket(address(pocSafe), txHash);

        assertTrue(_exec(data, sigs), "executable at exactly executableAt + TTL");
        assertEq(guard.getTransactionExecutableAt(address(pocSafe), txHash), 0, "consumed");
    }

    /// @notice One second later the complement holds: the hook reverts
    ///         `TicketExpired` and the permissionless sweep succeeds.
    function test_confirmed_ttlBoundaryPlusOneIsExpiredAndSweepable() public {
        (bytes memory data,, bytes32 txHash) = _scheduleMark();
        uint64 executableAt = guard.getTransactionExecutableAt(address(pocSafe), txHash);

        vm.warp(uint256(executableAt) + guard.TICKET_TTL() + 1);
        _execAsOwner_Revert(pocSafe, address(target), 0, data, Enum.Operation.Call, Timelock.TicketExpired.selector);

        vm.prank(RELAYER);
        guard.sweepExpiredOwnerTicket(address(pocSafe), txHash);
        assertEq(guard.getTransactionExecutableAt(address(pocSafe), txHash), 0, "swept");
    }

    /// @notice Lower boundary: `>=` at Timelock.sol:399 makes the ticket
    ///         executable at EXACTLY `executableAt`, and not one second before.
    function test_confirmed_executableAtExactSecondBoundary() public {
        (bytes memory data, bytes memory sigs, bytes32 txHash) = _scheduleMark();
        uint64 executableAt = guard.getTransactionExecutableAt(address(pocSafe), txHash);

        vm.warp(uint256(executableAt) - 1);
        _execAsOwner_Revert(
            pocSafe, address(target), 0, data, Enum.Operation.Call, Timelock.TimelockNotElapsed.selector
        );

        vm.warp(uint256(executableAt));
        assertTrue(_exec(data, sigs), "executable at the exact second");
    }

    // ------------------------------------------------------------------
    // Lead 4 - permissionless scheduling / far-future nonce farming
    // ------------------------------------------------------------------

    /// @notice REFUTED: ticket farming is not free. `scheduleTransaction` is
    ///         permissionless in the RELAY sense only - Timelock.sol:225
    ///         `checkSignatures` still demands a full owner quorum for the exact
    ///         (params, nonce) tuple, so a third party cannot mint tickets.
    function test_refuted_ticketFarmingWithoutQuorumSignatures() public {
        uint256 nonce = pocSafe.nonce() + 1_000_000;
        bytes memory data = abi.encodeCall(AccountingTarget.mark, ());
        bytes memory badSigs = _signTxAtNonce(pocSafe, OTHER_PK, address(target), 0, data, Enum.Operation.Call, nonce);

        vm.prank(RELAYER);
        vm.expectRevert(abi.encodeWithSignature("Error(string)", "GS026"));
        guard.scheduleTransaction(
            address(pocSafe), nonce, _params(address(target), 0, data, Enum.Operation.Call, 0), badSigs
        );
    }

    /// @notice REFUTED: an accounting residue farmed at a far-future nonce is
    ///         NOT readable as authorisation at any other nonce. The hook
    ///         recomputes the hash at `nonce() - 1`
    ///         (LockdownTimelock._verifyOwnerTimelock), so the far-nonce ticket
    ///         is invisible to the current transaction. DELIBERATE: the nonce is
    ///         part of the ticket key by construction.
    function test_refuted_farFutureNonceTicketIsNotAuthorisationNow() public {
        uint256 currentNonce = pocSafe.nonce();
        uint256 farNonce = currentNonce + 1_000_000;
        bytes memory data = abi.encodeCall(AccountingTarget.mark, ());

        bytes memory farSigs =
            _signTxAtNonce(pocSafe, OWNER_PK, address(target), 0, data, Enum.Operation.Call, farNonce);
        vm.prank(RELAYER);
        guard.scheduleTransaction(
            address(pocSafe), farNonce, _params(address(target), 0, data, Enum.Operation.Call, 0), farSigs
        );
        bytes32 farHash = _safeTxHash(pocSafe, address(target), 0, data, Enum.Operation.Call, farNonce);
        assertGt(guard.getTransactionExecutableAt(address(pocSafe), farHash), 0, "far ticket exists");

        vm.warp(vm.getBlockTimestamp() + DELAY + 1);
        // Same call, current nonce: the far ticket authorises nothing.
        _execAsOwner_Revert(pocSafe, address(target), 0, data, Enum.Operation.Call, Timelock.TicketNotFound.selector);
        assertEq(target.calls(), 0, "no execution");
    }

    // ------------------------------------------------------------------
    // Lead 5 - safeTxGas > 0 residue
    // ------------------------------------------------------------------

    /// @notice Documented limitation (Timelock.sol:381-388): with
    ///         `safeTxGas > 0` Safe v1.5.0 commits the outer transaction even
    ///         though the inner call reverted, so `checkAfterExecution(_, false)`
    ///         does NOT consume the ticket. The ticket survives as pure residue.
    ///         It is NOT double-spendable: the Safe nonce advanced, so the
    ///         surviving key can never match a future `nonce() - 1` hash. The
    ///         only cost is an orphan slot until cancel or TTL sweep.
    function test_limitation_safeTxGasFailureLeavesUnconsumableResidue() public {
        uint256 nonce = pocSafe.nonce();
        uint256 safeTxGas = 200_000;
        bytes memory data = abi.encodeCall(AccountingTarget.boom, ());
        bytes memory sigs =
            _signTxAtNonceFull(pocSafe, OWNER_PK, address(target), 0, data, Enum.Operation.Call, safeTxGas, nonce);
        bytes32 txHash = pocSafe.getTransactionHash(
            address(target), 0, data, Enum.Operation.Call, safeTxGas, 0, 0, address(0), address(0), nonce
        );

        vm.prank(RELAYER);
        guard.scheduleTransaction(
            address(pocSafe), nonce, _params(address(target), 0, data, Enum.Operation.Call, safeTxGas), sigs
        );
        vm.warp(vm.getBlockTimestamp() + DELAY);

        bool success = pocSafe.execTransaction(
            address(target), 0, data, Enum.Operation.Call, safeTxGas, 0, 0, address(0), payable(address(0)), sigs
        );
        assertFalse(success, "inner call reverted");
        assertEq(pocSafe.nonce(), nonce + 1, "outer tx committed, nonce advanced");
        assertGt(guard.getTransactionExecutableAt(address(pocSafe), txHash), 0, "ticket residue survives");

        // The residue is dead: replaying the same signatures now fails the Safe
        // signature check (the hash moved with the nonce), so no second
        // consumption of this ticket is reachable.
        vm.expectRevert(abi.encodeWithSignature("Error(string)", "GS026"));
        pocSafe.execTransaction(
            address(target), 0, data, Enum.Operation.Call, safeTxGas, 0, 0, address(0), payable(address(0)), sigs
        );

        // Only cleanup reclaims it.
        vm.warp(vm.getBlockTimestamp() + guard.TICKET_TTL() + 1);
        vm.prank(RELAYER);
        guard.sweepExpiredOwnerTicket(address(pocSafe), txHash);
        assertEq(guard.getTransactionExecutableAt(address(pocSafe), txHash), 0, "residue reclaimed");
    }

    // ------------------------------------------------------------------
    // Time and state boundaries
    // ------------------------------------------------------------------

    /// @notice A ticket armed BEFORE the incident keeps ticking through
    ///         LockedDown and Recovering: at the exact second of auto-resume the
    ///         pre-signed transaction is immediately executable, with no fresh
    ///         `timelockDelay` re-wait. The freeze buys no timelock time back.
    function test_confirmed_preIncidentTicketFiresAtTheAutoResumeSecond() public {
        (bytes memory data, bytes memory sigs, bytes32 txHash) = _scheduleMark();
        uint64 executableAt = guard.getTransactionExecutableAt(address(pocSafe), txHash);

        _triggerLockdown(pocSafe, keccak256("panic"));
        uint64 lockdownUntil = guard.getLockdownUntil(address(pocSafe));
        uint256 resumeAt = uint256(lockdownUntil) + guard.getResumeDelay(address(pocSafe));
        assertGt(resumeAt, uint256(executableAt), "the incident outlives the timelock delay");

        vm.warp(resumeAt - 1);
        (StateMachine.State s,) = guard.getState(address(pocSafe));
        assertEq(uint256(s), uint256(StateMachine.State.Recovering), "still recovering one second before");
        _execAsOwner_Revert(pocSafe, address(target), 0, data, Enum.Operation.Call, Lockdown.RecoveryActive.selector);

        vm.warp(resumeAt);
        (s,) = guard.getState(address(pocSafe));
        assertEq(uint256(s), uint256(StateMachine.State.Normal), "auto-resumed at the exact second");
        assertTrue(_exec(data, sigs), "pre-incident ticket fires immediately on resume");
        assertEq(target.calls(), 1, "no re-wait imposed by the incident");
    }

    /// @notice The quorum cannot defuse that pre-armed ticket during the
    ///         incident: `cancelTransaction` is not on the recovery whitelist
    ///         (`Lockdown._isRecoveryCall`), so the hook rejects it. The nonce
    ///         burn IS whitelisted and is the only in-incident mitigation.
    function test_confirmed_cancelIsUnreachableDuringRecovering() public {
        (,, bytes32 txHash) = _scheduleMark();
        _triggerLockdown(pocSafe, keccak256("panic"));
        vm.warp(uint256(guard.getLockdownUntil(address(pocSafe))) + 1);

        _execAsOwner_Revert(
            pocSafe,
            address(guard),
            0,
            abi.encodeCall(LockdownTimelock.cancelTransaction, (txHash)),
            Enum.Operation.Call,
            Lockdown.RecoveryActive.selector
        );
        assertGt(guard.getTransactionExecutableAt(address(pocSafe), txHash), 0, "ticket still armed");

        uint256 nonceBefore = pocSafe.nonce();
        _execAsOwner(pocSafe, address(pocSafe), 0, "", Enum.Operation.Call);
        assertEq(pocSafe.nonce(), nonceBefore + 1, "nonce burn is the only in-incident defusal");
    }

    /// @notice Pins every `==` second of the state machine: `t == lockdownUntil`
    ///         is already Recovering, `t == lockdownUntil + resumeDelay` is
    ///         already Normal, and both public normalisers flip at that same
    ///         second (StateMachine.getLockdownUntil / lastReasonHash).
    function test_confirmed_stateMachineExactSecondBoundaries() public {
        bytes32 reason = keccak256("boundary");
        _triggerLockdown(stateSafe, reason);
        uint64 lockdownUntil = guard.getLockdownUntil(address(stateSafe));
        uint64 resumeDelay = guard.getResumeDelay(address(stateSafe));

        vm.warp(uint256(lockdownUntil) - 1);
        (StateMachine.State s, uint64 remaining) = guard.getState(address(stateSafe));
        assertEq(uint256(s), uint256(StateMachine.State.LockedDown), "locked down one second before");
        assertEq(remaining, 1, "one second remaining");

        vm.warp(uint256(lockdownUntil));
        (s, remaining) = guard.getState(address(stateSafe));
        assertEq(uint256(s), uint256(StateMachine.State.Recovering), "recovering at exactly lockdownUntil");
        assertEq(remaining, 0, "no countdown reported during recovery");

        vm.warp(uint256(lockdownUntil) + resumeDelay - 1);
        (s,) = guard.getState(address(stateSafe));
        assertEq(uint256(s), uint256(StateMachine.State.Recovering), "recovering one second before resume");
        assertEq(guard.getLockdownUntil(address(stateSafe)), lockdownUntil, "raw value still exposed");
        assertEq(guard.lastReasonHash(address(stateSafe)), reason, "reason still exposed");

        vm.warp(uint256(lockdownUntil) + resumeDelay);
        (s,) = guard.getState(address(stateSafe));
        assertEq(uint256(s), uint256(StateMachine.State.Normal), "normal at exactly lockdownUntil + resumeDelay");
        assertEq(guard.getLockdownUntil(address(stateSafe)), 0, "normalised to 0 at the same second");
        assertEq(guard.lastReasonHash(address(stateSafe)), bytes32(0), "reason normalised at the same second");
    }

    /// @notice Configuration change landing exactly at the auto-resume second:
    ///         `_setResumeDelay` clears the elapsed incident before writing, so
    ///         raising the delay by the maximum cannot re-open the dead window.
    ///         One second earlier the setter is state-gated shut.
    function test_confirmed_setResumeDelayAtResumeSecondCannotReopenTheWindow() public {
        _triggerLockdown(stateSafe, keccak256("reopen"));
        uint64 lockdownUntil = guard.getLockdownUntil(address(stateSafe));
        uint256 resumeAt = uint256(lockdownUntil) + guard.getResumeDelay(address(stateSafe));

        vm.warp(resumeAt - 1);
        _execAsOwner_Revert(
            stateSafe,
            address(guard),
            0,
            abi.encodeCall(StateMachine.setResumeDelay, (7 days)),
            Enum.Operation.Call,
            Lockdown.RecoveryActive.selector
        );

        vm.warp(resumeAt);
        _execAsOwner(
            stateSafe, address(guard), 0, abi.encodeCall(StateMachine.setResumeDelay, (7 days)), Enum.Operation.Call
        );
        (StateMachine.State s,) = guard.getState(address(stateSafe));
        assertEq(uint256(s), uint256(StateMachine.State.Normal), "elapsed incident cleared, still Normal");
        assertEq(guard.getResumeDelay(address(stateSafe)), 7 days, "new delay applied");
        assertEq(guard.getLockdownUntil(address(stateSafe)), 0, "incident scalar zeroed");
    }

    // ------------------------------------------------------------------
    // Helpers
    // ------------------------------------------------------------------

    function _scheduleMark() private returns (bytes memory data, bytes memory sigs, bytes32 txHash) {
        uint256 nonce = pocSafe.nonce();
        data = abi.encodeCall(AccountingTarget.mark, ());
        sigs = _signTxAtNonce(pocSafe, OWNER_PK, address(target), 0, data, Enum.Operation.Call, nonce);
        txHash = _safeTxHash(pocSafe, address(target), 0, data, Enum.Operation.Call, nonce);
        vm.prank(RELAYER);
        guard.scheduleTransaction(
            address(pocSafe), nonce, _params(address(target), 0, data, Enum.Operation.Call, 0), sigs
        );
    }

    function _exec(bytes memory data, bytes memory sigs) private returns (bool) {
        return pocSafe.execTransaction(
            address(target), 0, data, Enum.Operation.Call, 0, 0, 0, address(0), payable(address(0)), sigs
        );
    }

    function _params(address to, uint256 value, bytes memory data, Enum.Operation operation, uint256 safeTxGas)
        private
        pure
        returns (Timelock.ExecTransactionParams memory)
    {
        return Timelock.ExecTransactionParams({
            to: to,
            value: value,
            data: data,
            operation: operation,
            safeTxGas: safeTxGas,
            baseGas: 0,
            gasPrice: 0,
            gasToken: address(0),
            refundReceiver: payable(address(0))
        });
    }

    function _signTxAtNonce(
        Safe safe,
        uint256 pk,
        address to,
        uint256 value,
        bytes memory data,
        Enum.Operation operation,
        uint256 nonce
    ) private view returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, _safeTxHash(safe, to, value, data, operation, nonce));
        return abi.encodePacked(r, s, v);
    }

    function _signTxAtNonceFull(
        Safe safe,
        uint256 pk,
        address to,
        uint256 value,
        bytes memory data,
        Enum.Operation operation,
        uint256 safeTxGas,
        uint256 nonce
    ) private view returns (bytes memory) {
        bytes32 h = safe.getTransactionHash(to, value, data, operation, safeTxGas, 0, 0, address(0), address(0), nonce);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, h);
        return abi.encodePacked(r, s, v);
    }
}
