// SPDX-License-Identifier: MIT
// Cancellation-semantics campaign. Grounds AUDIT_BRIEF.md question 14.
//
// The question of whether to make cancellation terminal - by a 0x-style per-hash sentinel
// (`SafeGuard.sol` writes `timelockEnd[txHash] = type(uint256).max`) or by a per-Safe
// generation counter folded into the ticket-key derivation - has so far rested on
// assertions about what each mechanism would achieve. This file replaces those assertions
// with executed facts about the CURRENT implementation, so the auditor question can be
// asked in terms of properties that have been demonstrated rather than assumed.
//
// TWO THREAT ACTORS, KEPT DISTINCT THROUGHOUT.
//
//   PUBLIC REPLAYER  - holds no key of any kind. Their entire capability is to resubmit
//                      calldata that is already public in a prior `scheduleTransaction`
//                      transaction. This is the attacker AR-16 is actually about, and the
//                      one a cancellation tombstone would durably stop.
//   QUORUM ATTACKER  - still controls the owner threshold and can therefore mint a fresh
//                      signature at any nonce. No guard-local revocation mechanism can
//                      stop them, because they can always re-authorise.
//
// Conflating the two makes exact-hash revocation look worthless: "the attacker can just
// re-sign at nonce n+1" is true only of the quorum attacker, and silently assumes the
// compromise is ongoing. Every finding below names which actor it concerns.
//
// Not re-derived here, already pinned elsewhere:
//   - `test/poc/TicketRevival.t.sol` proves the same public signatures reschedule after
//     BOTH cancel and sweep. That is AR-16's core and is taken as given.
//   - `test/poc/TimelockAccounting.t.sol` A8 proves a bypasser rearms a ticket past TTL
//     and refreshes it indefinitely. This file extends that to the two forms that bear on
//     a tombstone: creation with no prior schedule at all, and resurrection after an
//     explicit quorum cancellation.
pragma solidity ^0.8.24;

import {TestEnvironment} from "../TestEnvironment.sol";

import {Safe, Enum} from "@safe-global/safe-smart-account/Safe.sol";

import {Lockdown} from "../../src/Lockdown.sol";
import {LockdownTimelock} from "../../src/LockdownTimelock.sol";
import {Timelock} from "../../src/base/Timelock.sol";
import {StateMachine} from "../../src/base/StateMachine.sol";

contract CancellationTarget {
    uint256 public calls;

    function mark() external {
        ++calls;
    }
}

contract CancellationSemanticsPoC is TestEnvironment {
    uint64 private constant DELAY = 24 hours;

    /// @dev Holds no key. Can only resubmit already-public calldata.
    address private constant PUBLIC_REPLAYER = address(0x9EED1E55);
    address private constant HSM = address(0x4534);

    Safe private safe;
    CancellationTarget private target;

    function setUp() public override {
        super.setUp();

        safe = _createConfigureAndInitialise(0xCA9CE1);
        target = new CancellationTarget();

        // Register the bypasser BEFORE enabling the timelock, so its own self-call is not
        // itself timelocked. This is the documented operator ordering.
        _execAsOwner(
            safe,
            address(guard),
            0,
            abi.encodeCall(LockdownTimelock.setTimelockBypasser, (HSM, true)),
            Enum.Operation.Call
        );
        _enableTimelock(safe, DELAY);
    }

    // -------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------

    function _params(address to, bytes memory data) private pure returns (Timelock.ExecTransactionParams memory) {
        return Timelock.ExecTransactionParams({
            to: to,
            value: 0,
            data: data,
            operation: Enum.Operation.Call,
            safeTxGas: 0,
            baseGas: 0,
            gasPrice: 0,
            gasToken: address(0),
            refundReceiver: payable(address(0))
        });
    }

    function _signAt(address to, bytes memory data, uint256 nonce) private view returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(OWNER_PK, _safeTxHash(safe, to, 0, data, Enum.Operation.Call, nonce));
        return abi.encodePacked(r, s, v);
    }

    function _hashAt(address to, bytes memory data, uint256 nonce) private view returns (bytes32) {
        return _safeTxHash(safe, to, 0, data, Enum.Operation.Call, nonce);
    }

    function _exec(address to, bytes memory data, bytes memory sig) private returns (bool) {
        return safe.execTransaction(to, 0, data, Enum.Operation.Call, 0, 0, 0, address(0), payable(address(0)), sig);
    }

    /// @dev The standard subject: a `mark()` call signed and scheduled at the current nonce.
    function _scheduleMark() private returns (bytes memory data, bytes memory sig, bytes32 h, uint256 nonce) {
        nonce = safe.nonce();
        data = abi.encodeCall(CancellationTarget.mark, ());
        sig = _signAt(address(target), data, nonce);
        h = _hashAt(address(target), data, nonce);
        vm.prank(PUBLIC_REPLAYER);
        guard.scheduleTransaction(address(safe), nonce, _params(address(target), data), sig);
    }

    function _cancelAsQuorum(bytes32 h) private returns (bool) {
        bytes memory data = abi.encodeCall(Timelock.cancelTransaction, (h));
        return _exec(address(guard), data, _signAt(address(guard), data, safe.nonce()));
    }

    /// @dev Burns one Safe nonce while the timelock is active. `TestEnvironment._burnNonce`
    ///      submits a plain owner transaction, which needs a matured ticket of its own once
    ///      `timelockDelay > 0`. The AR-16 nonce-burn runbook is an emergency response, so
    ///      it is run here through the registered bypasser's inline lane
    ///      (`src/LockdownTimelock.sol:201`), which skips the delay for a bypasser
    ///      submitter. How the nonce advances is orthogonal to the finding; only that it
    ///      advances matters.
    function _burnNonceFast() private {
        uint256 nonce = safe.nonce();
        bytes memory sig = _signAt(address(0), "", nonce);
        vm.prank(HSM);
        require(
            safe.execTransaction(address(0), 0, "", Enum.Operation.Call, 0, 0, 0, address(0), payable(address(0)), sig),
            "nonce burn"
        );
    }

    // ===================================================================
    // Claim 1 - a bypasser would overwrite a tombstone
    // ===================================================================

    /// @dev CONFIRMED, and this is the strongest form of the claim. `bypassTimelock` does
    ///      not require a prior ticket at all: it writes `executableAt = now` into an
    ///      EMPTY slot, so a bypasser authorises a hash that was never scheduled by
    ///      anyone. A per-hash tombstone is therefore not merely overwritable by a
    ///      bypasser, it is irrelevant to one: the bypasser never needed the slot to be
    ///      in any particular state.
    ///      Actor: the compromised bypasser of accepted risk #8, not either attacker above.
    function test_confirmed_bypasserCreatesAnExecutableTicketWithNoPriorSchedule() public {
        uint256 nonce = safe.nonce();
        bytes memory data = abi.encodeCall(CancellationTarget.mark, ());
        bytes32 h = _hashAt(address(target), data, nonce);

        assertEq(guard.getTransactionExecutableAt(address(safe), h), 0, "nothing was ever scheduled");

        vm.prank(HSM);
        guard.bypassTimelock(address(safe), h);

        assertEq(
            guard.getTransactionExecutableAt(address(safe), h),
            uint64(block.timestamp),
            "bypasser wrote into a slot that no schedule had ever touched"
        );
        assertTrue(_exec(address(target), data, _signAt(address(target), data, nonce)), "and it executes at once");
        assertEq(target.calls(), 1, "no schedule, no delay, no prior ticket");
    }

    /// @dev CONFIRMED, the direct tombstone analogue: the quorum cancels, and the bypasser
    ///      puts the ticket straight back. Whatever value a cancellation carries today is
    ///      already erasable by the bypasser, so a tombstone would only be terminal if the
    ///      bypasser were explicitly forbidden from overwriting it.
    ///      Actor: compromised bypasser, after a legitimate quorum cancellation.
    function test_confirmed_bypasserResurrectsATicketTheQuorumJustCancelled() public {
        (bytes memory data, bytes memory sig, bytes32 h,) = _scheduleMark();

        assertTrue(_cancelAsQuorum(h), "quorum cancels");
        assertEq(guard.getTransactionExecutableAt(address(safe), h), 0, "slot cleared by cancellation");

        // The cancel consumed a nonce, so re-sign the subject at the nonce it must now use.
        uint256 nonce = safe.nonce();
        sig = _signAt(address(target), data, nonce);
        h = _hashAt(address(target), data, nonce);

        vm.prank(HSM);
        guard.bypassTimelock(address(safe), h);

        assertGt(guard.getTransactionExecutableAt(address(safe), h), 0, "bypasser rewrote the slot");
        assertTrue(_exec(address(target), data, sig), "the cancelled intent executes anyway");
        assertEq(target.calls(), 1, "cancellation was not terminal against a bypasser");
    }

    /// @dev CONFIRMED: an immature ticket is accelerated to immediately executable. This
    ///      is bypass working as designed, recorded here only to complete the three slot
    ///      states the claim asks about: empty, live, expired (A8 covers expired).
    function test_confirmed_bypasserOverwritesALiveImmatureTicketToImmediate() public {
        (bytes memory data, bytes memory sig, bytes32 h,) = _scheduleMark();

        uint64 scheduled = guard.getTransactionExecutableAt(address(safe), h);
        assertEq(scheduled, uint64(block.timestamp) + DELAY, "ticket is immature");

        vm.prank(HSM);
        guard.bypassTimelock(address(safe), h);

        assertEq(guard.getTransactionExecutableAt(address(safe), h), uint64(block.timestamp), "accelerated to now");
        assertTrue(_exec(address(target), data, sig), "executes without serving the delay");
    }

    /// @dev Control that bounds the bypasser findings above: bypass authority is
    ///      Normal-state only. It cannot be used to move anything during an incident,
    ///      which is what keeps accepted risk #8 from being an incident-time bypass.
    function test_control_bypassAuthorityDoesNotExtendIntoAnIncident() public {
        (,, bytes32 h,) = _scheduleMark();

        _triggerLockdown(safe, keccak256("incident"));
        (StateMachine.State state,) = guard.getState(address(safe));
        assertEq(uint256(state), uint256(StateMachine.State.LockedDown), "locked down");

        vm.prank(HSM);
        vm.expectRevert();
        guard.bypassTimelock(address(safe), h);
    }

    // ===================================================================
    // Claim 2 - sweep removes the TicketAlreadyExists bar
    // ===================================================================

    /// @dev CONFIRMED, and this is the part `TicketRevival.t.sol` does not say. Sweep is
    ///      permissionless, so an unrelated third party can delete an expired ticket. The
    ///      quorum then has NOTHING to cancel: `cancelTransaction` reverts `TicketNotFound`
    ///      while the underlying owner authorisation is untouched and reschedulable.
    ///      A public sweeper can therefore strip the quorum's cancellation handle without
    ///      holding any key.
    ///      Actor: public replayer, who is also the sweeper.
    function test_confirmed_permissionlessSweepStripsTheQuorumCancellationHandle() public {
        (bytes memory data, bytes memory sig, bytes32 h,) = _scheduleMark();

        uint64 executableAt = guard.getTransactionExecutableAt(address(safe), h);
        vm.warp(uint256(executableAt) + guard.TICKET_TTL() + 1);

        vm.prank(PUBLIC_REPLAYER);
        guard.sweepExpiredOwnerTicket(address(safe), h);

        // The quorum can no longer cancel: there is no ticket to cancel.
        bytes memory cancelData = abi.encodeCall(Timelock.cancelTransaction, (h));
        bytes memory cancelSig = _signAt(address(guard), cancelData, safe.nonce());
        vm.expectRevert(Timelock.TicketNotFound.selector);
        _exec(address(guard), cancelData, cancelSig);

        // But the authorisation is alive: the same public calldata reschedules it.
        vm.prank(PUBLIC_REPLAYER);
        guard.scheduleTransaction(address(safe), safe.nonce(), _params(address(target), data), sig);
        assertGt(guard.getTransactionExecutableAt(address(safe), h), 0, "authorisation survives the sweep");
    }

    /// @dev Control: while a ticket exists and has NOT expired, sweep is refused, so the
    ///      strip above requires the TTL to have elapsed. It is a slow attack, not an
    ///      instant one.
    function test_control_sweepIsRefusedBeforeTtlSoTheStripNeedsTheFullWindow() public {
        (,, bytes32 h,) = _scheduleMark();

        vm.prank(PUBLIC_REPLAYER);
        vm.expectRevert(Timelock.TicketNotExpired.selector);
        guard.sweepExpiredOwnerTicket(address(safe), h);
    }

    // ===================================================================
    // Claim 3 - a transaction outliving its cancellability
    // ===================================================================

    /// @dev CONFIRMED, and this is the real window, not the TTL one. `cancelTransaction`
    ///      is an owner-path self-call, so during LockedDown the hook rejects it and
    ///      during Recovering it is not on the recovery whitelist. For the whole incident
    ///      the quorum cannot cancel anything, while a matured pre-incident ticket stays
    ///      live and executes at the auto-resume second. This is AR-19's boundary, shown
    ///      end to end.
    ///      Actor: either. The point is the defender's loss of a control, not an attack.
    function test_confirmed_cancellationIsImpossibleForTheWholeIncidentWhileTheTicketStaysLive() public {
        (bytes memory data, bytes memory sig, bytes32 h,) = _scheduleMark();
        vm.warp(block.timestamp + DELAY + 1);

        _triggerLockdown(safe, keccak256("incident"));

        // LockedDown: the guard rejects the owner-path cancel before it reaches the singleton.
        bytes memory cancelData = abi.encodeCall(Timelock.cancelTransaction, (h));
        bytes memory cancelSig = _signAt(address(guard), cancelData, safe.nonce());
        vm.expectRevert(Lockdown.LockedDown.selector);
        _exec(address(guard), cancelData, cancelSig);

        // Recovering: cancel is deliberately not on the recovery whitelist.
        vm.warp(block.timestamp + 48 hours + 1);
        (StateMachine.State state,) = guard.getState(address(safe));
        assertEq(uint256(state), uint256(StateMachine.State.Recovering), "recovering");
        cancelSig = _signAt(address(guard), cancelData, safe.nonce());
        vm.expectRevert(Lockdown.RecoveryActive.selector);
        _exec(address(guard), cancelData, cancelSig);

        assertGt(guard.getTransactionExecutableAt(address(safe), h), 0, "ticket untouched by the whole incident");

        // Auto-resume, and the pre-incident authorisation executes with no fresh delay.
        vm.warp(block.timestamp + 4 hours + 1);
        (state,) = guard.getState(address(safe));
        assertEq(uint256(state), uint256(StateMachine.State.Normal), "auto-resumed");
        assertTrue(_exec(address(target), data, sig), "pre-incident ticket executes at resume");
        assertEq(target.calls(), 1, "the intent survived an incident the quorum could not cancel through");
    }

    /// @dev REFUTED for the TTL sense of the claim, and a deliberate divergence from 0x.
    ///      An expired ticket can no longer execute but can still be cancelled, because
    ///      `_cancelTicket` only requires a non-zero slot. 0x's `cancel` reverts
    ///      `TimelockElapsed` once the delay has passed, which Bailsec raised as Issue 05
    ///      and 0x acknowledged without fixing. We do not have that gap.
    function test_refuted_anExpiredTicketRemainsCancellable() public {
        (bytes memory data, bytes memory sig, bytes32 h,) = _scheduleMark();

        uint64 executableAt = guard.getTransactionExecutableAt(address(safe), h);
        vm.warp(uint256(executableAt) + guard.TICKET_TTL() + 1);

        // Expired: it cannot execute.
        vm.expectRevert(Timelock.TicketExpired.selector);
        _exec(address(target), data, sig);

        // But the quorum can still cancel it and reclaim the slot.
        assertTrue(_cancelAsQuorum(h), "expired ticket is still cancellable");
        assertEq(guard.getTransactionExecutableAt(address(safe), h), 0, "slot reclaimed");
    }

    /// @dev Control, the direct contrast with 0x: a matured ticket, well past its delay
    ///      and still inside TTL, is cancellable. There is no `TimelockElapsed` state in
    ///      which a known-malicious transaction becomes uncancellable.
    function test_control_aMaturedTicketIsStillCancellable() public {
        (,, bytes32 h,) = _scheduleMark();
        vm.warp(block.timestamp + DELAY + 30 days);
        assertTrue(_cancelAsQuorum(h), "no TimelockElapsed restriction on our cancel");
    }

    // ===================================================================
    // Claim 4 - what actually recreates a ticket, and what stops it
    // ===================================================================

    /// @dev CONFIRMED: the public replayer needs NOTHING but the public calldata. No key,
    ///      no owner status, no fresh signature. `scheduleTransaction` is permissionless
    ///      and the signatures were published in the original scheduling transaction.
    ///      This is the actor a tombstone would durably stop.
    function test_confirmed_publicReplayerRecreatesTheTicketFromPublicCalldataAlone() public {
        (bytes memory data,, bytes32 h,) = _scheduleMark();

        assertTrue(_cancelAsQuorum(h), "quorum cancels");
        assertEq(guard.getTransactionExecutableAt(address(safe), h), 0, "slot cleared");

        // The cancel consumed nonce `nonce`, so the subject's signed nonce is now in the
        // past and this exact hash is dead by nonce arithmetic. Re-run the scenario with
        // the subject signed at a FUTURE nonce, which is the case AR-16 is about.
        uint256 futureNonce = safe.nonce() + 5;
        bytes memory futureSig = _signAt(address(target), data, futureNonce);
        bytes32 futureHash = _hashAt(address(target), data, futureNonce);
        vm.prank(PUBLIC_REPLAYER);
        guard.scheduleTransaction(address(safe), futureNonce, _params(address(target), data), futureSig);
        assertTrue(_cancelAsQuorum(futureHash), "quorum cancels the future-nonce ticket");

        // Public replayer, holding no key, puts it straight back.
        vm.prank(PUBLIC_REPLAYER);
        guard.scheduleTransaction(address(safe), futureNonce, _params(address(target), data), futureSig);
        assertGt(
            guard.getTransactionExecutableAt(address(safe), futureHash),
            0,
            "keyless replayer revived a cancelled authorisation"
        );
    }

    /// @dev REFUTED against the public replayer, and this quantifies AR-16's `k+1` rule by
    ///      execution: once `Safe.nonce()` has advanced PAST the signed nonce,
    ///      `scheduleTransaction` rejects the same public calldata with `StaleSafeNonce`.
    ///      Nonce burn, not cancellation, is what durably kills the authorisation today.
    function test_refuted_nonceBurnPastTheSignedNonceDefeatsThePublicReplayer() public {
        uint256 start = safe.nonce();
        uint256 k = 3;
        uint256 signedNonce = start + k;

        bytes memory data = abi.encodeCall(CancellationTarget.mark, ());
        bytes memory sig = _signAt(address(target), data, signedNonce);
        bytes32 h = _hashAt(address(target), data, signedNonce);

        vm.prank(PUBLIC_REPLAYER);
        guard.scheduleTransaction(address(safe), signedNonce, _params(address(target), data), sig);
        assertTrue(_cancelAsQuorum(h), "cancelled; this consumed nonce start, so k burns remain");

        // AR-16: from `start`, killing a transaction signed at `start + k` needs the Safe
        // nonce to reach `start + k + 1`. The cancel already consumed one.
        assertEq(safe.nonce(), start + 1, "cancel consumed one nonce");
        for (uint256 i = 0; i < k; ++i) {
            _burnNonceFast();
        }
        assertEq(safe.nonce(), signedNonce + 1, "nonce advanced to signedNonce + 1, exactly k+1 from start");

        vm.prank(PUBLIC_REPLAYER);
        vm.expectRevert(Timelock.StaleSafeNonce.selector);
        guard.scheduleTransaction(address(safe), signedNonce, _params(address(target), data), sig);
    }

    /// @dev CONFIRMED, and this is why the two actors must not be conflated. After the
    ///      nonce burn above has permanently defeated the public replayer, a QUORUM
    ///      attacker simply signs the same intent at the current nonce and proceeds. No
    ///      guard-local revocation - tombstone, generation counter, or nonce burn - can
    ///      stop an actor who can still authorise. Dismissing exact-hash revocation on
    ///      "they can re-sign at n+1" therefore silently assumes ongoing compromise.
    function test_confirmed_quorumAttackerIsUnaffectedByAnyGuardLocalRevocation() public {
        uint256 signedNonce = safe.nonce() + 3;
        bytes memory data = abi.encodeCall(CancellationTarget.mark, ());
        bytes memory sig = _signAt(address(target), data, signedNonce);
        bytes32 h = _hashAt(address(target), data, signedNonce);

        vm.prank(PUBLIC_REPLAYER);
        guard.scheduleTransaction(address(safe), signedNonce, _params(address(target), data), sig);
        assertTrue(_cancelAsQuorum(h), "cancelled");
        while (safe.nonce() <= signedNonce) {
            _burnNonceFast();
        }

        // Public replayer is dead. Quorum attacker mints a fresh authorisation.
        uint256 fresh = safe.nonce();
        bytes memory freshSig = _signAt(address(target), data, fresh);
        vm.prank(PUBLIC_REPLAYER); // anyone may schedule; the SIGNATURE is what is fresh
        guard.scheduleTransaction(address(safe), fresh, _params(address(target), data), freshSig);
        vm.warp(block.timestamp + DELAY + 1);
        assertTrue(_exec(address(target), data, freshSig), "quorum attacker proceeds regardless");
        assertEq(target.calls(), 1, "revocation of a hash is not revocation of an authority");
    }

    // ===================================================================
    // Operational cost a sentinel would carry
    // ===================================================================

    /// @dev LIMITATION that the auditor question needs on the record: today
    ///      `getTransactionExecutableAt` returns 0 for "never scheduled", "cancelled",
    ///      "swept" and "consumed" alike. An off-chain indexer cannot distinguish them
    ///      from the getter and must reconstruct intent from events. A sentinel would fix
    ///      exactly this for the cancelled case, at the price of never reclaiming the slot
    ///      and of returning a magic value that every existing reader must learn.
    function test_limitation_theGetterCannotDistinguishCancelledFromNeverScheduledOrConsumed() public {
        bytes memory data = abi.encodeCall(CancellationTarget.mark, ());

        // Never scheduled.
        bytes32 unknown = _hashAt(address(target), data, safe.nonce() + 99);
        assertEq(guard.getTransactionExecutableAt(address(safe), unknown), 0, "never scheduled reads 0");

        // Cancelled.
        (,, bytes32 cancelled,) = _scheduleMark();
        assertTrue(_cancelAsQuorum(cancelled), "cancel");
        assertEq(guard.getTransactionExecutableAt(address(safe), cancelled), 0, "cancelled reads 0");

        // Consumed by a successful execution.
        uint256 nonce = safe.nonce();
        bytes memory sig = _signAt(address(target), data, nonce);
        bytes32 consumed = _hashAt(address(target), data, nonce);
        vm.prank(PUBLIC_REPLAYER);
        guard.scheduleTransaction(address(safe), nonce, _params(address(target), data), sig);
        vm.warp(block.timestamp + DELAY + 1);
        assertTrue(_exec(address(target), data, sig), "executes");
        assertEq(guard.getTransactionExecutableAt(address(safe), consumed), 0, "consumed reads 0");
    }
}
