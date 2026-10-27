// SPDX-License-Identifier: MIT
// Cross-audit mining campaign: the three APPLICABLE leads extracted from five public
// MixBytes reports and pointed at this codebase.
//
// A-1  The timelock-exempt meta-call lane consumes a Safe nonce, and every owner ticket
//      is rigidly bound to one exact nonce, so an attacker who can reach that lane can
//      strip a matured defensive queue without ever paying the delay.
// A-2  `scheduleModuleTransaction` applies no policy validation, so a ticket can be
//      written, waited out, and then refused at execution by `_checkCall`.
// A-3  AR-19 prescribes a Safe nonce burn as incident defusal. Module tickets carry no
//      nonce, so that instruction defuses nothing on the module path. The correct
//      primitive exists and is recovery-whitelisted: exact-length `disableModule`.
//
// These tests exist to settle the leads by execution rather than by reading. One of the
// three is corrected here: A-1's stated example does not work, and the reason it does
// not work is itself worth pinning.
pragma solidity ^0.8.24;

import {TestEnvironment} from "../TestEnvironment.sol";

import {Safe, Enum} from "@safe-global/safe-smart-account/Safe.sol";
import {ISafe} from "@safe-global/safe-smart-account/interfaces/ISafe.sol";
import {IModuleManager} from "@safe-global/safe-smart-account/interfaces/IModuleManager.sol";
import {ITransactionGuard} from "@safe-global/safe-smart-account/base/GuardManager.sol";

import {Lockdown} from "../../src/Lockdown.sol";
import {LockdownTimelock} from "../../src/LockdownTimelock.sol";
import {Timelock} from "../../src/base/Timelock.sol";
import {StateMachine} from "../../src/base/StateMachine.sol";

contract Sink {
    uint256 public hits;

    function work() external {
        hits++;
    }
}

contract MixBytesCrossAuditLeadsPoC is TestEnvironment {
    uint64 private constant DELAY = 24 hours;
    address private constant SENTINEL_MODULES = address(0x1);

    Safe private safe;
    Sink private sink;

    function setUp() public override {
        super.setUp();
        sink = new Sink();
        safe = _createConfigureAndInitialise(0xB17E5);
        vm.deal(address(safe), 10 ether);
        _enableTimelock(safe, DELAY);
    }

    // -------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------

    function _plain(address to, bytes memory data) private pure returns (Timelock.ExecTransactionParams memory) {
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

    function _sign(Timelock.ExecTransactionParams memory p, uint256 nonce) private view returns (bytes memory) {
        bytes32 h = safe.getTransactionHash(
            p.to, p.value, p.data, p.operation, p.safeTxGas, p.baseGas, p.gasPrice, p.gasToken, p.refundReceiver, nonce
        );
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(OWNER_PK, h);
        return abi.encodePacked(r, s, v);
    }

    function _exec(Timelock.ExecTransactionParams memory p, bytes memory sig) private returns (bool) {
        return safe.execTransaction(
            p.to, p.value, p.data, p.operation, p.safeTxGas, p.baseGas, p.gasPrice, p.gasToken, p.refundReceiver, sig
        );
    }

    function _schedule(Timelock.ExecTransactionParams memory p, uint256 nonce) private {
        guard.scheduleTransaction(address(safe), nonce, p, _sign(p, nonce));
    }

    /// @dev A defensive countermeasure the operator prepares BEFORE an incident and
    ///      pays the full timelock delay for: revoking a compromised bypasser.
    function _defensiveTx() private view returns (Timelock.ExecTransactionParams memory) {
        return _plain(address(guard), abi.encodeCall(LockdownTimelock.setTimelockBypasser, (address(0xBAD), false)));
    }

    /// @dev A junk module-schedule meta-call. It is on the timelock-exempt lane, it
    ///      always succeeds, and it therefore consumes a Safe nonce with no delay.
    function _junkMetaCall(uint256 salt) private view returns (Timelock.ExecTransactionParams memory) {
        return _plain(
            address(guard),
            abi.encodeCall(
                Timelock.scheduleModuleTransaction,
                (module, address(sink), salt, abi.encodeCall(Sink.work, ()), Enum.Operation.Call)
            )
        );
    }

    // ===================================================================
    // A-1: the meta-call lane as a free nonce burner
    // ===================================================================

    /// @dev CORRECTION to the mined lead. A-1 proposed `cancelTransaction(bytes32(0))`
    ///      as the free nonce burner. It does NOT burn a nonce. `_cancelTicket` reverts
    ///      `TicketNotFound` on a hash with no ticket, and the meta-call lane forces
    ///      `safeTxGas == 0` (INV-TIME-9), so Safe v1.5.0 bubbles the inner revert and
    ///      the whole transaction rolls back, nonce included. The refund gate added for
    ///      finding C1 is what incidentally closes this variant.
    function test_refuted_cancelTransactionOnAnUnknownHashDoesNotBurnANonce() public {
        uint256 nonceBefore = safe.nonce();
        Timelock.ExecTransactionParams memory p =
            _plain(address(guard), abi.encodeCall(Timelock.cancelTransaction, (bytes32(0))));
        bytes memory sig = _sign(p, nonceBefore);

        vm.expectRevert(Timelock.TicketNotFound.selector);
        _exec(p, sig);

        assertEq(safe.nonce(), nonceBefore, "nonce rolled back: this is NOT a free burner");
    }

    /// @dev Control that isolates the cause: the same lane with a meta-call that
    ///      SUCCEEDS does consume a nonce, immediately and with no ticket of its own.
    ///      `scheduleModuleTransaction` is the working primitive, not `cancelTransaction`.
    function test_control_schedulingMetaCallConsumesANonceWithNoDelay() public {
        uint256 nonceBefore = safe.nonce();
        Timelock.ExecTransactionParams memory p = _junkMetaCall(1);

        assertTrue(_exec(p, _sign(p, nonceBefore)), "meta-call executed immediately");
        assertEq(safe.nonce(), nonceBefore + 1, "one nonce consumed, zero delay paid");
    }

    /// @dev Positive control for the attack below: without interference the matured
    ///      defensive transaction really does execute. Without this, the attack test
    ///      could pass for an unrelated reason.
    function test_control_maturedDefensiveTicketExecutes() public {
        Timelock.ExecTransactionParams memory d = _defensiveTx();
        uint256 n = safe.nonce();
        _schedule(d, n);
        vm.warp(block.timestamp + DELAY + 1);

        assertTrue(_exec(d, _sign(d, n)), "defensive countermeasure executes after its delay");
    }

    /// @dev CONFIRMED, and this is the real A-1. An owner ticket is bound to one exact
    ///      Safe nonce: `scheduleTransaction` takes the nonce, and `_verifyOwnerTimelock`
    ///      recomputes the hash at `nonce() - 1`. One timelock-exempt meta-call moves the
    ///      Safe past that position, for free. The defenders' matured countermeasure is
    ///      then unreachable at its signed nonce, and re-signing it at the new nonce hits
    ///      `TicketNotFound`: they must schedule again and wait the FULL delay a second
    ///      time. The attacker paid no delay and can repeat this indefinitely.
    function test_confirmed_oneFreeMetaCallStripsAMaturedDefensiveTicket() public {
        Timelock.ExecTransactionParams memory d = _defensiveTx();
        uint256 n = safe.nonce();
        _schedule(d, n);
        vm.warp(block.timestamp + DELAY + 1);
        bytes memory sigAtN = _sign(d, n);

        // The attacker spends one nonce on the exempt lane. No delay, no ticket.
        Timelock.ExecTransactionParams memory junk = _junkMetaCall(1);
        assertTrue(_exec(junk, _sign(junk, n)), "attacker's meta-call executed instantly");
        assertEq(safe.nonce(), n + 1, "the queue position the ticket was bound to is gone");

        // The original signature no longer matches: Safe hashes at the new nonce.
        vm.expectRevert();
        _exec(d, sigAtN);

        // Re-signing at the new nonce reaches the guard, which finds no ticket there.
        // NOTE: signatures are computed BEFORE `expectRevert`, because `_sign` makes an
        // external `getTransactionHash` call that would otherwise consume the expectation.
        bytes memory sigAtNext = _sign(d, n + 1);
        vm.expectRevert(Timelock.TicketNotFound.selector);
        _exec(d, sigAtNext);

        // The countermeasure is not merely delayed, it is back to zero: a fresh
        // schedule plus a fresh full delay.
        _schedule(d, safe.nonce());
        bytes memory sigAfterReschedule = _sign(d, safe.nonce());
        vm.expectRevert(Timelock.TimelockNotElapsed.selector);
        _exec(d, sigAfterReschedule);
    }

    /// @dev The same primitive scales: three free meta-calls strip three defensive
    ///      tickets queued at consecutive nonces. This is the scenario the mined lead
    ///      describes, with the working primitive substituted for the one that reverts.
    function test_confirmed_threeFreeMetaCallsStripAThreeDeepDefensiveQueue() public {
        uint256 n = safe.nonce();
        Timelock.ExecTransactionParams memory d0 = _defensiveTx();
        Timelock.ExecTransactionParams memory d1 =
            _plain(address(guard), abi.encodeCall(LockdownTimelock.setLockdownDuration, (48 hours)));
        Timelock.ExecTransactionParams memory d2 =
            _plain(address(guard), abi.encodeCall(Lockdown.addRecoveryOwner, (address(0xFEED))));

        _schedule(d0, n);
        _schedule(d1, n + 1);
        _schedule(d2, n + 2);
        vm.warp(block.timestamp + DELAY + 1);

        for (uint256 i = 0; i < 3; ++i) {
            Timelock.ExecTransactionParams memory junk = _junkMetaCall(i + 100);
            assertTrue(_exec(junk, _sign(junk, safe.nonce())), "free meta-call");
        }
        assertEq(safe.nonce(), n + 3, "three nonces burnt with zero delay paid");

        // Every prepared countermeasure is now unreachable at its signed position.
        bytes memory sigNow = _sign(d0, safe.nonce());
        vm.expectRevert(Timelock.TicketNotFound.selector);
        _exec(d0, sigNow);
    }

    // ===================================================================
    // A-2: a ticket can be scheduled for a call the guard always refuses
    // ===================================================================

    /// @dev CONFIRMED: `scheduleModuleTransaction` performs no policy validation, so a
    ///      ticket is written for a call `_checkCall` refuses unconditionally under
    ///      `Privilege.Module`. The delay is paid in full before the failure surfaces,
    ///      and the slot stays occupied afterwards.
    function test_confirmed_moduleTicketSchedulableForACallTheGuardAlwaysRefuses() public {
        bytes memory data = abi.encodeCall(Lockdown.addLockdownSigner, (abi.encodePacked(other)));

        vm.prank(address(safe));
        guard.scheduleModuleTransaction(module, address(guard), 0, data, Enum.Operation.Call);
        assertGt(
            guard.getModuleTransactionExecutableAt(
                address(safe),
                guard.getModuleTransactionHash(address(safe), module, address(guard), 0, data, Enum.Operation.Call)
            ),
            0,
            "ticket written for a call that can never execute"
        );

        vm.warp(block.timestamp + DELAY + 1);

        // The full delay bought nothing: the guard refuses on policy, not on timing.
        _moduleCall_Revert(
            module, safe, address(guard), 0, data, Enum.Operation.Call, Lockdown.ModuleCallToSingletonDenied.selector
        );
    }

    /// @dev The dead ticket keeps its slot: re-scheduling the same parameters is refused
    ///      until an explicit `cancelModuleTransaction` or the 90-day TTL.
    function test_confirmed_theDeadModuleTicketBlocksItsOwnSlot() public {
        bytes memory data = abi.encodeCall(Lockdown.addLockdownSigner, (abi.encodePacked(other)));

        vm.startPrank(address(safe));
        guard.scheduleModuleTransaction(module, address(guard), 0, data, Enum.Operation.Call);
        vm.expectRevert(Timelock.TicketAlreadyExists.selector);
        guard.scheduleModuleTransaction(module, address(guard), 0, data, Enum.Operation.Call);
        vm.stopPrank();
    }

    /// @dev Same class on the DelegateCall arm: schedulable, never executable.
    function test_confirmed_moduleTicketSchedulableForANonCanonicalDelegateCall() public {
        bytes memory data = abi.encodeCall(Sink.work, ());

        vm.prank(address(safe));
        guard.scheduleModuleTransaction(module, address(sink), 0, data, Enum.Operation.DelegateCall);
        vm.warp(block.timestamp + DELAY + 1);

        _moduleCall_Revert(
            module, safe, address(sink), 0, data, Enum.Operation.DelegateCall, Lockdown.DelegateCallDenied.selector
        );
    }

    /// @dev Control: a policy-legal module ticket does execute after its delay, so the
    ///      refusals above are attributable to policy and not to the scheduling path.
    function test_control_policyLegalModuleTicketExecutesAfterItsDelay() public {
        bytes memory data = abi.encodeCall(Sink.work, ());

        vm.prank(address(safe));
        guard.scheduleModuleTransaction(module, address(sink), 0, data, Enum.Operation.Call);
        vm.warp(block.timestamp + DELAY + 1);

        _moduleCall(module, safe, address(sink), 0, data, Enum.Operation.Call);
        assertEq(sink.hits(), 1, "legal module ticket executed");
    }

    // ===================================================================
    // A-3: the incident defusal that AR-19 does not name
    // ===================================================================

    /// @dev CONFIRMED: a Safe nonce burn, which AR-19 prescribes as incident defusal,
    ///      does NOT defuse a pending module ticket. The module ticket key is
    ///      `moduleTxHash(safe, module, to, value, dataHash, operation)` and contains no
    ///      nonce, so burning nonces during Recovering changes nothing. At the exact
    ///      auto-resume second the module path reopens and the ticket fires.
    function test_confirmed_nonceBurnDoesNotDefuseAPendingModuleTicket() public {
        bytes memory data = abi.encodeCall(Sink.work, ());
        vm.prank(address(safe));
        guard.scheduleModuleTransaction(module, address(sink), 0, data, Enum.Operation.Call);
        vm.warp(block.timestamp + DELAY + 1);

        _triggerLockdown(safe, keccak256("mixbytes-a3"));
        (, uint64 remaining) = guard.getState(address(safe));
        vm.warp(block.timestamp + remaining); // enter Recovering

        // The runbook instruction, applied literally, inside the recovery window.
        // The burn must target the Safe itself: see the address(0) trap pinned below.
        _execAsOwner(safe, address(safe), 0, "", Enum.Operation.Call);
        _execAsOwner(safe, address(safe), 0, "", Enum.Operation.Call);

        // Auto-resume.
        vm.warp(block.timestamp + guard.getResumeDelay(address(safe)) + 1);
        (StateMachine.State state,) = guard.getState(address(safe));
        assertEq(uint256(state), uint256(StateMachine.State.Normal), "auto-resumed");

        _moduleCall(module, safe, address(sink), 0, data, Enum.Operation.Call);
        assertEq(sink.hits(), 1, "the module ticket survived the nonce burns and fired");
    }

    /// @dev CONFIRMED, and this is the test the mined lead says is missing. The correct
    ///      module-path defusal DOES exist and IS recovery-whitelisted: exact-length
    ///      `disableModule`. A disabled module cannot call `execTransactionFromModule`,
    ///      so the ticket becomes unreachable before the guard is ever consulted.
    ///      AR-19 must name this, because an operator applying the owner-path
    ///      instruction during a four-hour recovery window will reach for the wrong one.
    function test_confirmed_disableModuleDefusesPendingModuleTicket() public {
        bytes memory data = abi.encodeCall(Sink.work, ());
        vm.prank(address(safe));
        guard.scheduleModuleTransaction(module, address(sink), 0, data, Enum.Operation.Call);
        vm.warp(block.timestamp + DELAY + 1);

        _triggerLockdown(safe, keccak256("mixbytes-a3-fix"));
        (, uint64 remaining) = guard.getState(address(safe));
        vm.warp(block.timestamp + remaining); // enter Recovering

        // The correct countermeasure, accepted by the recovery whitelist.
        _execAsOwner(
            safe,
            address(safe),
            0,
            abi.encodeCall(IModuleManager.disableModule, (SENTINEL_MODULES, module)),
            Enum.Operation.Call
        );
        assertFalse(safe.isModuleEnabled(module), "module disabled inside the recovery window");

        vm.warp(block.timestamp + guard.getResumeDelay(address(safe)) + 1);

        // The ticket still exists, but it is now unreachable: the caller is no longer a
        // module, so the Safe rejects it before the guard runs.
        vm.prank(module);
        vm.expectRevert();
        safe.execTransactionFromModule(address(sink), 0, data, Enum.Operation.Call);
        assertEq(sink.hits(), 0, "defused");
    }

    /// @dev OPERATOR TRAP, found while writing the test above and worth its own pin.
    ///      The recovery whitelist accepts an empty self-call only when `to == safe`.
    ///      A nonce burn addressed to `address(0)` is REFUSED with `RecoveryActive`,
    ///      even though Safe v1.5.0 aliases `address(0)` to the Safe itself at execution
    ///      and the same transaction is perfectly valid in Normal mode. The guard reads
    ///      the literal top-level `to`; the alias rewrite applies only to inner MultiSend
    ///      leaves. `TestEnvironment._burnNonce` uses `address(0)`, so the repository's
    ///      own helper does not work inside a recovery window. Any runbook that says
    ///      "burn a nonce" during an incident must say `to == safe`.
    function test_limitation_recoveryNonceBurnMustTargetTheSafeNotAddressZero() public {
        _triggerLockdown(safe, keccak256("mixbytes-nonce-burn-trap"));
        (, uint64 remaining) = guard.getState(address(safe));
        vm.warp(block.timestamp + remaining); // Recovering

        // The form the repository's own helper uses: refused.
        _execAsOwner_Revert(safe, address(0), 0, "", Enum.Operation.Call, Lockdown.RecoveryActive.selector);

        // The form the runbook must specify: accepted.
        uint256 n = safe.nonce();
        _execAsOwner(safe, address(safe), 0, "", Enum.Operation.Call);
        assertEq(safe.nonce(), n + 1, "nonce burnt only when the call targets the Safe itself");
    }

    /// @dev Bounds the fix: `cancelModuleTransaction` is NOT on the recovery whitelist,
    ///      so the obvious countermeasure is unavailable exactly when it is wanted. This
    ///      is why `disableModule` is the one that must be documented.
    function test_limitation_cancelModuleTransactionIsUnreachableDuringRecovering() public {
        bytes memory data = abi.encodeCall(Sink.work, ());
        vm.prank(address(safe));
        guard.scheduleModuleTransaction(module, address(sink), 0, data, Enum.Operation.Call);
        bytes32 h = guard.getModuleTransactionHash(address(safe), module, address(sink), 0, data, Enum.Operation.Call);

        _triggerLockdown(safe, keccak256("mixbytes-a3-bound"));
        (, uint64 remaining) = guard.getState(address(safe));
        vm.warp(block.timestamp + remaining);

        _execAsOwner_Revert(
            safe,
            address(guard),
            0,
            abi.encodeCall(Timelock.cancelModuleTransaction, (h)),
            Enum.Operation.Call,
            Lockdown.RecoveryActive.selector
        );
    }
}
