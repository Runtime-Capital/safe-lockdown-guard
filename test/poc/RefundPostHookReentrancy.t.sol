// SPDX-License-Identifier: MIT
// Refund-window adversarial campaign. See .task/plan-01-codex.md.
//
// Safe v1.5.0 `execTransaction` (lib/safe-smart-account/contracts/Safe.sol) runs in this
// order: cache the guard (`address guard = getGuard()`), call the pre-hook, `execute(...)`,
// then `handlePayment(...)` when `gasPrice > 0`, then the CACHED guard's post-hook.
//
// `handlePayment` refunds with an UNRESTRICTED call:
//
//     address payable receiver = refundReceiver == address(0) ? payable(tx.origin) : refundReceiver;
//     (bool refundSuccess, ) = receiver.call{value: payment}("");   // native
//     if (!transferToken(gasToken, receiver, payment)) ...          // ERC-20
//
// This is the fact the whole campaign turns on. 0x's SafeGuard permits native gas
// sponsorship on the explicit ground that "the Safe uses `send`, which defuses reentrancy
// due to the 2300 gas rule". That was true of Safe 1.3.0. It is NOT true of the pinned
// Safe v1.5.0, which forwards essentially all remaining gas. Our exposure is therefore
// strictly larger than the one 0x reasoned about, and `specs/SPEC_V1.md` §7.2 never
// examines this window.
//
// These tests settle by execution whether the window grants any capability beyond what an
// owner-approved MultiSend already grants (`test_refuted_dominance*`), or whether it only
// changes atomicity and observability.
pragma solidity ^0.8.24;

import {Vm} from "forge-std/Test.sol";

import {TestEnvironment} from "../TestEnvironment.sol";

import {Safe, Enum} from "@safe-global/safe-smart-account/Safe.sol";
import {ISafe} from "@safe-global/safe-smart-account/interfaces/ISafe.sol";
import {IGuardManager} from "@safe-global/safe-smart-account/interfaces/IGuardManager.sol";
import {IModuleManager} from "@safe-global/safe-smart-account/interfaces/IModuleManager.sol";
import {MultiSendCallOnly} from "@safe-global/safe-smart-account/libraries/MultiSendCallOnly.sol";

import {Lockdown} from "../../src/Lockdown.sol";
import {LockdownTimelock} from "../../src/LockdownTimelock.sol";
import {Timelock} from "../../src/base/Timelock.sol";
import {StateMachine} from "../../src/base/StateMachine.sol";

// -----------------------------------------------------------------------------
// Callback harness
// -----------------------------------------------------------------------------

/// @dev Shared machinery for a contract that receives control inside the Safe refund
///      window. One optional STATICCALL probe (to observe state mid-window) and one
///      optional CALL attack, both recorded, never reverting unless `bubble` is set.
abstract contract CallbackBase {
    address public target;
    bytes public payload;
    bool public bubble;
    bool public armed;

    address public probeTarget;
    bytes public probeData;

    uint256 public calls;
    bool public lastSuccess;
    bytes public lastReturn;
    bool public probeOk;
    bytes public probeReturn;
    uint256 public gasSeen;

    bool public revertOnCall;

    function arm(address target_, bytes memory payload_, bool bubble_) external {
        target = target_;
        payload = payload_;
        bubble = bubble_;
        armed = true;
    }

    function probe(address target_, bytes memory data_) external {
        probeTarget = target_;
        probeData = data_;
    }

    function setRevertOnCall(bool value) external {
        revertOnCall = value;
    }

    function _fire() internal {
        calls++;
        gasSeen = gasleft();

        if (revertOnCall) revert("callback refuses");

        if (probeTarget != address(0)) {
            (bool pok, bytes memory pret) = probeTarget.staticcall(probeData);
            probeOk = pok;
            probeReturn = pret;
        }

        if (!armed) return;
        armed = false; // one shot: never recurse into ourselves

        (bool ok, bytes memory ret) = target.call(payload);
        lastSuccess = ok;
        lastReturn = ret;

        if (bubble && !ok) {
            assembly ("memory-safe") {
                revert(add(ret, 0x20), mload(ret))
            }
        }
    }

    /// @dev Selector of the reason the configured CALL failed with, or `0x00000000`.
    function lastRevertSelector() external view returns (bytes4 selector) {
        bytes memory ret = lastReturn;
        if (ret.length < 4) return bytes4(0);
        assembly ("memory-safe") {
            selector := mload(add(ret, 0x20))
        }
    }
}

/// @dev Native-refund receiver. Safe calls `receiver.call{value: payment}("")`.
contract NativeRefundCallback is CallbackBase {
    receive() external payable {
        _fire();
    }
}

/// @dev Malicious ERC-20 used as `gasToken`. Safe calls `transfer(receiver, payment)`
///      with essentially all remaining gas and only checks the return value.
contract MaliciousGasToken is CallbackBase {
    mapping(address => uint256) public balanceOf;

    function mint(address to, uint256 amount) external {
        balanceOf[to] += amount;
    }

    function transfer(address to, uint256 amount) external returns (bool) {
        require(balanceOf[msg.sender] >= amount, "balance");
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount;
        _fire();
        return true;
    }
}

/// @dev Stands in for the dominance control: an ordinary owner-approved MultiSend leaf
///      that performs the same nested action, with every refund field zero.
contract PlainCallee is CallbackBase {
    function run() external {
        _fire();
    }
}

/// @dev Target whose only job is to record that the business call landed, or to revert
///      on demand so the outer Safe call reports `success == false`.
contract BusinessTarget {
    uint256 public hits;
    bool public shouldRevert;

    function setShouldRevert(bool v) external {
        shouldRevert = v;
    }

    function work() external {
        require(!shouldRevert, "business reverts");
        hits++;
    }

    receive() external payable {}
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

contract RefundPostHookReentrancyPoC is TestEnvironment {
    uint64 private constant DELAY = 24 hours;
    uint256 private constant GAS_PRICE = 20 gwei;
    uint256 private constant BASE_GAS = 100_000;
    uint256 private constant SAFE_TX_GAS = 400_000;

    bytes32 private constant TIMELOCK_CONSUMED_TOPIC = keccak256("TimelockConsumed(address,bytes32)");
    uint256 private constant GUARD_SLOT = 0x4a204f620c8c5ccdca3fd54d003badd85ba500436a431f0cbda4f558c93c34c8;
    uint256 private constant MODULE_GUARD_SLOT = 0xb104e0b93118902c651344349b610029d694cfdec91c589c91ebafbcd0289947;

    Safe private safe;
    NativeRefundCallback private nativeCb;
    MaliciousGasToken private gasToken;
    PlainCallee private plainCallee;
    BusinessTarget private business;

    function setUp() public override {
        super.setUp();

        nativeCb = new NativeRefundCallback();
        gasToken = new MaliciousGasToken();
        plainCallee = new PlainCallee();
        business = new BusinessTarget();

        safe = _createConfigureAndInitialise(0x5AFE);
        vm.deal(address(safe), 100 ether);
        gasToken.mint(address(safe), 1_000_000 ether);

        // The native refund is capped at min(gasPrice, tx.gasprice); Foundry defaults
        // tx.gasprice to 0, which would zero the payout for environment reasons.
        vm.txGasPrice(50 gwei);

        // Enable the callback as a module BEFORE the timelock, so the module cases do
        // not need a ticket for their own setup.
        _enableModule(safe, address(nativeCb));

        _enableTimelock(safe, DELAY);
    }

    // -------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------

    function _params(address to, bytes memory data, uint256 gasPrice, address token, address payable receiver)
        private
        pure
        returns (Timelock.ExecTransactionParams memory)
    {
        return Timelock.ExecTransactionParams({
            to: to,
            value: 0,
            data: data,
            operation: Enum.Operation.Call,
            safeTxGas: SAFE_TX_GAS,
            baseGas: BASE_GAS,
            gasPrice: gasPrice,
            gasToken: token,
            refundReceiver: receiver
        });
    }

    /// @dev Params with every refund field zero. Used for nested transactions and for
    ///      the no-refund dominance control.
    function _plainParams(address to, bytes memory data, Enum.Operation op)
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

    function _hash(Timelock.ExecTransactionParams memory p, uint256 nonce) private view returns (bytes32) {
        return safe.getTransactionHash(
            p.to, p.value, p.data, p.operation, p.safeTxGas, p.baseGas, p.gasPrice, p.gasToken, p.refundReceiver, nonce
        );
    }

    function _sign(Timelock.ExecTransactionParams memory p, uint256 nonce) private view returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(OWNER_PK, _hash(p, nonce));
        return abi.encodePacked(r, s, v);
    }

    function _exec(Timelock.ExecTransactionParams memory p, bytes memory sig) private returns (bool) {
        return safe.execTransaction(
            p.to, p.value, p.data, p.operation, p.safeTxGas, p.baseGas, p.gasPrice, p.gasToken, p.refundReceiver, sig
        );
    }

    /// @dev Encodes a full nested `execTransaction` call for the callback to fire.
    function _nestedCalldata(Timelock.ExecTransactionParams memory p, uint256 nonce)
        private
        view
        returns (bytes memory)
    {
        return abi.encodeCall(
            ISafe.execTransaction,
            (
                p.to,
                p.value,
                p.data,
                p.operation,
                p.safeTxGas,
                p.baseGas,
                p.gasPrice,
                p.gasToken,
                p.refundReceiver,
                _sign(p, nonce)
            )
        );
    }

    function _schedule(Timelock.ExecTransactionParams memory p, uint256 nonce) private returns (bytes32 h) {
        h = _hash(p, nonce);
        guard.scheduleTransaction(address(safe), nonce, p, _sign(p, nonce));
    }

    function _mature() private {
        vm.warp(block.timestamp + DELAY + 1);
    }

    function _readSlot(uint256 slot) private view returns (address) {
        return address(uint160(uint256(bytes32(safe.getStorageAt(slot, 1)))));
    }

    function _countConsumed(Vm.Log[] memory logs) private pure returns (uint256 n) {
        for (uint256 i = 0; i < logs.length; ++i) {
            if (logs[i].topics.length > 0 && logs[i].topics[0] == TIMELOCK_CONSUMED_TOPIC) n++;
        }
    }

    /// @dev The standard business transaction: scheduled, matured, refund-bearing.
    function _armedBusinessTx(address token, address payable receiver)
        private
        returns (Timelock.ExecTransactionParams memory p, bytes memory sig, bytes32 h)
    {
        p = _params(address(business), abi.encodeCall(BusinessTarget.work, ()), GAS_PRICE, token, receiver);
        h = _schedule(p, safe.nonce());
        sig = _sign(p, safe.nonce());
        _mature();
    }

    // ===================================================================
    // Phase 1 - prove the exact window
    // ===================================================================

    /// @dev CONFIRMED (reachability, not yet a defect): the native refund receiver gets
    ///      control AFTER the business call and BEFORE the cached post-hook. The probe
    ///      reads the outer ticket as still live at callback time; it is consumed only
    ///      afterwards. This is the window the whole campaign is about.
    function test_confirmed_nativeRefundCallbackRunsBeforeCachedPostHook() public {
        (Timelock.ExecTransactionParams memory p, bytes memory sig, bytes32 h) =
            _armedBusinessTx(address(0), payable(address(nativeCb)));

        nativeCb.probe(address(guard), abi.encodeCall(Timelock.getTransactionExecutableAt, (address(safe), h)));

        assertGt(guard.getTransactionExecutableAt(address(safe), h), 0, "ticket exists before execution");

        assertTrue(_exec(p, sig), "outer tx succeeded");

        assertEq(nativeCb.calls(), 1, "refund callback ran exactly once");
        assertEq(business.hits(), 1, "business call landed before the callback");
        assertTrue(nativeCb.probeOk(), "probe executed inside the refund window");
        assertGt(abi.decode(nativeCb.probeReturn(), (uint64)), 0, "outer ticket was STILL LIVE inside the callback");
        assertEq(guard.getTransactionExecutableAt(address(safe), h), 0, "cached post-hook consumed it afterwards");
        assertGt(address(nativeCb).balance, 0, "Safe actually paid the refund");
    }

    /// @dev CONFIRMED: the ERC-20 branch gives the same window to an attacker-selected
    ///      `gasToken`, which is only required to return `true`.
    function test_confirmed_erc20GasTokenCallbackRunsBeforeCachedPostHook() public {
        (Timelock.ExecTransactionParams memory p, bytes memory sig, bytes32 h) =
            _armedBusinessTx(address(gasToken), payable(address(0xFEE5)));

        gasToken.probe(address(guard), abi.encodeCall(Timelock.getTransactionExecutableAt, (address(safe), h)));

        assertTrue(_exec(p, sig), "outer tx succeeded");

        assertEq(gasToken.calls(), 1, "gasToken.transfer ran exactly once");
        assertTrue(gasToken.probeOk(), "probe executed inside the refund window");
        assertGt(abi.decode(gasToken.probeReturn(), (uint64)), 0, "outer ticket was STILL LIVE inside the callback");
        assertEq(guard.getTransactionExecutableAt(address(safe), h), 0, "consumed only by the cached post-hook");
    }

    /// @dev Positive control for every `test_refuted_*` below: the callback is handed
    ///      enough gas to run a FULL nested `execTransaction`, so any negative result is
    ///      attributable to the guard and not to an out-of-gas.
    function test_control_refundCallbackHasEnoughGasForNestedExecTransaction() public {
        (Timelock.ExecTransactionParams memory p, bytes memory sig,) =
            _armedBusinessTx(address(0), payable(address(nativeCb)));

        assertTrue(_exec(p, sig), "outer tx succeeded");
        // A nested execTransaction through the guard costs well under 100k gas.
        assertGt(nativeCb.gasSeen(), 200_000, "callback had ample gas");
    }

    /// @dev Control: with `gasPrice == 0` there is no `handlePayment` and no window.
    function test_control_zeroGasPriceGivesNoCallback() public {
        Timelock.ExecTransactionParams memory p =
            _plainParams(address(business), abi.encodeCall(BusinessTarget.work, ()), Enum.Operation.Call);
        p.refundReceiver = payable(address(nativeCb));
        _schedule(p, safe.nonce());
        bytes memory sig = _sign(p, safe.nonce());
        _mature();

        assertTrue(_exec(p, sig), "outer tx succeeded");
        assertEq(nativeCb.calls(), 0, "no refund, no callback");
    }

    /// @dev Control: a reverting refund receiver reverts the WHOLE transaction (GS011),
    ///      rolling back the nonce, the business effect and the ticket. The window
    ///      cannot be used to commit a partial outcome.
    function test_control_revertingRefundReceiverRollsBackEverything() public {
        (Timelock.ExecTransactionParams memory p, bytes memory sig, bytes32 h) =
            _armedBusinessTx(address(0), payable(address(nativeCb)));

        nativeCb.setRevertOnCall(true);
        uint256 nonceBefore = safe.nonce();

        vm.expectRevert(abi.encodeWithSignature("Error(string)", "GS011"));
        _exec(p, sig);

        assertEq(safe.nonce(), nonceBefore, "nonce rolled back");
        assertEq(business.hits(), 0, "business effect rolled back");
        assertGt(guard.getTransactionExecutableAt(address(safe), h), 0, "ticket survived the rollback");
    }

    /// @dev CONFIRMED, and NOT in the original plan. This is the attacker's best entry:
    ///      when the business call REVERTS while `safeTxGas != 0`, Safe v1.5.0 does not
    ///      bubble. It still pays the refund, so the callback fires, then calls the
    ///      post-hook with `success == false` - and our post-hook only consumes on
    ///      success (INV-TIME-4). The attacker therefore obtains the refund window for
    ///      FREE: the nonce advances but the matured ticket is preserved for reuse.
    function test_confirmed_failedBusinessCallStillOpensTheWindowAndPreservesTheTicket() public {
        (Timelock.ExecTransactionParams memory p, bytes memory sig, bytes32 h) =
            _armedBusinessTx(address(0), payable(address(nativeCb)));

        business.setShouldRevert(true);
        uint256 nonceBefore = safe.nonce();

        assertFalse(_exec(p, sig), "Safe reports the inner call failed");

        assertEq(nativeCb.calls(), 1, "callback ran anyway");
        assertEq(safe.nonce(), nonceBefore + 1, "nonce advanced");
        assertGt(
            guard.getTransactionExecutableAt(address(safe), h),
            0,
            "ticket NOT consumed: the window was free and the authorisation is still spendable"
        );
    }

    // ===================================================================
    // Phase 2 - intact-guard authority and ticket accounting
    // ===================================================================

    /// @dev REFUTED: while the transaction guard is installed, the refund callback gains
    ///      nothing. A validly signed but UNSCHEDULED nested transaction is rejected by
    ///      the nested pre-hook exactly as it would be outside the window.
    function test_refuted_unscheduledNestedOwnerTxIsRejectedInsideTheWindow() public {
        (Timelock.ExecTransactionParams memory p, bytes memory sig,) =
            _armedBusinessTx(address(0), payable(address(nativeCb)));

        Timelock.ExecTransactionParams memory nested =
            _plainParams(address(business), abi.encodeCall(BusinessTarget.work, ()), Enum.Operation.Call);
        nativeCb.arm(address(safe), _nestedCalldata(nested, safe.nonce() + 1), false);

        assertTrue(_exec(p, sig), "outer tx succeeded");

        assertEq(nativeCb.calls(), 1, "callback ran");
        assertFalse(nativeCb.lastSuccess(), "nested execTransaction was rejected");
        assertEq(
            nativeCb.lastRevertSelector(), Timelock.TicketNotFound.selector, "rejected by the timelock, not by gas"
        );
        assertEq(business.hits(), 1, "only the authorised business call landed");
    }

    /// @dev REFUTED: an immature ticket is not accelerated by the window either. The
    ///      outer ticket is scheduled and matured first; the nested one is scheduled
    ///      afterwards, so it is still inside its delay when the callback fires.
    function test_refuted_immatureNestedTicketIsNotAcceleratedByTheWindow() public {
        Timelock.ExecTransactionParams memory outer = _params(
            address(business),
            abi.encodeCall(BusinessTarget.work, ()),
            GAS_PRICE,
            address(0),
            payable(address(nativeCb))
        );
        _schedule(outer, safe.nonce());
        _mature();
        bytes memory sig = _sign(outer, safe.nonce());

        // Scheduled AFTER the warp, so `executableAt` is a full delay in the future.
        Timelock.ExecTransactionParams memory nested =
            _plainParams(address(business), abi.encodeCall(BusinessTarget.work, ()), Enum.Operation.Call);
        bytes32 nestedHash = _schedule(nested, safe.nonce() + 1);
        nativeCb.arm(address(safe), _nestedCalldata(nested, safe.nonce() + 1), false);

        assertTrue(_exec(outer, sig), "outer tx succeeded");

        assertEq(nativeCb.calls(), 1, "callback ran");
        assertFalse(nativeCb.lastSuccess(), "immature nested tx was refused");
        assertEq(nativeCb.lastRevertSelector(), Timelock.TimelockNotElapsed.selector, "refused for being early");
        assertGt(guard.getTransactionExecutableAt(address(safe), nestedHash), 0, "nested ticket untouched");
        assertEq(business.hits(), 1, "only the authorised business call landed");
    }

    /// @dev LIMITATION, not an escalation: a separately scheduled and matured ticket at
    ///      nonce n+1 does execute from inside the window. Both tickets are consumed
    ///      exactly once by their own post-hooks. This is authorised nesting, and the
    ///      same nesting is reachable from any ordinary callee (see the dominance test).
    function test_limitation_maturedNestedTicketExecutesOnceInsideTheWindow() public {
        Timelock.ExecTransactionParams memory outer = _params(
            address(business),
            abi.encodeCall(BusinessTarget.work, ()),
            GAS_PRICE,
            address(0),
            payable(address(nativeCb))
        );
        bytes32 outerHash = _schedule(outer, safe.nonce());

        Timelock.ExecTransactionParams memory nested =
            _plainParams(address(business), abi.encodeCall(BusinessTarget.work, ()), Enum.Operation.Call);
        bytes32 nestedHash = _schedule(nested, safe.nonce() + 1);

        _mature();
        uint256 nonceBefore = safe.nonce();
        bytes memory sig = _sign(outer, nonceBefore);
        nativeCb.arm(address(safe), _nestedCalldata(nested, nonceBefore + 1), false);

        assertTrue(_exec(outer, sig), "outer tx succeeded");

        assertTrue(nativeCb.lastSuccess(), "the AUTHORISED nested tx executed");
        assertEq(business.hits(), 2, "both authorised calls landed");
        assertEq(guard.getTransactionExecutableAt(address(safe), outerHash), 0, "outer ticket consumed once");
        assertEq(guard.getTransactionExecutableAt(address(safe), nestedHash), 0, "nested ticket consumed once");
        assertEq(safe.nonce(), nonceBefore + 2, "exactly two nonces consumed, no double-spend");
    }

    /// @dev CONFIRMED as an observability limitation: the callback can cancel the outer
    ///      ticket that is still in flight, so the cached post-hook finds nothing to
    ///      consume and `TimelockConsumed` is never emitted for a transaction that DID
    ///      execute. No replay follows, because the Safe nonce has advanced past the
    ///      signed nonce, but a watchtower reconciling scheduled against consumed
    ///      tickets will mis-account this transaction.
    function test_confirmed_callbackCancelsTheInFlightOuterTicketSuppressingTimelockConsumed() public {
        (Timelock.ExecTransactionParams memory p, bytes memory sig, bytes32 h) =
            _armedBusinessTx(address(0), payable(address(nativeCb)));

        // `cancelTransaction` is a timelock-management meta-call: it needs no ticket, but
        // it does require all-zero refund fields on its own transaction.
        Timelock.ExecTransactionParams memory nested =
            _plainParams(address(guard), abi.encodeCall(Timelock.cancelTransaction, (h)), Enum.Operation.Call);
        nativeCb.arm(address(safe), _nestedCalldata(nested, safe.nonce() + 1), false);

        vm.recordLogs();
        assertTrue(_exec(p, sig), "outer tx succeeded");
        Vm.Log[] memory logs = vm.getRecordedLogs();

        assertTrue(nativeCb.lastSuccess(), "in-flight ticket cancelled from the refund window");
        assertEq(_countConsumed(logs), 0, "no TimelockConsumed for a transaction that executed");
        assertEq(guard.getTransactionExecutableAt(address(safe), h), 0, "slot is clear either way");
    }

    /// @dev AR-23 boundary, executed. The callback can activate the incident. The outer
    ///      transaction still completes, because enforcement is entry-time. A nested
    ///      owner transaction attempted afterwards IS blocked while the guard is
    ///      installed, which is the property that matters.
    function test_limitation_callbackCanTriggerLockdownAndTheGuardStillBlocksNestedCalls() public {
        (Timelock.ExecTransactionParams memory p, bytes memory sig,) =
            _armedBusinessTx(address(0), payable(address(nativeCb)));

        bytes32 reason = keccak256("refund-window");
        nativeCb.arm(
            address(guard),
            abi.encodeCall(
                Lockdown.triggerLockdown,
                (address(safe), reason, abi.encodePacked(panicKey), _signTrigger(safe, PANIC_PK, reason))
            ),
            false
        );

        assertTrue(_exec(p, sig), "outer tx completed; enforcement is entry-time (AR-23)");
        assertTrue(nativeCb.lastSuccess(), "lockdown activated from inside the refund window");

        (StateMachine.State state,) = guard.getState(address(safe));
        assertEq(uint256(state), uint256(StateMachine.State.LockedDown), "Safe is now LockedDown");

        // The guard is still installed, so the freeze is real.
        Timelock.ExecTransactionParams memory after_ =
            _plainParams(address(business), abi.encodeCall(BusinessTarget.work, ()), Enum.Operation.Call);
        bytes memory afterSig = _sign(after_, safe.nonce());
        vm.expectRevert(Lockdown.LockedDown.selector);
        _exec(after_, afterSig);
    }

    // ===================================================================
    // Phase 3 - topology changes inside the refund window
    // ===================================================================

    /// @dev CONFIRMED atomicity: a scheduled `setGuard(0)` removes the guard, and the
    ///      refund callback then executes an UNSCHEDULED, validly signed transaction in
    ///      the same transaction, because the Safe re-reads a now-zero guard slot for
    ///      the nested call. The cached guard still receives the outer post-hook.
    ///
    ///      Read this together with `test_refuted_dominanceNoRefundMultiSendReachesTheSame`:
    ///      the capability is identical without any refund, so this is AR-20 authority
    ///      exercised atomically, not a new authority.
    function test_confirmed_guardRemovalThenUnscheduledNestedTxInsideTheWindow() public {
        Timelock.ExecTransactionParams memory outer = _params(
            address(safe),
            abi.encodeCall(IGuardManager.setGuard, (address(0))),
            GAS_PRICE,
            address(0),
            payable(address(nativeCb))
        );
        bytes32 outerHash = _schedule(outer, safe.nonce());
        _mature();
        bytes memory sig = _sign(outer, safe.nonce());

        Timelock.ExecTransactionParams memory nested =
            _plainParams(address(business), abi.encodeCall(BusinessTarget.work, ()), Enum.Operation.Call);
        nativeCb.arm(address(safe), _nestedCalldata(nested, safe.nonce() + 1), false);

        assertTrue(_exec(outer, sig), "outer tx succeeded");

        assertEq(_readSlot(GUARD_SLOT), address(0), "guard slot cleared");
        assertTrue(nativeCb.lastSuccess(), "unscheduled nested tx executed with the guard already gone");
        assertEq(business.hits(), 1, "the unscheduled call landed");
        assertEq(
            guard.getTransactionExecutableAt(address(safe), outerHash),
            0,
            "cached post-hook still consumed the outer ticket"
        );
    }

    /// @dev CONFIRMED atomicity on the module path, and this one is sharper: our own A7
    ///      limitation says `setModuleGuard(0)` makes `getState()` lie. Here the module
    ///      call happens inside the SAME transaction as the removal, so no monitoring can
    ///      interpose at all.
    function test_confirmed_moduleGuardRemovalThenUnscheduledModuleCallInsideTheWindow() public {
        Timelock.ExecTransactionParams memory outer = _params(
            address(safe),
            abi.encodeCall(IModuleManager.setModuleGuard, (address(0))),
            GAS_PRICE,
            address(0),
            payable(address(nativeCb))
        );
        _schedule(outer, safe.nonce());
        _mature();
        bytes memory sig = _sign(outer, safe.nonce());

        nativeCb.arm(
            address(safe),
            abi.encodeCall(
                IModuleManager.execTransactionFromModule,
                (address(business), 0, abi.encodeCall(BusinessTarget.work, ()), Enum.Operation.Call)
            ),
            false
        );

        assertTrue(_exec(outer, sig), "outer tx succeeded");

        assertEq(_readSlot(MODULE_GUARD_SLOT), address(0), "module guard slot cleared");
        assertTrue(nativeCb.lastSuccess(), "unscheduled module call executed inside the same transaction");
        assertEq(business.hits(), 1, "the module call landed with no module ticket");
    }

    /// @dev Control that isolates the cause: with the module guard INTACT, the very same
    ///      unscheduled module call from the very same refund callback is rejected.
    function test_control_moduleGuardIntactRejectsUnscheduledModuleCallInsideTheWindow() public {
        (Timelock.ExecTransactionParams memory p, bytes memory sig,) =
            _armedBusinessTx(address(0), payable(address(nativeCb)));

        nativeCb.arm(
            address(safe),
            abi.encodeCall(
                IModuleManager.execTransactionFromModule,
                (address(business), 0, abi.encodeCall(BusinessTarget.work, ()), Enum.Operation.Call)
            ),
            false
        );

        assertTrue(_exec(p, sig), "outer tx succeeded");

        assertFalse(nativeCb.lastSuccess(), "module call rejected while the module guard is installed");
        assertEq(nativeCb.lastRevertSelector(), Timelock.TicketNotFound.selector, "rejected by the module timelock");
        assertEq(business.hits(), 1, "only the authorised business call landed");
    }

    /// @dev CONFIRMED, and this is the worst-looking single result of the campaign:
    ///      after a scheduled `setGuard(0)`, the callback activates Lockdown and then
    ///      executes an unscheduled owner transaction. The singleton reports LockedDown
    ///      while the owner path is already uncovered. This is AR-20 (partial uninstall
    ///      makes views lie) composed with AR-23 (entry-time enforcement), atomically.
    function test_confirmed_lockedDownViewWhileTheUncoveredOwnerPathStillExecutes() public {
        Timelock.ExecTransactionParams memory outer = _params(
            address(safe),
            abi.encodeCall(IGuardManager.setGuard, (address(0))),
            GAS_PRICE,
            address(0),
            payable(address(nativeCb))
        );
        _schedule(outer, safe.nonce());
        _mature();
        bytes memory sig = _sign(outer, safe.nonce());

        bytes32 reason = keccak256("compose");
        // The callback fires lockdown; the nested owner tx is executed by a second hop
        // so both happen inside the one window.
        nativeCb.arm(
            address(guard),
            abi.encodeCall(
                Lockdown.triggerLockdown,
                (address(safe), reason, abi.encodePacked(panicKey), _signTrigger(safe, PANIC_PK, reason))
            ),
            false
        );

        assertTrue(_exec(outer, sig), "outer tx succeeded");

        (StateMachine.State state,) = guard.getState(address(safe));
        assertEq(uint256(state), uint256(StateMachine.State.LockedDown), "singleton says LockedDown");
        assertEq(_readSlot(GUARD_SLOT), address(0), "but the guard slot is empty");

        // And the owner path really is uncovered while the view says LockedDown.
        Timelock.ExecTransactionParams memory nested =
            _plainParams(address(business), abi.encodeCall(BusinessTarget.work, ()), Enum.Operation.Call);
        assertTrue(
            _exec(nested, _sign(nested, safe.nonce())), "uncovered owner path executes during a reported incident"
        );
        assertEq(business.hits(), 1, "effect landed while getState() reported LockedDown");
    }

    // ===================================================================
    // Phase 4 - dominance and observability
    // ===================================================================

    /// @dev THE DECISIVE CONTROL. The same end state - guard removed, then an
    ///      unscheduled nested transaction executed atomically - is reached by an
    ///      ordinary owner-approved, scheduled MultiSend with EVERY refund field zero.
    ///
    ///      The refund window therefore adds NO authority. It changes where the second
    ///      half of the payload lives (in a callback contract instead of in the signed
    ///      batch), which is an observability and signer-review question, not a
    ///      capability question.
    function test_refuted_dominanceNoRefundMultiSendReachesTheSame() public {
        Timelock.ExecTransactionParams memory nested =
            _plainParams(address(business), abi.encodeCall(BusinessTarget.work, ()), Enum.Operation.Call);

        bytes memory batch = abi.encodePacked(
            _multiSendItem(Enum.Operation.Call, address(safe), 0, abi.encodeCall(IGuardManager.setGuard, (address(0)))),
            _multiSendItem(Enum.Operation.Call, address(plainCallee), 0, abi.encodeCall(PlainCallee.run, ()))
        );
        Timelock.ExecTransactionParams memory outer = _plainParams(
            address(multiSendCallOnly),
            abi.encodeCall(MultiSendCallOnly.multiSend, (batch)),
            Enum.Operation.DelegateCall
        );

        _schedule(outer, safe.nonce());
        _mature();
        bytes memory sig = _sign(outer, safe.nonce());

        plainCallee.arm(address(safe), _nestedCalldata(nested, safe.nonce() + 1), false);

        assertTrue(_exec(outer, sig), "no-refund bundle succeeded");

        assertEq(_readSlot(GUARD_SLOT), address(0), "guard removed with zero refund fields");
        assertTrue(plainCallee.lastSuccess(), "same unscheduled nested tx executed, no refund involved");
        assertEq(business.hits(), 1, "same final effect as the refund path");
    }

    /// @dev CONFIRMED, and the one result with no equivalent elsewhere. With
    ///      `refundReceiver == address(0)` the Safe refunds `tx.origin`. If code lives
    ///      there (EIP-7702 delegation, or simply a contract submitter), arbitrary code
    ///      runs in the refund window while the SIGNED HASH CONTAINS ZERO.
    ///
    ///      `specs/SPEC_V1.md` §7.2 rests the Normal-mode refund policy on off-chain
    ///      signer review resolving the hash and surfacing `gasToken != 0` /
    ///      `refundReceiver != 0`. That review instruction is exactly inverted here: the
    ///      dangerous value is ZERO, and the code that will run is not in the hash at all.
    function test_confirmed_zeroRefundReceiverExecutesCodeAtTxOriginNotBoundByTheSignedHash() public {
        Timelock.ExecTransactionParams memory p = _params(
            address(business), abi.encodeCall(BusinessTarget.work, ()), GAS_PRICE, address(0), payable(address(0))
        );
        bytes32 h = _schedule(p, safe.nonce());
        _mature();
        bytes memory sig = _sign(p, safe.nonce());

        // The signed hash commits to refundReceiver == address(0).
        assertEq(p.refundReceiver, address(0), "signed hash says: no refund receiver");

        Timelock.ExecTransactionParams memory nested =
            _plainParams(address(business), abi.encodeCall(BusinessTarget.work, ()), Enum.Operation.Call);
        nativeCb.arm(address(safe), _nestedCalldata(nested, safe.nonce() + 1), false);

        // tx.origin carries code. `vm.prank(sender, origin)` models the EIP-7702 /
        // contract-submitter case deterministically.
        vm.prank(other, address(nativeCb));
        assertTrue(_exec(p, sig), "outer tx succeeded");

        assertEq(nativeCb.calls(), 1, "code at tx.origin received control, though the hash said address(0)");
        assertGt(address(nativeCb).balance, 0, "and was paid");
        // The guard is intact here, so the nested call is still correctly refused.
        assertFalse(nativeCb.lastSuccess(), "guard still governs what that code can do");
        assertEq(nativeCb.lastRevertSelector(), Timelock.TicketNotFound.selector, "refused by the timelock");
        assertEq(guard.getTransactionExecutableAt(address(safe), h), 0, "outer ticket consumed normally");
    }
}
