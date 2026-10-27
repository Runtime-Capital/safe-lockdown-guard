// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {ISafe, Enum} from "@safe-global/safe-smart-account/interfaces/ISafe.sol";

import {TestEnvironment} from "../../TestEnvironment.sol";
import {LockdownTimelock} from "../../../src/LockdownTimelock.sol";
import {StateMachine} from "../../../src/base/StateMachine.sol";
import {Timelock} from "../../../src/base/Timelock.sol";

contract IncidentHookToken {
    mapping(address account => uint256 amount) public balanceOf;

    LockdownTimelock private lockdown;
    address private safe;
    bytes32 private reasonHash;
    bytes private signer;
    bytes private triggerSignature;

    function mint(address account, uint256 amount) external {
        balanceOf[account] += amount;
    }

    function arm(
        LockdownTimelock lockdown_,
        address safe_,
        bytes32 reasonHash_,
        bytes calldata signer_,
        bytes calldata triggerSignature_
    ) external {
        lockdown = lockdown_;
        safe = safe_;
        reasonHash = reasonHash_;
        signer = signer_;
        triggerSignature = triggerSignature_;
    }

    function transfer(address recipient, uint256 amount) external returns (bool) {
        lockdown.triggerLockdown(safe, reasonHash, signer, triggerSignature);
        balanceOf[msg.sender] -= amount;
        balanceOf[recipient] += amount;
        return true;
    }
}

contract InCallIncidentTransitionTest is TestEnvironment {
    uint256 private constant AMOUNT = 40 ether;
    bytes32 private constant REASON = keccak256("in-call incident transition");

    ISafe private instance;
    IncidentHookToken private token;

    function setUp() public override {
        super.setUp();
        instance = ISafe(payable(address(_createConfigureAndInitialise(71))));
        token = new IncidentHookToken();
        token.mint(address(instance), 100 ether);
        _enableTimelock(instance, 1 hours);
    }

    function test_limitation_ownerTicketCommitsAssetMovementAfterLockdownStarts() public {
        bytes memory callData = abi.encodeCall(IncidentHookToken.transfer, (other, AMOUNT));
        bytes memory ownerSignature = _signTx(instance, OWNER_PK, address(token), 0, callData, Enum.Operation.Call);
        bytes32 safeTxHash = _safeTxHash(instance, address(token), 0, callData, Enum.Operation.Call);

        Timelock.ExecTransactionParams memory params = Timelock.ExecTransactionParams({
            to: address(token),
            value: 0,
            data: callData,
            operation: Enum.Operation.Call,
            safeTxGas: 0,
            baseGas: 0,
            gasPrice: 0,
            gasToken: address(0),
            refundReceiver: payable(address(0))
        });
        guard.scheduleTransaction(address(instance), instance.nonce(), params, ownerSignature);
        token.arm(
            guard, address(instance), REASON, abi.encodePacked(panicKey), _signTrigger(instance, PANIC_PK, REASON)
        );
        vm.warp(block.timestamp + guard.getTimelockDelay(address(instance)));

        (StateMachine.State stateBefore,) = guard.getState(address(instance));
        assertEq(uint256(stateBefore), uint256(StateMachine.State.Normal));
        assertGt(guard.getTransactionExecutableAt(address(instance), safeTxHash), 0);

        bool success = instance.execTransaction(
            address(token), 0, callData, Enum.Operation.Call, 0, 0, 0, address(0), payable(address(0)), ownerSignature
        );

        (StateMachine.State stateAfter,) = guard.getState(address(instance));
        assertTrue(success);
        assertEq(uint256(stateAfter), uint256(StateMachine.State.LockedDown));
        assertEq(token.balanceOf(address(instance)), 60 ether);
        assertEq(token.balanceOf(other), AMOUNT);
        assertEq(guard.getTransactionExecutableAt(address(instance), safeTxHash), 0);
    }

    function test_limitation_moduleTicketCommitsAssetMovementAfterLockdownStarts() public {
        bytes memory callData = abi.encodeCall(IncidentHookToken.transfer, (other, AMOUNT));
        bytes32 moduleTxHash =
            guard.getModuleTransactionHash(address(instance), module, address(token), 0, callData, Enum.Operation.Call);
        _execAsOwner(
            instance,
            address(guard),
            0,
            abi.encodeCall(
                LockdownTimelock.scheduleModuleTransaction, (module, address(token), 0, callData, Enum.Operation.Call)
            ),
            Enum.Operation.Call
        );
        token.arm(
            guard, address(instance), REASON, abi.encodePacked(panicKey), _signTrigger(instance, PANIC_PK, REASON)
        );
        vm.warp(block.timestamp + guard.getTimelockDelay(address(instance)));

        (StateMachine.State stateBefore,) = guard.getState(address(instance));
        assertEq(uint256(stateBefore), uint256(StateMachine.State.Normal));
        assertGt(guard.getModuleTransactionExecutableAt(address(instance), moduleTxHash), 0);

        vm.prank(module);
        bool success = instance.execTransactionFromModule(address(token), 0, callData, Enum.Operation.Call);

        (StateMachine.State stateAfter,) = guard.getState(address(instance));
        assertTrue(success);
        assertEq(uint256(stateAfter), uint256(StateMachine.State.LockedDown));
        assertEq(token.balanceOf(address(instance)), 60 ether);
        assertEq(token.balanceOf(other), AMOUNT);
        assertEq(guard.getModuleTransactionExecutableAt(address(instance), moduleTxHash), 0);
    }
}
