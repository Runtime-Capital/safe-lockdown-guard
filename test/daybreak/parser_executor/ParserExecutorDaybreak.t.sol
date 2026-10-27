// SPDX-License-Identifier: MIT
pragma solidity 0.8.35;

import {Safe, Enum} from "@safe-global/safe-smart-account/Safe.sol";
import {MultiSendCallOnly} from "@safe-global/safe-smart-account/libraries/MultiSendCallOnly.sol";

import {TestEnvironment} from "../../TestEnvironment.sol";
import {Lockdown} from "../../../src/Lockdown.sol";
import {StateMachine} from "../../../src/base/StateMachine.sol";

contract LockRelay {
    Lockdown private lockdown;
    address private safe;
    bytes32 private reasonHash;
    bytes private signer;
    bytes private signature;

    function arm(
        Lockdown lockdown_,
        address safe_,
        bytes32 reasonHash_,
        bytes calldata signer_,
        bytes calldata signature_
    ) external {
        lockdown = lockdown_;
        safe = safe_;
        reasonHash = reasonHash_;
        signer = signer_;
        signature = signature_;
    }

    function lock() external {
        lockdown.triggerLockdown(safe, reasonHash, signer, signature);
    }
}

contract LockThenTransferToken {
    mapping(address account => uint256) public balanceOf;

    Lockdown private lockdown;
    address private safe;
    bytes32 private reasonHash;
    bytes private signer;
    bytes private signature;

    function mint(address account, uint256 amount) external {
        balanceOf[account] += amount;
    }

    function arm(
        Lockdown lockdown_,
        address safe_,
        bytes32 reasonHash_,
        bytes calldata signer_,
        bytes calldata signature_
    ) external {
        lockdown = lockdown_;
        safe = safe_;
        reasonHash = reasonHash_;
        signer = signer_;
        signature = signature_;
    }

    function transfer(address recipient, uint256 amount) external returns (bool) {
        lockdown.triggerLockdown(safe, reasonHash, signer, signature);

        require(balanceOf[msg.sender] >= amount, "insufficient balance");
        balanceOf[msg.sender] -= amount;
        balanceOf[recipient] += amount;
        return true;
    }
}

contract ParserExecutorDaybreakTest is TestEnvironment {
    function test_limitation_realSafeMultiSend_spendsAfterLockdownActivated() public {
        Safe instance = _createConfigureAndInitialise(91_001);
        LockRelay relay = new LockRelay();
        address sink = address(0xD4A1);
        uint256 amount = 1 ether;
        bytes32 reasonHash = keccak256("P1 lock during batch");
        bytes memory signer = abi.encodePacked(panicKey);
        bytes memory signature = _signTrigger(instance, PANIC_PK, reasonHash);

        vm.deal(address(instance), amount);
        bytes memory first = _multiSendItem(Enum.Operation.Call, address(relay), 0, abi.encodeCall(LockRelay.lock, ()));
        bytes memory second = _multiSendItem(Enum.Operation.Call, sink, amount, "");
        bytes memory batch = abi.encodeCall(MultiSendCallOnly.multiSend, (bytes.concat(first, second)));
        bytes memory preSignedOwnerTransaction =
            _signTx(instance, OWNER_PK, address(multiSendCallOnly), 0, batch, Enum.Operation.DelegateCall);

        // The owner signature already binds the exact batch while the callback is
        // inert. The panic holder arms it afterwards, without owning Safe quorum.
        relay.arm(Lockdown(address(guard)), address(instance), reasonHash, signer, signature);

        assertEq(sink.balance, 0);
        (StateMachine.State beforeState,) = guard.getState(address(instance));
        assertEq(uint256(beforeState), uint256(StateMachine.State.Normal));

        assertTrue(
            instance.execTransaction(
                address(multiSendCallOnly),
                0,
                batch,
                Enum.Operation.DelegateCall,
                0,
                0,
                0,
                address(0),
                payable(address(0)),
                preSignedOwnerTransaction
            )
        );

        (StateMachine.State afterState,) = guard.getState(address(instance));
        assertEq(uint256(afterState), uint256(StateMachine.State.LockedDown));
        assertEq(sink.balance, amount, "trailing batch value moved after lockdown became active");
        assertEq(address(instance).balance, 0);
    }

    function test_limitation_realSafe_leafTargetDebitsTokenAfterLockdownActivated() public {
        Safe instance = _createConfigureAndInitialise(91_002);
        LockThenTransferToken token = new LockThenTransferToken();
        address sink = address(0xD4A2);
        uint256 amount = 250 ether;
        bytes32 reasonHash = keccak256("P2 lock inside leaf");
        bytes memory signer = abi.encodePacked(panicKey);
        bytes memory signature = _signTrigger(instance, PANIC_PK, reasonHash);
        bytes memory transferData = abi.encodeCall(LockThenTransferToken.transfer, (sink, amount));
        bytes memory preSignedOwnerTransaction =
            _signTx(instance, OWNER_PK, address(token), 0, transferData, Enum.Operation.Call);

        token.mint(address(instance), amount);
        // As in P1, target state changes after the exact Safe transaction has
        // already been signed; no post-signature quorum control is assumed.
        token.arm(Lockdown(address(guard)), address(instance), reasonHash, signer, signature);

        assertEq(token.balanceOf(address(instance)), amount);
        assertEq(token.balanceOf(sink), 0);

        assertTrue(
            instance.execTransaction(
                address(token),
                0,
                transferData,
                Enum.Operation.Call,
                0,
                0,
                0,
                address(0),
                payable(address(0)),
                preSignedOwnerTransaction
            )
        );

        (StateMachine.State afterState,) = guard.getState(address(instance));
        assertEq(uint256(afterState), uint256(StateMachine.State.LockedDown));
        assertEq(token.balanceOf(address(instance)), 0, "Safe token balance debited after lockdown became active");
        assertEq(token.balanceOf(sink), amount);
    }
}
