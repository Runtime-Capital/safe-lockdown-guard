// SPDX-License-Identifier: MIT
// External audit NM-1060, Low: "Drill signatures produced with `testSigner(...)` remain
// valid triggers".
//
// `testSigner(signer, hash, signature)` verified a signature without burning the
// identity, and the runbook made that drill mandatory over the exact trigger digest. The
// drill signature is therefore a valid trigger for as long as the identity is
// registered, and a drill is naturally sent as an `eth_call` to an RPC provider: the
// provider, a log pipeline or anyone downstream could later lock the Safe at a time of
// their choosing and burn one panic identity.
//
// Answer (SPEC_V1 §6.4, §H.25): the view is removed and drills run off-chain
// (`script/DrillSigner.s.sol` in a local fork, or the lifecycle UI's in-browser check),
// so the signature never has to leave the operator's machine.
//
// Accepted residual: no message field can make a drill signature unusable as a trigger
// without also separating it from the real trigger digest, which is what the drill must
// prove. A drill signature stays a live trigger until its identity is burnt or removed;
// if it may have leaked, the quorum rotates the identity in Normal.
pragma solidity ^0.8.24;

import {TestEnvironment} from "../TestEnvironment.sol";

import {Safe} from "@safe-global/safe-smart-account/Safe.sol";

import {Lockdown} from "../../src/Lockdown.sol";
import {LockdownSigners} from "../../src/base/LockdownSigners.sol";
import {StateMachine} from "../../src/base/StateMachine.sol";
import {DrillSigner} from "../../script/DrillSigner.s.sol";

contract DrillSignatureExposurePoC is TestEnvironment {
    bytes32 private constant REASON = keccak256("drill");

    /// @dev Whoever ends up holding the drill data (RPC provider, log pipeline, ...).
    address private constant HOLDER = address(0xD1A7);

    Safe private safe;
    DrillSigner private drill;
    bytes private identity;

    function setUp() public override {
        super.setUp();
        safe = _createConfigureAndInitialise(0xD1A1);
        drill = new DrillSigner();
        identity = abi.encodePacked(panicKey); // registered by the fixture
    }

    /// @notice The on-chain drill view is gone: no singleton function verifies a
    ///         trigger signature without burning the identity.
    function test_regression_noOnChainDrillView() public {
        (bool ok,) = address(guard)
            .call(abi.encodeWithSelector(bytes4(keccak256("testSigner(bytes,bytes32,bytes)")), identity, REASON, hex""));
        assertFalse(ok, "testSigner selector removed");
    }

    /// @notice What remains true by construction: the drill proves the signature is a
    ///         valid trigger, so the same signature, if it leaks, triggers the Safe.
    function test_limitation_offChainDrillSignatureIsALiveTrigger() public {
        bytes memory signature = _signTrigger(safe, PANIC_PK, REASON);
        DrillSigner.Report memory r = drill.check(guard, address(safe), REASON, identity, signature);
        assertTrue(r.registered && r.valid && !r.burnt, "drill passes and burns nothing");

        vm.prank(HOLDER);
        guard.triggerLockdown(address(safe), REASON, identity, signature);

        (StateMachine.State s,) = guard.getState(address(safe));
        assertEq(uint256(s), uint256(StateMachine.State.LockedDown), "leaked drill signature locked the Safe");
        assertTrue(guard.isSignerBurntPermanently(address(safe), identity), "and burnt the identity");
    }

    /// @notice The operator remedy for a possibly leaked drill signature: rotate the
    ///         identity in Normal. The leaked signature is then dead.
    function test_control_rotationRevokesALeakedDrillSignature() public {
        bytes memory signature = _signTrigger(safe, PANIC_PK, REASON);
        assertTrue(drill.isValid(guard, address(safe), REASON, identity, signature), "drill passes");

        vm.prank(address(safe));
        guard.rotateLockdownSigner(identity, abi.encodePacked(other));

        vm.prank(HOLDER);
        vm.expectRevert(LockdownSigners.LockdownSigners_Unknown.selector);
        guard.triggerLockdown(address(safe), REASON, identity, signature);
    }
}
