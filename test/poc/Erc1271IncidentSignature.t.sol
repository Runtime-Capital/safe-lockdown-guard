// SPDX-License-Identifier: MIT
// Cross-source lead F-04: an ERC-1271 signature extracted from a coerced quorum DURING
// the incident becomes usable again the moment the Safe auto-resumes.
//
// `LockdownFallbackHandler` reads the CURRENT lifecycle state on every call
// (src/handlers/LockdownFallbackHandler.sol:118-122). There is no signature epoch and
// auto-resume performs no write, so nothing marks a signature as "produced during an
// incident". The handler header nevertheless promises to close the surface "for any
// signature produced during the incident" (:20-25), and the accepted-risk register
// entry #15 mentions only authorisations produced BEFORE the trigger.
//
// These tests settle what the freeze actually is (a deferral) and what the real
// mitigation is (the recovery owner swap, not the handler).
pragma solidity ^0.8.24;

import {TestEnvironment} from "../TestEnvironment.sol";

import {Safe, Enum} from "@safe-global/safe-smart-account/Safe.sol";
import {IOwnerManager} from "@safe-global/safe-smart-account/interfaces/IOwnerManager.sol";

import {LockdownFallbackHandler} from "../../src/handlers/LockdownFallbackHandler.sol";
import {StateMachine} from "../../src/base/StateMachine.sol";

contract Erc1271IncidentSignaturePoC is TestEnvironment {
    bytes4 private constant ERC1271_MAGIC = 0x1626ba7e;
    address private constant SENTINEL = address(0x1);

    Safe private safe;
    bytes32 private orderHash;

    function setUp() public override {
        super.setUp();
        safe = _createConfigureAndInitialise(101);
        // These proofs characterise a Safe that OPTED IN to ERC-1271 (SPEC_V1 H.27).
        // A default Safe refuses every signature here with `Erc1271Disabled`.
        _allowErc1271(safe);
        orderHash = keccak256("a settlement order with a far-future deadline");
    }

    /// @dev Calls `isValidSignature` the way a third-party settlement contract would:
    ///      through the Safe, which forwards to the fallback handler.
    function _isValidSignature(bytes memory sig) private returns (bool ok, bytes memory ret) {
        (ok, ret) = address(safe)
            .call(abi.encodeWithSelector(LockdownFallbackHandler.isValidSignature.selector, orderHash, sig));
    }

    function _assertValidates(bytes memory sig, string memory why) private {
        (bool ok, bytes memory ret) = _isValidSignature(sig);
        assertTrue(ok, why);
        assertEq(abi.decode(ret, (bytes4)), ERC1271_MAGIC, why);
    }

    function _assertFrozen(bytes memory sig) private {
        (bool ok, bytes memory ret) = _isValidSignature(sig);
        assertFalse(ok, "must not validate during an incident");
        assertEq(
            bytes4(ret),
            LockdownFallbackHandler.SignaturesFrozenDuringLockdown.selector,
            "frozen by the lockdown gate, not by something else"
        );
    }

    /// @dev CONFIRMED: the ERC-1271 freeze defers, it does not prevent. The signature is
    ///      produced while the Safe is LockedDown (the coercion window), is refused
    ///      throughout LockedDown and Recovering, and validates again as soon as the
    ///      Safe auto-resumes - with no transaction marking the transition.
    function test_confirmed_incidentEra1271SignatureValidatesAfterAutoResume() public {
        _triggerLockdown(safe, bytes32("wrench"));

        // Signature extracted from the coerced quorum DURING the incident.
        bytes memory sig = _signMessage(safe, OWNER_PK, orderHash);

        _assertFrozen(sig);

        vm.warp(block.timestamp + 48 hours + 1); // Recovering
        (StateMachine.State recovering,) = guard.getState(address(safe));
        assertEq(uint256(recovering), uint256(StateMachine.State.Recovering), "in Recovering");
        _assertFrozen(sig);

        vm.warp(block.timestamp + 4 hours + 1); // auto-resumed to Normal
        (StateMachine.State normal,) = guard.getState(address(safe));
        assertEq(uint256(normal), uint256(StateMachine.State.Normal), "auto-resumed");

        _assertValidates(sig, "the incident-era signature is valid again");
    }

    /// @dev The mitigation, and it is NOT the handler: if the quorum uses the recovery
    ///      window to swap the compromised owner out, the incident-era signature is dead
    ///      after resume because `checkSignatures` runs against the CURRENT owner set.
    ///      This is what the runbook relies on, so the guarantee is conditional on the
    ///      recovery actually being performed and on the swapped owner being the one
    ///      that signed.
    function test_refuted_recoveryOwnerSwapKillsTheIncidentEraSignature() public {
        _triggerLockdown(safe, bytes32("wrench"));
        bytes memory sig = _signMessage(safe, OWNER_PK, orderHash);

        vm.warp(block.timestamp + 48 hours + 1); // Recovering
        _execAsOwner(
            safe,
            address(safe),
            0,
            abi.encodeCall(IOwnerManager.swapOwner, (SENTINEL, owner, recovery)),
            Enum.Operation.Call
        );

        vm.warp(block.timestamp + 4 hours + 1); // auto-resumed

        (bool ok,) = _isValidSignature(sig);
        assertFalse(ok, "swapped-out owner's signature no longer validates");
    }

    /// @dev The same signature signed by the NEW owner validates, confirming the test
    ///      above fails for the intended reason (owner set changed) and not because the
    ///      Safe is broken.
    function test_control_newOwnerSignatureValidatesAfterRecovery() public {
        _triggerLockdown(safe, bytes32("wrench"));
        vm.warp(block.timestamp + 48 hours + 1);
        _execAsOwner(
            safe,
            address(safe),
            0,
            abi.encodeCall(IOwnerManager.swapOwner, (SENTINEL, owner, recovery)),
            Enum.Operation.Call
        );
        vm.warp(block.timestamp + 4 hours + 1);

        _assertValidates(_signMessage(safe, RECOVERY_PK, orderHash), "new owner can sign");
    }

    /// @dev Scope note, tested so it cannot rot: a signature produced BEFORE the trigger
    ///      is equally valid after resume. That half is accepted risk #15; this test
    ///      exists to show the two halves are indistinguishable on-chain, which is why
    ///      the register wording matters.
    function test_limitation_preIncidentAndIncidentEraSignaturesAreIndistinguishable() public {
        bytes memory preIncident = _signMessage(safe, OWNER_PK, orderHash);
        _assertValidates(preIncident, "valid before the incident");

        _triggerLockdown(safe, bytes32("wrench"));
        bytes memory duringIncident = _signMessage(safe, OWNER_PK, orderHash);

        // Byte-identical: the digest has no epoch, nonce or timestamp component, so the
        // handler could not tell them apart even if it wanted to.
        assertEq(keccak256(preIncident), keccak256(duringIncident), "same bytes, no epoch to separate them");

        vm.warp(block.timestamp + 48 hours + 4 hours + 2);
        _assertValidates(duringIncident, "both validate after resume");
    }
}
