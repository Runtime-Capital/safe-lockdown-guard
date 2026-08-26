// SPDX-License-Identifier: MIT
// Prompt C priority lead 5 ("armed but inert") and cross-source lead F-05 (EIP-7702).
//
// This is the failure mode that matters most for an anti-coercion product and the one a
// test suite is least likely to catch, because everything LOOKS configured: all three
// slots wired, `getLockdownSignerCount > 0`, config initialised, preflight green.
//
// Each test builds a Safe that reports itself as armed and then proves, by execution,
// that `triggerLockdown` does not work - or, worse, that it works for ANYONE. For every
// case the final assertion answers the operator's real question: can this be DISCOVERED
// BEFORE the incident, using the read-only drill primitive
// `Lockdown.testSigner(signer, hash, signature)` (src/Lockdown.sol:255)?
//
// A guard that silently does not work is worse than no guard, because it replaces
// caution with false confidence.
pragma solidity ^0.8.24;

import {TestEnvironment} from "../TestEnvironment.sol";

import {Safe, Enum} from "@safe-global/safe-smart-account/Safe.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";

import {Lockdown} from "../../src/Lockdown.sol";
import {StateMachine} from "../../src/base/StateMachine.sol";
import {MockSecretVerifier} from "../mocks/MockSecretVerifier.sol";

/// @dev Stands in for an EIP-7702 delegation target that does not implement ERC-1271.
///      Any non-empty code at the EOA address is enough to flip OpenZeppelin's
///      `SignatureChecker` from the ECDSA branch to the ERC-1271 branch
///      (SignatureChecker.sol:32-38).
contract NotAn1271Wallet {
    function unrelated() external pure returns (uint256) {
        return 1;
    }
}

/// @dev The opposite EIP-7702 outcome: a delegation that validates EVERYTHING.
contract AlwaysMagic1271 {
    function isValidSignature(bytes32, bytes memory) external pure returns (bytes4) {
        return 0x1626ba7e;
    }
}

contract ArmedButInertPoC is TestEnvironment {
    Safe private safe;

    function setUp() public override {
        super.setUp();
        safe = _createConfigureAndInitialise(97);
    }

    // -------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------

    /// @dev The exact EIP-712 digest `triggerLockdown` will check. An operator running a
    ///      drill must use this digest for `testSigner` to be meaningful.
    function _triggerDigest(address safe_, bytes32 reasonHash) private view returns (bytes32) {
        (
            bytes1 fields,
            string memory name,
            string memory version,
            uint256 chainId,
            address verifyingContract,
            bytes32 salt,
        ) = guard.eip712Domain();
        return MessageHashUtils.toTypedDataHash(
            MessageHashUtils.toDomainSeparator(fields, name, version, chainId, verifyingContract, salt),
            keccak256(abi.encode(guard.LOCKDOWN_TYPEHASH(), safe_, reasonHash))
        );
    }

    function _addSigner(bytes memory signer) private {
        _execAsOwner(safe, address(guard), 0, abi.encodeCall(Lockdown.addLockdownSigner, (signer)), Enum.Operation.Call);
    }

    /// @dev Asserts the Safe still LOOKS fully armed: initialised, Normal, non-zero
    ///      signer count. This is what an operator dashboard and the verify script see.
    function _assertLooksArmed(uint256 expectedSigners) private view {
        (,,, uint256 signersCount,) = guard.getConfigSnapshot(address(safe));
        assertEq(signersCount, expectedSigners, "Safe reports a non-empty signer set");
        (StateMachine.State state,) = guard.getState(address(safe));
        assertEq(uint256(state), uint256(StateMachine.State.Normal), "Safe reports Normal");
    }

    function _assertStillNormal() private view {
        (StateMachine.State state,) = guard.getState(address(safe));
        assertEq(uint256(state), uint256(StateMachine.State.Normal), "trigger did not fire");
    }

    // -------------------------------------------------------------------
    // F-05 - EIP-7702 turns a registered EOA signer into an ERC-1271 signer
    // -------------------------------------------------------------------

    /// @dev CONFIRMED (liveness loss). `panicKey` is registered as a 20-byte identity and
    ///      works. After the EOA gains code - which an EIP-7702 authorisation does,
    ///      entirely outside the Safe and outside Lockdown - `SignatureChecker` takes the
    ///      ERC-1271 branch and the very same correct ECDSA signature stops working.
    ///      The Safe still reports one armed signer.
    function test_confirmed_eip7702DelegationMakesEoaSignerInert() public {
        bytes32 reason = bytes32("wrench");
        bytes memory sig = _signTrigger(safe, PANIC_PK, reason);

        // Pre-condition: the drill passes today.
        assertTrue(guard.testSigner(abi.encodePacked(panicKey), _triggerDigest(address(safe), reason), sig), "armed");

        // The EOA gains code (EIP-7702 delegation), with no Safe or Lockdown tx at all.
        vm.etch(panicKey, address(new NotAn1271Wallet()).code);

        vm.expectRevert(Lockdown.BadSignature.selector);
        guard.triggerLockdown(address(safe), reason, abi.encodePacked(panicKey), sig);

        _assertStillNormal();
        _assertLooksArmed(1);

        // DETECTABLE: the same drill primitive now returns false.
        assertFalse(
            guard.testSigner(abi.encodePacked(panicKey), _triggerDigest(address(safe), reason), sig),
            "testSigner detects the inert signer pre-incident"
        );
    }

    /// @dev CONFIRMED (exclusivity loss), the more alarming half. If the delegation
    ///      target validates everything, the panic trigger becomes PUBLIC: any
    ///      unrelated address can freeze the Safe with arbitrary signature bytes.
    ///      Accepted risk #2 covers 1-of-N grief by a REGISTERED signer; this is an
    ///      UNREGISTERED third party, so it is an escalation beyond the register.
    function test_confirmed_eip7702DelegationCanMakeTriggerPublic() public {
        bytes32 reason = bytes32("hijack");
        vm.etch(panicKey, address(new AlwaysMagic1271()).code);

        vm.prank(address(0xDEADBEEF));
        guard.triggerLockdown(address(safe), reason, abi.encodePacked(panicKey), hex"00");

        (StateMachine.State state,) = guard.getState(address(safe));
        assertEq(uint256(state), uint256(StateMachine.State.LockedDown), "stranger froze the Safe");
    }

    // -------------------------------------------------------------------
    // Registration accepts more than verification requires
    // -------------------------------------------------------------------

    /// @dev CONFIRMED. `_validateSigner` (src/base/LockdownSigners.sol:121-132) requires
    ///      code ONLY for identities longer than 20 bytes. A 20-byte identity is checked
    ///      for `!= address(0)` and nothing else, so an address holding code that does
    ///      not implement ERC-1271 registers cleanly and is inert forever.
    function test_confirmed_20ByteIdentityWithNon1271CodeRegistersButCannotTrigger() public {
        address wallet = address(new NotAn1271Wallet());
        _addSigner(abi.encodePacked(wallet));
        _assertLooksArmed(2);

        bytes32 reason = bytes32("wrench");
        vm.expectRevert(Lockdown.BadSignature.selector);
        guard.triggerLockdown(address(safe), reason, abi.encodePacked(wallet), hex"00");

        _assertStillNormal();
        assertFalse(
            guard.testSigner(abi.encodePacked(wallet), _triggerDigest(address(safe), reason), hex"00"),
            "testSigner detects it pre-incident"
        );
    }

    /// @dev CONFIRMED. A codeless 20-byte identity registers too (only `address(0)` is
    ///      rejected), and is inert because no private key exists for it.
    function test_confirmed_codeless20ByteIdentityRegistersButCannotTrigger() public {
        address ghost = address(0xBEEF);
        _addSigner(abi.encodePacked(ghost));
        _assertLooksArmed(2);

        bytes32 reason = bytes32("wrench");
        vm.expectRevert(Lockdown.BadSignature.selector);
        guard.triggerLockdown(address(safe), reason, abi.encodePacked(ghost), hex"");
        _assertStillNormal();
    }

    /// @dev CONFIRMED. Registration only bounds the key length (`<= 20 + 256`); it never
    ///      asks the verifier whether the key SHAPE is usable. `MockSecretVerifier`
    ///      requires a 32-byte key and returns non-magic for anything else, so a 1-byte
    ///      key registers happily and can never fire.
    function test_confirmed_keyLengthAcceptedAtRegistrationRejectedByVerifier() public {
        MockSecretVerifier verifier = new MockSecretVerifier();
        bytes memory signer = abi.encodePacked(address(verifier), bytes1(0x01));
        _addSigner(signer);
        _assertLooksArmed(2);

        bytes32 reason = bytes32("wrench");
        vm.expectRevert(Lockdown.BadSignature.selector);
        guard.triggerLockdown(address(safe), reason, signer, hex"1234");

        _assertStillNormal();
        assertFalse(
            guard.testSigner(signer, _triggerDigest(address(safe), reason), hex"1234"),
            "testSigner detects the unusable key shape pre-incident"
        );
    }

    // -------------------------------------------------------------------
    // A verifier that was valid at registration and is not at trigger time
    // -------------------------------------------------------------------

    /// @dev CONFIRMED. `_validateSigner` checks verifier code AT REGISTRATION ONLY. A
    ///      verifier that later loses its code (self-destruct in a pre-Cancun sense, or
    ///      simply a mis-managed proxy) leaves an identity that registers as valid and
    ///      cannot fire.
    function test_confirmed_verifierBecomingCodelessAfterRegistrationIsInert() public {
        MockSecretVerifier verifier = new MockSecretVerifier();
        bytes memory secret = "open-sesame";
        bytes memory signer = abi.encodePacked(address(verifier), keccak256(secret));
        _addSigner(signer);

        bytes32 reason = bytes32("wrench");
        assertTrue(guard.testSigner(signer, _triggerDigest(address(safe), reason), secret), "armed at registration");

        vm.etch(address(verifier), hex"");

        vm.expectRevert(Lockdown.BadSignature.selector);
        guard.triggerLockdown(address(safe), reason, signer, secret);

        _assertStillNormal();
        _assertLooksArmed(2);
        assertFalse(
            guard.testSigner(signer, _triggerDigest(address(safe), reason), secret),
            "testSigner detects the dead verifier pre-incident"
        );
    }

    // -------------------------------------------------------------------
    // Domain binding
    // -------------------------------------------------------------------

    /// @dev REFUTED as a silent failure: a signature made for a DIFFERENT Safe simply
    ///      does not verify, and the drill primitive says so. The EIP-712 domain and the
    ///      `safe` field do their job (INV-DOM-1).
    function test_refuted_signatureForAnotherSafeIsRejectedAndDetectable() public {
        Safe otherSafe = _createConfigureAndInitialise(98);
        bytes32 reason = bytes32("wrench");
        bytes memory sigForOther = _signTrigger(otherSafe, PANIC_PK, reason);

        vm.expectRevert(Lockdown.BadSignature.selector);
        guard.triggerLockdown(address(safe), reason, abi.encodePacked(panicKey), sigForOther);

        assertFalse(
            guard.testSigner(abi.encodePacked(panicKey), _triggerDigest(address(safe), reason), sigForOther),
            "detectable"
        );
    }

    /// @dev REFUTED. A FAILED trigger attempt does not burn the identity: the removal is
    ///      rolled back with the revert, so a fumbled attempt under duress does not
    ///      disarm the Safe. This is the reassuring answer to an obvious duress worry.
    function test_refuted_failedTriggerAttemptDoesNotBurnTheSigner() public {
        bytes32 reason = bytes32("wrench");
        vm.expectRevert(Lockdown.BadSignature.selector);
        guard.triggerLockdown(address(safe), reason, abi.encodePacked(panicKey), hex"00");

        assertTrue(guard.isLockdownSigner(address(safe), abi.encodePacked(panicKey)), "signer survives a failed try");
        assertFalse(guard.isSignerBurntPermanently(address(safe), abi.encodePacked(panicKey)), "not burnt");

        // And it still works afterwards.
        _triggerLockdown(safe, reason);
        (StateMachine.State state,) = guard.getState(address(safe));
        assertEq(uint256(state), uint256(StateMachine.State.LockedDown), "still able to fire");
    }

    // -------------------------------------------------------------------
    // The composite: a Safe that is fully "green" and completely inert
    // -------------------------------------------------------------------

    /// @dev The headline. Every observable an operator or the verify script checks is
    ///      green - three slots wired, initialised, Normal, signer count 1 - and the
    ///      Safe has NO working trigger. Only `testSigner`, run with real key material
    ///      against the real digest, separates this from a healthy Safe.
    function test_limitation_fullyGreenSafeCanHaveNoWorkingTrigger() public {
        Safe inert = _createAndConfigure(99);
        address ghost = address(new NotAn1271Wallet());

        address[] memory recoveryOwners = new address[](1);
        recoveryOwners[0] = recovery;
        bytes[] memory signers = new bytes[](1);
        signers[0] = abi.encodePacked(ghost);
        _execAsOwner(
            inert,
            address(guard),
            0,
            abi.encodeCall(Lockdown.initialize, (48 hours, 4 hours, recoveryOwners, signers)),
            Enum.Operation.Call
        );

        // Everything the operator can cheaply observe is green.
        (uint64 duration,,, uint256 signersCount, uint256 recoveryCount) = guard.getConfigSnapshot(address(inert));
        assertGt(duration, 0, "initialised");
        assertEq(signersCount, 1, "reports one armed signer");
        assertEq(recoveryCount, 1, "reports a recovery owner");
        (StateMachine.State state,) = guard.getState(address(inert));
        assertEq(uint256(state), uint256(StateMachine.State.Normal), "Normal");

        // And yet there is no trigger.
        bytes32 reason = bytes32("wrench");
        vm.expectRevert(Lockdown.BadSignature.selector);
        guard.triggerLockdown(address(inert), reason, abi.encodePacked(ghost), hex"00");

        assertFalse(
            guard.testSigner(abi.encodePacked(ghost), _triggerDigest(address(inert), reason), hex"00"),
            "only testSigner distinguishes armed from inert"
        );
    }
}
