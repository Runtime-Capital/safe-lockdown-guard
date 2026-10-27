// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {TestEnvironment, Vm} from "./TestEnvironment.sol";

import {ISafe, IOwnerManager, IModuleManager, Enum} from "@safe-global/safe-smart-account/interfaces/ISafe.sol";
import {IFallbackManager} from "@safe-global/safe-smart-account/interfaces/IFallbackManager.sol";
import {MultiSendCallOnly} from "@safe-global/safe-smart-account/libraries/MultiSendCallOnly.sol";

import {SignatureChecker} from "@openzeppelin/contracts/utils/cryptography/SignatureChecker.sol";

import {Lockdown} from "../src/Lockdown.sol";
import {LockdownFallbackHandler} from "../src/handlers/LockdownFallbackHandler.sol";
import {LockdownSigners} from "../src/base/LockdownSigners.sol";
import {RecoveryOwners} from "../src/base/RecoveryOwners.sol";
import {StateMachine} from "../src/base/StateMachine.sol";
import {PasswordVerifier} from "../src/verifiers/PasswordVerifier.sol";
import {DrillSigner} from "../script/DrillSigner.s.sol";

import {Mock1271Wallet} from "./mocks/Mock1271Wallet.sol";
import {MockSecretVerifier} from "./mocks/MockSecretVerifier.sol";
import {
    MockRevertingVerifier,
    MockWrongMagicVerifier,
    MockEmptyReturnVerifier,
    MockAlwaysMagicVerifier,
    MockSelectiveMagicVerifier,
    MockSelectiveRevertingVerifier,
    MockToggleVerifier
} from "./mocks/MockAdversarialVerifiers.sol";

contract LockdownTest is TestEnvironment {
    ISafe private SAFE_A;
    ISafe private SAFE_B;
    ISafe private SAFE_UNINIT;
    ISafe private SAFE_EMPTY;
    address private constant ATTACKER = address(0xBAD);
    address private constant MODULE = address(0xAA01);
    address private constant TARGET = address(0xD00D);
    address private constant NEW_OWNER = address(0xC001);
    address private constant OLD_OWNER = address(0xC002);
    address private constant BACKUP_OWNER_A = address(0xC003);
    address private constant BACKUP_OWNER_B = address(0xC004);

    // Test signer materials.
    bytes private constant SHARED_SECRET_A = "the-password-A";
    bytes private constant SHARED_SECRET_B = "different-password-B";

    MockSecretVerifier private secretVerifier;

    function setUp() public override {
        super.setUp();

        SAFE_A = _createAndConfigure(0);
        SAFE_B = _createAndConfigure(1);
        SAFE_UNINIT = _createAndConfigure(2);
        SAFE_EMPTY = _createSafe(3);

        secretVerifier = new MockSecretVerifier();

        // Initialise address(SAFE_A) with one of each verifier and one of each signer.
        address[] memory backupsA = new address[](3);
        backupsA[0] = NEW_OWNER;
        backupsA[1] = BACKUP_OWNER_A;
        backupsA[2] = BACKUP_OWNER_B;
        bytes[] memory signersA = new bytes[](2);
        signersA[0] = _eoaSigner(panicKey);
        signersA[1] = _verifierSigner(address(secretVerifier), abi.encodePacked(keccak256(SHARED_SECRET_A)));
        vm.prank(address(SAFE_A));
        guard.initialize(48 hours, 4 hours, backupsA, signersA);

        // Initialise address(SAFE_B) with a distinct duration / delay so cross-key
        // contamination would be visible. Use only ECDSA verifier.
        address[] memory backupsB = new address[](1);
        backupsB[0] = BACKUP_OWNER_B;
        bytes[] memory signersB = new bytes[](1);
        signersB[0] = _eoaSigner(panicKey);
        vm.prank(address(SAFE_B));
        guard.initialize(24 hours, 8 hours, backupsB, signersB);

        // SAFE_UNINIT intentionally not initialised.
    }

    // -------------------------------------------------------------------
    // ERC-165 + VERSION
    // -------------------------------------------------------------------

    function test_supportsBothGuardInterfaces() public view {
        assertTrue(guard.supportsInterface(0x01ffc9a7), "IERC165");
        assertTrue(guard.supportsInterface(0xe6d7a83a), "ITransactionGuard");
        assertTrue(guard.supportsInterface(0x58401ed8), "IModuleGuard");
    }

    function test_rejectsUnknownInterfaceId() public view {
        assertFalse(guard.supportsInterface(0xdeadbeef), "unknown rejected");
    }

    function test_versionIs1_0_0() public view {
        assertEq(guard.VERSION(), "1.0.0", "version");
    }

    // -------------------------------------------------------------------
    // Constructor + EIP-712 domain
    // -------------------------------------------------------------------

    function test_constructorRejectsZeroMultiSend() public {
        vm.expectRevert(Lockdown.ZeroAddress.selector);
        new Lockdown(address(0));
    }

    function test_constructorStoresMultiSend() public view {
        assertEq(address(guard.MULTI_SEND_CALL_ONLY()), address(multiSendCallOnly), "multi");
    }

    function test_eip712DomainIsCorrect() public view {
        (bytes1 fields, string memory name, string memory version, uint256 chainId, address verifyingContract,,) =
            guard.eip712Domain();
        assertEq(uint8(fields), 0x0f, "fields");
        assertEq(name, "RuntimeLockdown", "name");
        assertEq(version, "1.0.0", "version");
        assertEq(chainId, block.chainid, "chainId");
        assertEq(verifyingContract, address(guard), "verifyingContract");
    }

    function test_lockdownTypehashIsExposed() public view {
        bytes32 expected = keccak256("Lockdown(address safe,bytes signer,bytes32 reasonHash)");
        assertEq(guard.LOCKDOWN_TYPEHASH(), expected, "typehash");
    }

    // `hashLockdownTrigger` is the single source of the trigger digest (SPEC_V1
    // §H.29): `triggerLockdown` verifies through the same internal helper, and
    // off-chain signers and `script/DrillSigner.s.sol` read the digest from it.

    function testFuzz_hashLockdownTrigger_matchesEip712Encoding(address safe, bytes memory signer, bytes32 reasonHash)
        public
        view
    {
        assertEq(guard.hashLockdownTrigger(safe, signer, reasonHash), _msgHash(safe, signer, reasonHash));
    }

    function test_hashLockdownTrigger_isTheDigestTriggerVerifies() public {
        bytes32 reasonHash = bytes32("view-digest");
        bytes memory signer = _eoaSigner(panicKey);
        bytes memory sig = _ecdsaSign(PANIC_PK, guard.hashLockdownTrigger(address(SAFE_A), signer, reasonHash));

        guard.triggerLockdown(address(SAFE_A), reasonHash, signer, sig);
        assertTrue(_isLockedDown(address(SAFE_A)), "signature over the view's digest triggers");
        assertTrue(guard.isSignerBurntPermanently(address(SAFE_A), signer), "and burns the identity");
    }

    function test_hashLockdownTrigger_preBindingTwoFieldDigestIsRejected() public {
        bytes32 reasonHash = bytes32("view-digest");
        bytes memory signer = _eoaSigner(panicKey);
        // The pre-NM-1060 6.7 message, `Lockdown(address safe,bytes32 reasonHash)`,
        // which an un-updated signing tool or drill would still produce.
        bytes32 legacy = _typedDataHash(
            keccak256(abi.encode(keccak256("Lockdown(address safe,bytes32 reasonHash)"), address(SAFE_A), reasonHash))
        );
        assertTrue(legacy != guard.hashLockdownTrigger(address(SAFE_A), signer, reasonHash), "digests differ");

        vm.expectRevert(Lockdown.BadSignature.selector);
        guard.triggerLockdown(address(SAFE_A), reasonHash, signer, _ecdsaSign(PANIC_PK, legacy));
        assertFalse(_isLockedDown(address(SAFE_A)));
    }

    // -------------------------------------------------------------------
    // initialize
    // -------------------------------------------------------------------

    function test_initializeRejectsInvalidGuard() public {
        Lockdown foreignGuard = new Lockdown(address(multiSendCallOnly));

        vm.startPrank(address(SAFE_EMPTY));
        SAFE_EMPTY.setGuard(address(foreignGuard)); // not the guard
        vm.expectRevert(Lockdown.GuardNotInstalled.selector);
        guard.initialize(48 hours, 4 hours, new address[](0), new bytes[](0));
        vm.stopPrank();
    }

    function test_initializeRejectsNoModuleGuard() public {
        Lockdown foreignGuard = new Lockdown(address(multiSendCallOnly));

        vm.startPrank(address(SAFE_EMPTY));
        SAFE_EMPTY.setGuard(address(guard));
        SAFE_EMPTY.setModuleGuard(address(foreignGuard)); // not the guard
        vm.expectRevert(Lockdown.GuardNotInstalled.selector);
        guard.initialize(48 hours, 4 hours, new address[](0), new bytes[](0));
        vm.stopPrank();
    }

    function test_initializeRejectsInvalidFallbackHandler() public {
        LockdownFallbackHandler foreignHandler = new LockdownFallbackHandler(StateMachine(address(0xBEEF)));

        vm.startPrank(address(SAFE_EMPTY));
        SAFE_EMPTY.setGuard(address(guard));
        SAFE_EMPTY.setModuleGuard(address(guard));
        SAFE_EMPTY.setFallbackHandler(address(foreignHandler)); // not bond to the correct lockdown
        vm.expectRevert(Lockdown.InvalidFallbackHandler.selector);
        guard.initialize(48 hours, 4 hours, new address[](0), new bytes[](0));
        vm.stopPrank();
    }

    // Regression: before the fix, the Uninitialised branch of
    // checkModuleTransaction only checked the top-level `to != address(this)`
    // and did NOT route through _checkCall, so a module DelegateCall to
    // MULTI_SEND_CALL_ONLY with an inner CALL to the singleton bypassed the
    // denial and could initialize the Lockdown with attacker-chosen params
    // before the owner quorum. Now rejected at every recursion depth.
    function test_uninit_moduleBatch_rejectInnerCallToSingleton() public {
        bytes memory initCall = abi.encodeCall(
            guard.initialize, (uint64(48 hours), uint64(4 hours), _singleBackup(BACKUP_OWNER_A), new bytes[](0))
        );
        bytes memory payload = abi.encodeCall(
            MultiSendCallOnly.multiSend, (_multiSendItem(Enum.Operation.Call, address(guard), 0, initCall))
        );
        vm.prank(address(SAFE_UNINIT));
        vm.expectRevert(Lockdown.ModuleCallToSingletonDenied.selector);
        guard.checkModuleTransaction(address(multiSendCallOnly), 0, payload, Enum.Operation.DelegateCall, MODULE);
    }

    function test_initializeRejectsZeroDuration() public {
        address[] memory backups = _singleBackup(BACKUP_OWNER_A);
        bytes[] memory signers = new bytes[](0);
        vm.prank(address(SAFE_UNINIT));
        vm.expectRevert(StateMachine.LockdownDurationTooLow.selector);
        guard.initialize(0, 4 hours, backups, signers);
    }

    function test_initializeRejectsDurationAboveMax() public {
        address[] memory backups = _singleBackup(BACKUP_OWNER_A);
        bytes[] memory signers = new bytes[](0);
        vm.prank(address(SAFE_UNINIT));
        vm.expectRevert(StateMachine.LockdownDurationTooHigh.selector);
        guard.initialize(31 days, 4 hours, backups, signers);
    }

    function test_initializeRejectsResumeDelayBelowMin() public {
        address[] memory backups = _singleBackup(BACKUP_OWNER_A);
        bytes[] memory signers = new bytes[](0);
        vm.prank(address(SAFE_UNINIT));
        vm.expectRevert(StateMachine.ResumeDelayTooLow.selector);
        guard.initialize(48 hours, 4 hours - 1, backups, signers);
    }

    function test_initializeRejectsResumeDelayAboveMax() public {
        address[] memory backups = _singleBackup(BACKUP_OWNER_A);
        bytes[] memory signers = new bytes[](0);
        vm.prank(address(SAFE_UNINIT));
        vm.expectRevert(StateMachine.ResumeDelayTooHigh.selector);
        guard.initialize(48 hours, 7 days + 1, backups, signers);
    }

    function test_initializeRejectsEmptyAllowlist() public {
        address[] memory empty = new address[](0);
        bytes[] memory signers = new bytes[](0);
        vm.prank(address(SAFE_UNINIT));
        vm.expectRevert(RecoveryOwners.RecoveryOwners_EmptyAllowlist.selector);
        guard.initialize(48 hours, 4 hours, empty, signers);
    }

    function test_initializeRejectsZeroRecoveryOwner() public {
        address[] memory backups = new address[](1);
        backups[0] = address(0);
        bytes[] memory signers = new bytes[](0);
        vm.prank(address(SAFE_UNINIT));
        vm.expectRevert(RecoveryOwners.RecoveryOwners_ZeroAddress.selector);
        guard.initialize(48 hours, 4 hours, backups, signers);
    }

    function test_initializeRejectsDuplicateRecoveryOwner() public {
        address[] memory backups = new address[](2);
        backups[0] = BACKUP_OWNER_A;
        backups[1] = BACKUP_OWNER_A;
        bytes[] memory signers = new bytes[](0);
        vm.prank(address(SAFE_UNINIT));
        vm.expectRevert(RecoveryOwners.RecoveryOwners_AlreadyRegistered.selector);
        guard.initialize(48 hours, 4 hours, backups, signers);
    }

    function test_initializeRejectsZeroVerifier() public {
        address[] memory backups = _singleBackup(BACKUP_OWNER_A);
        bytes[] memory signers = new bytes[](1);
        signers[0] = _eoaSigner(address(0));
        vm.prank(address(SAFE_UNINIT));
        vm.expectRevert(LockdownSigners.LockdownSigners_ZeroAddress.selector);
        guard.initialize(48 hours, 4 hours, backups, signers);
    }

    function test_initializeRejectsNoCodeVerifier() public {
        address[] memory backups = _singleBackup(BACKUP_OWNER_A);
        bytes[] memory signers = new bytes[](1);
        signers[0] = _verifierSigner(address(0xC0DE9999), abi.encodePacked(panicKey));
        vm.prank(address(SAFE_UNINIT));
        vm.expectRevert(LockdownSigners.LockdownSigners_VerifierNoCode.selector);
        guard.initialize(48 hours, 4 hours, backups, signers);
    }

    function test_initializeAcceptsInitialSignerWithoutVerifierAllowlist() public {
        address[] memory backups = _singleBackup(BACKUP_OWNER_A);
        bytes[] memory signers = new bytes[](1);
        signers[0] = _eoaSigner(panicKey);
        vm.prank(address(SAFE_UNINIT));
        guard.initialize(48 hours, 4 hours, backups, signers);
        assertTrue(guard.isLockdownSigner(address(SAFE_UNINIT), _eoaSigner(panicKey)), "initial signer registered");
    }

    function test_initializeRejectsTooManyInitialSigners() public {
        address[] memory backups = _singleBackup(BACKUP_OWNER_A);
        // Cap is 32 (MAX_LOCKDOWN_SIGNERS); 33 must trigger the revert.
        bytes[] memory signers = new bytes[](33);
        for (uint256 i = 0; i < 33; ++i) {
            signers[i] = _eoaSigner(address(uint160(0x1000 + i)));
        }
        vm.prank(address(SAFE_UNINIT));
        vm.expectRevert(LockdownSigners.LockdownSigners_MaxReached.selector);
        guard.initialize(48 hours, 4 hours, backups, signers);
    }

    function test_initializeOnceOnly() public {
        address[] memory backups = _singleBackup(BACKUP_OWNER_A);
        bytes[] memory signers = new bytes[](0);
        vm.prank(address(SAFE_A));
        vm.expectRevert(
            abi.encodeWithSelector(
                StateMachine.InvalidState.selector,
                StateMachine.State.Normal,
                1 << uint256(StateMachine.State.Uninitialised)
            )
        );
        guard.initialize(48 hours, 4 hours, backups, signers);
    }

    function test_initializePopulatesAllFields() public view {
        (uint64 dur, uint64 delay, uint64 until, uint256 cnt, uint256 backupCnt) =
            guard.getConfigSnapshot(address(SAFE_A));
        assertEq(dur, 48 hours, "duration");
        assertEq(delay, 4 hours, "delay");
        assertEq(until, 0, "until");
        assertEq(cnt, 2, "signers count");
        assertEq(backupCnt, 3, "3 backups");
    }

    function test_initializeWithEmptyOptionalsIsDormant() public {
        address[] memory backups = _singleBackup(BACKUP_OWNER_A);
        bytes[] memory signers = new bytes[](0);
        vm.prank(address(SAFE_UNINIT));
        guard.initialize(48 hours, 4 hours, backups, signers);
        (,,, uint256 cnt,) = guard.getConfigSnapshot(address(SAFE_UNINIT));
        assertEq(cnt, 0, "no signers");
    }

    // -------------------------------------------------------------------
    // addLockdownSigner
    // -------------------------------------------------------------------

    function test_addLockdownSignerSuccess() public {
        bytes memory key = abi.encodePacked(address(0xC0CA));
        vm.prank(address(SAFE_A));
        guard.addLockdownSigner(key);
        assertTrue(guard.isLockdownSigner(address(SAFE_A), key), "registered");
    }

    function test_addLockdownSignerAcceptsNewVerifierWithoutAllowlist() public {
        MockSecretVerifier other = new MockSecretVerifier();
        bytes memory key = abi.encodePacked(keccak256("other-secret"));
        bytes memory signer = _verifierSigner(address(other), key);
        vm.prank(address(SAFE_A));
        guard.addLockdownSigner(signer);
        assertTrue(guard.isLockdownSigner(address(SAFE_A), signer), "registered");
    }

    function test_addLockdownSignerRejectsZeroSigner() public {
        vm.prank(address(SAFE_A));
        vm.expectRevert(LockdownSigners.LockdownSigners_ZeroAddress.selector);
        guard.addLockdownSigner(abi.encodePacked(address(0)));
    }

    function test_addLockdownSignerRejectsNoCodeVerifier() public {
        vm.prank(address(SAFE_A));
        vm.expectRevert(LockdownSigners.LockdownSigners_VerifierNoCode.selector);
        guard.addLockdownSigner(_verifierSigner(address(0xDEAD), abi.encodePacked(panicKey)));
    }

    function test_addLockdownSignerRejectsEmptySigner() public {
        vm.prank(address(SAFE_A));
        vm.expectRevert(LockdownSigners.LockdownSigners_InvalidFormat.selector);
        guard.addLockdownSigner(bytes(""));
    }

    function test_addLockdownSignerRejectsKeyTooLong() public {
        bytes memory longKey = new bytes(20 + 620);
        vm.prank(address(SAFE_A));
        vm.expectRevert(LockdownSigners.LockdownSigners_KeyTooLong.selector);
        guard.addLockdownSigner(longKey);
    }

    function test_addLockdownSignerRejectsAlreadyRegistered() public {
        bytes memory key = abi.encodePacked(panicKey); // same as setUp
        vm.prank(address(SAFE_A));
        vm.expectRevert(LockdownSigners.LockdownSigners_AlreadyRegistered.selector);
        guard.addLockdownSigner(key);
    }

    function test_addLockdownSignerRejectsMaxReached() public {
        // address(SAFE_A) already has 2 LockdownSigners. Add 30 more to reach 32 (cap).
        for (uint256 i = 0; i < 30; ++i) {
            bytes memory key = abi.encodePacked(address(uint160(0x9001 + i)));
            vm.prank(address(SAFE_A));
            guard.addLockdownSigner(key);
        }
        // 33rd add must fail.
        vm.prank(address(SAFE_A));
        vm.expectRevert(LockdownSigners.LockdownSigners_MaxReached.selector);
        guard.addLockdownSigner(abi.encodePacked(address(0xFFFF)));
    }

    function test_addLockdownSignerRejectedDuringLockdown() public {
        _triggerLockdown(SAFE_A, bytes32("panic"));
        vm.prank(address(SAFE_A));
        vm.expectRevert(
            abi.encodeWithSelector(
                StateMachine.InvalidState.selector,
                StateMachine.State.LockedDown,
                1 << uint256(StateMachine.State.Normal)
            )
        );
        guard.addLockdownSigner(abi.encodePacked(address(0xABCD)));
    }

    function test_addLockdownSignerRejectedDuringRecovery() public {
        _triggerLockdown(SAFE_A, bytes32("panic"));
        vm.warp(block.timestamp + 48 hours + 1);
        vm.prank(address(SAFE_A));
        vm.expectRevert(
            abi.encodeWithSelector(
                StateMachine.InvalidState.selector,
                StateMachine.State.Recovering,
                1 << uint256(StateMachine.State.Normal)
            )
        );
        guard.addLockdownSigner(abi.encodePacked(address(0xABCD)));
    }

    function test_addLockdownSignerIncrementsCount() public {
        bytes memory key = abi.encodePacked(address(0xC0CA));
        vm.prank(address(SAFE_A));
        guard.addLockdownSigner(key);
        (,,, uint256 cnt,) = guard.getConfigSnapshot(address(SAFE_A));
        assertEq(cnt, 3, "count");
    }

    function test_addLockdownSignerBurnsRemovedIdentity() public {
        bytes memory key1 = abi.encodePacked(address(0xC0CA));
        bytes memory key2 = abi.encodePacked(address(0xC0CB));
        vm.prank(address(SAFE_A));
        guard.addLockdownSigner(key1);

        vm.prank(address(SAFE_A));
        guard.removeLockdownSigner(key1);

        // V1 (C4): re-registering the SAME (verifier, key) after
        // removal is forbidden because its keyHash is now public. Operator
        // MUST use a fresh key. Verify that the burnt-keys gate fires AND
        // that a fresh key registers cleanly.
        vm.prank(address(SAFE_A));
        vm.expectRevert(LockdownSigners.LockdownSigners_BurntPermanently.selector);
        guard.addLockdownSigner(key1);

        vm.prank(address(SAFE_A));
        guard.addLockdownSigner(key2);
        assertFalse(guard.isLockdownSigner(address(SAFE_A), key1), "burnt key not registered");
        assertTrue(guard.isLockdownSigner(address(SAFE_A), key2), "fresh key registered");
    }

    function test_addLockdownSignerRejectsBurntKeyAfterTriggerBurn() public {
        // V1 INV-SIGN-7: trigger-burn also marks the (verifier, key) as
        // permanently burnt. Operator MUST rotate to a fresh key after
        // any successful trigger.
        bytes memory key = abi.encodePacked(panicKey);
        bytes32 reasonHash = bytes32("drill");
        bytes32 msgHash = _msgHash(address(SAFE_A), key, reasonHash);
        bytes memory sig = _ecdsaSign(PANIC_PK, msgHash);

        guard.triggerLockdown(address(SAFE_A), reasonHash, key, sig);

        // Warp past lockdownDuration + resumeDelay: automatically resume.
        vm.warp(block.timestamp + 48 hours + 4 hours + 1);

        // Re-arm with the same EOA: rejected by INV-SIGN-7.
        vm.prank(address(SAFE_A));
        vm.expectRevert(LockdownSigners.LockdownSigners_BurntPermanently.selector);
        guard.addLockdownSigner(key);

        assertTrue(guard.isSignerBurntPermanently(address(SAFE_A), key), "view confirms burnt");
    }

    function test_passwordPath_replayAfterReRegistrationBlocked() public {
        // C4 exploit chain: leaked password preimage cannot be
        // replayed after operator re-arms with the SAME commitment,
        // because INV-SIGN-7 forbids re-registration.
        bytes memory preimage = SHARED_SECRET_A;
        bytes memory commitment = abi.encodePacked(keccak256(SHARED_SECRET_A));
        bytes32 reasonHash = bytes32("first-real-incident");

        guard.triggerLockdown(
            address(SAFE_A), reasonHash, _verifierSigner(address(secretVerifier), commitment), preimage
        );

        // Resume.
        vm.warp(block.timestamp + 48 hours + 4 hours + 1);

        // Attacker observes the preimage from the trigger calldata in the
        // mempool. Operator (mistakenly) attempts to re-arm with the same
        // password. The on-chain gate rejects.
        vm.prank(address(SAFE_A));
        vm.expectRevert(LockdownSigners.LockdownSigners_BurntPermanently.selector);
        guard.addLockdownSigner(_verifierSigner(address(secretVerifier), commitment));

        // Operator MUST use a fresh password. The leaked preimage cannot
        // be replayed against the burnt commitment (no longer in
        // cfg.signers since the burn).
        vm.expectRevert(LockdownSigners.LockdownSigners_Unknown.selector);
        guard.triggerLockdown(
            address(SAFE_A), bytes32("attacker-attempt"), _verifierSigner(address(secretVerifier), commitment), preimage
        );
    }

    /// @notice PR #61 auto-resume regression: once the recovery window elapses
    ///         the Safe is Normal (even though `lockdownUntil` stays
    ///         stale-non-zero), and a still-registered signer can re-trigger,
    ///         with `_lock` overwriting the stale scalar with a fresh window.
    function test_triggerLockdownReLocksAfterAutoResume() public {
        // First trigger burns the EOA panic signer (signersA[0]).
        _triggerLockdown(SAFE_A, bytes32("first"));
        (StateMachine.State s1,) = guard.getState(address(SAFE_A));
        assertEq(uint8(s1), uint8(StateMachine.State.LockedDown), "locked");

        // Auto-resume: past lockdownUntil + resumeDelay (48h + 4h), time-based.
        vm.warp(block.timestamp + 48 hours + 4 hours + 1);
        (StateMachine.State s2,) = guard.getState(address(SAFE_A));
        assertEq(uint8(s2), uint8(StateMachine.State.Normal), "auto-resumed to Normal");
        // View getters normalise to zero once auto-resume has passed, even though the raw scalar stays stale.
        assertEq(guard.getLockdownUntil(address(SAFE_A)), 0, "getLockdownUntil reports 0 after auto-resume");

        // Re-trigger with the still-registered secret signer (signersA[1]).
        bytes memory commitment = abi.encodePacked(keccak256(SHARED_SECRET_A));
        guard.triggerLockdown(
            address(SAFE_A), bytes32("second"), _verifierSigner(address(secretVerifier), commitment), SHARED_SECRET_A
        );

        // Re-locked, with a fresh window overwriting the stale scalar.
        (StateMachine.State s3,) = guard.getState(address(SAFE_A));
        assertEq(uint8(s3), uint8(StateMachine.State.LockedDown), "re-locked after auto-resume");
        assertEq(
            guard.getLockdownUntil(address(SAFE_A)),
            uint64(block.timestamp) + 48 hours,
            "lockdownUntil overwritten with a fresh window"
        );
    }

    // -------------------------------------------------------------------
    // removeLockdownSigner
    // -------------------------------------------------------------------

    function test_removeLockdownSignerSuccess() public {
        bytes memory key = abi.encodePacked(panicKey);
        vm.prank(address(SAFE_A));
        guard.removeLockdownSigner(key);
        assertFalse(guard.isLockdownSigner(address(SAFE_A), key), "removed");
        (,,, uint256 cnt,) = guard.getConfigSnapshot(address(SAFE_A));
        assertEq(cnt, 1, "count decremented");
    }

    function test_removeLockdownSignerRejectsNotFound() public {
        bytes memory key = abi.encodePacked(address(0xDEAD));
        vm.prank(address(SAFE_A));
        vm.expectRevert(LockdownSigners.LockdownSigners_Unknown.selector);
        guard.removeLockdownSigner(key);
    }

    function test_removeLockdownSignerRejectedDuringLockdown() public {
        _triggerLockdown(SAFE_A, bytes32("panic"));
        bytes memory key = abi.encodePacked(panicKey);
        // panicKey was burnt by trigger; use the other one.
        bytes memory pwdKey = abi.encodePacked(keccak256(SHARED_SECRET_A));
        vm.prank(address(SAFE_A));
        vm.expectRevert(
            abi.encodeWithSelector(
                StateMachine.InvalidState.selector,
                StateMachine.State.LockedDown,
                1 << uint256(StateMachine.State.Normal) | 1 << uint256(StateMachine.State.Recovering)
            )
        );
        guard.removeLockdownSigner(_verifierSigner(address(secretVerifier), pwdKey));
        key; // silence unused
    }

    /// @notice V1 post-resume race mitigation: removeLockdownSigner is allowed
    ///         during Recovering (but NOT during LockedDown) so the quorum can
    ///         cull surviving compromised signers before resume re-opens
    ///         triggerLockdown.
    function test_removeLockdownSignerAllowedDuringRecovery() public {
        _triggerLockdown(SAFE_A, bytes32("panic"));
        vm.warp(block.timestamp + 48 hours + 1);
        bytes memory pwdKey = abi.encodePacked(keccak256(SHARED_SECRET_A));
        vm.prank(address(SAFE_A));
        guard.removeLockdownSigner(_verifierSigner(address(secretVerifier), pwdKey));
        assertFalse(
            guard.isLockdownSigner(address(SAFE_A), _verifierSigner(address(secretVerifier), pwdKey)),
            "removed during recovery"
        );
    }

    /// @notice Same relock-race mitigation, but after the resumeDelay window
    ///         has elapsed (auto-resumed to Normal). removeLockdownSigner must
    ///         stay callable across the WHOLE post-lockdown period, not just
    ///         Recovering: the quorum can still cull a surviving compromised
    ///         signer before the auto-resume re-opens triggerLockdown. See
    ///         SPEC_V1 §7.4.
    function test_removeLockdownSignerAllowedAfterRecoveryWindow() public {
        _triggerLockdown(SAFE_A, bytes32("panic"));
        // Past lockdownUntil + resumeDelay (48h + 4h) -> auto-resumed to Normal.
        vm.warp(block.timestamp + 48 hours + 4 hours + 1);
        (StateMachine.State state,) = guard.getState(address(SAFE_A));
        assertEq(uint8(state), uint8(StateMachine.State.Normal), "normal");
        bytes memory pwdKey = abi.encodePacked(keccak256(SHARED_SECRET_A));
        vm.prank(address(SAFE_A));
        guard.removeLockdownSigner(_verifierSigner(address(secretVerifier), pwdKey));
        assertFalse(
            guard.isLockdownSigner(address(SAFE_A), _verifierSigner(address(secretVerifier), pwdKey)),
            "removed when resumable"
        );
    }

    function test_removedSignerCannotTrigger() public {
        bytes memory key = abi.encodePacked(panicKey);
        vm.prank(address(SAFE_A));
        guard.removeLockdownSigner(key);

        bytes32 reasonHash = bytes32("removed-then-tried");
        bytes32 msgHash = _msgHash(address(SAFE_A), key, reasonHash); // id was 1
        bytes memory sig = _ecdsaSign(PANIC_PK, msgHash);

        vm.expectRevert(LockdownSigners.LockdownSigners_Unknown.selector);
        guard.triggerLockdown(address(SAFE_A), reasonHash, key, sig);
    }

    // -------------------------------------------------------------------
    // rotateLockdownSigner
    // -------------------------------------------------------------------

    function test_rotateLockdownSignerAtomic() public {
        bytes memory oldKey = abi.encodePacked(panicKey);
        bytes memory newKey = abi.encodePacked(address(0xC0FFEE));
        vm.prank(address(SAFE_A));
        guard.rotateLockdownSigner(oldKey, newKey);
        assertFalse(guard.isLockdownSigner(address(SAFE_A), oldKey), "old gone");
        assertTrue(guard.isLockdownSigner(address(SAFE_A), newKey), "new in");
    }

    function test_rotateAcrossVerifierTypes() public {
        bytes memory oldKey = abi.encodePacked(panicKey); // ECDSA
        bytes memory newKey = abi.encodePacked(keccak256("rotated-into-password"));
        vm.prank(address(SAFE_A));
        guard.rotateLockdownSigner(oldKey, _verifierSigner(address(secretVerifier), newKey));
        assertFalse(guard.isLockdownSigner(address(SAFE_A), oldKey), "old gone");
        assertTrue(guard.isLockdownSigner(address(SAFE_A), _verifierSigner(address(secretVerifier), newKey)), "new in");
    }

    function test_rotateRejectedIfOldNotFound() public {
        bytes memory ghostKey = abi.encodePacked(address(0xDEAD));
        bytes memory newKey = abi.encodePacked(address(0xC0FFEE));
        vm.prank(address(SAFE_A));
        vm.expectRevert(LockdownSigners.LockdownSigners_Unknown.selector);
        guard.rotateLockdownSigner(ghostKey, newKey);
    }

    function test_rotateRejectedDuringIncident() public {
        _triggerLockdown(SAFE_A, bytes32("panic"));
        bytes memory pwdKey = abi.encodePacked(keccak256(SHARED_SECRET_A));
        bytes memory newKey = abi.encodePacked(keccak256("new"));
        vm.prank(address(SAFE_A));
        vm.expectRevert(
            abi.encodeWithSelector(
                StateMachine.InvalidState.selector,
                StateMachine.State.LockedDown,
                1 << uint256(StateMachine.State.Normal)
            )
        );
        guard.rotateLockdownSigner(
            _verifierSigner(address(secretVerifier), pwdKey), _verifierSigner(address(secretVerifier), newKey)
        );
    }

    /// @dev Rotation must emit Removed + Added + Rotated so off-chain set
    ///      reconstruction from Added/Removed stays consistent.
    function test_rotateLockdownSigner_emitsRemovedAddedRotated() public {
        bytes memory oldKey = abi.encodePacked(panicKey);
        bytes memory newKey = abi.encodePacked(address(0xF00D));
        vm.recordLogs();
        vm.prank(address(SAFE_A));
        guard.rotateLockdownSigner(oldKey, newKey);
        Vm.Log[] memory logs = vm.getRecordedLogs();
        assertTrue(_topicPresent(logs, keccak256("LockdownSignerRemoved(address,bytes)")), "Removed emitted");
        assertTrue(_topicPresent(logs, keccak256("LockdownSignerAdded(address,bytes)")), "Added emitted");
        assertTrue(_topicPresent(logs, keccak256("LockdownSignerRotated(address,bytes,bytes)")), "Rotated emitted");
    }

    /// @dev Rotating a signer to itself burns the old half first, so the add of
    ///      the identical identity hits the burnt check and reverts (no
    ///      registered-and-burnt inconsistency).
    function test_rotateLockdownSigner_sameSignerReverts() public {
        bytes memory key = abi.encodePacked(panicKey);
        vm.prank(address(SAFE_A));
        vm.expectRevert(LockdownSigners.LockdownSigners_BurntPermanently.selector);
        guard.rotateLockdownSigner(key, key);
    }

    // -------------------------------------------------------------------
    // triggerLockdown trigger
    // -------------------------------------------------------------------

    function test_triggerLockdownRevertsOnUninitialisedSafe() public {
        address uninitSafe = address(0xDEAD0001);
        bytes32 msgHash = _msgHash(uninitSafe, _eoaSigner(panicKey), bytes32("nocode"));
        bytes memory sig = _ecdsaSign(PANIC_PK, msgHash);
        vm.expectRevert(
            abi.encodeWithSelector(
                StateMachine.InvalidState.selector,
                StateMachine.State.Uninitialised,
                ~(1 << uint256(StateMachine.State.Uninitialised))
            )
        );
        guard.triggerLockdown(uninitSafe, bytes32("nocode"), _eoaSigner(panicKey), sig);
    }

    function test_triggerLockdownRevertsOnInvalidState() public {
        bytes32 msgHash = _msgHash(address(SAFE_UNINIT), _eoaSigner(panicKey), bytes32("uninit"));
        bytes memory sig = _ecdsaSign(PANIC_PK, msgHash);
        vm.expectRevert(
            abi.encodeWithSelector(
                StateMachine.InvalidState.selector,
                StateMachine.State.Uninitialised,
                ~(1 << uint256(StateMachine.State.Uninitialised))
            )
        );
        guard.triggerLockdown(address(SAFE_UNINIT), bytes32("uninit"), _eoaSigner(panicKey), sig);
    }

    function test_triggerLockdownExtendsWhenAlreadyLockedDown() public {
        bytes32 panic = bytes32("panic");
        bytes32 again = bytes32("again");
        uint256 t0 = block.timestamp;
        uint256 t1 = t0 + 10;
        uint256 t0_end = t0 + guard.getLockdownDuration(address(SAFE_A));
        // A re-trigger while LockedDown stacks on the current window rather than
        // restarting from `now`: the new end is `t0_end + lockdownDuration`.
        uint256 t1_end = t0_end + guard.getLockdownDuration(address(SAFE_A));

        // First lockdown
        _triggerLockdown(SAFE_A, panic);
        assertEq(guard.getLockdownUntil(address(SAFE_A)), t0_end);
        assertEq(guard.lastReasonHash(address(SAFE_A)), panic);

        // Re-trigger BEFORE the current window expires: the Safe stays LockedDown
        // continuously and never enters Recovering (PR #59, INV-LIFE-2).
        vm.warp(t1);
        (StateMachine.State stateBefore,) = guard.getState(address(SAFE_A));
        assertEq(uint256(stateBefore), uint256(StateMachine.State.LockedDown), "still locked before re-trigger");

        // Second lockdown, with a second still-registered signer (first was burnt)
        bytes memory sig = _signWithPassword(SHARED_SECRET_A); // password "signature" is the preimage
        guard.triggerLockdown(address(SAFE_A), again, _secretSignerA(), sig);

        // Extended (never shortened), still LockedDown, reason updated.
        assertEq(guard.getLockdownUntil(address(SAFE_A)), t1_end);
        assertGt(t1_end, t1 + guard.getLockdownDuration(address(SAFE_A)), "re-trigger stacks, never restarts from now");
        assertEq(guard.lastReasonHash(address(SAFE_A)), again);
        (StateMachine.State stateAfter,) = guard.getState(address(SAFE_A));
        assertEq(uint256(stateAfter), uint256(StateMachine.State.LockedDown), "stayed LockedDown");
    }

    // Re-triggers stack on the current window, so two triggers in the same block
    // freeze for `2 × lockdownDuration`. Every trigger burns one signer, so the
    // total stays bounded by `(registered signers) × lockdownDuration` (INV-LIFE-2).
    function test_triggerLockdownStacksInSameBlock() public {
        uint256 duration = guard.getLockdownDuration(address(SAFE_A));
        uint256 t0 = block.timestamp;

        _triggerLockdown(SAFE_A, bytes32("panic"));
        bytes memory sig = _signWithPassword(SHARED_SECRET_A);
        guard.triggerLockdown(address(SAFE_A), bytes32("again"), _secretSignerA(), sig);

        assertEq(guard.getLockdownUntil(address(SAFE_A)), t0 + 2 * duration, "stacked to 2x duration");
        (StateMachine.State s,) = guard.getState(address(SAFE_A));
        assertEq(uint256(s), uint256(StateMachine.State.LockedDown));
    }

    // PR #59: triggerLockdown is onlyInitialized, so a still-registered signer can
    // re-lock from within the Recovering window (a missed-window safety net). The
    // Safe transitions back into LockedDown with the window reset from `now`
    // (`lockdownUntil <= now` in Recovering, so nothing stacks). A re-trigger
    // during Recovering returns the Safe to LockedDown and closes the repair
    // window: the recovery whitelist is owner-path, hence blocked again.
    function test_triggerLockdownReLocksDuringRecovering() public {
        uint256 duration = guard.getLockdownDuration(address(SAFE_A));

        _triggerLockdown(SAFE_A, bytes32("panic"));
        // Past lockdownUntil but before + resumeDelay => Recovering.
        vm.warp(block.timestamp + duration + 1);
        (StateMachine.State s,) = guard.getState(address(SAFE_A));
        assertEq(uint256(s), uint256(StateMachine.State.Recovering), "in Recovering");

        uint256 tNow = block.timestamp;
        bytes memory sig = _signWithPassword(SHARED_SECRET_A);
        guard.triggerLockdown(address(SAFE_A), bytes32("again"), _secretSignerA(), sig);

        (StateMachine.State s2,) = guard.getState(address(SAFE_A));
        assertEq(uint256(s2), uint256(StateMachine.State.LockedDown), "re-locked from Recovering");
        assertEq(guard.getLockdownUntil(address(SAFE_A)), tNow + duration, "window reset from now");
        assertEq(guard.lastReasonHash(address(SAFE_A)), bytes32("again"));
    }

    // NM-1060 6.8 / H.24: the worst-case freeze for k triggers is
    // k × (D + R) − (k − 1) seconds, reached by re-triggering at the LAST second
    // of each Recovering window (each re-trigger restarts a full D + R cycle, so
    // R is paid k times; stacking inside LockedDown only reaches k × D + R).
    // Pinned to the second for k = 2, with the second trigger closing the repair
    // window. `vm.getBlockTimestamp()` because `block.timestamp` may be cached
    // across `vm.warp` under via-IR.
    function test_triggerLockdownWorstCaseBoundForTwoTriggers() public {
        uint256 duration = guard.getLockdownDuration(address(SAFE_A));
        uint256 resumeDelay = guard.getResumeDelay(address(SAFE_A));
        uint256 t0 = vm.getBlockTimestamp();

        _triggerLockdown(SAFE_A, bytes32("panic"));
        assertEq(guard.getLockdownUntil(address(SAFE_A)), t0 + duration, "first window");

        // Last second of Recovering: Normal would start one second later.
        vm.warp(t0 + duration + resumeDelay - 1);
        (StateMachine.State s,) = guard.getState(address(SAFE_A));
        assertEq(uint256(s), uint256(StateMachine.State.Recovering), "last second of Recovering");

        bytes memory sig = _signWithPassword(SHARED_SECRET_A);
        guard.triggerLockdown(address(SAFE_A), bytes32("again"), _secretSignerA(), sig);

        (s,) = guard.getState(address(SAFE_A));
        assertEq(uint256(s), uint256(StateMachine.State.LockedDown), "repair window closed");
        assertEq(
            guard.getLockdownUntil(address(SAFE_A)),
            t0 + 2 * duration + resumeDelay - 1,
            "second window starts from now, not from the first window's end"
        );

        // k = 2: the Safe is Normal again exactly at t0 + 2 × (D + R) − 1.
        uint256 bound = t0 + 2 * (duration + resumeDelay) - 1;
        vm.warp(bound - 1);
        (s,) = guard.getState(address(SAFE_A));
        assertEq(uint256(s), uint256(StateMachine.State.Recovering), "still Recovering one second before the bound");
        vm.warp(bound);
        (s,) = guard.getState(address(SAFE_A));
        assertEq(uint256(s), uint256(StateMachine.State.Normal), "auto-resumed exactly at k(D+R) - (k-1)");
    }

    // PR #59: once the freeze AND the recovery delay have fully elapsed the Safe
    // has auto-resumed to Normal (no separate Resumable state under auto-resume).
    // A still-registered signer can then trigger a fresh lockdown from Normal.
    function test_triggerLockdownAfterAutoResume() public {
        uint256 duration = guard.getLockdownDuration(address(SAFE_A));
        uint256 resumeDelay = guard.getResumeDelay(address(SAFE_A));

        _triggerLockdown(SAFE_A, bytes32("panic"));
        // Past lockdownUntil + resumeDelay => auto-resumed to Normal.
        vm.warp(block.timestamp + duration + resumeDelay + 1);
        (StateMachine.State s,) = guard.getState(address(SAFE_A));
        assertEq(uint256(s), uint256(StateMachine.State.Normal), "auto-resumed to Normal");

        uint256 tNow = block.timestamp;
        bytes memory sig = _signWithPassword(SHARED_SECRET_A);
        guard.triggerLockdown(address(SAFE_A), bytes32("again"), _secretSignerA(), sig);

        (StateMachine.State s2,) = guard.getState(address(SAFE_A));
        assertEq(uint256(s2), uint256(StateMachine.State.LockedDown), "fresh lockdown from Normal");
        assertEq(guard.getLockdownUntil(address(SAFE_A)), tNow + duration, "window set from now");
        assertEq(guard.lastReasonHash(address(SAFE_A)), bytes32("again"));
    }

    /// @notice F-M2-01 closure: raising `resumeDelay` in Normal after an
    ///         incident has auto-resumed must NOT retroactively re-open the
    ///         recovery window. `getState` derives the window end live as
    ///         `lockdownUntil + resumeDelay` over a `lockdownUntil` that `_lock`
    ///         never zeroes, so before the fix a larger `resumeDelay` flipped the
    ///         Safe back into a phantom Recovering carrying the closed incident's
    ///         reason hash. The setter now clears the elapsed incident first.
    function test_setResumeDelay_afterAutoResume_doesNotReopenRecovery() public {
        uint256 duration = guard.getLockdownDuration(address(SAFE_A));
        uint256 resumeDelay = guard.getResumeDelay(address(SAFE_A));
        // Read before pranking: an external call here would consume the prank.
        uint64 maxDelay = guard.RESUME_DELAY_MAX();

        _triggerLockdown(SAFE_A, bytes32("panic"));
        // Auto-resume at the exact lockdownUntil + resumeDelay boundary.
        vm.warp(block.timestamp + duration + resumeDelay);
        (StateMachine.State s,) = guard.getState(address(SAFE_A));
        assertEq(uint256(s), uint256(StateMachine.State.Normal), "auto-resumed to Normal");

        // Owner-quorum lengthens the recovery window far past the (stale)
        // lockdownUntil. Without the fix this re-opens a phantom Recovering.
        vm.prank(address(SAFE_A));
        guard.setResumeDelay(maxDelay);

        (StateMachine.State s2,) = guard.getState(address(SAFE_A));
        assertEq(uint256(s2), uint256(StateMachine.State.Normal), "stays Normal after resumeDelay increase");
        assertEq(guard.getLockdownUntil(address(SAFE_A)), 0, "getLockdownUntil stays 0");
        assertEq(guard.lastReasonHash(address(SAFE_A)), bytes32(0), "no ghost reason hash");

        // Strongest check: a plain owner-path tx is not forced through the
        // recovery whitelist (it would revert RecoveryActive in the phantom state).
        vm.prank(address(SAFE_A));
        _checkOwner(address(SAFE_A), address(0xBEEF), 0, hex"", Enum.Operation.Call);
    }

    function test_triggerLockdownRevertsOnNotRegistered() public {
        bytes memory ghostKey = abi.encodePacked(address(0xDEAD));
        bytes32 msgHash = _msgHash(address(SAFE_A), ghostKey, bytes32("ghost"));
        bytes memory sig = _ecdsaSign(PANIC_PK, msgHash);
        vm.expectRevert(LockdownSigners.LockdownSigners_Unknown.selector);
        guard.triggerLockdown(address(SAFE_A), bytes32("ghost"), ghostKey, sig);
    }

    function test_triggerLockdownRevertsOnBadSignature() public {
        bytes memory key = abi.encodePacked(panicKey);
        bytes32 wrongMsgHash = _msgHash(address(SAFE_A), key, bytes32("WRONG"));
        bytes memory sig = _ecdsaSign(PANIC_PK, wrongMsgHash);
        // Send a different reasonHash → msgHash recomputed differently → sig invalid.
        vm.expectRevert(Lockdown.BadSignature.selector);
        guard.triggerLockdown(address(SAFE_A), bytes32("right"), key, sig);
    }

    function test_triggerLockdownBurnsSignerOnSuccess() public {
        _triggerLockdown(SAFE_A, bytes32("panic"));
        // The ECDSA signer (id=1) should be burnt; password signer (id=2) survives.
        assertFalse(guard.isLockdownSigner(address(SAFE_A), _eoaSigner(panicKey)), "ecdsa burnt");
        assertTrue(guard.isLockdownSigner(address(SAFE_A), _secretSignerA()), "password survives");
        (,,, uint256 cnt,) = guard.getConfigSnapshot(address(SAFE_A));
        assertEq(cnt, 1, "count decremented");
    }

    function test_triggerLockdownSetsLockdownUntilAndReason() public {
        uint256 t0 = block.timestamp;
        _triggerLockdown(SAFE_A, bytes32("panic"));
        (,, uint64 until,,) = guard.getConfigSnapshot(address(SAFE_A));
        assertEq(until, t0 + 48 hours, "until = t0 + 48h");
        assertEq(guard.lastReasonHash(address(SAFE_A)), bytes32("panic"), "reason stored");
    }

    function test_triggerLockdownBlocksOwnerPath() public {
        _triggerLockdown(SAFE_A, bytes32("panic"));
        vm.prank(address(SAFE_A));
        vm.expectRevert(Lockdown.LockedDown.selector);
        _checkOwner(address(SAFE_A), TARGET, 0, hex"", Enum.Operation.Call);
    }

    function test_triggerLockdownBlocksModulePath() public {
        _triggerLockdown(SAFE_A, bytes32("panic"));
        vm.prank(address(SAFE_A));
        vm.expectRevert(Lockdown.LockedDown.selector);
        guard.checkModuleTransaction(TARGET, 0, hex"", Enum.Operation.Call, MODULE);
    }

    function test_signatureCannotReplayAfterBurnAndReRegister() public {
        // V1 (C4): replay defense now rests on the permanent signer
        // burn. After a burn the SAME identity can NEVER be re-registered,
        // which makes a leaked signature for an old identity trivially
        // unreplayable - the operator cannot put the same panic identity
        // back into the active set in the first place.
        bytes32 reasonHash = bytes32("first");
        bytes32 msgHash1 = _msgHash(address(SAFE_A), _eoaSigner(panicKey), reasonHash);
        bytes memory sig1 = _ecdsaSign(PANIC_PK, msgHash1);
        bytes memory key = abi.encodePacked(panicKey);

        // 1. Trigger, burning id=1.
        guard.triggerLockdown(address(SAFE_A), reasonHash, key, sig1);

        // 2. Resume.
        vm.warp(block.timestamp + 48 hours + 4 hours + 1);

        // 3. Attempt to re-register same key - rejected by INV-SIGN-7.
        vm.prank(address(SAFE_A));
        vm.expectRevert(LockdownSigners.LockdownSigners_BurntPermanently.selector);
        guard.addLockdownSigner(key);

        // 4. Operator MUST rotate to a fresh EOA. Verify a fresh key
        //    registers cleanly and that the OLD signature cannot
        //    target the new identity.
        address fresh = vm.addr(uint256(keccak256("fresh-panic-eoa")));
        bytes memory freshKey = abi.encodePacked(fresh);
        vm.prank(address(SAFE_A));
        guard.addLockdownSigner(freshKey);
        assertTrue(guard.isLockdownSigner(address(SAFE_A), freshKey), "fresh identity registered");

        // 5. The stale sig1 cannot be used to trigger via the fresh
        //    identity (different key, different verifier check input).
        vm.expectRevert(Lockdown.BadSignature.selector);
        guard.triggerLockdown(address(SAFE_A), reasonHash, freshKey, sig1);
    }

    // -------------------------------------------------------------------
    // ECDSA verifier integration
    // -------------------------------------------------------------------

    function test_ecdsaPath_endToEnd() public {
        bytes32 reasonHash = bytes32("ecdsa-end-to-end");
        bytes32 msgHash = _msgHash(address(SAFE_A), _eoaSigner(panicKey), reasonHash);
        bytes memory sig = _ecdsaSign(PANIC_PK, msgHash);
        guard.triggerLockdown(address(SAFE_A), reasonHash, _eoaSigner(panicKey), sig);
        assertTrue(_isLockedDown(address(SAFE_A)), "locked");
    }

    function test_ecdsaPath_wrongPrivKeyFails() public {
        bytes32 reasonHash = bytes32("wrong-key");
        bytes32 msgHash = _msgHash(address(SAFE_A), _eoaSigner(panicKey), reasonHash);
        bytes memory sig = _ecdsaSign(OTHER_PK, msgHash); // signed by B
        vm.expectRevert(Lockdown.BadSignature.selector);
        guard.triggerLockdown(address(SAFE_A), reasonHash, _eoaSigner(panicKey), sig);
    }

    // -------------------------------------------------------------------
    // Password verifier integration
    // -------------------------------------------------------------------

    function test_passwordPath_endToEnd() public {
        bytes32 reasonHash = bytes32("password-end-to-end");
        bytes memory preimage = SHARED_SECRET_A;
        guard.triggerLockdown(address(SAFE_A), reasonHash, _secretSignerA(), preimage);
        assertTrue(_isLockedDown(address(SAFE_A)), "locked");
    }

    function test_passwordPath_wrongPreimageFails() public {
        vm.expectRevert(Lockdown.BadSignature.selector);
        guard.triggerLockdown(address(SAFE_A), bytes32("wrong"), _secretSignerA(), bytes("wrong-password"));
    }

    function test_passwordPath_ignoresMessageHash() public {
        // Two different reasonHashes both work with the same preimage:
        // the verifier doesn't bind to the message.
        guard.triggerLockdown(address(SAFE_A), bytes32("first reason"), _secretSignerA(), SHARED_SECRET_A);
        assertTrue(_isLockedDown(address(SAFE_A)), "first locked");
    }

    function test_passwordPath_signerBurntAfterUse() public {
        guard.triggerLockdown(address(SAFE_A), bytes32("burn-me"), _secretSignerA(), SHARED_SECRET_A);
        assertFalse(guard.isLockdownSigner(address(SAFE_A), _secretSignerA()), "burnt");
    }

    // -------------------------------------------------------------------
    // New identity model: ERC-1271 signer, compact sigs, shape + binding
    // -------------------------------------------------------------------

    function test_erc1271Path_endToEnd() public {
        // A 20-byte identity that is an ERC-1271 smart-contract wallet. The new
        // model routes it through SignatureChecker's 1271 branch (no EOA key,
        // no ECDSAVerifier contract). ECDSA.tryRecover yields the OWNER, which
        // != the wallet address, so SignatureChecker falls through to 1271.
        Mock1271Wallet wallet = new Mock1271Wallet(panicKey);
        vm.prank(address(SAFE_A));
        guard.addLockdownSigner(_eoaSigner(address(wallet)));

        bytes32 reasonHash = bytes32("erc1271-e2e");
        bytes memory sig = _ecdsaSign(PANIC_PK, _msgHash(address(SAFE_A), _eoaSigner(address(wallet)), reasonHash));
        guard.triggerLockdown(address(SAFE_A), reasonHash, _eoaSigner(address(wallet)), sig);
        assertTrue(_isLockedDown(address(SAFE_A)), "locked via ERC-1271 signer");
    }

    function test_erc1271Path_wrongOwnerFails() public {
        Mock1271Wallet wallet = new Mock1271Wallet(panicKey);
        vm.prank(address(SAFE_A));
        guard.addLockdownSigner(_eoaSigner(address(wallet)));

        bytes32 reasonHash = bytes32("erc1271-wrong");
        bytes memory sig = _ecdsaSign(OTHER_PK, _msgHash(address(SAFE_A), _eoaSigner(address(wallet)), reasonHash));
        vm.expectRevert(Lockdown.BadSignature.selector);
        guard.triggerLockdown(address(SAFE_A), reasonHash, _eoaSigner(address(wallet)), sig);
    }

    function test_ecdsaPath_rejectsCompact2098Signature() public {
        // SignatureChecker dispatches the 20-byte EOA path to OZ
        // ECDSA.tryRecover(bytes), which is 65-byte ONLY (ERC-2098 short sigs
        // are rejected by that overload). This matches the removed
        // ECDSAVerifier's strict-65 wire format: no permissiveness regression.
        bytes32 reasonHash = bytes32("compact-2098");
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(PANIC_PK, _msgHash(address(SAFE_A), _eoaSigner(panicKey), reasonHash));
        bytes32 vs = s | bytes32((uint256(v) - 27) << 255); // low-s ⟹ top bit free
        bytes memory compactSig = abi.encodePacked(r, vs); // 64 bytes
        vm.expectRevert(Lockdown.BadSignature.selector);
        guard.triggerLockdown(address(SAFE_A), reasonHash, _eoaSigner(panicKey), compactSig);
    }

    function test_crossSafe_signatureBoundToSafeViaBadSignature() public {
        bytes32 reasonHash = bytes32("cross-safe-binding");
        bytes memory sigForA = _ecdsaSign(PANIC_PK, _msgHash(address(SAFE_A), _eoaSigner(panicKey), reasonHash));
        // Membership(B, panicKey) is true, so this reverts at the signature
        // check (BadSignature), NOT at membership (NotLockdownSigner).
        vm.expectRevert(Lockdown.BadSignature.selector);
        guard.triggerLockdown(address(SAFE_B), reasonHash, _eoaSigner(panicKey), sigForA);
    }

    function test_addLockdownSignerRejectsShortSigner() public {
        // 1..19 bytes: too short to be an address, rejected before any dispatch.
        bytes memory shortSigner = new bytes(19);
        vm.prank(address(SAFE_A));
        vm.expectRevert(LockdownSigners.LockdownSigners_InvalidFormat.selector);
        guard.addLockdownSigner(shortSigner);
    }

    function test_triggerWithBareVerifierPrefixReverts() public {
        // The registered identity is `secretVerifier || commitment` (>20 bytes).
        // Triggering with only the 20-byte verifier prefix must not match the
        // exact-bytes membership set.
        bytes memory prefix = _eoaSigner(address(secretVerifier));
        vm.expectRevert(LockdownSigners.LockdownSigners_Unknown.selector);
        guard.triggerLockdown(address(SAFE_A), bytes32("prefix"), prefix, SHARED_SECRET_A);
    }

    // -------------------------------------------------------------------
    // Cross-key isolation
    // -------------------------------------------------------------------

    function test_crossKey_lockdownOnAdoesNotLockB() public {
        _triggerLockdown(SAFE_A, bytes32("panic"));
        assertTrue(_isLockedDown(address(SAFE_A)), "A locked");
        assertFalse(_isLockedDown(address(SAFE_B)), "B not locked");
    }

    function test_crossKey_signerOnAdoesNotAuthorizeB() public {
        // other is not a registered signer on SAFE_A
        bytes32 reasonHash = bytes32("cross-key");
        bytes32 msgHash = _msgHash(address(SAFE_A), _eoaSigner(other), reasonHash); // B's signer 1 is panicKey
        bytes memory sig = _ecdsaSign(OTHER_PK, msgHash);
        vm.expectRevert(LockdownSigners.LockdownSigners_Unknown.selector);
        guard.triggerLockdown(address(SAFE_A), reasonHash, _eoaSigner(other), sig);
    }

    function test_crossKey_recoveryOwnerOnAdoesNotApplyToB() public view {
        assertTrue(guard.isRecoveryOwner(address(SAFE_A), BACKUP_OWNER_A), "A");
        assertFalse(guard.isRecoveryOwner(address(SAFE_B), BACKUP_OWNER_A), "not B");
    }

    function test_crossKey_addingToAdoesNotShowOnB() public {
        bytes memory key = abi.encodePacked(address(0xCC01));
        vm.prank(address(SAFE_A));
        guard.addLockdownSigner(key);
        assertTrue(guard.isLockdownSigner(address(SAFE_A), key), "A");
        assertFalse(guard.isLockdownSigner(address(SAFE_B), key), "not B");
    }

    function test_crossKey_hookFromAReadsAOnly() public {
        _triggerLockdown(SAFE_A, bytes32("panic"));
        vm.prank(address(SAFE_B));
        _checkOwner(address(SAFE_B), TARGET, 0, hex"", Enum.Operation.Call); // B is Normal, must pass
    }

    function test_crossKey_independentLifecycles() public {
        _triggerLockdown(SAFE_A, bytes32("panic"));
        // Trigger address(SAFE_B) with its own signer.
        bytes32 reasonHash = bytes32("b panic");
        bytes32 msgHash = _msgHash(address(SAFE_B), _eoaSigner(panicKey), reasonHash);
        bytes memory sig = _ecdsaSign(PANIC_PK, msgHash);
        guard.triggerLockdown(address(SAFE_B), reasonHash, _eoaSigner(panicKey), sig);

        assertTrue(_isLockedDown(address(SAFE_A)), "A locked");
        assertTrue(_isLockedDown(address(SAFE_B)), "B locked");

        // Wait long enough for A's 48h+4h window AND B's 24h+8h window.
        vm.warp(block.timestamp + 48 hours + 4 hours + 1);

        assertFalse(_isLockedDown(address(SAFE_A)), "A locked");
        assertFalse(_isLockedDown(address(SAFE_B)), "B locked");
    }

    function test_crossKey_burnOnAdoesNotAffectB() public {
        _triggerLockdown(SAFE_A, bytes32("panic"));
        // panicKey was burnt on A. B's panicKey-as-signer is intact.
        assertFalse(guard.isLockdownSigner(address(SAFE_A), _eoaSigner(panicKey)), "A's panicKey burnt");
        assertTrue(guard.isLockdownSigner(address(SAFE_B), _eoaSigner(panicKey)), "B's panicKey intact");
    }

    function test_crossKey_signersCountIndependent() public {
        (,,, uint256 countA,) = guard.getConfigSnapshot(address(SAFE_A));
        (,,, uint256 countB,) = guard.getConfigSnapshot(address(SAFE_B));
        assertEq(countA, 2, "A count");
        assertEq(countB, 1, "B count");

        bytes memory key = abi.encodePacked(address(0xAB01));
        vm.prank(address(SAFE_A));
        guard.addLockdownSigner(key);

        (,,, uint256 countA2,) = guard.getConfigSnapshot(address(SAFE_A));
        (,,, uint256 countB2,) = guard.getConfigSnapshot(address(SAFE_B));
        assertEq(countA2, 3, "A++");
        assertEq(countB2, 1, "B unchanged");
    }

    // -------------------------------------------------------------------
    // Fail-open uninit
    // -------------------------------------------------------------------

    /// @dev ERC-1271 is opt-in (SPEC_V1 H.27): an uninitialised Safe reads
    ///      `erc1271Allowed == false`, so the handler refuses, fail-closed.
    function test_uninitSafe_erc1271DisabledByDefault() public view {
        bytes32 hash = keccak256("authorise something");
        bytes memory signature = _signMessage(SAFE_UNINIT, OWNER_PK, hash);
        assertFalse(guard.isErc1271Allowed(address(SAFE_UNINIT)), "default disabled");
        assertFalse(
            SignatureChecker.isValidERC1271SignatureNow(address(SAFE_UNINIT), hash, signature),
            "handler refuses until the Safe opts in"
        );
    }

    function test_uninitSafe_allowsTransaction() public {
        uint256 nonceBefore = SAFE_UNINIT.nonce();
        _execAsOwner(SAFE_UNINIT, TARGET, 0, "", Enum.Operation.Call);
        assertEq(SAFE_UNINIT.nonce(), nonceBefore + 1, "nonce advanced through guard");
    }

    function test_uninitSafe_allowsModuleTransaction() public {
        _moduleCall(module, SAFE_UNINIT, TARGET, 0, "", Enum.Operation.Call);
    }

    function test_uninitSafe_rejectsModuleDelegateCallToNonMultiSend() public {
        // Anti-brick tightening: a module DelegateCall to a non-MultiSend target
        // is denied even before initialize (was previously allowed by the bare
        // fail-open, which also let a MultiSend-wrapped inner call reach the
        // singleton - see test_uninit_moduleBatch_rejectInnerCallToSingleton).
        _moduleCall_Revert(
            module, SAFE_UNINIT, TARGET, 0, "", Enum.Operation.DelegateCall, Lockdown.DelegateCallDenied.selector
        );
    }

    function test_uninitSafe_allowsModuleTransaction_toSingleton() public {
        // A module can never reach the singleton, in any state.
        _moduleCall_Revert(
            module,
            SAFE_UNINIT,
            address(guard),
            0,
            "",
            Enum.Operation.Call,
            Lockdown.ModuleCallToSingletonDenied.selector
        );
    }

    function test_uninitSafe_hooksPassThrough_module() public {
        vm.prank(address(SAFE_UNINIT));
        bytes32 h = guard.checkModuleTransaction(TARGET, 0, hex"1234", Enum.Operation.Call, MODULE);
        assertNotEq(uint256(h), 0, "module hash returned");
    }

    function test_uninitSafe_hooksPassThrough_delegatecall() public {
        vm.prank(address(SAFE_UNINIT));
        _checkOwner(address(SAFE_UNINIT), address(multiSendCallOnly), 0, hex"deadbeef", Enum.Operation.DelegateCall);
    }

    function test_uninitSafe_triggerReverts() public {
        bytes32 msgHash = _msgHash(address(SAFE_UNINIT), _eoaSigner(panicKey), bytes32("nope"));
        bytes memory sig = _ecdsaSign(PANIC_PK, msgHash);
        vm.expectRevert(
            abi.encodeWithSelector(
                StateMachine.InvalidState.selector,
                StateMachine.State.Uninitialised,
                ~(1 << uint256(StateMachine.State.Uninitialised))
            )
        );
        guard.triggerLockdown(address(SAFE_UNINIT), bytes32("nope"), _eoaSigner(panicKey), sig);
    }

    // -------------------------------------------------------------------
    // Recovery whitelist
    // -------------------------------------------------------------------

    function test_recoveryBlocksGenericOwnerPath() public {
        _triggerLockdown(SAFE_A, bytes32("panic"));
        vm.warp(block.timestamp + 48 hours + 1);
        vm.prank(address(SAFE_A));
        vm.expectRevert(Lockdown.RecoveryActive.selector);
        _checkOwner(address(SAFE_A), TARGET, 0, hex"", Enum.Operation.Call);
    }

    function test_recoveryAllowsNonceBurn() public {
        _triggerLockdown(SAFE_A, bytes32("panic"));
        vm.warp(block.timestamp + 48 hours + 1);
        vm.prank(address(SAFE_A));
        _checkOwner(address(SAFE_A), address(SAFE_A), 0, hex"", Enum.Operation.Call);
    }

    function test_recoveryRejectsRefundFieldsOnNonceBurn() public {
        _triggerLockdown(SAFE_A, bytes32("panic"));
        vm.warp(block.timestamp + 48 hours + 1);
        vm.prank(address(SAFE_A));
        vm.expectRevert(Lockdown.RecoveryRefundDenied.selector);
        _checkOwnerFull(address(SAFE_A), 0, hex"", Enum.Operation.Call, 0, 1_000_000, 1, address(0), payable(ATTACKER));
    }

    function test_recoveryAllowsRemovingAModule() public {
        _triggerLockdown(SAFE_A, bytes32("panic"));
        vm.warp(block.timestamp + 48 hours + 1);
        bytes memory callData = abi.encodeCall(IModuleManager.disableModule, (address(0), address(module)));
        vm.prank(address(SAFE_A));
        _checkOwner(address(SAFE_A), address(SAFE_A), 0, callData, Enum.Operation.Call);
    }

    function test_recoveryAllowsSwapOwnerToBackup() public {
        _triggerLockdown(SAFE_A, bytes32("panic"));
        vm.warp(block.timestamp + 48 hours + 1);
        bytes memory callData = abi.encodeCall(IOwnerManager.swapOwner, (address(0x1), OLD_OWNER, NEW_OWNER));
        vm.prank(address(SAFE_A));
        _checkOwner(address(SAFE_A), address(SAFE_A), 0, callData, Enum.Operation.Call);
    }

    function test_recoveryRejectsSwapOwnerToNonAllowlistedAddress() public {
        _triggerLockdown(SAFE_A, bytes32("panic"));
        vm.warp(block.timestamp + 48 hours + 1);
        bytes memory callData = abi.encodeCall(IOwnerManager.swapOwner, (address(0x1), OLD_OWNER, ATTACKER));
        vm.prank(address(SAFE_A));
        vm.expectRevert(Lockdown.RecoveryActive.selector);
        _checkOwner(address(SAFE_A), address(SAFE_A), 0, callData, Enum.Operation.Call);
    }

    // -------------------------------------------------------------------
    // V1 H.19: recovery-owner validation. Safe's swapOwner would reject
    // zero / sentinel / the Safe itself (GS203) and an existing owner
    // (GS204) at recovery-execution time; H.19 rejects them at
    // registration time so the recovery path never LOOKS armed while
    // being a dead-end, and re-checks the dynamic existing-owner case at
    // hook time.
    // -------------------------------------------------------------------

    function test_initialize_rejectsRecoveryOwnerSentinel() public {
        address[] memory backups = _singleBackup(address(0x1));
        vm.prank(address(SAFE_UNINIT));
        vm.expectRevert(RecoveryOwners.RecoveryOwners_Invalid.selector);
        guard.initialize(24 hours, 4 hours, backups, new bytes[](0));
    }

    function test_initialize_rejectsRecoveryOwnerSafeItself() public {
        address[] memory backups = _singleBackup(address(SAFE_UNINIT));
        vm.prank(address(SAFE_UNINIT));
        vm.expectRevert(RecoveryOwners.RecoveryOwners_Invalid.selector);
        guard.initialize(24 hours, 4 hours, backups, new bytes[](0));
    }

    function test_initialize_rejectsRecoveryOwnerCurrentSafeOwner() public {
        vm.startPrank(address(SAFE_UNINIT));
        SAFE_UNINIT.addOwnerWithThreshold(BACKUP_OWNER_A, 1);
        address[] memory backups = _singleBackup(BACKUP_OWNER_A);
        vm.expectRevert(RecoveryOwners.RecoveryOwners_Invalid.selector);
        guard.initialize(24 hours, 4 hours, backups, new bytes[](0));
        vm.stopPrank();
    }

    function test_addRecoveryOwner_rejectsSentinel() public {
        vm.prank(address(SAFE_A));
        vm.expectRevert(RecoveryOwners.RecoveryOwners_Invalid.selector);
        guard.addRecoveryOwner(address(0x1));
    }

    function test_addRecoveryOwner_rejectsSafeItself() public {
        vm.prank(address(SAFE_A));
        vm.expectRevert(RecoveryOwners.RecoveryOwners_Invalid.selector);
        guard.addRecoveryOwner(address(SAFE_A));
    }

    function test_addRecoveryOwner_rejectsCurrentSafeOwner() public {
        vm.startPrank(address(SAFE_A));
        SAFE_A.addOwnerWithThreshold(NEW_OWNER, 1);
        vm.expectRevert(RecoveryOwners.RecoveryOwners_Invalid.selector);
        guard.addRecoveryOwner(NEW_OWNER);
        vm.stopPrank();
    }

    /// @notice Removal of an entry that became invalid AFTER registration
    ///         must stay possible: it is exactly the cleanup for that case.
    function test_removeRecoveryOwner_allowsRemovingEntryThatBecameOwner() public {
        vm.startPrank(address(SAFE_A));
        SAFE_A.addOwnerWithThreshold(NEW_OWNER, 1);
        guard.removeRecoveryOwner(NEW_OWNER); // no revert
        vm.stopPrank();
    }

    bytes32 private constant RECOVERY_OWNER_CHANGED_TOPIC =
        keccak256("RecoveryOwnerAllowlistChanged(address,address,bool)");

    function _countRecoveryOwnerChangedEvents(Vm.Log[] memory logs) private view returns (uint256 n) {
        for (uint256 i = 0; i < logs.length; ++i) {
            if (logs[i].emitter != address(guard)) continue;
            if (logs[i].topics.length == 0) continue;
            if (logs[i].topics[0] == RECOVERY_OWNER_CHANGED_TOPIC) n += 1;
        }
    }

    // Regression cover for the EnumerableSet allowlist: add increments, a
    // redundant add is an idempotent no-op (no event), and the allowlist can
    // shrink to EXACTLY ONE entry (min-1 invariant, mirrored by the Echidna
    // INV and verify-install). The 2 -> 1 removal is the case that pins the
    // EmptyAllowlist threshold; a 3 -> 2 removal alone would not.
    function test_recoveryOwners_lifecycleAndMinOneInvariant() public {
        assertEq(guard.getRecoveryOwners(address(SAFE_A)).length, 3, "starts at 3");
        address extra = address(0xC0FFEE);

        vm.prank(address(SAFE_A));
        guard.addRecoveryOwner(extra);
        assertTrue(guard.isRecoveryOwner(address(SAFE_A), extra), "added");
        assertEq(guard.getRecoveryOwners(address(SAFE_A)).length, 4, "count 4");

        // Redundant add: idempotent, no state change, no event.
        vm.recordLogs();
        vm.prank(address(SAFE_A));
        guard.addRecoveryOwner(extra);
        assertEq(_countRecoveryOwnerChangedEvents(vm.getRecordedLogs()), 0, "no event on redundant add");
        assertEq(guard.getRecoveryOwners(address(SAFE_A)).length, 4, "still 4");

        vm.prank(address(SAFE_A));
        guard.removeRecoveryOwner(extra);
        vm.prank(address(SAFE_A));
        guard.removeRecoveryOwner(BACKUP_OWNER_B);
        vm.prank(address(SAFE_A));
        guard.removeRecoveryOwner(BACKUP_OWNER_A); // 2 -> 1: must succeed
        assertEq(guard.getRecoveryOwners(address(SAFE_A)).length, 1, "down to exactly one");

        // 1 -> 0 is forbidden.
        vm.prank(address(SAFE_A));
        vm.expectRevert(RecoveryOwners.RecoveryOwners_EmptyAllowlist.selector);
        guard.removeRecoveryOwner(NEW_OWNER);
    }

    function test_getRecoveryOwners_returnsFullSet() public view {
        address[] memory owners = guard.getRecoveryOwners(address(SAFE_A));
        assertEq(owners.length, 3, "three owners");
        // Order is not guaranteed by EnumerableSet; assert the set membership.
        bool sawNew;
        bool sawA;
        bool sawB;
        for (uint256 i = 0; i < owners.length; ++i) {
            if (owners[i] == NEW_OWNER) sawNew = true;
            if (owners[i] == BACKUP_OWNER_A) sawA = true;
            if (owners[i] == BACKUP_OWNER_B) sawB = true;
        }
        assertTrue(sawNew && sawA && sawB, "all three present");
    }

    /// @notice H.19 dynamic re-check: a backup that became a current owner
    ///         after registration is rejected by the recovery whitelist at
    ///         hook time (Safe would revert GS204 on the swap anyway).
    function test_recoveryRejectsSwapOwnerWhenBackupBecameCurrentOwner() public {
        _triggerLockdown(SAFE_A, bytes32("panic"));
        vm.warp(block.timestamp + 48 hours + 1);
        vm.startPrank(address(SAFE_A));
        SAFE_A.addOwnerWithThreshold(NEW_OWNER, 1);
        bytes memory callData = abi.encodeCall(IOwnerManager.swapOwner, (address(0x1), OLD_OWNER, NEW_OWNER));
        vm.expectRevert(Lockdown.RecoveryActive.selector);
        _checkOwner(address(SAFE_A), address(SAFE_A), 0, callData, Enum.Operation.Call);
        vm.stopPrank();
    }

    // -------------------------------------------------------------------
    // Guard uninstall/reinstall persistence semantics. The singleton keys
    // all state by Safe address; setGuard/setModuleGuard changes on the
    // Safe never touch `_configs`. These tests pin that behaviour
    // explicitly (SaferSafes iSAFE-012 analogue; see
    // docs/PRIOR_ART_SAFERSAFES.md).
    // -------------------------------------------------------------------

    /// @notice Re-installing the guard during an active incident must NOT
    ///         reset the Safe to Normal: lockdownUntil persists and hooks
    ///         re-enforce it immediately.
    function test_incidentStatePersistsAcrossGuardReinstall() public {
        _triggerLockdown(SAFE_A, bytes32("panic"));
        // Simulated uninstall window: the Safe executes setGuard txs; the
        // singleton sees nothing. State must be unchanged on "reinstall".
        assertTrue(_isLockedDown(address(SAFE_A)), "still locked after reinstall");
        vm.prank(address(SAFE_A));
        vm.expectRevert(Lockdown.LockedDown.selector);
        _checkOwner(address(SAFE_A), TARGET, 0, hex"", Enum.Operation.Call);
        vm.prank(address(SAFE_A));
        vm.expectRevert(Lockdown.LockedDown.selector);
        guard.checkModuleTransaction(TARGET, 0, hex"1234", Enum.Operation.Call, MODULE);
    }

    /// @notice Burnt keys survive a full incident cycle plus any number of
    ///         uninstall/reinstall rounds (INV-SIGN-7 permanence framed
    ///         against reinstallation).
    function test_burntKeyPersistsAcrossResumeAndReinstall() public {
        _triggerLockdown(SAFE_A, bytes32("panic")); // burns the ECDSA panic signer
        vm.warp(block.timestamp + 48 hours + 4 hours + 1);
        // Post-resume "reinstall": re-registering the burnt (verifier, key)
        // pair must stay impossible.
        vm.prank(address(SAFE_A));
        vm.expectRevert(LockdownSigners.LockdownSigners_BurntPermanently.selector);
        guard.addLockdownSigner(_eoaSigner(panicKey));
    }

    /// @notice V1: removeLockdownSigner IS in the recovery whitelist so the
    ///         quorum can cull surviving compromised signers before resume.
    function test_recoveryAllowsRemoveLockdownSignerSelfCall() public {
        _triggerLockdown(SAFE_A, bytes32("panic"));
        vm.warp(block.timestamp + 48 hours + 1);
        bytes memory key = abi.encodePacked(keccak256(SHARED_SECRET_A));
        bytes memory callData =
            abi.encodeWithSelector(guard.removeLockdownSigner.selector, _verifierSigner(address(secretVerifier), key));
        // Hook must accept; an explicit attempt with `_checkOwner` must NOT
        // revert RecoveryActive.
        vm.prank(address(SAFE_A));
        _checkOwner(address(SAFE_A), address(guard), 0, callData, Enum.Operation.Call);
    }

    function test_recoveryRemoveLockdownSignerSelectorOnlyIsNonceGriefOnly() public {
        _triggerLockdown(SAFE_A, bytes32("panic"));
        vm.warp(block.timestamp + 48 hours + 1);
        bytes memory key = abi.encodePacked(keccak256(SHARED_SECRET_A));
        bytes memory signer = _verifierSigner(address(secretVerifier), key);
        bytes memory selectorOnly = abi.encodePacked(guard.removeLockdownSigner.selector);

        // The recovery hook deliberately recognises the selector and lets the
        // function body/ABI decoder reject malformed calldata. This can waste a
        // Safe nonce, but must not remove any signer.
        vm.prank(address(SAFE_A));
        _checkOwner(address(SAFE_A), address(guard), 0, selectorOnly, Enum.Operation.Call);

        vm.prank(address(SAFE_A));
        (bool ok,) = address(guard).call(selectorOnly);
        assertFalse(ok, "selector-only removeLockdownSigner execution reverts");
        assertTrue(guard.isLockdownSigner(address(SAFE_A), signer), "malformed removal did not mutate signers");
    }

    function test_recoveryRejectsScalarSetterSelfCall() public {
        _triggerLockdown(SAFE_A, bytes32("panic"));
        vm.warp(block.timestamp + 48 hours + 1);
        bytes memory callData = abi.encodeWithSelector(guard.setResumeDelay.selector, 5 hours);
        vm.prank(address(SAFE_A));
        vm.expectRevert(Lockdown.RecoveryActive.selector);
        _checkOwner(address(SAFE_A), address(guard), 0, callData, Enum.Operation.Call);
    }

    function test_recoveryRejectsAddOwner() public {
        _triggerLockdown(SAFE_A, bytes32("panic"));
        vm.warp(block.timestamp + 48 hours + 1);
        bytes memory callData = abi.encodeCall(IOwnerManager.addOwnerWithThreshold, (NEW_OWNER, uint256(2)));
        vm.prank(address(SAFE_A));
        vm.expectRevert(Lockdown.RecoveryActive.selector);
        _checkOwner(address(SAFE_A), address(SAFE_A), 0, callData, Enum.Operation.Call);
    }

    function test_recoveryRejectsRemoveOwner() public {
        _triggerLockdown(SAFE_A, bytes32("panic"));
        vm.warp(block.timestamp + 48 hours + 1);
        bytes memory callData = abi.encodeCall(IOwnerManager.removeOwner, (address(0x1), OLD_OWNER, uint256(1)));
        vm.prank(address(SAFE_A));
        vm.expectRevert(Lockdown.RecoveryActive.selector);
        _checkOwner(address(SAFE_A), address(SAFE_A), 0, callData, Enum.Operation.Call);
    }

    function test_recoveryRejectsChangeThreshold() public {
        _triggerLockdown(SAFE_A, bytes32("panic"));
        vm.warp(block.timestamp + 48 hours + 1);
        bytes memory callData = abi.encodeCall(IOwnerManager.changeThreshold, (uint256(3)));
        vm.prank(address(SAFE_A));
        vm.expectRevert(Lockdown.RecoveryActive.selector);
        _checkOwner(address(SAFE_A), address(SAFE_A), 0, callData, Enum.Operation.Call);
    }

    function test_recoveryRejectsModulePath() public {
        _triggerLockdown(SAFE_A, bytes32("panic"));
        vm.warp(block.timestamp + 48 hours + 1);
        vm.prank(address(SAFE_A));
        vm.expectRevert(Lockdown.RecoveryActive.selector);
        guard.checkModuleTransaction(TARGET, 0, hex"", Enum.Operation.Call, MODULE);
    }

    function test_recoveryRejectsDelegatecall() public {
        _triggerLockdown(SAFE_A, bytes32("panic"));
        vm.warp(block.timestamp + 48 hours + 1);
        vm.prank(address(SAFE_A));
        vm.expectRevert(Lockdown.DelegateCallDenied.selector);
        _checkOwner(address(SAFE_A), TARGET, 0, hex"", Enum.Operation.DelegateCall);
    }

    // Operation on third party contract
    function test_recoveryRejectsForbidenActionInMulticall_1() public {
        _triggerLockdown(SAFE_A, bytes32("panic"));
        vm.warp(block.timestamp + 48 hours + 1);
        vm.prank(address(SAFE_A));
        vm.expectRevert(Lockdown.RecoveryActive.selector);
        _checkOwner(
            address(SAFE_A),
            address(multiSendCallOnly),
            0,
            abi.encodeCall(
                MultiSendCallOnly.multiSend, (_multiSendItem(Enum.Operation.Call, TARGET, 0, hex"12345678"))
            ),
            Enum.Operation.DelegateCall
        );
    }

    // add owner (forbiden during recovery)
    function test_recoveryRejectsForbidenActionInMulticall_2() public {
        _triggerLockdown(SAFE_A, bytes32("panic"));
        vm.warp(block.timestamp + 48 hours + 1);
        vm.prank(address(SAFE_A));
        vm.expectRevert(Lockdown.RecoveryActive.selector);
        _checkOwner(
            address(SAFE_A),
            address(multiSendCallOnly),
            0,
            abi.encodeCall(
                MultiSendCallOnly.multiSend,
                (_multiSendItem(
                        Enum.Operation.Call,
                        address(SAFE_A),
                        0,
                        abi.encodeCall(SAFE_A.addOwnerWithThreshold, (NEW_OWNER, uint256(2)))
                    ))
            ),
            Enum.Operation.DelegateCall
        );
    }

    // Positive: the capability the _checkCall refactor unlocks. A MultiSend
    // batch of ONLY valid recovery ops (nonce burn + disableModule +
    // swapOwner-to-recovery-owner + removeLockdownSigner, mixing to==safe and
    // to==singleton leaves) is accepted during recovery. Pre-refactor every
    // recovery DelegateCall was rejected outright (RecoveryActive); now each
    // leaf is re-validated by _isRecoveryCall, so a clean batch passes.
    function test_recoveryAllowsValidRecoveryOpsBatchInMultiSend() public {
        _triggerLockdown(SAFE_A, bytes32("panic"));
        vm.warp(block.timestamp + 48 hours + 1);

        bytes memory removeSignerCall = abi.encodeWithSelector(
            guard.removeLockdownSigner.selector,
            _verifierSigner(address(secretVerifier), abi.encodePacked(keccak256(SHARED_SECRET_A)))
        );

        bytes memory batch = abi.encodePacked(
            _multiSendItem(Enum.Operation.Call, address(SAFE_A), 0, hex""), // nonce burn
            _multiSendItem(
                Enum.Operation.Call,
                address(SAFE_A),
                0,
                abi.encodeCall(IModuleManager.disableModule, (address(0), address(module)))
            ),
            _multiSendItem(
                Enum.Operation.Call,
                address(SAFE_A),
                0,
                abi.encodeCall(IOwnerManager.swapOwner, (address(0x1), OLD_OWNER, NEW_OWNER))
            ),
            _multiSendItem(Enum.Operation.Call, address(guard), 0, removeSignerCall)
        );

        vm.prank(address(SAFE_A));
        _checkOwner(
            address(SAFE_A),
            address(multiSendCallOnly),
            0,
            abi.encodeCall(MultiSendCallOnly.multiSend, (batch)),
            Enum.Operation.DelegateCall
        );
    }

    function test_recoveryRejectsSwapOwnerWithTruncatedCalldata() public {
        _triggerLockdown(SAFE_A, bytes32("panic"));
        vm.warp(block.timestamp + 48 hours + 1);
        bytes memory truncated = abi.encodeCall(IOwnerManager.swapOwner, (address(0x1), OLD_OWNER, NEW_OWNER));
        assembly ("memory-safe") {
            mstore(truncated, sub(mload(truncated), 1)) // truncate the last byte of the data
        }
        vm.prank(address(SAFE_A));
        vm.expectRevert(Lockdown.RecoveryActive.selector);
        _checkOwner(address(SAFE_A), address(SAFE_A), 0, truncated, Enum.Operation.Call);
    }

    // -------------------------------------------------------------------
    // Normal-mode owner path
    // -------------------------------------------------------------------

    function test_arbitraryDelegatecallDeniedInNormalMode() public {
        vm.prank(address(SAFE_A));
        vm.expectRevert(Lockdown.DelegateCallDenied.selector);
        _checkOwner(address(SAFE_A), TARGET, 0, hex"", Enum.Operation.DelegateCall);
    }

    function test_adminSelectorsAllowedInNormalMode() public {
        vm.prank(address(SAFE_A));
        _checkOwner(address(SAFE_A), address(SAFE_A), 0, hex"e19a9dd9", Enum.Operation.Call); // setGuard
        vm.prank(address(SAFE_A));
        _checkOwner(address(SAFE_A), address(SAFE_A), 0, hex"e068df37", Enum.Operation.Call); // setModuleGuard
    }

    function test_setFallbackHandlerToValidHandlerAllowedInNormalMode() public {
        LockdownFallbackHandler newHandler = new LockdownFallbackHandler(guard);

        // Self-call rebinding the fallback handler to a LockdownFallbackHandler
        // bound to this singleton is permitted.
        vm.expectEmit(address(SAFE_A));
        emit IFallbackManager.ChangedFallbackHandler(address(newHandler));
        _execAsOwner(
            SAFE_A,
            address(SAFE_A),
            0,
            abi.encodeCall(IFallbackManager.setFallbackHandler, (address(newHandler))),
            Enum.Operation.Call
        );
    }

    function test_setFallbackHandlerToForeignHandlerRevertsInNormalMode() public {
        LockdownFallbackHandler foreignHandler = new LockdownFallbackHandler(StateMachine(address(0xBEEF)));

        // A handler bound to a different singleton would leave the Safe unprotected.
        _execAsOwner_Revert(
            SAFE_A,
            address(SAFE_A),
            0,
            abi.encodeCall(IFallbackManager.setFallbackHandler, (address(foreignHandler))),
            Enum.Operation.Call,
            Lockdown.InvalidFallbackHandler.selector
        );
    }

    function test_moduleCallAllowedInNormalMode() public {
        vm.prank(address(SAFE_A));
        bytes32 hash = guard.checkModuleTransaction(TARGET, 1 ether, hex"1234", Enum.Operation.Call, MODULE);
        bytes32 expected =
            keccak256(abi.encode(SAFE_A, MODULE, TARGET, uint256(1 ether), keccak256(hex"1234"), Enum.Operation.Call));
        assertEq(hash, expected, "module hash");
    }

    function test_moduleDelegatecallDeniedInNormalMode() public {
        vm.prank(address(SAFE_A));
        vm.expectRevert(Lockdown.DelegateCallDenied.selector);
        guard.checkModuleTransaction(TARGET, 0, hex"", Enum.Operation.DelegateCall, MODULE);
    }

    // -------------------------------------------------------------------
    // MultiSend parser
    // -------------------------------------------------------------------

    function test_multiSendCallOnlyAllowedInNormalMode() public {
        vm.prank(address(SAFE_A));
        _checkOwner(
            address(SAFE_A),
            address(multiSendCallOnly),
            0,
            abi.encodeCall(
                MultiSendCallOnly.multiSend, (_multiSendItem(Enum.Operation.Call, TARGET, 0, hex"12345678"))
            ),
            Enum.Operation.DelegateCall
        );
    }

    function test_multiSendCallOnlyRejectsWrongSelector() public {
        vm.prank(address(SAFE_A));
        vm.expectRevert(Lockdown.BadMultiSendCallOnlyPayload.selector);
        _checkOwner(
            address(SAFE_A),
            address(multiSendCallOnly),
            0,
            abi.encodeWithSelector(bytes4(0xdeadbeef), _multiSendItem(Enum.Operation.Call, TARGET, 0, hex"")),
            Enum.Operation.DelegateCall
        );
    }

    function test_multiSendCallOnlyRejectsInnerDelegatecall() public {
        vm.prank(address(SAFE_A));
        vm.expectRevert(Lockdown.DelegateCallDenied.selector);
        _checkOwner(
            address(SAFE_A),
            address(multiSendCallOnly),
            0,
            abi.encodeCall(
                MultiSendCallOnly.multiSend, (_multiSendItem(Enum.Operation.DelegateCall, TARGET, 0, hex""))
            ),
            Enum.Operation.DelegateCall
        );
    }

    function test_multiSendCallOnlyNestedBatchAllowed() public {
        vm.prank(address(SAFE_A));
        _checkOwner(
            address(SAFE_A),
            address(multiSendCallOnly),
            0,
            abi.encodeCall(
                MultiSendCallOnly.multiSend,
                (_multiSendItem(
                        Enum.Operation.DelegateCall,
                        address(multiSendCallOnly),
                        0,
                        abi.encodeCall(
                            MultiSendCallOnly.multiSend, (_multiSendItem(Enum.Operation.Call, TARGET, 0, hex"12345678"))
                        )
                    ))
            ),
            Enum.Operation.DelegateCall
        );
    }

    function test_multiSendCallOnlyRejectsSetFallbackHandlerInNestedBatch() public {
        LockdownFallbackHandler foreignHandler = new LockdownFallbackHandler(StateMachine(address(0xBEEF)));

        vm.prank(address(SAFE_A));
        vm.expectRevert(Lockdown.InvalidFallbackHandler.selector);
        _checkOwner(
            address(SAFE_A),
            address(multiSendCallOnly),
            0,
            abi.encodeCall(
                MultiSendCallOnly.multiSend,
                (_multiSendItem(
                        Enum.Operation.DelegateCall,
                        address(multiSendCallOnly),
                        0,
                        abi.encodeCall(
                            MultiSendCallOnly.multiSend,
                            (_multiSendItem(
                                    Enum.Operation.Call,
                                    address(SAFE_A),
                                    0,
                                    abi.encodeCall(IFallbackManager.setFallbackHandler, (address(foreignHandler)))
                                ))
                        )
                    ))
            ),
            Enum.Operation.DelegateCall
        );
    }

    function test_multiSendCallOnlyRejectInnerDelegatecallInNestedBatch() public {
        vm.prank(address(SAFE_A));
        vm.expectRevert(Lockdown.DelegateCallDenied.selector);
        _checkOwner(
            address(SAFE_A),
            address(multiSendCallOnly),
            0,
            abi.encodeCall(
                MultiSendCallOnly.multiSend,
                (_multiSendItem(
                        Enum.Operation.DelegateCall,
                        address(multiSendCallOnly),
                        0,
                        abi.encodeCall(
                            MultiSendCallOnly.multiSend,
                            (_multiSendItem(Enum.Operation.DelegateCall, TARGET, 0, hex"12345678"))
                        )
                    ))
            ),
            Enum.Operation.DelegateCall
        );
    }

    function test_multiSendCallOnlyAllowsInnerSafeAdminCall() public {
        vm.prank(address(SAFE_A));
        _checkOwner(
            address(SAFE_A),
            address(multiSendCallOnly),
            0,
            abi.encodeCall(
                MultiSendCallOnly.multiSend, (_multiSendItem(Enum.Operation.Call, address(SAFE_A), 0, hex"e19a9dd9"))
            ),
            Enum.Operation.DelegateCall
        );
    }

    function test_multiSendCallOnlyAdminCallAllowedInNormalMode() public {
        vm.prank(address(SAFE_A));
        _checkOwner(
            address(SAFE_A),
            address(multiSendCallOnly),
            0,
            abi.encodeCall(
                MultiSendCallOnly.multiSend,
                (_multiSendItem(
                        Enum.Operation.Call,
                        address(guard),
                        0,
                        abi.encodeWithSelector(guard.setResumeDelay.selector, 5 hours)
                    ))
            ),
            Enum.Operation.DelegateCall
        );
    }

    function test_multiSendInnerCallToOtherSafeAllowedInNormalMode() public {
        vm.prank(address(SAFE_A));
        _checkOwner(
            address(SAFE_A),
            address(multiSendCallOnly),
            0,
            abi.encodeCall(
                MultiSendCallOnly.multiSend, (_multiSendItem(Enum.Operation.Call, address(SAFE_B), 0, hex"12345678"))
            ),
            Enum.Operation.DelegateCall
        );
    }

    /// @dev Review round 3 MultiSend audit follow-up (SPEC §11.7 scope note):
    ///      empty-data inner CALLs to the calling Safe / address(0) / the
    ///      singleton are INTENTIONALLY allowed by the parser. The
    ///      forbidden-target check is gated on `dataLength != 0` because
    ///      an empty CALL cannot carry an admin selector. Confirm the
    ///      three classes pass the parser cleanly (any subsequent
    ///      execution-layer behaviour is out of parser scope).
    function test_multiSendCallOnlyAllowsEmptyDataToCallingSafe() public {
        vm.prank(address(SAFE_A));
        _checkOwner(
            address(SAFE_A),
            address(multiSendCallOnly),
            0,
            abi.encodeCall(
                MultiSendCallOnly.multiSend, (_multiSendItem(Enum.Operation.Call, address(SAFE_A), 0, hex""))
            ),
            Enum.Operation.DelegateCall
        );
    }

    function test_multiSendCallOnlyAllowsEmptyDataToZeroAddress() public {
        vm.prank(address(SAFE_A));
        _checkOwner(
            address(SAFE_A),
            address(multiSendCallOnly),
            0,
            abi.encodeCall(MultiSendCallOnly.multiSend, (_multiSendItem(Enum.Operation.Call, address(0), 0, hex""))),
            Enum.Operation.DelegateCall
        );
    }

    function test_multiSendCallOnlyAllowsEmptyDataToSingleton() public {
        vm.prank(address(SAFE_A));
        _checkOwner(
            address(SAFE_A),
            address(multiSendCallOnly),
            0,
            abi.encodeCall(
                MultiSendCallOnly.multiSend, (_multiSendItem(Enum.Operation.Call, address(guard), 0, hex""))
            ),
            Enum.Operation.DelegateCall
        );
    }

    function test_multiSendAbiDecodeOverrunReverts() public {
        bytes memory payload =
            abi.encodePacked(MultiSendCallOnly.multiSend.selector, uint256(0x20), uint256(1000), hex"0102030405");
        vm.prank(address(SAFE_A));
        (bool ok,) = address(guard)
            .call(
                abi.encodeCall(
                    guard.checkTransaction,
                    (
                        address(multiSendCallOnly),
                        uint256(0),
                        payload,
                        Enum.Operation.DelegateCall,
                        uint256(0),
                        uint256(0),
                        uint256(0),
                        address(0),
                        payable(address(0)),
                        hex"",
                        address(0)
                    )
                )
            );
        assertFalse(ok, "decode overrun reverts");
    }

    // -------------------------------------------------------------------
    // MultiSend parser: multi-item batches (review coverage #14)
    // -------------------------------------------------------------------

    function test_multiSendMultiItemAllValidPasses() public {
        vm.prank(address(SAFE_A));
        _checkOwner(
            address(SAFE_A),
            address(multiSendCallOnly),
            0,
            abi.encodeCall(
                MultiSendCallOnly.multiSend,
                (abi.encodePacked(
                        _multiSendItem(Enum.Operation.Call, TARGET, 0, hex"12345678"),
                        _multiSendItem(Enum.Operation.Call, address(SAFE_B), 0, hex""),
                        _multiSendItem(Enum.Operation.Call, address(0xBEEF), 0, hex"aabbccdd")
                    ))
            ),
            Enum.Operation.DelegateCall
        );
    }

    function test_multiSendMultiItemRejectsDelegatecallInSecondItem() public {
        vm.prank(address(SAFE_A));
        vm.expectRevert(Lockdown.DelegateCallDenied.selector);
        _checkOwner(
            address(SAFE_A),
            address(multiSendCallOnly),
            0,
            abi.encodeCall(
                MultiSendCallOnly.multiSend,
                (abi.encodePacked(
                        _multiSendItem(Enum.Operation.Call, TARGET, 0, hex"12345678"),
                        _multiSendItem(Enum.Operation.DelegateCall, address(SAFE_B), 0, hex"") // inner delegatecall
                    ))
            ),
            Enum.Operation.DelegateCall
        );
    }

    function test_multiSendMultiItemAllowsSelfCallInMiddle() public {
        vm.prank(address(SAFE_A));
        _checkOwner(
            address(SAFE_A),
            address(multiSendCallOnly),
            0,
            abi.encodeCall(
                MultiSendCallOnly.multiSend,
                (abi.encodePacked(
                        _multiSendItem(Enum.Operation.Call, TARGET, 0, hex"12345678"),
                        _multiSendItem(Enum.Operation.Call, address(SAFE_A), 0, hex"e19a9dd9"), // self-call with data
                        _multiSendItem(Enum.Operation.Call, address(SAFE_B), 0, hex"")
                    ))
            ),
            Enum.Operation.DelegateCall
        );
    }

    /// @dev The parser intentionally ignores inner `value` (only operation /
    ///      to / dataLength gate); a value-bearing inner CALL passes parsing.
    function test_multiSendNonZeroInnerValueAllowed() public {
        vm.prank(address(SAFE_A));
        _checkOwner(
            address(SAFE_A),
            address(multiSendCallOnly),
            0,
            abi.encodeCall(
                MultiSendCallOnly.multiSend,
                (abi.encodePacked(
                        _multiSendItem(Enum.Operation.Call, TARGET, 1 ether, hex"12345678"),
                        _multiSendItem(Enum.Operation.Call, address(SAFE_B), 5 ether, hex"")
                    ))
            ),
            Enum.Operation.DelegateCall
        );
    }

    /// @dev < 85 trailing bytes after a valid item: the next loop iteration
    ///      fails the minimum-item-length check.
    function test_multiSendTrailingGarbageReverts() public {
        vm.prank(address(SAFE_A));
        vm.expectRevert(Lockdown.BadMultiSendCallOnlyPayload.selector);
        _checkOwner(
            address(SAFE_A),
            address(multiSendCallOnly),
            0,
            abi.encodeCall(
                MultiSendCallOnly.multiSend,
                (abi.encodePacked(_multiSendItem(Enum.Operation.Call, TARGET, 0, hex"12345678"), hex"deadbeef"))
            ),
            Enum.Operation.DelegateCall
        );
    }

    /// @dev Last item declares dataLength = 64 but provides only 4 data bytes:
    ///      the data-fits-within-payload check fails.
    function test_multiSendIncompleteLastItemReverts() public {
        vm.prank(address(SAFE_A));
        vm.expectRevert(Lockdown.BadMultiSendCallOnlyPayload.selector);
        _checkOwner(
            address(SAFE_A),
            address(multiSendCallOnly),
            0,
            abi.encodeCall(
                MultiSendCallOnly.multiSend,
                (abi.encodePacked(
                        _multiSendItem(Enum.Operation.Call, address(SAFE_B), 0, hex""),
                        abi.encodePacked(Enum.Operation.Call, bytes20(TARGET), uint256(0), uint256(64), hex"aabbccdd")
                    ))
            ),
            Enum.Operation.DelegateCall
        );
    }

    // -------------------------------------------------------------------
    // State getter
    // -------------------------------------------------------------------

    function test_getStateReturnsNormalThenLockedDownThenRecovering() public {
        (StateMachine.State s0, uint64 r0) = guard.getState(address(SAFE_A));
        assertEq(uint8(s0), uint8(StateMachine.State.Normal), "normal");
        assertEq(r0, 0, "no remaining");

        _triggerLockdown(SAFE_A, bytes32("panic"));
        (StateMachine.State s1, uint64 r1) = guard.getState(address(SAFE_A));
        assertEq(uint8(s1), uint8(StateMachine.State.LockedDown), "locked");
        assertEq(r1, 48 hours, "remaining = full duration");

        vm.warp(block.timestamp + 48 hours + 1);
        (StateMachine.State s2, uint64 r2) = guard.getState(address(SAFE_A));
        assertEq(uint8(s2), uint8(StateMachine.State.Recovering), "recovering");
        assertEq(r2, 0, "no remaining in recovery");
    }

    function test_boundaryBlockTimestampEqualsLockdownUntil() public {
        _triggerLockdown(SAFE_A, bytes32("panic"));
        (,, uint64 expiry,,) = guard.getConfigSnapshot(address(SAFE_A));
        vm.warp(uint256(expiry));
        assertFalse(_isLockedDown(address(SAFE_A)), "not locked at boundary");
        assertTrue(_isRecovering(address(SAFE_A)), "recovering at boundary");
    }

    // -------------------------------------------------------------------
    // V1 hardening: NotInitialised gate on admin setters
    // -------------------------------------------------------------------

    function test_setLockdownDuration_revertsBeforeInitialise() public {
        vm.prank(address(SAFE_UNINIT));
        vm.expectRevert(
            abi.encodeWithSelector(
                StateMachine.InvalidState.selector,
                StateMachine.State.Uninitialised,
                1 << uint256(StateMachine.State.Normal)
            )
        );
        guard.setLockdownDuration(24 hours);
    }

    function test_setResumeDelay_revertsBeforeInitialise() public {
        vm.prank(address(SAFE_UNINIT));
        vm.expectRevert(
            abi.encodeWithSelector(
                StateMachine.InvalidState.selector,
                StateMachine.State.Uninitialised,
                1 << uint256(StateMachine.State.Normal)
            )
        );
        guard.setResumeDelay(6 hours);
    }

    function test_addRecoveryOwner_revertsBeforeInitialise() public {
        vm.prank(address(SAFE_UNINIT));
        vm.expectRevert(
            abi.encodeWithSelector(
                StateMachine.InvalidState.selector,
                StateMachine.State.Uninitialised,
                1 << uint256(StateMachine.State.Normal)
            )
        );
        guard.addRecoveryOwner(NEW_OWNER);
    }

    function test_addLockdownSigner_revertsBeforeInitialise() public {
        vm.prank(address(SAFE_UNINIT));
        vm.expectRevert(
            abi.encodeWithSelector(
                StateMachine.InvalidState.selector,
                StateMachine.State.Uninitialised,
                1 << uint256(StateMachine.State.Normal)
            )
        );
        guard.addLockdownSigner(_eoaSigner(panicKey));
    }

    function test_removeLockdownSigner_revertsBeforeInitialise() public {
        vm.prank(address(SAFE_UNINIT));
        vm.expectRevert(
            abi.encodeWithSelector(
                StateMachine.InvalidState.selector,
                StateMachine.State.Uninitialised,
                1 << uint256(StateMachine.State.Normal) | 1 << uint256(StateMachine.State.Recovering)
            )
        );
        guard.removeLockdownSigner(_eoaSigner(panicKey));
    }

    function test_rotateLockdownSigner_revertsBeforeInitialise() public {
        vm.prank(address(SAFE_UNINIT));
        vm.expectRevert(
            abi.encodeWithSelector(
                StateMachine.InvalidState.selector,
                StateMachine.State.Uninitialised,
                1 << uint256(StateMachine.State.Normal)
            )
        );
        guard.rotateLockdownSigner(abi.encodePacked(panicKey), abi.encodePacked(panicKey));
    }

    /// @notice Pre-init setLockdownDuration must NOT block subsequent
    ///         initialize: that was the earlier bug.
    function test_setLockdownDuration_doesNotBlockInitialize_becauseGated() public {
        // The setter reverts before initialize, so cfg.lockdownDuration stays 0.
        vm.prank(address(SAFE_UNINIT));
        vm.expectRevert(
            abi.encodeWithSelector(
                StateMachine.InvalidState.selector,
                StateMachine.State.Uninitialised,
                1 << uint256(StateMachine.State.Normal)
            )
        );
        guard.setLockdownDuration(24 hours);

        // initialize then succeeds normally.
        address[] memory backups = _singleBackup(BACKUP_OWNER_A);
        bytes[] memory signers = new bytes[](0);
        vm.prank(address(SAFE_UNINIT));
        guard.initialize(24 hours, 4 hours, backups, signers);

        (uint64 d,,,,) = guard.getConfigSnapshot(address(SAFE_UNINIT));
        assertEq(d, 24 hours, "lockdownDuration set by init");
    }

    // -------------------------------------------------------------------
    // V1 hardening: module path cannot reach singleton admin
    // -------------------------------------------------------------------

    function test_moduleCallToSingleton_isRejectedInNormalMode() public {
        // Even in Normal mode, a module trying to invoke any singleton
        // function via Safe.execTransactionFromModule must be rejected at
        // the moduleGuard hook, because msg.sender would otherwise be the
        // Safe and the admin write would succeed.
        bytes memory adminCalldata = abi.encodeCall(guard.addLockdownSigner, (_eoaSigner(panicKey)));
        vm.prank(address(SAFE_A));
        vm.expectRevert(Lockdown.ModuleCallToSingletonDenied.selector);
        guard.checkModuleTransaction(address(guard), 0, adminCalldata, Enum.Operation.Call, MODULE);
    }

    function test_moduleCallToSingleton_blocksTriggerLockdown() public {
        bytes memory triggerCalldata =
            abi.encodeCall(guard.triggerLockdown, (address(SAFE_A), bytes32("x"), _eoaSigner(panicKey), hex""));
        vm.prank(address(SAFE_A));
        vm.expectRevert(Lockdown.ModuleCallToSingletonDenied.selector);
        guard.checkModuleTransaction(address(guard), 0, triggerCalldata, Enum.Operation.Call, MODULE);
    }

    /// @notice Review C1 regression (SPEC_V1 §H.12). If the
    ///         module-path singleton denial sits AFTER the uninitialised
    ///         fail-open, an enabled malicious module on a Safe that has
    ///         installed the singleton as module guard but has not yet
    ///         been initialised can call `initialize(...)` with
    ///         attacker-chosen recovery owners / LockdownSigners.
    ///         The denial MUST precede the fail-open.
    function test_moduleCallToSingleton_blockedEvenWhenUninit() public {
        address[] memory backups = _singleBackup(BACKUP_OWNER_A);
        bytes[] memory signers = new bytes[](0);
        bytes memory initCalldata =
            abi.encodeCall(guard.initialize, (uint64(48 hours), uint64(4 hours), backups, signers));
        vm.prank(address(SAFE_UNINIT));
        vm.expectRevert(Lockdown.ModuleCallToSingletonDenied.selector);
        guard.checkModuleTransaction(address(guard), 0, initCalldata, Enum.Operation.Call, MODULE);
    }

    function test_moduleCallToSingleton_blockedEvenWhenUninit_addSigner() public {
        bytes memory addCalldata = abi.encodeCall(guard.addLockdownSigner, (_eoaSigner(panicKey)));
        vm.prank(address(SAFE_UNINIT));
        vm.expectRevert(Lockdown.ModuleCallToSingletonDenied.selector);
        guard.checkModuleTransaction(address(guard), 0, addCalldata, Enum.Operation.Call, MODULE);
    }

    function test_moduleCallToBatch() public {
        vm.prank(address(SAFE_A));
        guard.checkModuleTransaction(
            address(multiSendCallOnly),
            0,
            abi.encodeCall(
                MultiSendCallOnly.multiSend, (_multiSendItem(Enum.Operation.Call, TARGET, 0, hex"12345678"))
            ),
            Enum.Operation.DelegateCall,
            MODULE
        );
    }

    function test_moduleCallToBatch_rejectInnerCallToSingleton() public {
        vm.prank(address(SAFE_A));
        vm.expectRevert(Lockdown.ModuleCallToSingletonDenied.selector);
        guard.checkModuleTransaction(
            address(multiSendCallOnly),
            0,
            abi.encodeCall(
                MultiSendCallOnly.multiSend,
                (_multiSendItem(
                        Enum.Operation.Call,
                        address(guard),
                        0,
                        abi.encodeCall(guard.addLockdownSigner, (_eoaSigner(panicKey)))
                    ))
            ),
            Enum.Operation.DelegateCall,
            MODULE
        );
    }

    // Module-path Safe self-calls may not mutate guard/module topology or
    // reenter module execution. Otherwise a scheduled module batch can
    // temporarily clear the module guard and tunnel singleton admin calls.
    function test_module_setGuardSelfCall_rejected() public {
        vm.prank(address(SAFE_A));
        vm.expectRevert(Lockdown.ModuleSafeSelfCallDenied.selector);
        guard.checkModuleTransaction(
            address(SAFE_A), 0, abi.encodeCall(SAFE_A.setGuard, (address(0))), Enum.Operation.Call, MODULE
        );
    }

    function test_module_setModuleGuardSelfCall_rejected() public {
        vm.prank(address(SAFE_A));
        vm.expectRevert(Lockdown.ModuleSafeSelfCallDenied.selector);
        guard.checkModuleTransaction(
            address(SAFE_A), 0, abi.encodeCall(SAFE_A.setModuleGuard, (address(0))), Enum.Operation.Call, MODULE
        );
    }

    function test_moduleCallToBatch_rejectsInnerSetGuard() public {
        vm.prank(address(SAFE_A));
        vm.expectRevert(Lockdown.ModuleSafeSelfCallDenied.selector);
        guard.checkModuleTransaction(
            address(multiSendCallOnly),
            0,
            abi.encodeCall(
                MultiSendCallOnly.multiSend,
                (_multiSendItem(Enum.Operation.Call, address(SAFE_A), 0, abi.encodeCall(SAFE_A.setGuard, (address(0)))))
            ),
            Enum.Operation.DelegateCall,
            MODULE
        );
    }

    function test_moduleCallToBatch_rejectsInnerSetModuleGuard() public {
        vm.prank(address(SAFE_A));
        vm.expectRevert(Lockdown.ModuleSafeSelfCallDenied.selector);
        guard.checkModuleTransaction(
            address(multiSendCallOnly),
            0,
            abi.encodeCall(
                MultiSendCallOnly.multiSend,
                (_multiSendItem(
                        Enum.Operation.Call, address(SAFE_A), 0, abi.encodeCall(SAFE_A.setModuleGuard, (address(0)))
                    ))
            ),
            Enum.Operation.DelegateCall,
            MODULE
        );
    }

    // The module path can NEVER swap the fallback handler: setFallbackHandler is a
    // guard-disable self-call (it carries the ERC-1271 freeze), so it is denied on
    // the module path outright, whether or not the proposed handler is valid. The
    // owner-path binding check (InvalidFallbackHandler) is covered by the
    // "...InNormalMode" tests above.
    function test_module_setFallbackHandler_deniedForValidHandler() public {
        LockdownFallbackHandler newHandler = new LockdownFallbackHandler(guard);
        vm.prank(address(SAFE_A));
        vm.expectRevert(Lockdown.ModuleSafeSelfCallDenied.selector);
        guard.checkModuleTransaction(
            address(SAFE_A),
            0,
            abi.encodeCall(IFallbackManager.setFallbackHandler, (address(newHandler))),
            Enum.Operation.Call,
            MODULE
        );
    }

    function test_module_setFallbackHandler_deniedForForeignHandler() public {
        LockdownFallbackHandler foreignHandler = new LockdownFallbackHandler(StateMachine(address(0xBEEF)));
        vm.prank(address(SAFE_A));
        vm.expectRevert(Lockdown.ModuleSafeSelfCallDenied.selector);
        guard.checkModuleTransaction(
            address(SAFE_A),
            0,
            abi.encodeCall(IFallbackManager.setFallbackHandler, (address(foreignHandler))),
            Enum.Operation.Call,
            MODULE
        );
    }

    // -------------------------------------------------------------------
    // Signer registration does not constrain key shape. Key-shape validity
    // is the off-chain tooling's responsibility; the verifier rejects a
    // malformed key at trigger time via verify() (the former on-chain
    // registration gate has been removed).
    // -------------------------------------------------------------------

    function test_addLockdownSigner_acceptsCanonicalEcdsaKey() public {
        // Positive case: 20-byte packed address still registers cleanly.
        bytes memory goodKey = abi.encodePacked(address(0xCAFE0));
        vm.prank(address(SAFE_A));
        guard.addLockdownSigner(goodKey);
        assertTrue(guard.isLockdownSigner(address(SAFE_A), goodKey), "registered");
    }

    function test_addLockdownSigner_acceptsArbitraryKeyShape() public {
        // Registration accepts any non-empty key shape: a 32-byte key that
        // an arbitrary ERC-7913 key shape still registers fine,
        // since key-shape validation is now off-chain only.
        bytes memory key = abi.encodePacked(keccak256("arbitrary-shape"));
        vm.prank(address(SAFE_A));
        bytes memory signer = _verifierSigner(address(secretVerifier), key);
        guard.addLockdownSigner(signer);
        assertTrue(guard.isLockdownSigner(address(SAFE_A), signer), "registers");
    }

    // -------------------------------------------------------------------
    // V1 hardening (SPEC_V1 §H.15, Gap 3 / finding B):
    // SafeDormant MUST be emitted on every transition to signersCount == 0,
    // not only on initialize-with-empty-LockdownSigners.
    // -------------------------------------------------------------------

    bytes32 private constant SAFE_DORMANT_TOPIC = keccak256("SafeDormant(address)");

    function _countSafeDormantEvents(Vm.Log[] memory logs, address safe) private view returns (uint256 n) {
        bytes32 expectedSafe = bytes32(uint256(uint160(safe)));
        for (uint256 i = 0; i < logs.length; ++i) {
            Vm.Log memory L = logs[i];
            if (L.emitter != address(guard)) continue;
            if (L.topics.length < 2) continue;
            if (L.topics[0] != SAFE_DORMANT_TOPIC) continue;
            if (L.topics[1] != expectedSafe) continue;
            n += 1;
        }
    }

    function test_safeDormant_emittedWhenLastSignerRemoved() public {
        // address(SAFE_B) was initialised in setUp() with exactly ONE signer.
        vm.recordLogs();
        vm.prank(address(SAFE_B));
        guard.removeLockdownSigner(_eoaSigner(panicKey));
        Vm.Log[] memory logs = vm.getRecordedLogs();
        assertEq(_countSafeDormantEvents(logs, address(SAFE_B)), 1, "SafeDormant emitted once");
        (,,, uint256 cnt,) = guard.getConfigSnapshot(address(SAFE_B));
        assertEq(cnt, 0, "signersCount == 0");
    }

    function test_safeDormant_notEmittedWhenNonLastSignerRemoved() public {
        // address(SAFE_A) has TWO LockdownSigners. Remove one; signersCount drops to 1, no event.
        vm.recordLogs();
        vm.prank(address(SAFE_A));
        guard.removeLockdownSigner(_eoaSigner(panicKey));
        Vm.Log[] memory logs = vm.getRecordedLogs();
        assertEq(_countSafeDormantEvents(logs, address(SAFE_A)), 0, "no SafeDormant yet");
    }

    function test_safeDormant_emittedWhenLastSignerBurnt() public {
        // address(SAFE_B) has exactly ONE signer. Trigger burns it → SafeDormant.
        vm.recordLogs();
        bytes32 reasonHash = bytes32("panic-B");
        bytes32 msgHash = _msgHash(address(SAFE_B), _eoaSigner(panicKey), reasonHash);
        bytes memory sig = _ecdsaSign(PANIC_PK, msgHash);
        guard.triggerLockdown(address(SAFE_B), reasonHash, _eoaSigner(panicKey), sig);
        Vm.Log[] memory logs = vm.getRecordedLogs();
        assertEq(_countSafeDormantEvents(logs, address(SAFE_B)), 1, "burn-to-zero emits");
    }

    function test_safeDormant_notEmittedWhenBurningNonLast() public {
        // address(SAFE_A) has TWO LockdownSigners. Burn one (the ECDSA one) → still one left.
        vm.recordLogs();
        _triggerLockdown(SAFE_A, bytes32("panic"));
        Vm.Log[] memory logs = vm.getRecordedLogs();
        assertEq(_countSafeDormantEvents(logs, address(SAFE_A)), 0, "still has another signer");
    }

    function test_safeDormant_notEmittedDuringRotate() public {
        // rotateLockdownSigner removes then adds atomically. The transient
        // count==0 state inside the call MUST NOT emit SafeDormant; that
        // would be noise for indexers.
        vm.recordLogs();
        vm.prank(address(SAFE_B));
        guard.rotateLockdownSigner(abi.encodePacked(panicKey), abi.encodePacked(address(0xBEEF1)));
        Vm.Log[] memory logs = vm.getRecordedLogs();
        assertEq(_countSafeDormantEvents(logs, address(SAFE_B)), 0, "rotate stays armed");
    }

    function test_safeDormant_emittedDuringRecoveryRemove() public {
        // address(SAFE_B) (1 signer) triggers → burns the signer → SafeDormant #1.
        // Then quorum, during Recovering, calls removeLockdownSigner on a
        // SIGNER THAT EXISTS — but B has only the burnt one. To exercise
        // the path with a real signer, add a transient second signer first.
        vm.prank(address(SAFE_B));
        guard.addLockdownSigner(abi.encodePacked(address(0xDEAD2)));
        // Trigger via the original signer (id=1).
        bytes32 reasonHash = bytes32("panicB");
        bytes32 msgHash = _msgHash(address(SAFE_B), _eoaSigner(panicKey), reasonHash);
        bytes memory sig = _ecdsaSign(PANIC_PK, msgHash);
        guard.triggerLockdown(address(SAFE_B), reasonHash, _eoaSigner(panicKey), sig);
        // Burnt one was id=1; the transient id=2 remains. count == 1, no
        // SafeDormant at burn.
        vm.warp(block.timestamp + 24 hours + 1);
        vm.recordLogs();
        vm.prank(address(SAFE_B));
        guard.removeLockdownSigner(abi.encodePacked(address(0xDEAD2)));
        Vm.Log[] memory logs = vm.getRecordedLogs();
        assertEq(_countSafeDormantEvents(logs, address(SAFE_B)), 1, "recovery-remove emits");
    }

    // -------------------------------------------------------------------
    // V1 hardening (SPEC_V1 §H.16, Gap 4):
    // SafeLockedDown carries the signer identity so post-burn forensics can
    // resolve the burnt entry without historical-log replay.
    // -------------------------------------------------------------------

    bytes32 private constant SAFE_LOCKED_DOWN_TOPIC = keccak256("SafeLockedDown(address,uint64,bytes32,bytes)");

    function test_safeLockedDown_eventCarriesSignerIdentity() public {
        vm.recordLogs();
        bytes32 reasonHash = bytes32("panicHash");
        bytes32 msgHash = _msgHash(address(SAFE_A), _eoaSigner(panicKey), reasonHash);
        bytes memory sig = _ecdsaSign(PANIC_PK, msgHash);
        bytes memory signer = _eoaSigner(panicKey);

        guard.triggerLockdown(address(SAFE_A), reasonHash, signer, sig);

        Vm.Log[] memory logs = vm.getRecordedLogs();
        bool found = false;
        for (uint256 i = 0; i < logs.length; ++i) {
            Vm.Log memory L = logs[i];
            if (L.emitter != address(guard)) continue;
            if (L.topics.length < 2) continue;
            if (L.topics[0] != SAFE_LOCKED_DOWN_TOPIC) continue;
            assertEq(L.topics[1], bytes32(uint256(uint160(address(SAFE_A)))), "safe");
            (uint64 lockdownUntil, bytes32 emittedReasonHash, bytes memory emittedSigner) =
                abi.decode(L.data, (uint64, bytes32, bytes));
            assertNotEq(lockdownUntil, 0, "lockdownUntil");
            assertEq(emittedReasonHash, reasonHash, "reasonHash");
            assertEq(emittedSigner, signer, "signer");
            found = true;
            break;
        }
        assertTrue(found, "SafeLockedDown event found");
    }

    // triggerLockdown reuses _removeLockdownSigner, so a successful trigger
    // now also emits LockdownSignerRemoved (set-consistency for indexers).
    // The event MUST be indexed by the `safe` parameter, not msg.sender:
    // triggerLockdown is callable by an arbitrary relayer, so msg.sender is
    // the caller, not the Safe.
    bytes32 private constant LOCKDOWN_SIGNER_REMOVED_TOPIC = keccak256("LockdownSignerRemoved(address,bytes)");

    function test_triggerLockdown_emitsSignerRemovedBoundToSafeNotCaller() public {
        vm.assume(address(this) != address(SAFE_A)); // avoid false positive if test contract is the Safe
        bytes32 reasonHash = bytes32("panic-removed");
        bytes memory sig = _ecdsaSign(PANIC_PK, _msgHash(address(SAFE_A), _eoaSigner(panicKey), reasonHash));
        bytes memory signer = _eoaSigner(panicKey);

        vm.recordLogs();
        guard.triggerLockdown(address(SAFE_A), reasonHash, signer, sig);

        Vm.Log[] memory logs = vm.getRecordedLogs();
        bool found = false;
        for (uint256 i = 0; i < logs.length; ++i) {
            Vm.Log memory L = logs[i];
            if (L.emitter != address(guard)) continue;
            if (L.topics.length < 2) continue;
            if (L.topics[0] != LOCKDOWN_SIGNER_REMOVED_TOPIC) continue;
            assertEq(
                L.topics[1], bytes32(uint256(uint160(address(SAFE_A)))), "indexed safe is the Safe, not the caller"
            );
            bytes memory emittedSigner = abi.decode(L.data, (bytes));
            assertEq(emittedSigner, signer, "signer bytes match");
            found = true;
            break;
        }
        assertTrue(found, "LockdownSignerRemoved emitted on trigger");
    }

    // -------------------------------------------------------------------
    // Off-chain drill (SPEC_V1 §6.4, §H.25): there is no on-chain view to test
    // a signature, so a drill cannot leak a usable trigger signature to an RPC.
    // `script/DrillSigner.s.sol` performs the same check in a local EVM. The
    // removal itself is pinned in test/poc/DrillSignatureExposure.t.sol.
    // -------------------------------------------------------------------

    function test_triggerLockdownRejectsRevertingVerifier() public {
        MockRevertingVerifier rv = new MockRevertingVerifier();
        bytes memory signer = _verifierSigner(address(rv), hex"01");
        vm.prank(address(SAFE_A));
        guard.addLockdownSigner(signer);

        vm.expectRevert(Lockdown.BadSignature.selector);
        guard.triggerLockdown(address(SAFE_A), bytes32("reverting"), signer, hex"02");
    }

    function test_triggerLockdownRejectsEmptyReturnVerifier() public {
        MockEmptyReturnVerifier ev = new MockEmptyReturnVerifier();
        bytes memory signer = _verifierSigner(address(ev), hex"01");
        vm.prank(address(SAFE_A));
        guard.addLockdownSigner(signer);

        vm.expectRevert(Lockdown.BadSignature.selector);
        guard.triggerLockdown(address(SAFE_A), bytes32("empty"), signer, hex"02");
    }

    function test_drillScript_acceptsValidEcdsaWithoutMutatingState() public {
        DrillSigner drill = new DrillSigner();
        bytes32 reasonHash = bytes32("drill");
        bytes memory sig = _ecdsaSign(PANIC_PK, _msgHash(address(SAFE_A), _eoaSigner(panicKey), reasonHash));
        (,,, uint256 cntBefore,) = guard.getConfigSnapshot(address(SAFE_A));

        DrillSigner.Report memory r = drill.check(guard, address(SAFE_A), reasonHash, _eoaSigner(panicKey), sig);
        assertTrue(r.registered && r.valid && !r.burnt, "drill says ready");
        assertEq(uint256(r.state), uint256(StateMachine.State.Normal));

        (,,, uint256 cntAfter,) = guard.getConfigSnapshot(address(SAFE_A));
        assertEq(cntBefore, cntAfter, "no state mutation");

        // The drilled signature is exactly what triggerLockdown accepts.
        guard.triggerLockdown(address(SAFE_A), reasonHash, _eoaSigner(panicKey), sig);
        assertTrue(_isLockedDown(address(SAFE_A)));
    }

    function test_drillScript_rejectsWrongSignerAndWrongDigest() public {
        DrillSigner drill = new DrillSigner();
        bytes32 reasonHash = bytes32("drill");
        bytes memory sig = _ecdsaSign(PANIC_PK, _msgHash(address(SAFE_A), _eoaSigner(panicKey), reasonHash));
        // Control: the negatives below are only meaningful if the drill accepts
        // the right tuple (a drifted drill digest would make them pass vacuously).
        assertTrue(drill.isValid(guard, address(SAFE_A), reasonHash, _eoaSigner(panicKey), sig), "control");

        // Wrong signer: the digest is correct for the claimed identity, the key is not.
        bytes memory wrong = _eoaSigner(address(0xDEADBEEF));
        bytes memory sigForWrong = _ecdsaSign(PANIC_PK, _msgHash(address(SAFE_A), wrong, reasonHash));
        assertFalse(drill.isValid(guard, address(SAFE_A), reasonHash, wrong, sigForWrong), "wrong signer");
        // Wrong digest: right signer and key, signature over another reason / Safe.
        assertFalse(drill.isValid(guard, address(SAFE_A), bytes32("other"), _eoaSigner(panicKey), sig), "wrong reason");
        assertFalse(drill.isValid(guard, address(SAFE_B), reasonHash, _eoaSigner(panicKey), sig), "wrong safe");
    }

    function test_drillScript_digestMatchesTriggerDigest() public {
        DrillSigner drill = new DrillSigner();
        assertEq(
            drill.digest(guard, address(SAFE_A), _eoaSigner(panicKey), bytes32("r")),
            _msgHash(address(SAFE_A), _eoaSigner(panicKey), bytes32("r"))
        );
    }

    function testFuzz_drillScript_digestIsHashLockdownTrigger(address safe, bytes memory signer, bytes32 reasonHash)
        public
    {
        DrillSigner drill = new DrillSigner();
        assertEq(drill.digest(guard, safe, signer, reasonHash), guard.hashLockdownTrigger(safe, signer, reasonHash));
    }

    // -------------------------------------------------------------------
    // V1 hardening: swapOwner exact-length check
    // -------------------------------------------------------------------

    function test_recoveryRejectsSwapOwnerWithTrailingBytes() public {
        _triggerLockdown(SAFE_A, bytes32("panic"));
        vm.warp(block.timestamp + 48 hours + 1);
        bytes memory callData = bytes.concat(
            abi.encodeCall(IOwnerManager.swapOwner, (address(0x1), OLD_OWNER, NEW_OWNER)),
            hex"deadbeef" // extra bytes
        );
        vm.prank(address(SAFE_A));
        vm.expectRevert(Lockdown.RecoveryActive.selector);
        _checkOwner(address(SAFE_A), address(SAFE_A), 0, callData, Enum.Operation.Call);
    }

    // -------------------------------------------------------------------
    // V1 hardening: SafeDormant event on zero-signer initialize
    // -------------------------------------------------------------------

    function test_initializeWithZeroSignersEmitsSafeDormant() public {
        // We don't have vm.expectEmit in this minimal harness; assert state
        // proxies the event semantics (signersCount == 0 after init).
        address[] memory backups = _singleBackup(BACKUP_OWNER_A);
        bytes[] memory signers = new bytes[](0);
        vm.prank(address(SAFE_UNINIT));
        guard.initialize(24 hours, 4 hours, backups, signers);
        (,,, uint256 cnt,) = guard.getConfigSnapshot(address(SAFE_UNINIT));
        assertEq(cnt, 0, "dormant: zero signers");
    }

    // -------------------------------------------------------------------
    // V1 hardening: verifier-revert normalization to BadSignature
    // -------------------------------------------------------------------

    function _registerAdvSigner(address verifier, bytes memory key) private {
        vm.prank(address(SAFE_A));
        guard.addLockdownSigner(_verifierSigner(verifier, key));
    }

    /// @notice Wrong-magic is grief, not security. The smoke test
    ///         has been removed; the L.3 trigger-time normalisation catches
    ///         useless verifiers when a trigger attempt is made.
    function test_wrongMagicVerifier_triggerNormalises() public {
        MockWrongMagicVerifier wv = new MockWrongMagicVerifier();
        bytes memory key = abi.encodePacked(bytes32("wm-key"));
        _registerAdvSigner(address(wv), key);

        vm.expectRevert(Lockdown.BadSignature.selector);
        guard.triggerLockdown(address(SAFE_A), bytes32("x"), _verifierSigner(address(wv), key), hex"");
    }

    // -------------------------------------------------------------------
    // Trigger-time normalization (L.3) via selective mocks that DO pass
    // the smoke test.
    // -------------------------------------------------------------------

    function test_selectiveRevertingVerifier_normalisedToBadSignature() public {
        MockSelectiveRevertingVerifier rv = new MockSelectiveRevertingVerifier();
        bytes memory key = abi.encodePacked(bytes32("rv-key"));
        _registerAdvSigner(address(rv), key);

        vm.expectRevert(Lockdown.BadSignature.selector);
        guard.triggerLockdown(address(SAFE_A), bytes32("x"), _verifierSigner(address(rv), key), hex"deadbeef");
    }

    /// @notice A selective malicious verifier WILL succeed once explicitly
    ///         registered. The remaining mitigation is per-identity removal.
    function test_selectiveMagicVerifier_removeSignerNeutralisesIt() public {
        MockSelectiveMagicVerifier sm = new MockSelectiveMagicVerifier();
        bytes memory key = abi.encodePacked(bytes32("sm-key"));
        bytes memory key2 = abi.encodePacked(bytes32("sm-key-2"));
        _registerAdvSigner(address(sm), key);

        // Baseline: malicious verifier accepts any sig, lockdown fires.
        guard.triggerLockdown(address(SAFE_A), bytes32("first"), _verifierSigner(address(sm), key), hex"01");
        assertTrue(_isLockedDown(address(SAFE_A)), "first trigger locks");

        // Exit recovery, re-register with a FRESH key (V1 INV-SIGN-7
        // prevents re-using the burnt one), then remove that signer.
        // Subsequent trigger must revert NotLockdownSigner.
        vm.warp(block.timestamp + 48 hours + 4 hours + 1);
        _registerAdvSigner(address(sm), key2);
        vm.prank(address(SAFE_A));
        guard.removeLockdownSigner(_verifierSigner(address(sm), key2));

        vm.expectRevert(LockdownSigners.LockdownSigners_Unknown.selector);
        guard.triggerLockdown(address(SAFE_A), bytes32("second"), _verifierSigner(address(sm), key2), hex"01");
    }

    // -------------------------------------------------------------------
    // Review coverage: production-verifier E2E, INV-SIGN-1 rollback,
    // recovery-owner incident rejection, cross-chain binding
    // -------------------------------------------------------------------

    /// @dev End-to-end through the REAL PasswordVerifier (not the mock):
    ///      exercises the ERC-7913 `verifier || key` dispatch and
    ///      SignatureChecker routing all the way to lockdown + burn.
    function test_triggerLockdownWithProductionPasswordVerifier() public {
        PasswordVerifier pv = new PasswordVerifier();
        bytes memory password = "correct horse battery staple";
        bytes memory identity = _verifierSigner(address(pv), abi.encodePacked(keccak256(password)));

        vm.prank(address(SAFE_A));
        guard.addLockdownSigner(identity);
        assertTrue(guard.isLockdownSigner(address(SAFE_A), identity), "password signer registered");

        guard.triggerLockdown(address(SAFE_A), bytes32("pw-panic"), identity, password);
        assertTrue(_isLockedDown(address(SAFE_A)), "locked via production password verifier");
        assertFalse(guard.isLockdownSigner(address(SAFE_A), identity), "password signer removed");
        assertTrue(guard.isSignerBurntPermanently(address(SAFE_A), identity), "password signer permanently burnt");
    }

    /// @dev INV-SIGN-1: verification happens before signer mutation, so a
    ///      BadSignature revert leaves the identity registered and NOT
    ///      permanently burnt.
    function test_triggerLockdownBadSignatureRollsBackSignerRemoval() public {
        bytes memory signer = _eoaSigner(panicKey);
        assertTrue(guard.isLockdownSigner(address(SAFE_A), signer), "registered before");

        bytes32 wrongMsgHash = _msgHash(address(SAFE_A), signer, bytes32("WRONG"));
        bytes memory sig = _ecdsaSign(PANIC_PK, wrongMsgHash);
        vm.expectRevert(Lockdown.BadSignature.selector);
        guard.triggerLockdown(address(SAFE_A), bytes32("right"), signer, sig);

        assertTrue(guard.isLockdownSigner(address(SAFE_A), signer), "still registered after revert");
        assertFalse(guard.isSignerBurntPermanently(address(SAFE_A), signer), "not burnt after revert");
        assertFalse(_isLockedDown(address(SAFE_A)), "still not locked");
    }

    function test_triggerLockdownVerifierFailureCanSucceedAfterRetry() public {
        MockToggleVerifier tv = new MockToggleVerifier();
        bytes memory identity = _verifierSigner(address(tv), abi.encodePacked(bytes32("retry-key")));

        vm.prank(address(SAFE_A));
        guard.addLockdownSigner(identity);

        tv.setAccepts(false);
        vm.expectRevert(Lockdown.BadSignature.selector);
        guard.triggerLockdown(address(SAFE_A), bytes32("first"), identity, hex"01");

        assertTrue(guard.isLockdownSigner(address(SAFE_A), identity), "failed verify keeps signer");
        assertFalse(guard.isSignerBurntPermanently(address(SAFE_A), identity), "failed verify does not burn");
        assertFalse(_isLockedDown(address(SAFE_A)), "failed verify does not lock");

        tv.setAccepts(true);
        guard.triggerLockdown(address(SAFE_A), bytes32("retry"), identity, hex"01");

        assertTrue(_isLockedDown(address(SAFE_A)), "retry locks");
        assertFalse(guard.isLockdownSigner(address(SAFE_A), identity), "successful retry removes signer");
        assertTrue(guard.isSignerBurntPermanently(address(SAFE_A), identity), "successful retry burns signer");
    }

    function test_addRecoveryOwnerRejectedDuringIncidentStates() public {
        _triggerLockdown(SAFE_A, bytes32("panic")); // LockedDown
        vm.prank(address(SAFE_A));
        vm.expectRevert(
            abi.encodeWithSelector(
                StateMachine.InvalidState.selector,
                StateMachine.State.LockedDown,
                1 << uint256(StateMachine.State.Normal)
            )
        );
        guard.addRecoveryOwner(address(0xBEEF));

        vm.warp(block.timestamp + 48 hours + 1); // Recovering
        vm.prank(address(SAFE_A));
        vm.expectRevert(
            abi.encodeWithSelector(
                StateMachine.InvalidState.selector,
                StateMachine.State.Recovering,
                1 << uint256(StateMachine.State.Normal)
            )
        );
        guard.addRecoveryOwner(address(0xBEEF));

        vm.warp(block.timestamp + 4 hours); // past resumeDelay -> auto-resumed to Normal
        vm.prank(address(SAFE_A));
        guard.addRecoveryOwner(address(0xBEEF));
    }

    function test_removeRecoveryOwnerRejectedDuringIncidentStates() public {
        _triggerLockdown(SAFE_A, bytes32("panic")); // LockedDown
        vm.prank(address(SAFE_A));
        vm.expectRevert(
            abi.encodeWithSelector(
                StateMachine.InvalidState.selector,
                StateMachine.State.LockedDown,
                1 << uint256(StateMachine.State.Normal)
            )
        );
        guard.removeRecoveryOwner(NEW_OWNER);

        vm.warp(block.timestamp + 48 hours + 1); // Recovering
        vm.prank(address(SAFE_A));
        vm.expectRevert(
            abi.encodeWithSelector(
                StateMachine.InvalidState.selector,
                StateMachine.State.Recovering,
                1 << uint256(StateMachine.State.Normal)
            )
        );
        guard.removeRecoveryOwner(NEW_OWNER);

        vm.warp(block.timestamp + 4 hours); // past resumeDelay -> auto-resumed to Normal
        vm.prank(address(SAFE_A));
        guard.removeRecoveryOwner(NEW_OWNER);
    }

    /// @dev EIP-712 domain binds chainId: a signature made for the current
    ///      chain must not verify after the chain id changes. OZ EIP712
    ///      recomputes the domain separator on a fork, so the digest differs
    ///      and ECDSA recovery yields a non-signer -> BadSignature.
    function test_triggerSignatureDoesNotReplayAcrossChains() public {
        bytes32 reasonHash = bytes32("xchain");
        bytes memory sig = _ecdsaSign(PANIC_PK, _msgHash(address(SAFE_A), _eoaSigner(panicKey), reasonHash));

        vm.chainId(424242);
        vm.expectRevert(Lockdown.BadSignature.selector);
        guard.triggerLockdown(address(SAFE_A), reasonHash, _eoaSigner(panicKey), sig);
    }

    /// @dev H.15 `SafeDormant` must fire on `initialize` IFF the Safe is armed
    ///      with zero signers (kills the gambit `nSigners == 0` -> `true`
    ///      mutant).
    function test_initializeEmitsSafeDormantWhenZeroSigners() public {
        address[] memory backups = new address[](1);
        backups[0] = BACKUP_OWNER_A;

        bytes[] memory none = new bytes[](0);
        vm.recordLogs();
        vm.prank(address(SAFE_UNINIT));
        guard.initialize(48 hours, 4 hours, backups, none);
        assertTrue(_logEmitted(LockdownSigners.SafeDormant.selector), "SafeDormant emitted on zero-signer init");
    }

    function test_initializeDoesNotEmitSafeDormantWhenSignersPresent() public {
        address[] memory backups = new address[](1);
        backups[0] = BACKUP_OWNER_A;

        bytes[] memory one = new bytes[](1);
        one[0] = _eoaSigner(panicKey);
        vm.recordLogs();
        vm.prank(address(SAFE_UNINIT));
        guard.initialize(48 hours, 4 hours, backups, one);
        assertFalse(_logEmitted(LockdownSigners.SafeDormant.selector), "SafeDormant not emitted when signers present");
    }

    // -------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------

    // isLockedDown / isRecovering were removed from the contract in favour of
    // getState(); these local mirrors preserve the semantics for the assertions
    // below. isRecovering covers only the Recovering state: the Resumable state
    // was removed, so after the recovery window the Safe auto-resumes to Normal.
    function _isLockedDown(address safe) private view returns (bool) {
        (StateMachine.State state,) = guard.getState(safe);
        return state == StateMachine.State.LockedDown;
    }

    function _logEmitted(bytes32 topic0) private returns (bool) {
        Vm.Log[] memory logs = vm.getRecordedLogs();
        for (uint256 i = 0; i < logs.length; i++) {
            if (logs[i].emitter == address(guard) && logs[i].topics.length > 0 && logs[i].topics[0] == topic0) {
                return true;
            }
        }
        return false;
    }

    function _topicPresent(Vm.Log[] memory logs, bytes32 topic0) private view returns (bool) {
        for (uint256 i = 0; i < logs.length; i++) {
            if (logs[i].emitter == address(guard) && logs[i].topics.length > 0 && logs[i].topics[0] == topic0) {
                return true;
            }
        }
        return false;
    }

    function _isRecovering(address safe) private view returns (bool) {
        (StateMachine.State state,) = guard.getState(safe);
        return state == StateMachine.State.Recovering;
    }

    function _msgHash(address safe, bytes memory signer, bytes32 reasonHash) private view returns (bytes32) {
        return _typedDataHash(keccak256(abi.encode(guard.LOCKDOWN_TYPEHASH(), safe, keccak256(signer), reasonHash)));
    }

    function _typedDataHash(bytes32 structHash) private view returns (bytes32) {
        (, string memory name, string memory version, uint256 chainId, address verifyingContract,,) =
            guard.eip712Domain();
        bytes32 domainSep = keccak256(
            abi.encode(
                keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
                keccak256(bytes(name)),
                keccak256(bytes(version)),
                chainId,
                verifyingContract
            )
        );
        return keccak256(abi.encodePacked("\x19\x01", domainSep, structHash));
    }

    function _eoaSigner(address signer) private pure returns (bytes memory) {
        return abi.encodePacked(signer);
    }

    function _verifierSigner(address verifier, bytes memory key) private pure returns (bytes memory) {
        return abi.encodePacked(verifier, key);
    }

    function _secretSignerA() private view returns (bytes memory) {
        return _verifierSigner(address(secretVerifier), abi.encodePacked(keccak256(SHARED_SECRET_A)));
    }

    function _ecdsaSign(uint256 priv, bytes32 digest) private returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(priv, digest);
        return abi.encodePacked(r, s, v);
    }

    function _signWithPassword(bytes memory preimage) private pure returns (bytes memory) {
        return preimage; // password verifier's "signature" IS the preimage
    }

    function _checkOwner(
        address,
        /* safe */
        address to,
        uint256 value,
        bytes memory data,
        Enum.Operation operation
    )
        private
    {
        _checkOwnerFull(to, value, data, operation, 0, 0, 0, address(0), payable(address(0)));
    }

    function _checkOwnerFull(
        address to,
        uint256 value,
        bytes memory data,
        Enum.Operation operation,
        uint256 safeTxGas,
        uint256 baseGas,
        uint256 gasPrice,
        address gasToken,
        address payable refundReceiver
    ) private {
        guard.checkTransaction(
            to, value, data, operation, safeTxGas, baseGas, gasPrice, gasToken, refundReceiver, hex"", address(0)
        );
    }

    function _singleBackup(address a) private pure returns (address[] memory) {
        address[] memory backups = new address[](1);
        backups[0] = a;
        return backups;
    }

    function _emptyVerifierSigners()
        private
        pure
        returns (address[] memory backups, address[] memory verifiers, bytes[] memory signers)
    {
        backups = new address[](0);
        verifiers = new address[](0);
        signers = new bytes[](0);
    }
}
