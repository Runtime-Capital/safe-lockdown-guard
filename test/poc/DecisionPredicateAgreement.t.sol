// SPDX-License-Identifier: MIT
// Decision-predicate / executor agreement campaign.
//
// Provenance. 0x shipped two post-audit fixes inside this exact construction, a
// selector blacklist embedded in a MultiSend walk:
//
//   d3ba88d4b1  "You have to check the selector when blacklisting a specific selector"
//               read the argument word at a fixed offset without first proving the selector
//   35abfb5601  "Reversed `if` condition"
//               inverted polarity on an address-canonicality check (`potentialModule >> 160`)
//
// Neither defect exists here: every local predicate compares `bytes4(data)` before
// reading any argument, and each is consumed with the intended polarity. The
// encoding half of the family is already settled by `CalldataEncoding.t.sol` and
// `DecodeCalldataBytesAdversarial.t.sol` (A4/A5 bounds, B17/B18/B19, mutants T6/T7),
// including dirty `swapOwner` high bits and `address(0)` aliasing at top level.
//
// This file covers what those do NOT: whether a predicate can be INCOMPLETE with
// respect to the executor's real surface, and the untested length-arm asymmetry in
// `_isTimelockManagementCall`. Findings are classified strictly:
//
//   (a) guard ACCEPTS a payload the executor decodes into a different call
//       -> potential policy bypass, highest severity
//   (b) guard REJECTS a call that is valid and legitimate
//       -> liveness failure, severe only inside the incident window
pragma solidity ^0.8.24;

import {TestEnvironment} from "../TestEnvironment.sol";

import {Safe, Enum} from "@safe-global/safe-smart-account/Safe.sol";
import {MultiSendCallOnly} from "@safe-global/safe-smart-account/libraries/MultiSendCallOnly.sol";
import {IGuardManager} from "@safe-global/safe-smart-account/interfaces/IGuardManager.sol";
import {IModuleManager} from "@safe-global/safe-smart-account/interfaces/IModuleManager.sol";
import {IFallbackManager} from "@safe-global/safe-smart-account/interfaces/IFallbackManager.sol";
import {IOwnerManager} from "@safe-global/safe-smart-account/interfaces/IOwnerManager.sol";

import {Lockdown} from "../../src/Lockdown.sol";
import {LockdownTimelock} from "../../src/LockdownTimelock.sol";
import {Timelock} from "../../src/base/Timelock.sol";
import {StateMachine} from "../../src/base/StateMachine.sol";

contract PredicateTarget {
    uint256 public calls;

    function mark() external {
        ++calls;
    }
}

contract DecisionPredicateAgreementPoC is TestEnvironment {
    address private constant SENTINEL_OWNERS = address(0x1);
    address private constant SENTINEL_MODULES = address(0x1);
    uint64 private constant DELAY = 24 hours;

    uint256 private constant GUARD_SLOT = 0x4a204f620c8c5ccdca3fd54d003badd85ba500436a431f0cbda4f558c93c34c8;
    uint256 private constant MODULE_GUARD_SLOT = 0xb104e0b93118902c651344349b610029d694cfdec91c589c91ebafbcd0289947;
    uint256 private constant FALLBACK_SLOT = 0x6c9a6c4a39284e37ed1cf53d337577d14212a4870fb976a4366c693b939918d5;

    Safe private pocSafe;
    PredicateTarget private target;
    address private newOwner;

    function setUp() public override {
        super.setUp();
        pocSafe = _createConfigureAndInitialise(77);
        target = new PredicateTarget();
        newOwner = address(0xBEEF01);
        vm.deal(address(pocSafe), 10 ether);
    }

    // ------------------------------------------------------------------
    // Helpers
    // ------------------------------------------------------------------

    function _multiSend(bytes memory transactions) private pure returns (bytes memory) {
        return abi.encodeCall(MultiSendCallOnly.multiSend, (transactions));
    }

    /// @dev Isolates the module-path predicate: calls the module guard pre-hook
    ///      directly as the Safe, so the verdict is the predicate's and not some
    ///      downstream ABI-decode accident.
    function _pokeModuleHook(address to, bytes memory data) private {
        vm.prank(address(pocSafe));
        guard.checkModuleTransaction(to, 0, data, Enum.Operation.Call, module);
    }

    function _pokeModuleHook_Revert(address to, bytes memory data, bytes4 err) private {
        vm.prank(address(pocSafe));
        vm.expectRevert(err);
        guard.checkModuleTransaction(to, 0, data, Enum.Operation.Call, module);
    }

    function _readSlot(uint256 slot) private view returns (address) {
        return address(uint160(uint256(bytes32(pocSafe.getStorageAt(slot, 1)))));
    }

    function _enterRecovery() private {
        _triggerLockdown(pocSafe, keccak256("predicate-poc"));
        vm.warp(block.timestamp + 48 hours + 1);
        (StateMachine.State state,) = guard.getState(address(pocSafe));
        assertEq(uint256(state), uint256(StateMachine.State.Recovering), "recovering");
    }

    function _rawExec(address to, uint256 value, bytes memory data, Enum.Operation op)
        private
        returns (bool ok, bytes memory ret)
    {
        bytes memory sig = _signTx(pocSafe, OWNER_PK, to, value, data, op);
        (ok, ret) = address(pocSafe)
            .call(
                abi.encodeCall(
                    Safe.execTransaction, (to, value, data, op, 0, 0, 0, address(0), payable(address(0)), sig)
                )
            );
    }

    /// @dev Schedules a real owner ticket for `target.mark()` and returns its hash.
    function _scheduleMarkTicket() private returns (bytes32 h) {
        Timelock.ExecTransactionParams memory p = Timelock.ExecTransactionParams({
            to: address(target),
            value: 0,
            data: abi.encodeCall(PredicateTarget.mark, ()),
            operation: Enum.Operation.Call,
            safeTxGas: 0,
            baseGas: 0,
            gasPrice: 0,
            gasToken: address(0),
            refundReceiver: payable(address(0))
        });
        uint256 n = pocSafe.nonce();
        h = pocSafe.getTransactionHash(
            p.to, p.value, p.data, p.operation, p.safeTxGas, p.baseGas, p.gasPrice, p.gasToken, p.refundReceiver, n
        );
        (uint8 v, bytes32 r, bytes32 s_) = vm.sign(OWNER_PK, h);
        guard.scheduleTransaction(address(pocSafe), n, p, abi.encodePacked(r, s_, v));
    }

    // ==================================================================
    // A - predicate COMPLETENESS against the executor's real surface
    //
    // The encoding-level questions are settled elsewhere. The unasked question
    // is whether the blacklist covers every function that can actually reach
    // the slot it protects. Safe v1.5.0's complete `authorized` self-call
    // surface is exactly eight external functions.
    // ==================================================================

    /// @dev REFUTED, and this is the load-bearing completeness proof. Safe v1.5.0
    ///      exposes exactly eight `authorized` self-call entry points:
    ///      setGuard, setModuleGuard, setFallbackHandler, addOwnerWithThreshold,
    ///      removeOwner, swapOwner, changeThreshold, enableModule, disableModule.
    ///      `_isForbiddenModuleSafeSelfCall` blacklists three of them. This test
    ///      pins that the three denied ones are exactly the three that can write a
    ///      protection slot, and that no other member of the surface can.
    ///
    ///      Deleting any one selector from the blacklist turns this test red.
    function test_refuted_moduleBlacklistCoversEverySlotWritingSafeFunction() public {
        // The three that write a protection slot: DENIED.
        _pokeModuleHook_Revert(
            address(pocSafe),
            abi.encodeCall(IGuardManager.setGuard, (address(0))),
            Lockdown.ModuleSafeSelfCallDenied.selector
        );
        _pokeModuleHook_Revert(
            address(pocSafe),
            abi.encodeCall(IModuleManager.setModuleGuard, (address(0))),
            Lockdown.ModuleSafeSelfCallDenied.selector
        );
        _pokeModuleHook_Revert(
            address(pocSafe),
            abi.encodeCall(IFallbackManager.setFallbackHandler, (address(0))),
            Lockdown.ModuleSafeSelfCallDenied.selector
        );

        // The remaining five: ALLOWED by design (SPEC_V1 7.2 / H.12 accepted
        // Normal-mode residual). None of them can reach a protection slot.
        _pokeModuleHook(address(pocSafe), abi.encodeCall(IOwnerManager.addOwnerWithThreshold, (newOwner, 1)));
        _pokeModuleHook(address(pocSafe), abi.encodeCall(IOwnerManager.removeOwner, (SENTINEL_OWNERS, owner, 1)));
        _pokeModuleHook(address(pocSafe), abi.encodeCall(IOwnerManager.swapOwner, (SENTINEL_OWNERS, owner, newOwner)));
        _pokeModuleHook(address(pocSafe), abi.encodeCall(IOwnerManager.changeThreshold, (1)));
        _pokeModuleHook(address(pocSafe), abi.encodeCall(IModuleManager.enableModule, (address(0xB0B0B0))));
        _pokeModuleHook(address(pocSafe), abi.encodeCall(IModuleManager.disableModule, (SENTINEL_MODULES, module)));
    }

    /// @dev REFUTED, executed end to end rather than through the hook: a genuine
    ///      module transaction really cannot clear the module-guard slot, and the
    ///      slot is unchanged afterwards. Positive control below proves the module
    ///      entry point itself works, so the denial is the predicate's doing.
    function test_refuted_moduleCannotClearModuleGuardSlotEndToEnd() public {
        assertEq(_readSlot(MODULE_GUARD_SLOT), address(guard), "module guard installed");

        _moduleCall_Revert(
            module,
            pocSafe,
            address(pocSafe),
            0,
            abi.encodeCall(IModuleManager.setModuleGuard, (address(0))),
            Enum.Operation.Call,
            Lockdown.ModuleSafeSelfCallDenied.selector
        );

        assertEq(_readSlot(MODULE_GUARD_SLOT), address(guard), "slot untouched");
    }

    /// @dev Positive control for the test above: the same module, same entry point,
    ///      a permitted self-call, executes. The denial is not a broken module path.
    function test_control_moduleSelfCallsThatAreNotSlotWritesStillExecute() public {
        _moduleCall(
            module,
            pocSafe,
            address(pocSafe),
            0,
            abi.encodeCall(IOwnerManager.addOwnerWithThreshold, (newOwner, 1)),
            Enum.Operation.Call
        );
        assertTrue(pocSafe.isOwner(newOwner), "permitted module self-call executed");
    }

    /// @dev REFUTED, and this is the completeness case nobody had asked about.
    ///      `Safe.setup(...)` writes the fallback-handler slot through
    ///      `internalSetFallbackHandler`, and it is NOT in
    ///      `_isForbiddenModuleSafeSelfCall`. It is nevertheless a dead end on a
    ///      live Safe: `setupOwners` reverts GS200 once the threshold is non-zero.
    ///      Guard accepts, executor refuses, and the slot is unchanged. Fail-closed
    ///      divergence, so class (a) in shape but not in effect.
    function test_refuted_setupCannotRewriteTheFallbackSlotOnALiveSafe() public {
        address handlerBefore = _readSlot(FALLBACK_SLOT);
        assertEq(handlerBefore, address(handler), "lockdown-bound handler installed");

        address[] memory owners = new address[](1);
        owners[0] = newOwner;
        bytes memory setupCall = abi.encodeCall(
            Safe.setup, (owners, 1, address(0), "", address(0xDEAD), address(0), 0, payable(address(0)))
        );

        // The guard's blacklist does not name `setup`, so the predicate lets it by.
        _pokeModuleHook(address(pocSafe), setupCall);

        // The executor is what stops it.
        vm.prank(module);
        (bool ok,) = address(pocSafe)
            .call(
                abi.encodeCall(
                    IModuleManager.execTransactionFromModule, (address(pocSafe), 0, setupCall, Enum.Operation.Call)
                )
            );
        assertTrue(ok, "module entry point itself returns");

        assertEq(_readSlot(FALLBACK_SLOT), handlerBefore, "fallback slot unchanged: setup reverted GS200");
        assertEq(_readSlot(GUARD_SLOT), address(guard), "guard slot unchanged");
    }

    /// @dev REFUTED: the same `setup` attempt on the OWNER path is also inert, and
    ///      here the guard does inspect it, because the owner-path
    ///      `setFallbackHandler` binding check keys on that selector only. `setup`
    ///      carries a different selector, so it passes the predicate and dies in
    ///      the executor exactly as above.
    function test_refuted_setupOnOwnerPathCannotRewriteTheFallbackSlot() public {
        address handlerBefore = _readSlot(FALLBACK_SLOT);

        address[] memory owners = new address[](1);
        owners[0] = newOwner;
        bytes memory setupCall = abi.encodeCall(
            Safe.setup, (owners, 1, address(0), "", address(0xDEAD), address(0), 0, payable(address(0)))
        );

        (bool ok,) = _rawExec(address(pocSafe), 0, setupCall, Enum.Operation.Call);
        assertFalse(ok, "setup reverts on a live Safe");
        assertEq(_readSlot(FALLBACK_SLOT), handlerBefore, "fallback slot unchanged");
    }

    // ==================================================================
    // B - `_isTimelockManagementCall` length-arm asymmetry
    //
    // The predicate mixes one EXACT arm with two MINIMUM arms:
    //   cancelTransaction        data.length == 0x24
    //   scheduleModuleTransaction data.length >= 0x04
    //   cancelModuleTransaction   data.length >= 0x04
    // Mutant T6 and disposition B20 cover only the exact arm. The asymmetry
    // itself has never been executed.
    // ==================================================================

    /// @dev LIMITATION, class (b), fail-closed. Solidity's ABI decoder ignores
    ///      trailing bytes for fixed-size arguments, so the executor accepts a
    ///      `cancelTransaction(bytes32)` payload padded to 0x25. The guard's EXACT
    ///      arm does not, so the padded form is not treated as a management call
    ///      and falls through to the timelock, where it dies `TicketNotFound`.
    ///
    ///      Guard stricter than executor. This is the direction T6 protects, so
    ///      the strictness is deliberate, but it means a signer-review tool that
    ///      pads calldata would silently lose the management-call carve-out.
    function test_limitation_paddedCancelTransactionLosesTheManagementCarveOut() public {
        _enableTimelock(pocSafe, DELAY);

        // Schedule a REAL ticket, so that "carve-out granted" and "carve-out
        // refused" have different observable outcomes. Without this the test would
        // be ambiguous: `cancelTransaction` on an unknown hash and the timelock
        // pre-hook both revert `TicketNotFound`.
        bytes32 victim = _scheduleMarkTicket();
        assertGt(guard.getTransactionExecutableAt(address(pocSafe), victim), 0, "victim ticket exists");

        bytes memory padded = abi.encodePacked(abi.encodeCall(Timelock.cancelTransaction, (victim)), hex"00");
        assertEq(padded.length, 0x25, "one trailing byte");

        // Guard: not a management call, so the timelock applies to THIS transaction,
        // which has no ticket of its own.
        _execAsOwner_Revert(pocSafe, address(guard), 0, padded, Enum.Operation.Call, Timelock.TicketNotFound.selector);

        // The disambiguator: the carve-out was refused, so the cancel never ran and
        // the victim ticket is still there. Had the carve-out been granted, this
        // would be 0.
        assertGt(
            guard.getTransactionExecutableAt(address(pocSafe), victim),
            0,
            "carve-out refused: the cancel never executed"
        );
    }

    /// @dev Positive control proving the executor really would have accepted the
    ///      padded payload: called directly as the Safe, the padded calldata
    ///      cancels a real scheduled ticket. So the rejection above is the guard's
    ///      exact-length arm, not the ABI decoder.
    function test_control_executorAcceptsPaddedCancelTransactionCalldata() public {
        _enableTimelock(pocSafe, DELAY);

        bytes32 h = _scheduleMarkTicket();
        assertGt(guard.getTransactionExecutableAt(address(pocSafe), h), 0, "ticket exists");

        bytes memory padded = abi.encodePacked(abi.encodeCall(Timelock.cancelTransaction, (h)), hex"00");
        vm.prank(address(pocSafe));
        (bool ok,) = address(guard).call(padded);

        assertTrue(ok, "executor accepts the padded calldata");
        assertEq(guard.getTransactionExecutableAt(address(pocSafe), h), 0, "and really cancelled the ticket");
    }

    /// @dev REFUTED, class (a) candidate that does not materialise. The two MINIMUM
    ///      arms grant the timelock carve-out on selector alone, so a malformed
    ///      `scheduleModuleTransaction` payload DOES get the bypass. It buys
    ///      nothing: the singleton's own ABI decoder reverts, the whole Safe
    ///      transaction rolls back, and no ticket is created.
    function test_refuted_malformedScheduleModuleTransactionGetsBypassButCannotExecute() public {
        _enableTimelock(pocSafe, DELAY);

        // Selector only: passes `data.length >= 0x04`, so the carve-out is granted.
        bytes memory stub = abi.encodePacked(LockdownTimelock.scheduleModuleTransaction.selector);
        assertEq(stub.length, 0x04, "selector only");

        uint256 nonceBefore = pocSafe.nonce();
        (bool ok,) = _rawExec(address(guard), 0, stub, Enum.Operation.Call);

        assertFalse(ok, "the singleton's ABI decoder rejects it; whole tx rolls back");
        assertEq(pocSafe.nonce(), nonceBefore, "rolled back, not even a burnt nonce");
    }

    /// @dev Control isolating the claim above: the carve-out really is what the
    ///      minimum arm grants. A well-formed `cancelModuleTransaction` with a
    ///      TRAILING byte is accepted by both guard and executor, with no ticket
    ///      and no delay, which an ordinary singleton call would not get.
    function test_control_minimumLengthArmGrantsTheCarveOutWithTrailingBytes() public {
        _enableTimelock(pocSafe, DELAY);

        // Create a module ticket so the cancel has something to remove.
        bytes32 moduleHash = guard.getModuleTransactionHash(
            address(pocSafe), module, address(target), 0, abi.encodeCall(PredicateTarget.mark, ()), Enum.Operation.Call
        );
        _execAsOwner(
            pocSafe,
            address(guard),
            0,
            abi.encodeCall(
                Timelock.scheduleModuleTransaction,
                (module, address(target), 0, abi.encodeCall(PredicateTarget.mark, ()), Enum.Operation.Call)
            ),
            Enum.Operation.Call
        );
        assertGt(guard.getModuleTransactionExecutableAt(address(pocSafe), moduleHash), 0, "module ticket exists");

        bytes memory padded = abi.encodePacked(abi.encodeCall(Timelock.cancelModuleTransaction, (moduleHash)), hex"00");
        (bool ok,) = _rawExec(address(guard), 0, padded, Enum.Operation.Call);

        assertTrue(ok, "minimum arm tolerates trailing bytes on both sides");
        assertEq(guard.getModuleTransactionExecutableAt(address(pocSafe), moduleHash), 0, "module ticket cancelled");
    }

    // ==================================================================
    // C - the same minimum-arm shape inside the RECOVERY window,
    //     where a class (b) failure has no second chance
    // ==================================================================

    /// @dev LIMITATION, class (b), inside the incident window. The recovery
    ///      whitelist admits `removeLockdownSigner` on selector plus
    ///      `data.length >= 0x04`, so a malformed payload is whitelisted by the
    ///      guard and then reverts in the singleton's decoder. The transaction
    ///      rolls back entirely, so the quorum keeps its nonce and can retry.
    ///      Worth pinning because the recovery window is exactly where a burnt
    ///      nonce would matter.
    function test_limitation_malformedRemoveLockdownSignerIsWhitelistedThenRollsBack() public {
        _enterRecovery();

        bytes memory stub = abi.encodePacked(Lockdown.removeLockdownSigner.selector);
        uint256 nonceBefore = pocSafe.nonce();

        (bool ok,) = _rawExec(address(guard), 0, stub, Enum.Operation.Call);

        assertFalse(ok, "malformed payload dies in the singleton decoder");
        assertEq(pocSafe.nonce(), nonceBefore, "no nonce burnt: the quorum can retry inside the window");
    }

    /// @dev Positive control with a live signer: two signers registered, one burnt by
    ///      the trigger, the survivor culled inside the recovery window through the
    ///      exact whitelist arm under test.
    function test_control_recoveryRemoveSignerWithLiveSigner() public {
        // Register a second panic identity while still Normal.
        bytes memory second = abi.encodePacked(other);
        _execAsOwner(
            pocSafe, address(guard), 0, abi.encodeCall(Lockdown.addLockdownSigner, (second)), Enum.Operation.Call
        );
        assertEq(guard.getLockdownSignerCount(address(pocSafe)), 2, "two signers");

        _enterRecovery();
        assertEq(guard.getLockdownSignerCount(address(pocSafe)), 1, "one burnt by the trigger");

        _execAsOwner(
            pocSafe, address(guard), 0, abi.encodeCall(Lockdown.removeLockdownSigner, (second)), Enum.Operation.Call
        );
        assertEq(guard.getLockdownSignerCount(address(pocSafe)), 0, "survivor culled inside the window");
    }

    // ==================================================================
    // D - dirty argument words at DEPTH
    //
    // `CalldataEncoding.t.sol::test_refuted_swapOwnerDirtyUpperBytesAreMasked
    // Consistently` settles the top-level case. The recursion is where a
    // fixed-offset read could diverge, because the leaf is re-sliced by the
    // parser before the predicate sees it.
    // ==================================================================

    /// @dev REFUTED: a `swapOwner` leaf with dirty high bits, nested inside a
    ///      canonical MultiSend envelope under Privilege.Recovery, is judged by the
    ///      guard on the same low 20 bytes that the Safe later acts on. The owner
    ///      installed is the one the whitelist authorised, at depth as at top level.
    function test_refuted_dirtySwapOwnerWordAgreesAtMultiSendDepth() public {
        // Register the recovery owner target before the incident.
        _enterRecovery();

        bytes memory dirty = abi.encodePacked(
            IOwnerManager.swapOwner.selector,
            bytes32(uint256(uint160(SENTINEL_OWNERS))),
            bytes32(uint256(uint160(owner))),
            bytes32((uint256(0xdead) << 232) | uint256(uint160(recovery)))
        );
        assertEq(dirty.length, 0x64, "exact swapOwner length preserved at depth");

        bytes memory batch = _multiSend(_multiSendItem(Enum.Operation.Call, address(pocSafe), 0, dirty));

        (bool ok,) = _rawExec(address(multiSendCallOnly), 0, batch, Enum.Operation.DelegateCall);

        assertTrue(ok, "guard accepted and executor executed the nested dirty leaf");
        assertTrue(pocSafe.isOwner(recovery), "the guard-authorised recovery owner is the one installed");
        assertFalse(pocSafe.isOwner(owner), "old owner swapped out");
    }

    /// @dev REFUTED: the same nested leaf pointing at an address that is NOT a
    ///      registered recovery owner is rejected at depth, so the depth-level
    ///      predicate is genuinely enforcing and the test above is not vacuous.
    function test_refuted_nestedSwapOwnerToUnregisteredAddressDeniedAtDepth() public {
        _enterRecovery();

        bytes memory payload = abi.encodeCall(IOwnerManager.swapOwner, (SENTINEL_OWNERS, owner, newOwner));
        bytes memory batch = _multiSend(_multiSendItem(Enum.Operation.Call, address(pocSafe), 0, payload));

        _execAsOwner_Revert(
            pocSafe, address(multiSendCallOnly), 0, batch, Enum.Operation.DelegateCall, Lockdown.RecoveryActive.selector
        );
        assertFalse(pocSafe.isOwner(newOwner), "unregistered address not installed");
    }
}
