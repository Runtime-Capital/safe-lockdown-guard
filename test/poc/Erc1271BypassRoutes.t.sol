// SPDX-License-Identifier: MIT
// ERC-1271 bypass-route matrix (NM-1060 6.1 follow-up, SPEC_V1 H.27).
// Every route by which a Safe's ERC-1271 validation could succeed although the opt-in flag
// is false or the Safe is in an incident, or by which the flag could flip without waiting
// the timelock. `test_confirmed_*` = route CLOSED, `test_limitation_*` = accepted residual
// that DOES work.
pragma solidity ^0.8.24;

import {TestEnvironment} from "../TestEnvironment.sol";

import {ISafe} from "@safe-global/safe-smart-account/interfaces/ISafe.sol";
import {Safe, Enum} from "@safe-global/safe-smart-account/Safe.sol";
import {IOwnerManager} from "@safe-global/safe-smart-account/interfaces/IOwnerManager.sol";
import {IFallbackManager} from "@safe-global/safe-smart-account/interfaces/IFallbackManager.sol";
import {IGuardManager} from "@safe-global/safe-smart-account/interfaces/IGuardManager.sol";
import {IModuleManager} from "@safe-global/safe-smart-account/interfaces/IModuleManager.sol";
import {MultiSendCallOnly} from "@safe-global/safe-smart-account/libraries/MultiSendCallOnly.sol";
import {SignMessageLib} from "@safe-global/safe-smart-account/libraries/SignMessageLib.sol";
import {CompatibilityFallbackHandler} from "@safe-global/safe-smart-account/handler/CompatibilityFallbackHandler.sol";

import {Lockdown} from "../../src/Lockdown.sol";
import {LockdownTimelock} from "../../src/LockdownTimelock.sol";
import {Timelock} from "../../src/base/Timelock.sol";
import {StateMachine} from "../../src/base/StateMachine.sol";
import {LockdownFallbackHandler} from "../../src/handlers/LockdownFallbackHandler.sol";

/// @dev Owner contract that approves everything (ERC-1271 `bytes32` flavour used by Safe v1.5.0).
contract AlwaysValidWallet {
    function isValidSignature(bytes32, bytes memory) external pure returns (bytes4) {
        return 0x1626ba7e;
    }
}

/// @dev Hostile fallback-handler shim: exposes `LOCKDOWN()` == singleton (passes the binding
///      check) but has no incident gate and no opt-in gate.
contract HostileShim {
    address public immutable LOCKDOWN;

    constructor(address lockdown) {
        LOCKDOWN = lockdown;
    }

    function isValidSignature(bytes32, bytes calldata) external pure returns (bytes4) {
        return 0x1626ba7e;
    }
}

contract Erc1271BypassRoutesPoC is TestEnvironment {
    bytes4 private constant MAGIC = 0x1626ba7e;
    bytes4 private constant LEGACY_IS_VALID_SIGNATURE = 0x20c13b0b; // isValidSignature(bytes,bytes)
    uint64 private constant DELAY = 1 days;
    address private constant HSM = address(0xB1A55);

    Safe private safe;
    bytes32 private constant H = keccak256("order");

    function setUp() public override {
        super.setUp();
        safe = _createConfigureAndInitialise(711);
    }

    // ------------------------------------------------------------------
    // Helpers
    // ------------------------------------------------------------------

    function _isValid(ISafe instance, bytes32 hash, bytes memory sig) private returns (bool ok, bytes memory ret) {
        (ok, ret) = address(instance)
            .call(abi.encodeWithSelector(LockdownFallbackHandler.isValidSignature.selector, hash, sig));
    }

    function _assertValid(ISafe instance, bytes memory sig) private {
        (bool ok, bytes memory ret) = _isValid(instance, H, sig);
        assertTrue(ok, "valid: call ok");
        assertEq(abi.decode(ret, (bytes4)), MAGIC, "valid: magic");
    }

    function _assertRevertsWith(ISafe instance, bytes memory sig, bytes4 err) private {
        (bool ok, bytes memory ret) = _isValid(instance, H, sig);
        assertFalse(ok, "must revert");
        assertEq(bytes4(ret), err, "error selector");
    }

    function _setAllowed(ISafe instance, bool allowed) private {
        _execAsOwner(
            instance, address(guard), 0, abi.encodeCall(Lockdown.setErc1271Allowed, (allowed)), Enum.Operation.Call
        );
    }

    function _selfCall(ISafe instance, bytes memory data) private {
        _execAsOwner(instance, address(instance), 0, data, Enum.Operation.Call);
    }

    function _initCall() private view returns (bytes memory) {
        address[] memory recoveryOwners = new address[](1);
        recoveryOwners[0] = recovery;
        bytes[] memory signers = new bytes[](1);
        signers[0] = abi.encodePacked(panicKey);
        return abi.encodeCall(Lockdown.initialize, (48 hours, 4 hours, recoveryOwners, signers));
    }

    function _raw(uint256 pk, bytes32 hash) private pure returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, hash);
        return abi.encodePacked(r, s, v);
    }

    // ------------------------------------------------------------------
    // 1. Handler entrypoints
    // ------------------------------------------------------------------

    /// @dev Route: legacy `isValidSignature(bytes,bytes)` (0x20c13b0b) on the Safe. CLOSED: the
    ///      handler (verbatim v1.5.0 shape) only defines `isValidSignature(bytes32,bytes)`, and
    ///      has no `fallback()`, so the Safe's FallbackManager forwards the unknown selector and
    ///      the handler reverts. LockdownFallbackHandler.sol: contract has no overload / fallback.
    function test_confirmed_legacyIsValidSignatureSelectorNotServed() public {
        bytes memory legacy = abi.encodeWithSelector(LEGACY_IS_VALID_SIGNATURE, bytes("msg"), bytes("sig"));
        (bool ok, bytes memory ret) = address(safe).call(legacy);
        assertFalse(ok, "legacy selector reverts, flag false");
        assertTrue(ret.length < 4 || bytes4(ret) != MAGIC, "no magic");

        _setAllowed(safe, true);
        (ok, ret) = address(safe).call(legacy);
        assertFalse(ok, "legacy selector reverts, flag true");
        assertEq(ret.length, 0, "no handler function: empty revert");
    }

    // ------------------------------------------------------------------
    // 2. Direct Safe.checkSignatures / checkNSignatures
    // ------------------------------------------------------------------

    /// @dev Route: third party calls the Safe's PUBLIC `checkSignatures(address(0),hash,sigs)` /
    ///      `checkNSignatures` directly. NOT closed, by construction: Safe.sol:checkSignatures is
    ///      public view and not routed through the fallback handler, and no guard hook exists
    ///      for view calls. Residual: no standard protocol (permit, EIP-3009, Permit2, CoW,
    ///      Seaport) validates contract signatures this way; ERC-1271 `isValidSignature` is the
    ///      standard. This is Safe's own surface, outside the handler's reach.
    function test_limitation_directCheckSignaturesBypassesHandler() public {
        bytes memory sig = _raw(OWNER_PK, H);
        // Through the handler: disabled.
        _assertRevertsWith(safe, bytes(""), LockdownFallbackHandler.Erc1271Disabled.selector);
        (bool ok, bytes memory ret) = _isValid(safe, H, sig);
        assertFalse(ok);
        assertEq(bytes4(ret), LockdownFallbackHandler.Erc1271Disabled.selector, "handler: disabled");

        // Directly: succeeds with flag false.
        vm.prank(address(0xCAFE));
        safe.checkSignatures(address(0), H, sig);
        vm.prank(address(0xCAFE));
        safe.checkNSignatures(address(0), H, sig, 1);

        // ...and while LockedDown.
        _triggerLockdown(safe, bytes32("wrench"));
        _assertRevertsWith(safe, sig, LockdownFallbackHandler.SignaturesFrozenDuringLockdown.selector);
        vm.prank(address(0xCAFE));
        safe.checkSignatures(address(0), H, sig);
        vm.warp(block.timestamp + 48 hours + 1); // Recovering
        vm.prank(address(0xCAFE));
        safe.checkNSignatures(address(0), H, sig, 1);
    }

    /// @dev Route: `v == 1` approved-hash signature after an owner calls `safe.approveHash(hash)`
    ///      directly (no execTransaction, no guard hook). Direct `checkSignatures` accepts it
    ///      (limitation, same reason as above); through `isValidSignature` it stays closed:
    ///      Erc1271Disabled while the flag is false (LockdownFallbackHandler.sol:isValidSignature
    ///      opt-in gate). Once opted in, a recorded owner approval validates (observed).
    function test_limitation_directCheckSignaturesApprovedHash() public {
        vm.prank(owner);
        safe.approveHash(H);
        bytes memory approved = abi.encodePacked(bytes32(uint256(uint160(owner))), bytes32(0), uint8(1));

        vm.prank(address(0xCAFE));
        safe.checkSignatures(address(0), H, approved); // works: Safe's own surface

        // The messageHash the handler checks is the SafeMessage hash, not H, so also approve it.
        bytes32 messageHash = handler.getMessageHashForSafe(safe, abi.encode(H));
        vm.prank(owner);
        safe.approveHash(messageHash);
        _assertRevertsWith(safe, approved, LockdownFallbackHandler.Erc1271Disabled.selector);

        _setAllowed(safe, true);
        // Opted in: an on-chain approval by an owner is a legitimate signature (executor ==
        // address(0) only stops the "caller is the owner" shortcut, not a recorded approval).
        _assertValid(safe, approved);
    }

    // ------------------------------------------------------------------
    // 3. Contract owners
    // ------------------------------------------------------------------

    /// @dev Route: an owner of the protected Safe is a contract (v == 0 signature). CLOSED: the
    ///      owner-contract validation happens inside `checkSignatures`, which runs only after the
    ///      handler's incident + opt-in gates (LockdownFallbackHandler.sol:isValidSignature).
    function test_confirmed_contractOwnerSignatureStillGated() public {
        AlwaysValidWallet wallet = new AlwaysValidWallet();
        _selfCall(safe, abi.encodeCall(IOwnerManager.addOwnerWithThreshold, (address(wallet), 1)));
        // Contract signature layout: r = owner, s = offset of dynamic part (65), v = 0, then len + data.
        bytes memory sig = abi.encodePacked(
            bytes32(uint256(uint160(address(wallet)))), bytes32(uint256(65)), uint8(0), bytes32(uint256(1)), hex"01"
        );

        _assertRevertsWith(safe, sig, LockdownFallbackHandler.Erc1271Disabled.selector);
        // Direct checkSignatures accepts it (limitation of test 2, shown for contrast).
        safe.checkSignatures(address(0), handler.getMessageHashForSafe(safe, abi.encode(H)), sig);

        _setAllowed(safe, true);
        _assertValid(safe, sig);
    }

    // ------------------------------------------------------------------
    // 4. signedMessages entries
    // ------------------------------------------------------------------

    function _signMessageViaLib(Safe s, bytes32 d, Enum.Operation op, address lib) private {
        _execAsOwner(s, lib, 0, abi.encodeCall(SignMessageLib.signMessage, (abi.encode(d))), op);
    }

    /// @dev Route: pre-install `signedMessages` entry (written through SignMessageLib DELEGATECALL
    ///      before the guard existed). CLOSED while the flag is false (opt-in gate runs before the
    ///      `signedMessages` branch: LockdownFallbackHandler.sol:isValidSignature). Post-install
    ///      writing a NEW entry is impossible: owner-path DelegateCall is only allowed to
    ///      MultiSendCallOnly (Lockdown.sol:_checkCall -> DelegateCallDenied), including nested
    ///      inside a MultiSend batch, and MultiSendCallOnly itself reverts on operation 1.
    function test_confirmed_signedMessagesPreInstallGatedAndNoPostInstallWrite() public {
        Safe fresh = _createSafe(712);
        SignMessageLib lib = new SignMessageLib();
        bytes32 d = keccak256("pre-install");
        _signMessageViaLib(fresh, d, Enum.Operation.DelegateCall, address(lib));
        bytes32 messageHash = handler.getMessageHashForSafe(fresh, abi.encode(d));
        assertTrue(fresh.signedMessages(messageHash) != 0, "entry written pre-install");

        vm.startPrank(address(fresh));
        fresh.setGuard(address(guard));
        fresh.setModuleGuard(address(guard));
        fresh.setFallbackHandler(address(handler));
        vm.stopPrank();
        _execAsOwner(fresh, address(guard), 0, _initCall(), Enum.Operation.Call);

        (bool ok, bytes memory ret) = _isValid(fresh, d, "");
        assertFalse(ok);
        assertEq(bytes4(ret), LockdownFallbackHandler.Erc1271Disabled.selector, "gated while false");

        // Post-install: direct DELEGATECALL to SignMessageLib denied by the guard.
        bytes32 d2 = keccak256("post-install");
        bytes memory signCall = abi.encodeCall(SignMessageLib.signMessage, (abi.encode(d2)));
        _execAsOwner_Revert(
            fresh, address(lib), 0, signCall, Enum.Operation.DelegateCall, Lockdown.DelegateCallDenied.selector
        );

        // Nested in a MultiSend batch: the guard's recursion rejects the inner DelegateCall.
        bytes memory batch = _multiSendItem(Enum.Operation.DelegateCall, address(lib), 0, signCall);
        bytes memory multiSendCall = abi.encodeCall(MultiSendCallOnly.multiSend, (batch));
        _execAsOwner_Revert(
            fresh,
            address(multiSendCallOnly),
            0,
            multiSendCall,
            Enum.Operation.DelegateCall,
            Lockdown.DelegateCallDenied.selector
        );

        // Defence in depth: the library itself rejects operation == 1 (empty revert), so even an
        // allowed inner DelegateCall to MultiSendCallOnly can never carry a nested delegatecall.
        vm.prank(address(fresh));
        vm.expectRevert();
        multiSendCallOnly.multiSend(batch);
        bytes memory nestedBatch =
            _multiSendItem(Enum.Operation.DelegateCall, address(multiSendCallOnly), 0, multiSendCall);
        vm.prank(address(fresh));
        vm.expectRevert();
        multiSendCallOnly.multiSend(nestedBatch);

        assertEq(fresh.signedMessages(handler.getMessageHashForSafe(fresh, abi.encode(d2))), 0, "no new entry");

        _setAllowed(fresh, true);
        (ok, ret) = _isValid(fresh, d, "");
        assertTrue(ok, "honoured once opted in");
        assertEq(abi.decode(ret, (bytes4)), MAGIC);
    }

    // ------------------------------------------------------------------
    // 5. Fallback-handler replacement
    // ------------------------------------------------------------------

    /// @dev Route 5a: owner-path `setFallbackHandler(CompatibilityFallbackHandler)`. CLOSED by
    ///      Lockdown.sol:_checkCall (setFallbackHandler binding check). OBSERVED BEHAVIOUR: the
    ///      canonical handler has no `LOCKDOWN()` function, so the high-level call in the check
    ///      reverts with EMPTY returndata (not `InvalidFallbackHandler`); the Safe bubbles the
    ///      guard revert. An EOA / non-contract hits the extcodesize check, also empty revert.
    function test_confirmed_ownerPathCompatibilityHandlerReplacementReverts() public {
        CompatibilityFallbackHandler compat = new CompatibilityFallbackHandler();
        bytes memory data = abi.encodeCall(IFallbackManager.setFallbackHandler, (address(compat)));
        bytes memory sig = _signTx(safe, OWNER_PK, address(safe), 0, data, Enum.Operation.Call);
        vm.expectRevert(bytes(""));
        safe.execTransaction(address(safe), 0, data, Enum.Operation.Call, 0, 0, 0, address(0), payable(0), sig);

        data = abi.encodeCall(IFallbackManager.setFallbackHandler, (address(0xE0A)));
        sig = _signTx(safe, OWNER_PK, address(safe), 0, data, Enum.Operation.Call);
        // Low-level call: under `-vvv` Foundry reports the guard's call to a codeless address as
        // "call to non-contract address" instead of a plain revert, which breaks `expectRevert`.
        (bool sent,) = address(safe)
            .call(
                abi.encodeCall(
                    safe.execTransaction,
                    (address(safe), 0, data, Enum.Operation.Call, 0, 0, 0, address(0), payable(0), sig)
                )
            );
        assertFalse(sent, "non-contract handler refused");

        (bool ok, bytes memory ret) = _isValid(safe, H, "");
        assertFalse(ok);
        assertEq(bytes4(ret), LockdownFallbackHandler.Erc1271Disabled.selector, "handler still in place");
    }

    /// @dev Route 5b: hostile shim exposing `LOCKDOWN()` == singleton with no gates. ACTUAL: the
    ///      binding check (Lockdown.sol:_checkCall, `LOCKDOWN() == address(this)`) only checks the
    ///      getter, so the shim PASSES and ERC-1271 becomes open and even incident-proof.
    ///      Accepted residual: the quorum could equally `setGuard(0)` in Normal. It is an
    ///      owner-path tx, hence timelocked like any other when `timelockDelay > 0` (asserted
    ///      below: TicketNotFound without a ticket). Never reachable in an incident (owner path
    ///      blocked) nor from a module (5c).
    function test_limitation_hostileShimPassesBindingCheck() public {
        HostileShim shim = new HostileShim(address(guard));
        bytes memory data = abi.encodeCall(IFallbackManager.setFallbackHandler, (address(shim)));

        _enableTimelock(safe, DELAY);
        _execAsOwner_Revert(safe, address(safe), 0, data, Enum.Operation.Call, Timelock.TicketNotFound.selector);
        // (delay-0 branch below: use a fresh Safe without timelock)
        Safe s0 = _createConfigureAndInitialise(713);
        _selfCall(s0, data);
        assertEq(
            address(
                uint160(
                    uint256(
                        vm.load(
                            address(s0),
                            bytes32(uint256(0x6c9a6c4a39284e37ed1cf53d337577d14212a4870fb976a4366c693b939918d5))
                        )
                    )
                )
            ),
            address(shim)
        );

        assertFalse(guard.isErc1271Allowed(address(s0)), "flag false, yet:");
        _assertValid(s0, ""); // shim ignores both gates
        _triggerLockdown(s0, bytes32("wrench"));
        _assertValid(s0, ""); // incident-proof as well
    }

    /// @dev Route 5c: module-path `setFallbackHandler(anything)`. CLOSED by
    ///      Lockdown.sol:_checkCall (`_isForbiddenModuleSafeSelfCall` -> ModuleSafeSelfCallDenied).
    function test_confirmed_modulePathSetFallbackHandlerDenied() public {
        CompatibilityFallbackHandler compat = new CompatibilityFallbackHandler();
        _moduleCall_Revert(
            module,
            safe,
            address(safe),
            0,
            abi.encodeCall(IFallbackManager.setFallbackHandler, (address(compat))),
            Enum.Operation.Call,
            Lockdown.ModuleSafeSelfCallDenied.selector
        );
        _moduleCall_Revert(
            module,
            safe,
            address(safe),
            0,
            abi.encodeCall(IFallbackManager.setFallbackHandler, (address(handler))),
            Enum.Operation.Call,
            Lockdown.ModuleSafeSelfCallDenied.selector
        );
    }

    // ------------------------------------------------------------------
    // 6. Install at delay 0 / free first timelock activation
    // ------------------------------------------------------------------

    /// @dev Route: install-time opt-in and the free first activation `setTimelockDelay(0 -> N)`.
    ///      Install batch (initialize + setErc1271Allowed(true)) is instant at delay 0 by design
    ///      (no timelock exists yet). Activating the timelock does not touch the flag:
    ///      LockdownTimelock.sol:setTimelockDelay writes only the timelock config, the flag lives
    ///      in the lifecycle config of Lockdown.sol:setErc1271Allowed.
    function test_confirmed_firstTimelockActivationDoesNotTouchFlag() public {
        Safe fresh = _createAndConfigure(714);
        bytes memory batch = abi.encodePacked(
            _multiSendItem(Enum.Operation.Call, address(guard), 0, _initCall()),
            _multiSendItem(Enum.Operation.Call, address(guard), 0, abi.encodeCall(Lockdown.setErc1271Allowed, (true)))
        );
        _execAsOwner(
            fresh,
            address(multiSendCallOnly),
            0,
            abi.encodeCall(MultiSendCallOnly.multiSend, (batch)),
            Enum.Operation.DelegateCall
        );
        assertTrue(guard.isErc1271Allowed(address(fresh)), "install batch opts in instantly");

        assertFalse(guard.isErc1271Allowed(address(safe)), "control safe: false");
        _enableTimelock(fresh, DELAY);
        _enableTimelock(safe, DELAY);
        assertTrue(guard.isErc1271Allowed(address(fresh)), "true stays true");
        assertFalse(guard.isErc1271Allowed(address(safe)), "false stays false");
        _assertRevertsWith(safe, bytes(""), LockdownFallbackHandler.Erc1271Disabled.selector);
    }

    /// @dev Route closed by tooling, not by the contract: the operator sets the ERC-1271 choice
    ///      in the SAME batch that activates the timelock. At delay 0 the guard checks the outer
    ///      MultiSend once, so `[setErc1271Allowed(false), setTimelockDelay(N)]` lands atomically
    ///      with no ticket, in either order, and the handler refuses in the same block. This is
    ///      what the lifecycle helper's step 6 builds (deploy/README.md).
    function test_confirmed_timelockActivationBatchCarriesTheErc1271Choice() public {
        for (uint256 i; i < 2; ++i) {
            Safe fresh = _createConfigureAndInitialise(720 + i);
            _setAllowed(fresh, true);
            _assertValid(fresh, _signMessage(fresh, OWNER_PK, H));

            bytes memory off = _multiSendItem(
                Enum.Operation.Call, address(guard), 0, abi.encodeCall(Lockdown.setErc1271Allowed, (false))
            );
            bytes memory activate = _multiSendItem(
                Enum.Operation.Call, address(guard), 0, abi.encodeCall(LockdownTimelock.setTimelockDelay, (DELAY))
            );
            bytes memory batch = i == 0 ? abi.encodePacked(off, activate) : abi.encodePacked(activate, off);
            _execAsOwner(
                fresh,
                address(multiSendCallOnly),
                0,
                abi.encodeCall(MultiSendCallOnly.multiSend, (batch)),
                Enum.Operation.DelegateCall
            );

            assertEq(guard.getTimelockDelay(address(fresh)), DELAY, "timelock active");
            assertFalse(guard.isErc1271Allowed(address(fresh)), "flag off in the same tx");
            _assertRevertsWith(
                fresh, _signMessage(fresh, OWNER_PK, H), LockdownFallbackHandler.Erc1271Disabled.selector
            );
        }
    }

    // ------------------------------------------------------------------
    // 7. Bypasser
    // ------------------------------------------------------------------

    /// @dev Route: with `timelockDelay = N`, a registered bypasser flips the flag with no wait via
    ///      `bypassTimelock(safe, safeTxHash)` (Timelock.sol:bypassTimelock sets executableAt =
    ///      now). Accepted residual, SPEC H.27: the bypasser holds full owner-path authority
    ///      (owner signatures are still required); trust is off-chain (HSM).
    function test_limitation_bypasserEnablesFlagWithoutWaiting() public {
        _enableTimelock(safe, DELAY);
        vm.prank(address(safe));
        guard.setTimelockBypasser(HSM, true);

        bytes memory data = abi.encodeCall(Lockdown.setErc1271Allowed, (true));
        _execAsOwner_Revert(safe, address(guard), 0, data, Enum.Operation.Call, Timelock.TicketNotFound.selector);

        bytes32 txHash = _safeTxHash(safe, address(guard), 0, data, Enum.Operation.Call);
        vm.prank(HSM);
        guard.bypassTimelock(address(safe), txHash);
        _execAsOwner(safe, address(guard), 0, data, Enum.Operation.Call);

        assertTrue(guard.isErc1271Allowed(address(safe)), "flag flipped with zero wait");
        _assertValid(safe, _signMessage(safe, OWNER_PK, H));
    }

    // ------------------------------------------------------------------
    // 8. Nested MultiSend, module vs owner
    // ------------------------------------------------------------------

    /// @dev Route: `setErc1271Allowed(true)` nested in a MultiSendCallOnly batch. Module path:
    ///      CLOSED at every depth (Lockdown.sol:_checkCall -> ModuleCallToSingletonDenied).
    ///      Owner path: works in Normal at delay 0 (owner quorum), but the batch is timelocked as
    ///      one unit when delay > 0 (LockdownTimelock.sol:checkTransaction DelegateCall branch ->
    ///      _verifyOwnerTimelock -> TicketNotFound).
    function test_confirmed_nestedMultiSendModuleDeniedOwnerTimelockedAsUnit() public {
        bytes memory batch =
            _multiSendItem(Enum.Operation.Call, address(guard), 0, abi.encodeCall(Lockdown.setErc1271Allowed, (true)));
        bytes memory ms = abi.encodeCall(MultiSendCallOnly.multiSend, (batch));

        _moduleCall_Revert(
            module,
            safe,
            address(multiSendCallOnly),
            0,
            ms,
            Enum.Operation.DelegateCall,
            Lockdown.ModuleCallToSingletonDenied.selector
        );
        assertFalse(guard.isErc1271Allowed(address(safe)));

        // Owner path with delay > 0: no ticket for the whole batch -> reverts.
        _enableTimelock(safe, DELAY);
        _execAsOwner_Revert(
            safe, address(multiSendCallOnly), 0, ms, Enum.Operation.DelegateCall, Timelock.TicketNotFound.selector
        );
        assertFalse(guard.isErc1271Allowed(address(safe)));

        // Owner path with delay 0 (fresh Safe): the nested call works.
        Safe s0 = _createConfigureAndInitialise(715);
        _execAsOwner(s0, address(multiSendCallOnly), 0, ms, Enum.Operation.DelegateCall);
        assertTrue(guard.isErc1271Allowed(address(s0)), "owner-path nested works in Normal at delay 0");
    }

    // ------------------------------------------------------------------
    // 9. Migration / uninstall
    // ------------------------------------------------------------------

    /// @dev Route 9a: migrate an opted-in Safe to a SECOND singleton + handler. FAIL-CLOSED: the
    ///      second singleton has fresh storage, flag false, state Uninitialised, so its handler
    ///      reverts Erc1271Disabled (LockdownFallbackHandler.sol:isValidSignature). Ordering
    ///      surprise: the old guard's binding check (Lockdown.sol:_checkCall) compares
    ///      `LOCKDOWN()` to the OLD singleton, so the handler swap is only accepted AFTER the
    ///      guard has been switched (new guard is uninitialised -> pass-through).
    function test_confirmed_migrationToSecondSingletonIsFailClosed() public {
        _setAllowed(safe, true);
        _assertValid(safe, _signMessage(safe, OWNER_PK, H));

        Lockdown second = new Lockdown(address(multiSendCallOnly));
        LockdownFallbackHandler handler2 = new LockdownFallbackHandler(second);

        // Handler first is refused by the old singleton's binding check (empty-data? no: typed).
        bytes memory swapHandler = abi.encodeCall(IFallbackManager.setFallbackHandler, (address(handler2)));
        _execAsOwner_Revert(
            safe, address(safe), 0, swapHandler, Enum.Operation.Call, Lockdown.InvalidFallbackHandler.selector
        );

        _selfCall(safe, abi.encodeCall(IGuardManager.setGuard, (address(second))));
        _selfCall(safe, abi.encodeCall(IModuleManager.setModuleGuard, (address(second))));
        _selfCall(safe, swapHandler);

        bytes memory sig = _signMessage(safe, OWNER_PK, H);
        (bool ok, bytes memory ret) = _isValid(safe, H, sig);
        assertFalse(ok);
        assertEq(bytes4(ret), LockdownFallbackHandler.Erc1271Disabled.selector, "fresh storage: disabled");
        assertFalse(second.isErc1271Allowed(address(safe)));
        assertTrue(guard.isErc1271Allowed(address(safe)), "old singleton flag lingers, unused");
    }

    /// @dev Route 9b: uninstall in Normal at delay 0 (setGuard(0), setModuleGuard(0),
    ///      setFallbackHandler(CompatibilityFallbackHandler)). ERC-1271 is then fully open:
    ///      residual, the quorum removed the protection (not a bypass of it). Reinstalling the same
    ///      singleton: `initialize` reverts InvalidState (config lingers, StateMachine.sol
    ///      onlyUninitialised) and the opt-in made before the uninstall persisted (`true`).
    function test_limitation_uninstallOpensErc1271AndReinstallKeepsFlag() public {
        _setAllowed(safe, true);
        CompatibilityFallbackHandler compat = new CompatibilityFallbackHandler();

        _selfCall(safe, abi.encodeCall(IGuardManager.setGuard, (address(0))));
        _selfCall(safe, abi.encodeCall(IModuleManager.setModuleGuard, (address(0))));
        _selfCall(safe, abi.encodeCall(IFallbackManager.setFallbackHandler, (address(compat))));

        // Open regardless of the flag, no gate.
        (bool ok, bytes memory ret) = _isValid(safe, H, _signMessage(safe, OWNER_PK, H));
        assertTrue(ok, "ERC-1271 fully open after uninstall");
        assertEq(abi.decode(ret, (bytes4)), MAGIC);

        // Reinstall the same singleton + handler.
        _selfCall(safe, abi.encodeCall(IGuardManager.setGuard, (address(guard))));
        _selfCall(safe, abi.encodeCall(IModuleManager.setModuleGuard, (address(guard))));
        _selfCall(safe, abi.encodeCall(IFallbackManager.setFallbackHandler, (address(handler))));

        vm.prank(address(safe));
        vm.expectRevert(
            abi.encodeWithSelector(
                StateMachine.InvalidState.selector,
                StateMachine.State.Normal,
                1 << uint256(StateMachine.State.Uninitialised)
            )
        );
        guard.initialize(48 hours, 4 hours, _recoveryOwners(), _signers());
        // The opt-in made before the uninstall is still in force: same quorum decision,
        // same singleton storage (no re-`initialize`, so nothing reset it).
        assertTrue(guard.isErc1271Allowed(address(safe)), "flag value persisted across uninstall/reinstall");
        _assertValid(safe, _signMessage(safe, OWNER_PK, H));
    }

    function _recoveryOwners() private view returns (address[] memory r) {
        r = new address[](1);
        r[0] = recovery;
    }

    function _signers() private view returns (bytes[] memory s) {
        s = new bytes[](1);
        s[0] = abi.encodePacked(panicKey);
    }

    // ------------------------------------------------------------------
    // 10. Incident with flag true
    // ------------------------------------------------------------------

    /// @dev Route: flag true during an incident. CLOSED: both the inline and `signedMessages`
    ///      branches revert SignaturesFrozenDuringLockdown in LockedDown and Recovering
    ///      (LockdownFallbackHandler.sol:isValidSignature incident gate runs before the branch).
    function test_confirmed_incidentFreezesBothBranchesEvenWhenOptedIn() public {
        _setAllowed(safe, true);
        bytes memory sig = _signMessage(safe, OWNER_PK, H);
        _triggerLockdown(safe, bytes32("wrench"));
        bytes4 frozen = LockdownFallbackHandler.SignaturesFrozenDuringLockdown.selector;
        _assertRevertsWith(safe, sig, frozen);
        _assertRevertsWith(safe, bytes(""), frozen);
        vm.warp(block.timestamp + 48 hours + 1);
        _assertRevertsWith(safe, sig, frozen);
        _assertRevertsWith(safe, bytes(""), frozen);
    }
}
