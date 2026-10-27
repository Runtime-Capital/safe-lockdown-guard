// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {TestEnvironment} from "../TestEnvironment.sol";

import {ISafe} from "@safe-global/safe-smart-account/interfaces/ISafe.sol";
import {Safe, Enum} from "@safe-global/safe-smart-account/Safe.sol";
import {MultiSendCallOnly} from "@safe-global/safe-smart-account/libraries/MultiSendCallOnly.sol";
import {IGuardManager} from "@safe-global/safe-smart-account/interfaces/IGuardManager.sol";
import {IModuleManager} from "@safe-global/safe-smart-account/interfaces/IModuleManager.sol";
import {IFallbackManager} from "@safe-global/safe-smart-account/interfaces/IFallbackManager.sol";
import {IOwnerManager} from "@safe-global/safe-smart-account/interfaces/IOwnerManager.sol";

import {SignatureChecker, IERC1271} from "@openzeppelin/contracts/utils/cryptography/SignatureChecker.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";

import {Lockdown} from "../../src/Lockdown.sol";
import {LockdownTimelock} from "../../src/LockdownTimelock.sol";
import {LockdownFallbackHandler} from "../../src/handlers/LockdownFallbackHandler.sol";
import {StateMachine} from "../../src/base/StateMachine.sol";
import {Timelock} from "../../src/base/Timelock.sol";

contract Counter {
    uint256 public calls;

    function mark() external {
        ++calls;
    }
}

/// @notice Shared fixture. Safe v1.5.0 integration + install/uninstall/reinstall lifecycle PoCs.
/// @notice Executable verdicts for the "install slots are only checked inside
///         `initialize`" lead, hook ordering around a transaction that mutates
///         the very slots it is checked by, singleton migration, and cross-Safe
///         isolation. Every test either PROVES a limitation (`test_limitation_`)
///         or pins the protection that refutes / confirms a lead.
abstract contract LifecycleBase is TestEnvironment {
    bytes32 internal constant GUARD_SLOT = 0x4a204f620c8c5ccdca3fd54d003badd85ba500436a431f0cbda4f558c93c34c8;
    bytes32 internal constant MODULE_GUARD_SLOT = 0xb104e0b93118902c651344349b610029d694cfdec91c589c91ebafbcd0289947;
    bytes32 internal constant FALLBACK_SLOT = 0x6c9a6c4a39284e37ed1cf53d337577d14212a4870fb976a4366c693b939918d5;
    address internal constant SENTINEL = address(0x1);

    Counter internal counter;

    function setUp() public virtual override {
        super.setUp();
        counter = new Counter();
    }

    // ------------------------------------------------------------------
    // Helpers
    // ------------------------------------------------------------------

    function _initCalldata() internal view returns (bytes memory) {
        address[] memory recoveryOwners = new address[](1);
        recoveryOwners[0] = recovery;
        bytes[] memory signers = new bytes[](1);
        signers[0] = abi.encodePacked(panicKey);
        return abi.encodeCall(Lockdown.initialize, (48 hours, 4 hours, recoveryOwners, signers));
    }

    function _initRevert(Safe safe, bytes4 expected) internal {
        _execAsOwner_Revert(safe, address(guard), 0, _initCalldata(), Enum.Operation.Call, expected);
    }

    function _deployNewSingleton() internal returns (LockdownTimelock, LockdownFallbackHandler) {
        LockdownTimelock newGuard = new LockdownTimelock(address(multiSendCallOnly));
        return (newGuard, new LockdownFallbackHandler(newGuard));
    }

    /// @dev `_signTrigger` is hard-wired to the fixture singleton; this variant
    ///      signs a trigger for an arbitrary singleton (needed for migration).
    function _signTriggerFor(LockdownTimelock target, Safe safe, uint256 pk, bytes32 reasonHash)
        internal
        view
        returns (bytes memory)
    {
        (bytes1 fields, string memory name, string memory version, uint256 chainId, address verifying, bytes32 salt,) =
            target.eip712Domain();
        bytes32 digest = MessageHashUtils.toTypedDataHash(
            MessageHashUtils.toDomainSeparator(fields, name, version, chainId, verifying, salt),
            keccak256(
                abi.encode(target.LOCKDOWN_TYPEHASH(), safe, keccak256(abi.encodePacked(vm.addr(pk))), reasonHash)
            )
        );
        (uint8 v, bytes32 r, bytes32 sv) = vm.sign(pk, digest);
        return abi.encodePacked(r, sv, v);
    }

    function _slot(Safe safe, bytes32 slot) internal view returns (address result) {
        bytes memory raw = safe.getStorageAt(uint256(slot), 1);
        assembly ("memory-safe") {
            result := mload(add(raw, 0x20))
        }
    }

    function _params(address to, uint256 value, bytes memory data, Enum.Operation op)
        internal
        pure
        returns (Timelock.ExecTransactionParams memory)
    {
        return Timelock.ExecTransactionParams({
            to: to,
            value: value,
            data: data,
            operation: op,
            safeTxGas: 0,
            baseGas: 0,
            gasPrice: 0,
            gasToken: address(0),
            refundReceiver: payable(address(0))
        });
    }

    function _signAt(
        Safe safe,
        uint256 pk,
        address to,
        uint256 value,
        bytes memory data,
        Enum.Operation op,
        uint256 nonce
    ) internal view returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, _safeTxHash(safe, to, value, data, op, nonce));
        return abi.encodePacked(r, s, v);
    }

    function _returnDataRevert(Safe safe, address to, bytes memory data, bytes4 expected) internal {
        vm.prank(module);
        vm.expectRevert(expected);
        safe.execTransactionFromModuleReturnData(to, 0, data, Enum.Operation.Call);
    }

    // --- 2-of-2 Safe ---------------------------------------------------

    function _create2of2(uint256 nonce) internal returns (Safe safe) {
        address[] memory owners = new address[](2);
        owners[0] = owner;
        owners[1] = other;
        safe = Safe(
            payable(factory.createProxyWithNonce(
                    address(singleton),
                    abi.encodeCall(
                        Safe.setup, (owners, 2, address(0), "", address(0), address(0), 0, payable(address(0)))
                    ),
                    nonce
                ))
        );
        vm.startPrank(address(safe));
        safe.setGuard(address(guard));
        safe.setModuleGuard(address(guard));
        safe.setFallbackHandler(address(handler));
        safe.enableModule(module);
        vm.stopPrank();
        _exec2(safe, address(guard), _initCalldata(), Enum.Operation.Call);
    }

    function _sign2(Safe safe, address to, bytes memory data, Enum.Operation op) internal view returns (bytes memory) {
        bytes32 hash = _safeTxHash(safe, to, 0, data, op);
        (uint8 v1, bytes32 r1, bytes32 s1) = vm.sign(OWNER_PK, hash);
        (uint8 v2, bytes32 r2, bytes32 s2) = vm.sign(OTHER_PK, hash);
        return owner < other ? abi.encodePacked(r1, s1, v1, r2, s2, v2) : abi.encodePacked(r2, s2, v2, r1, s1, v1);
    }

    function _signMessage2(Safe safe, bytes32 hash) internal view returns (bytes memory) {
        bytes32 digest = handler.getMessageHashForSafe(safe, abi.encode(hash));
        (uint8 v1, bytes32 r1, bytes32 s1) = vm.sign(OWNER_PK, digest);
        (uint8 v2, bytes32 r2, bytes32 s2) = vm.sign(OTHER_PK, digest);
        return owner < other ? abi.encodePacked(r1, s1, v1, r2, s2, v2) : abi.encodePacked(r2, s2, v2, r1, s1, v1);
    }

    function _exec2(Safe safe, address to, bytes memory data, Enum.Operation op) internal {
        bytes memory sig = _sign2(safe, to, data, op);
        require(safe.execTransaction(to, 0, data, op, 0, 0, 0, address(0), payable(address(0)), sig));
    }

    function _exec2Revert(Safe safe, address to, bytes memory data, Enum.Operation op, bytes4 expected) internal {
        bytes memory sig = _sign2(safe, to, data, op);
        vm.expectRevert(expected);
        safe.execTransaction(to, 0, data, op, 0, 0, 0, address(0), payable(address(0)), sig);
    }
}

contract SafeInstallLifecyclePoC is LifecycleBase {
    // ------------------------------------------------------------------
    // 1. Partial / wrong-order install
    // ------------------------------------------------------------------

    /// Lead: `initialize` is the ONLY place the three install slots are checked.
    /// Verdict: the check itself is complete - each missing slot has its own error.
    function test_confirmed_initializeRejectsEachMissingInstallSlot() public {
        LockdownTimelock foreignGuard = new LockdownTimelock(address(multiSendCallOnly));
        LockdownFallbackHandler foreignHandler = new LockdownFallbackHandler(foreignGuard);

        // (a) nothing wired at all
        Safe a = _createSafe(101);
        _initRevert(a, Lockdown.GuardNotInstalled.selector);

        // (b) transaction guard only
        Safe b = _createSafe(102);
        vm.prank(address(b));
        b.setGuard(address(guard));
        _initRevert(b, Lockdown.GuardNotInstalled.selector);

        // (c) both guards, but a fallback handler bound to another singleton
        Safe c = _createSafe(103);
        vm.startPrank(address(c));
        c.setGuard(address(guard));
        c.setModuleGuard(address(guard));
        c.setFallbackHandler(address(foreignHandler));
        vm.stopPrank();
        _initRevert(c, Lockdown.InvalidFallbackHandler.selector);

        // (d) all three wired -> succeeds
        Safe d = _createAndConfigure(104);
        _execAsOwner(d, address(guard), 0, _initCalldata(), Enum.Operation.Call);
        (StateMachine.State state,) = guard.getState(address(d));
        assertEq(uint256(state), uint256(StateMachine.State.Normal), "initialised");
    }

    /// Lead: the anti-brick fail-open leaves a real window between wiring the
    /// slots and calling `initialize`.
    /// Verdict: LIMITATION (deliberate, SPEC_V1 §7.1) - both paths pass through,
    /// but the module path is still denied the singleton pre-init.
    function test_limitation_uninitialisedSafeFailsOpenOnBothPaths() public {
        Safe safe = _createAndConfigure(105);
        (StateMachine.State state,) = guard.getState(address(safe));
        assertEq(uint256(state), uint256(StateMachine.State.Uninitialised), "pre-init");

        _execAsOwner(safe, address(counter), 0, abi.encodeCall(Counter.mark, ()), Enum.Operation.Call);
        _moduleCall(module, safe, address(counter), 0, abi.encodeCall(Counter.mark, ()), Enum.Operation.Call);
        assertEq(counter.calls(), 2, "both paths fail open pre-init");

        // ... except a module reaching the singleton, which is denied even pre-init.
        _moduleCall_Revert(
            module,
            safe,
            address(guard),
            0,
            _initCalldata(),
            Enum.Operation.Call,
            Lockdown.ModuleCallToSingletonDenied.selector
        );
    }

    // ------------------------------------------------------------------
    // 2. Uninstall during an incident
    // ------------------------------------------------------------------

    /// Lead: can a coerced quorum uninstall the guard mid-incident?
    /// Verdict: REFUTED. Both paths are frozen before the self-call is inspected.
    function test_refuted_uninstallUnreachableDuringLockdownAndRecovery() public {
        Safe safe = _createConfigureAndInitialise(110);
        _triggerLockdown(safe, keccak256("wrench"));

        bytes memory dropGuard = abi.encodeCall(IGuardManager.setGuard, (address(0)));
        bytes memory dropModuleGuard = abi.encodeCall(IModuleManager.setModuleGuard, (address(0)));

        _execAsOwner_Revert(safe, address(safe), 0, dropGuard, Enum.Operation.Call, Lockdown.LockedDown.selector);
        _moduleCall_Revert(module, safe, address(safe), 0, dropGuard, Enum.Operation.Call, Lockdown.LockedDown.selector);

        vm.warp(block.timestamp + 48 hours + 1); // Recovering
        (StateMachine.State state,) = guard.getState(address(safe));
        assertEq(uint256(state), uint256(StateMachine.State.Recovering), "recovering");

        _execAsOwner_Revert(safe, address(safe), 0, dropGuard, Enum.Operation.Call, Lockdown.RecoveryActive.selector);
        _execAsOwner_Revert(
            safe, address(safe), 0, dropModuleGuard, Enum.Operation.Call, Lockdown.RecoveryActive.selector
        );
        _moduleCall_Revert(
            module, safe, address(safe), 0, dropGuard, Enum.Operation.Call, Lockdown.RecoveryActive.selector
        );

        // Even wrapped in a MultiSend bundle alongside a whitelisted nonce burn.
        bytes memory bundle = abi.encodeCall(
            MultiSendCallOnly.multiSend,
            (bytes.concat(
                    _multiSendItem(Enum.Operation.Call, address(safe), 0, ""),
                    _multiSendItem(Enum.Operation.Call, address(safe), 0, dropGuard)
                ))
        );
        _execAsOwner_Revert(
            safe, address(multiSendCallOnly), 0, bundle, Enum.Operation.DelegateCall, Lockdown.RecoveryActive.selector
        );
    }

    /// Lead: what does the singleton still enforce on a Safe that removed its guard?
    /// Verdict: LIMITATION. `triggerLockdown` has no install check, so any still-
    /// registered signer can freeze the ERC-1271 surface of a Safe that already
    /// uninstalled the guards. Escape hatch: with no guard, the handler slot is
    /// free again, so the quorum can unfreeze itself.
    function test_limitation_triggerLockdownStillFreezesErc1271AfterGuardUninstall() public {
        Safe safe = _createConfigureAndInitialise(111);

        _execAsOwner(
            safe,
            address(multiSendCallOnly),
            0,
            abi.encodeCall(
                MultiSendCallOnly.multiSend,
                (bytes.concat(
                        _multiSendItem(
                            Enum.Operation.Call, address(safe), 0, abi.encodeCall(IGuardManager.setGuard, (address(0)))
                        ),
                        _multiSendItem(
                            Enum.Operation.Call,
                            address(safe),
                            0,
                            abi.encodeCall(IModuleManager.setModuleGuard, (address(0)))
                        )
                    ))
            ),
            Enum.Operation.DelegateCall
        );
        assertEq(_slot(safe, GUARD_SLOT), address(0), "guard uninstalled");
        assertEq(_slot(safe, MODULE_GUARD_SLOT), address(0), "module guard uninstalled");

        // No install check on the trigger path.
        _triggerLockdown(safe, keccak256("wrench"));
        (StateMachine.State state,) = guard.getState(address(safe));
        assertEq(uint256(state), uint256(StateMachine.State.LockedDown), "singleton still locks the Safe down");

        // Execution is NOT frozen (no guard) ...
        _execAsOwner(safe, address(counter), 0, abi.encodeCall(Counter.mark, ()), Enum.Operation.Call);
        _moduleCall(module, safe, address(counter), 0, abi.encodeCall(Counter.mark, ()), Enum.Operation.Call);
        assertEq(counter.calls(), 2, "execution unaffected by the lockdown");

        // ... but the ERC-1271 surface IS, because the handler is still installed.
        bytes32 hash = keccak256("order");
        bytes memory signature = _signMessage(safe, OWNER_PK, hash);
        vm.expectRevert(LockdownFallbackHandler.SignaturesFrozenDuringLockdown.selector);
        IERC1271(address(safe)).isValidSignature(hash, signature);

        // Escape hatch: with no guard installed, the handler slot is unconstrained.
        _execAsOwner(
            safe,
            address(safe),
            0,
            abi.encodeCall(IFallbackManager.setFallbackHandler, (address(0))),
            Enum.Operation.Call
        );
        assertEq(_slot(safe, FALLBACK_SLOT), address(0), "handler removable once the guard is gone");
    }

    // ------------------------------------------------------------------
    // 3. Partial uninstall / reinstall - the "checked only in initialize" lead
    // ------------------------------------------------------------------

    /// Lead (weaponised): nothing re-checks the module-guard slot after
    /// `initialize`. Dropping it alone is an owner-path-legal, silent,
    /// permanent downgrade that survives INTO the incident: the panic freeze
    /// no longer covers the module path, while every singleton view still
    /// reports a healthy LockedDown Safe.
    /// Verdict: CONFIRMED limitation.
    function test_limitation_moduleGuardRemovalSilentlyDefeatsLockdownOnModulePath() public {
        Safe safe = _createConfigureAndInitialise(120);

        // Owner-path legal: `_isForbiddenModuleSafeSelfCall` only gates Privilege.Module.
        _execAsOwner(
            safe, address(safe), 0, abi.encodeCall(IModuleManager.setModuleGuard, (address(0))), Enum.Operation.Call
        );
        assertEq(_slot(safe, MODULE_GUARD_SLOT), address(0), "module guard silently dropped");
        assertEq(_slot(safe, GUARD_SLOT), address(guard), "transaction guard still installed");

        _triggerLockdown(safe, keccak256("wrench"));
        (StateMachine.State state,) = guard.getState(address(safe));
        assertEq(uint256(state), uint256(StateMachine.State.LockedDown), "views report a healthy incident");

        // Owner path frozen as advertised ...
        _execAsOwner_Revert(
            safe,
            address(counter),
            0,
            abi.encodeCall(Counter.mark, ()),
            Enum.Operation.Call,
            Lockdown.LockedDown.selector
        );
        // ... module path is wide open DURING the lockdown.
        _moduleCall(module, safe, address(counter), 0, abi.encodeCall(Counter.mark, ()), Enum.Operation.Call);
        assertEq(counter.calls(), 1, "module executes while the Safe is LockedDown");
    }

    /// Lead: reinstall over stale per-Safe storage.
    /// Verdict: CONFIRMED escalation beyond "state persists" (register item 12).
    /// A partial re-install can never be detected on-chain: `initialize` is the
    /// only slot check and it is permanently unreachable after the first call,
    /// so a Safe that re-installs ONLY the transaction guard hands every enabled
    /// module unrestricted admin over the singleton's roots of trust.
    function test_limitation_reinstallNeverRechecksInstallSlots() public {
        Safe safe = _createConfigureAndInitialise(121);

        // Full uninstall (Normal state, owner path).
        _execAsOwner(
            safe,
            address(multiSendCallOnly),
            0,
            abi.encodeCall(
                MultiSendCallOnly.multiSend,
                (bytes.concat(
                        _multiSendItem(
                            Enum.Operation.Call, address(safe), 0, abi.encodeCall(IGuardManager.setGuard, (address(0)))
                        ),
                        _multiSendItem(
                            Enum.Operation.Call,
                            address(safe),
                            0,
                            abi.encodeCall(IModuleManager.setModuleGuard, (address(0)))
                        )
                    ))
            ),
            Enum.Operation.DelegateCall
        );

        // Partial re-install: transaction guard only.
        _execAsOwner(
            safe, address(safe), 0, abi.encodeCall(IGuardManager.setGuard, (address(guard))), Enum.Operation.Call
        );

        // `initialize` cannot be re-run, so the slot check can never fire again.
        _execAsOwner_Revert(
            safe,
            address(guard),
            0,
            _initCalldata(),
            Enum.Operation.Call,
            abi.encodeWithSelector(
                StateMachine.InvalidState.selector,
                StateMachine.State.Normal,
                uint256(1) << uint256(StateMachine.State.Uninitialised)
            )
        );

        // With no module guard, an enabled module owns the anti-coercion roots of trust.
        bytes memory rogue = abi.encodePacked(other);
        _moduleCall(
            module, safe, address(guard), 0, abi.encodeCall(Lockdown.addLockdownSigner, (rogue)), Enum.Operation.Call
        );
        assertEq(guard.getLockdownSignerCount(address(safe)), 2, "module registered its own panic identity");

        guard.triggerLockdown(
            address(safe), keccak256("module-owned"), rogue, _signTrigger(safe, OTHER_PK, keccak256("module-owned"))
        );
        _execAsOwner_Revert(
            safe,
            address(counter),
            0,
            abi.encodeCall(Counter.mark, ()),
            Enum.Operation.Call,
            Lockdown.LockedDown.selector
        );
    }
}

contract SafeMigrationLifecyclePoC is LifecycleBase {
    // ------------------------------------------------------------------
    // F-03: singleton A -> B migration
    // ------------------------------------------------------------------

    /// F-03 step 2. The published runbook (`docs/V1_USER_SCENARIOS.md:1201-1203`,
    /// "a single MultiSend on each Safe to switch `setGuard` and `setModuleGuard`")
    /// executed literally.
    /// Verdict: CONFIRMED fail-open on BOTH paths - B was never initialised, so
    /// its hooks pass owner and module traffic through
    /// (`src/Lockdown.sol:300-305,334-346`). PARTIAL REFUTATION of the claim
    /// that "an A trigger is no longer consulted": the fallback handler is still
    /// H_A, so an A trigger still freezes the Safe's ERC-1271 surface - it just
    /// no longer freezes execution.
    function test_confirmed_publishedGuardsOnlyMigrationLeavesBothPathsFailOpen() public {
        Safe safe = _createConfigureAndInitialise(133);
        (LockdownTimelock b, LockdownFallbackHandler handlerB) = _deployNewSingleton();

        _execAsOwner(safe, address(multiSendCallOnly), 0, _swapGuardsBundle(safe, b), Enum.Operation.DelegateCall);

        assertEq(_slot(safe, GUARD_SLOT), address(b), "guard slot -> B");
        assertEq(_slot(safe, MODULE_GUARD_SLOT), address(b), "module guard slot -> B");
        assertEq(_slot(safe, FALLBACK_SLOT), address(handler), "handler still H_A");
        (StateMachine.State stateB,) = b.getState(address(safe));
        assertEq(uint256(stateB), uint256(StateMachine.State.Uninitialised), "B never initialised");

        // The Safe is now protected by nobody: A is no longer a guard, B fails open.
        _triggerLockdown(safe, keccak256("wrench"));
        (StateMachine.State stateA,) = guard.getState(address(safe));
        assertEq(uint256(stateA), uint256(StateMachine.State.LockedDown), "A still holds the incident");

        _execAsOwner(safe, address(counter), 0, abi.encodeCall(Counter.mark, ()), Enum.Operation.Call);
        _moduleCall(module, safe, address(counter), 0, abi.encodeCall(Counter.mark, ()), Enum.Operation.Call);
        assertEq(counter.calls(), 2, "owner AND module paths execute during an A incident");

        // Not fully open: B's uninitialised module branch still routes through
        // _checkCall, so the module cannot reach B or disable the guard slots.
        _moduleCall_Revert(
            module,
            safe,
            address(b),
            0,
            _initCalldata(),
            Enum.Operation.Call,
            Lockdown.ModuleCallToSingletonDenied.selector
        );
        _moduleCall_Revert(
            module,
            safe,
            address(safe),
            0,
            abi.encodeCall(IGuardManager.setGuard, (address(0))),
            Enum.Operation.Call,
            Lockdown.ModuleSafeSelfCallDenied.selector
        );

        // The one thing A still enforces: the ERC-1271 freeze, via H_A.
        bytes32 hash = keccak256("order");
        bytes memory signature = _signMessage(safe, OWNER_PK, hash);
        vm.expectRevert(LockdownFallbackHandler.SignaturesFrozenDuringLockdown.selector);
        IERC1271(address(safe)).isValidSignature(hash, signature);
        assertEq(uint256(uint160(address(handlerB))) > 0, true, "H_B deployed but unused");
    }

    /// F-03 step 3. The genuinely complete atomic bundle:
    /// setGuard(B) + setModuleGuard(B) + setFallbackHandler(H_B) + B.initialize.
    /// Verdict: CONFIRMED blocked, by A's pre-hook fallback-handler binding
    /// (`src/Lockdown.sol:399-407`), which inspects the entire batch before any
    /// write and requires `H_B.LOCKDOWN() == A`.
    function test_confirmed_atomicMigrationBundleRevertsInvalidFallbackHandler() public {
        Safe safe = _createConfigureAndInitialise(134);
        (LockdownTimelock b, LockdownFallbackHandler handlerB) = _deployNewSingleton();

        bytes memory bundle = abi.encodeCall(
            MultiSendCallOnly.multiSend,
            (bytes.concat(
                    _swapGuardsItems(safe, b),
                    _multiSendItem(
                        Enum.Operation.Call,
                        address(safe),
                        0,
                        abi.encodeCall(IFallbackManager.setFallbackHandler, (address(handlerB)))
                    ),
                    _multiSendItem(Enum.Operation.Call, address(b), 0, _initCalldata())
                ))
        );
        _execAsOwner_Revert(
            safe,
            address(multiSendCallOnly),
            0,
            bundle,
            Enum.Operation.DelegateCall,
            Lockdown.InvalidFallbackHandler.selector
        );
    }

    /// F-03 step 3/4. The two escapes from A's binding both die inside
    /// `B.initialize` (`src/Lockdown.sol:103-133`), which requires the handler to
    /// be bound to B: (a) omit the handler swap, (b) swap to a handler bound to
    /// A (which A happily accepts).
    /// Verdict: CONFIRMED - no single fallback handler can satisfy A's pre-hook
    /// (`LOCKDOWN() == A`) and B's initialiser (`LOCKDOWN() == B`) in one
    /// transaction. Atomic migration is impossible by construction, not by
    /// oversight.
    function test_confirmed_noHandlerSatisfiesBothAAndBInOneTransaction() public {
        Safe safe = _createConfigureAndInitialise(135);
        (LockdownTimelock b,) = _deployNewSingleton();

        // (a) no handler swap at all
        bytes memory noSwap = abi.encodeCall(
            MultiSendCallOnly.multiSend,
            (bytes.concat(
                    _swapGuardsItems(safe, b), _multiSendItem(Enum.Operation.Call, address(b), 0, _initCalldata())
                ))
        );
        _execAsOwner_Revert(
            safe,
            address(multiSendCallOnly),
            0,
            noSwap,
            Enum.Operation.DelegateCall,
            Lockdown.InvalidFallbackHandler.selector
        );

        // (b) swap to a *fresh* handler still bound to A: A's pre-hook accepts it,
        //     B's initialiser rejects it. Same selector, different check.
        LockdownFallbackHandler handlerBoundToA = new LockdownFallbackHandler(guard);
        bytes memory boundToA = abi.encodeCall(
            MultiSendCallOnly.multiSend,
            (bytes.concat(
                    _swapGuardsItems(safe, b),
                    _multiSendItem(
                        Enum.Operation.Call,
                        address(safe),
                        0,
                        abi.encodeCall(IFallbackManager.setFallbackHandler, (address(handlerBoundToA)))
                    ),
                    _multiSendItem(Enum.Operation.Call, address(b), 0, _initCalldata())
                ))
        );
        _execAsOwner_Revert(
            safe,
            address(multiSendCallOnly),
            0,
            boundToA,
            Enum.Operation.DelegateCall,
            Lockdown.InvalidFallbackHandler.selector
        );

        // Nothing was written: the Safe is still fully on A.
        assertEq(_slot(safe, GUARD_SLOT), address(guard), "still on A");
        assertEq(_slot(safe, FALLBACK_SLOT), address(handler), "handler untouched");
    }

    /// F-03 step 4. Minimum-cost correct migration: TWO owner transactions.
    /// tx1 (checked by A) may only move the two guard slots; tx2 (checked by B,
    /// Uninitialised -> fail-open) does the handler swap plus `B.initialize`.
    /// Verdict: LIMITATION - the window between tx1 and tx2 is unavoidable. In
    /// it, owner and module execution are ungoverned; only the ERC-1271 freeze
    /// (still H_A/A) survives. A's config also stays live and triggerable
    /// forever afterwards.
    function test_limitation_migrationNeedsTwoTransactionsWithAFailOpenWindow() public {
        Safe safe = _createConfigureAndInitialise(136);
        (LockdownTimelock b, LockdownFallbackHandler handlerB) = _deployNewSingleton();

        // tx1: guards only (everything else is refused by A - see the tests above).
        _execAsOwner(safe, address(multiSendCallOnly), 0, _swapGuardsBundle(safe, b), Enum.Operation.DelegateCall);

        // tx2: handler + initialise, atomically, checked by the fail-open B.
        bytes memory finish = abi.encodeCall(
            MultiSendCallOnly.multiSend,
            (bytes.concat(
                    _multiSendItem(
                        Enum.Operation.Call,
                        address(safe),
                        0,
                        abi.encodeCall(IFallbackManager.setFallbackHandler, (address(handlerB)))
                    ),
                    _multiSendItem(Enum.Operation.Call, address(b), 0, _initCalldata())
                ))
        );
        _execAsOwner(safe, address(multiSendCallOnly), 0, finish, Enum.Operation.DelegateCall);

        (StateMachine.State stateB,) = b.getState(address(safe));
        assertEq(uint256(stateB), uint256(StateMachine.State.Normal), "migrated to B in two transactions");
        assertEq(_slot(safe, FALLBACK_SLOT), address(handlerB), "handler -> H_B");

        // B now really governs both paths.
        b.triggerLockdown(
            address(safe),
            keccak256("wrench"),
            abi.encodePacked(panicKey),
            _signTriggerFor(b, safe, PANIC_PK, keccak256("wrench"))
        );
        _execAsOwner_Revert(
            safe,
            address(counter),
            0,
            abi.encodeCall(Counter.mark, ()),
            Enum.Operation.Call,
            Lockdown.LockedDown.selector
        );
        _moduleCall_Revert(
            module,
            safe,
            address(counter),
            0,
            abi.encodeCall(Counter.mark, ()),
            Enum.Operation.Call,
            Lockdown.LockedDown.selector
        );

        // Residual: A keeps a live config and a live panic identity for this Safe.
        (StateMachine.State stateA,) = guard.getState(address(safe));
        assertEq(uint256(stateA), uint256(StateMachine.State.Normal), "A config never retired");
        assertEq(guard.getLockdownSignerCount(address(safe)), 1, "A signer never revoked by migration");
    }

    /// Lead: can the handler slot be cleared while the guard is installed?
    /// Verdict: no - and the operator does NOT get `InvalidFallbackHandler`.
    /// The `.LOCKDOWN()` staticcall to address(0) fails the extcodesize check
    /// first, so the revert carries no selector to diagnose from. A limitation
    /// for operator diagnosis only.
    /// @dev Asserts the ABSENCE of the selector rather than an exact revert
    ///      length. The length is a property of the test harness, not of the
    ///      contract: forge returns empty data at default verbosity and a
    ///      160-byte decoded error at -vvv, which is what CI runs.
    function test_limitation_setFallbackHandlerZeroRevertsWithoutInvalidFallbackHandlerSelector() public {
        Safe safe = _createConfigureAndInitialise(132);
        bytes memory data = abi.encodeCall(IFallbackManager.setFallbackHandler, (address(0)));
        bytes memory sig = _signTx(safe, OWNER_PK, address(safe), 0, data, Enum.Operation.Call);

        try safe.execTransaction(
            address(safe), 0, data, Enum.Operation.Call, 0, 0, 0, address(0), payable(address(0)), sig
        ) returns (
            bool
        ) {
            revert("setFallbackHandler(0) should have reverted");
        } catch (bytes memory err) {
            if (err.length >= 4) {
                assertTrue(
                    bytes4(err) != Lockdown.InvalidFallbackHandler.selector,
                    "no InvalidFallbackHandler selector for the operator to read"
                );
            }
        }
        assertEq(_slot(safe, FALLBACK_SLOT), address(handler), "handler slot pinned while the guard is installed");
    }

    function _swapGuardsItems(Safe safe, LockdownTimelock b) private pure returns (bytes memory) {
        return bytes.concat(
            _multiSendItem(Enum.Operation.Call, address(safe), 0, abi.encodeCall(IGuardManager.setGuard, (address(b)))),
            _multiSendItem(
                Enum.Operation.Call, address(safe), 0, abi.encodeCall(IModuleManager.setModuleGuard, (address(b)))
            )
        );
    }

    function _swapGuardsBundle(Safe safe, LockdownTimelock b) private pure returns (bytes memory) {
        return abi.encodeCall(MultiSendCallOnly.multiSend, (_swapGuardsItems(safe, b)));
    }
}

contract SafeHookOrderingLifecyclePoC is LifecycleBase {
    // ------------------------------------------------------------------
    // 5. Hook ordering / nonce()-1
    // ------------------------------------------------------------------

    /// Lead: what does the post-hook see when the transaction it is checking
    /// removed the guard slot?
    /// Verdict: REFUTED as a bug. Safe v1.5.0 caches `getGuard()` before the
    /// pre-hook, so the OLD guard still receives `checkAfterExecution` and the
    /// timelock ticket is consumed exactly once even though the Safe is now
    /// unguarded.
    function test_refuted_postHookRunsOnCachedGuardWhenTxRemovesGuardSlot() public {
        Safe safe = _createConfigureAndInitialise(140);
        _enableTimelock(safe, 24 hours);

        uint256 nonce = safe.nonce();
        bytes memory data = abi.encodeCall(IGuardManager.setGuard, (address(0)));
        bytes memory sig = _signAt(safe, OWNER_PK, address(safe), 0, data, Enum.Operation.Call, nonce);
        bytes32 txHash = _safeTxHash(safe, address(safe), 0, data, Enum.Operation.Call, nonce);

        guard.scheduleTransaction(address(safe), nonce, _params(address(safe), 0, data, Enum.Operation.Call), sig);
        vm.warp(block.timestamp + 24 hours + 1);

        assertTrue(
            safe.execTransaction(
                address(safe), 0, data, Enum.Operation.Call, 0, 0, 0, address(0), payable(address(0)), sig
            ),
            "uninstall executes"
        );
        assertEq(_slot(safe, GUARD_SLOT), address(0), "guard removed by the checked transaction");
        assertEq(guard.getTransactionExecutableAt(address(safe), txHash), 0, "post-hook still consumed the ticket");
    }

    /// Lead: the timelock pre-hook recomputes the hash from `nonce() - 1`.
    /// Does a nested `execTransaction` (a self-call inside the checked payload)
    /// break that assumption?
    /// Verdict: REFUTED. Each nesting level increments the nonce before its own
    /// pre-hook, so both tickets verify and both are consumed exactly once.
    function test_refuted_nonceMinusOneHoldsUnderNestedExecTransaction() public {
        Safe safe = _createConfigureAndInitialise(141);
        _enableTimelock(safe, 24 hours);

        uint256 outerNonce = safe.nonce();
        uint256 innerNonce = outerNonce + 1;

        bytes memory innerData = abi.encodeCall(Counter.mark, ());
        bytes memory innerSig = _signAt(safe, OWNER_PK, address(counter), 0, innerData, Enum.Operation.Call, innerNonce);
        bytes32 innerHash = _safeTxHash(safe, address(counter), 0, innerData, Enum.Operation.Call, innerNonce);

        bytes memory outerData = abi.encodeWithSelector(
            ISafe.execTransaction.selector,
            address(counter),
            uint256(0),
            innerData,
            Enum.Operation.Call,
            uint256(0),
            uint256(0),
            uint256(0),
            address(0),
            address(0),
            innerSig
        );
        bytes memory outerSig = _signAt(safe, OWNER_PK, address(safe), 0, outerData, Enum.Operation.Call, outerNonce);
        bytes32 outerHash = _safeTxHash(safe, address(safe), 0, outerData, Enum.Operation.Call, outerNonce);

        guard.scheduleTransaction(
            address(safe), outerNonce, _params(address(safe), 0, outerData, Enum.Operation.Call), outerSig
        );
        guard.scheduleTransaction(
            address(safe), innerNonce, _params(address(counter), 0, innerData, Enum.Operation.Call), innerSig
        );
        vm.warp(block.timestamp + 24 hours + 1);

        assertTrue(
            safe.execTransaction(
                address(safe), 0, outerData, Enum.Operation.Call, 0, 0, 0, address(0), payable(address(0)), outerSig
            ),
            "nested execution"
        );
        assertEq(counter.calls(), 1, "inner transaction ran once");
        assertEq(safe.nonce(), innerNonce + 1, "both nonces consumed");
        assertEq(guard.getTransactionExecutableAt(address(safe), innerHash), 0, "inner ticket consumed");
        assertEq(guard.getTransactionExecutableAt(address(safe), outerHash), 0, "outer ticket consumed");
    }

    // ------------------------------------------------------------------
    // 6. Module entry points
    // ------------------------------------------------------------------

    /// Verdict: CONFIRMED. `execTransactionFromModuleReturnData` shares
    /// `preModuleExecution`, so it is gated identically to
    /// `execTransactionFromModule` in every state.
    function test_confirmed_moduleReturnDataPathGuardedIdentically() public {
        Safe safe = _createConfigureAndInitialise(150);

        vm.prank(module);
        (bool ok,) = safe.execTransactionFromModuleReturnData(
            address(counter), 0, abi.encodeCall(Counter.mark, ()), Enum.Operation.Call
        );
        assertTrue(ok, "normal state passes");

        _returnDataRevert(
            safe,
            address(safe),
            abi.encodeCall(IGuardManager.setGuard, (address(0))),
            Lockdown.ModuleSafeSelfCallDenied.selector
        );
        _returnDataRevert(safe, address(guard), _initCalldata(), Lockdown.ModuleCallToSingletonDenied.selector);

        _triggerLockdown(safe, keccak256("wrench"));
        _returnDataRevert(safe, address(counter), abi.encodeCall(Counter.mark, ()), Lockdown.LockedDown.selector);

        vm.warp(block.timestamp + 48 hours + 1);
        _returnDataRevert(safe, address(counter), abi.encodeCall(Counter.mark, ()), Lockdown.RecoveryActive.selector);

        vm.warp(block.timestamp + 4 hours + 1); // auto-resume
        vm.prank(module);
        (ok,) = safe.execTransactionFromModuleReturnData(
            address(counter), 0, abi.encodeCall(Counter.mark, ()), Enum.Operation.Call
        );
        assertTrue(ok, "auto-resumed");
        assertEq(counter.calls(), 2, "exactly the two permitted module calls landed");
    }

    // ------------------------------------------------------------------
    // 7. Threshold-N Safe
    // ------------------------------------------------------------------

    /// Verdict: CONFIRMED - the full incident lifecycle behaves identically on a
    /// 2-of-2 Safe: freeze, ERC-1271 freeze, then a 2-of-2 recovery `swapOwner`.
    function test_confirmed_thresholdTwoSafeLockdownRecoveryAndErc1271() public {
        Safe safe = _create2of2(160);
        // Opt in to ERC-1271 (SPEC_V1 H.27; disabled by default) with a 2-of-2 self-call.
        _exec2(safe, address(guard), abi.encodeCall(Lockdown.setErc1271Allowed, (true)), Enum.Operation.Call);

        bytes32 hash = keccak256("order");
        assertTrue(
            SignatureChecker.isValidERC1271SignatureNow(address(safe), hash, _signMessage2(safe, hash)),
            "2-of-2 ERC-1271 valid in Normal"
        );

        _triggerLockdown(safe, keccak256("wrench"));
        _exec2Revert(
            safe, address(counter), abi.encodeCall(Counter.mark, ()), Enum.Operation.Call, Lockdown.LockedDown.selector
        );
        bytes memory frozenSig = _signMessage2(safe, hash);
        vm.expectRevert(LockdownFallbackHandler.SignaturesFrozenDuringLockdown.selector);
        IERC1271(address(safe)).isValidSignature(hash, frozenSig);

        vm.warp(block.timestamp + 48 hours + 1); // Recovering
        _exec2Revert(
            safe,
            address(counter),
            abi.encodeCall(Counter.mark, ()),
            Enum.Operation.Call,
            Lockdown.RecoveryActive.selector
        );

        address[] memory owners = safe.getOwners();
        _exec2(
            safe,
            address(safe),
            abi.encodeCall(IOwnerManager.swapOwner, (SENTINEL, owners[0], recovery)),
            Enum.Operation.Call
        );
        assertTrue(safe.isOwner(recovery), "recovery owner swapped in under a 2-of-2 threshold");
        assertEq(safe.getThreshold(), 2, "threshold untouched by recovery");
    }

    // ------------------------------------------------------------------
    // 8. Cross-Safe isolation
    // ------------------------------------------------------------------

    /// Verdict: REFUTED as a risk. Two Safes sharing one singleton, one handler
    /// and one panic identity are fully isolated: the burn, the incident state
    /// and the ERC-1271 freeze are all per-Safe.
    function test_refuted_crossSafeIsolationForSharedSingletonAndHandler() public {
        Safe a = _createConfigureAndInitialise(170);
        Safe b = _createConfigureAndInitialise(171);
        // Both opt in to ERC-1271 (SPEC_V1 H.27) so the freeze is the only difference.
        _allowErc1271(a);
        _allowErc1271(b);

        _triggerLockdown(a, keccak256("wrench"));

        assertEq(guard.getLockdownSignerCount(address(a)), 0, "A's identity burnt");
        assertEq(guard.getLockdownSignerCount(address(b)), 1, "B's identical identity untouched");
        (StateMachine.State stateB,) = guard.getState(address(b));
        assertEq(uint256(stateB), uint256(StateMachine.State.Normal), "B unaffected");

        _execAsOwner(b, address(counter), 0, abi.encodeCall(Counter.mark, ()), Enum.Operation.Call);
        _moduleCall(module, b, address(counter), 0, abi.encodeCall(Counter.mark, ()), Enum.Operation.Call);
        assertEq(counter.calls(), 2, "B keeps executing on both paths");

        bytes32 hash = keccak256("order");
        assertTrue(
            SignatureChecker.isValidERC1271SignatureNow(address(b), hash, _signMessage(b, OWNER_PK, hash)),
            "B's ERC-1271 not frozen"
        );
        bytes memory frozenSig = _signMessage(a, OWNER_PK, hash);
        vm.expectRevert(LockdownFallbackHandler.SignaturesFrozenDuringLockdown.selector);
        IERC1271(address(a)).isValidSignature(hash, frozenSig);
    }
}
