// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {TestEnvironment} from "../TestEnvironment.sol";

import {Safe, Enum} from "@safe-global/safe-smart-account/Safe.sol";
import {SafeProxy} from "@safe-global/safe-smart-account/proxies/SafeProxy.sol";
import {SafeProxyFactory} from "@safe-global/safe-smart-account/proxies/SafeProxyFactory.sol";
import {MultiSendCallOnly} from "@safe-global/safe-smart-account/libraries/MultiSendCallOnly.sol";
import {IGuardManager} from "@safe-global/safe-smart-account/interfaces/IGuardManager.sol";
import {IModuleManager} from "@safe-global/safe-smart-account/interfaces/IModuleManager.sol";
import {IFallbackManager} from "@safe-global/safe-smart-account/interfaces/IFallbackManager.sol";

import {SignatureChecker, IERC1271} from "@openzeppelin/contracts/utils/cryptography/SignatureChecker.sol";

import {Lockdown} from "../../src/Lockdown.sol";
import {LockdownTimelock} from "../../src/LockdownTimelock.sol";
import {LockdownFallbackHandler} from "../../src/handlers/LockdownFallbackHandler.sol";
import {Timelock} from "../../src/base/Timelock.sol";

/// @title Module-path + timelock integration against a real Safe v1.5.0.
/// @notice Complements `SafeIntegration.t.sol` (owner-path) by driving the two
///         hardest subsystems over a genuine Safe deployment:
///         - the module guard (`checkModuleTransaction`) via a real enabled
///           module calling `execTransactionFromModule`;
///         - the owner-path timelock (schedule / wait / execute and the HSM
///           bypass) over a real signed `execTransaction`, validating the
///           `nonce() - 1` ticket wiring against Safe v1.5.0 EIP-712.
contract SafeIntegrationTest is TestEnvironment {
    Safe internal safe;

    // Other addresses
    address internal constant TARGET = address(0xBEEF);
    address internal constant HSM = address(0x4584);

    //--------------------------------------------------------------------
    // Setup
    //--------------------------------------------------------------------
    function setUp() public override {
        super.setUp();

        // Create Safes and install the guard as BOTH the transaction guard and
        // the module guard, enable the relay module, then initialise the per-
        // Safe config. All via real signed owner self-transactions.
        safe = _createSafe(0);

        // Configure the lockdown guard on the Safe via a single operation.
        address[] memory recoveryOwners = new address[](1);
        recoveryOwners[0] = recovery;
        bytes[] memory signers = new bytes[](1);
        signers[0] = abi.encodePacked(panicKey);

        _execAsOwner(
            safe,
            address(multiSendCallOnly),
            0,
            abi.encodeCall(
                MultiSendCallOnly.multiSend,
                (bytes.concat(
                        _multiSendItem(
                            Enum.Operation.Call,
                            address(safe),
                            0,
                            abi.encodeCall(IGuardManager.setGuard, (address(guard)))
                        ),
                        _multiSendItem(
                            Enum.Operation.Call,
                            address(safe),
                            0,
                            abi.encodeCall(IModuleManager.setModuleGuard, (address(guard)))
                        ),
                        _multiSendItem(
                            Enum.Operation.Call,
                            address(safe),
                            0,
                            abi.encodeCall(IFallbackManager.setFallbackHandler, (address(handler)))
                        ),
                        _multiSendItem(
                            Enum.Operation.Call,
                            address(guard),
                            0,
                            abi.encodeCall(Lockdown.initialize, (48 hours, 4 hours, recoveryOwners, signers))
                        )
                    ))
            ),
            Enum.Operation.DelegateCall
        );

        // Enable module for testing (not part of the production setup)
        _enableModule(safe, module);
    }

    //--------------------------------------------------------------------
    // Tests
    //--------------------------------------------------------------------

    function test_setup() public {
        assertEq(
            address(
                uint160(
                    uint256(vm.load(address(safe), 0x4a204f620c8c5ccdca3fd54d003badd85ba500436a431f0cbda4f558c93c34c8))
                )
            ),
            address(guard),
            "guard installed"
        );
        assertEq(
            address(
                uint160(
                    uint256(vm.load(address(safe), 0xb104e0b93118902c651344349b610029d694cfdec91c589c91ebafbcd0289947))
                )
            ),
            address(guard),
            "guard installed"
        );
        assertEq(
            address(
                uint160(
                    uint256(vm.load(address(safe), 0x6c9a6c4a39284e37ed1cf53d337577d14212a4870fb976a4366c693b939918d5))
                )
            ),
            address(handler),
            "fallback handler installed"
        );
        assertEq(guard.getLockdownSignerCount(address(safe)), 1, "panic signer registered");
    }

    // -------------------------------------------------------------------
    // Owner path
    // -------------------------------------------------------------------

    function test_module_normal_allowsTransaction() public {
        uint256 nonceBefore = safe.nonce();
        _execAsOwner(safe, TARGET, 0, "", Enum.Operation.Call);
        assertEq(safe.nonce(), nonceBefore + 1, "nonce advanced through guard");
    }

    function test_module_lockdown_blocksTransaction() public {
        _triggerLockdown(safe, keccak256("wrench"));
        assertTrue(guard.getLockdownUntil(address(safe)) > block.timestamp, "locked down");
        bytes memory ownerSig = _signTx(safe, OWNER_PK, TARGET, 0, "", Enum.Operation.Call);
        vm.expectRevert(Lockdown.LockedDown.selector);
        safe.execTransaction(TARGET, 0, "", Enum.Operation.Call, 0, 0, 0, address(0), payable(address(0)), ownerSig);
    }

    function test_module_recovery_blocksTransaction() public {
        _triggerLockdown(safe, keccak256("wrench"));
        vm.warp(block.timestamp + 48 hours + 1);
        assertTrue(guard.getLockdownUntil(address(safe)) < block.timestamp, "locked down");
        bytes memory ownerSig = _signTx(safe, OWNER_PK, TARGET, 0, "", Enum.Operation.Call);
        vm.expectRevert(Lockdown.RecoveryActive.selector);
        safe.execTransaction(TARGET, 0, "", Enum.Operation.Call, 0, 0, 0, address(0), payable(address(0)), ownerSig);
    }

    // -------------------------------------------------------------------
    // Owner path timelock
    // -------------------------------------------------------------------

    function test_timelock_schedule_wait_execute() public {
        _enableTimelock(safe, 24 hours);

        uint256 nonce = safe.nonce();
        bytes32 targetHash =
            safe.getTransactionHash(TARGET, 0, "", Enum.Operation.Call, 0, 0, 0, address(0), address(0), nonce);
        bytes memory signatures = _signTx(safe, OWNER_PK, TARGET, 0, "", Enum.Operation.Call);
        Timelock.ExecTransactionParams memory params = _ownerParams(TARGET, 0, "", Enum.Operation.Call);

        // Unscheduled => Revert
        vm.expectRevert(Timelock.TicketNotFound.selector);
        safe.execTransaction(TARGET, 0, "", Enum.Operation.Call, 0, 0, 0, address(0), payable(address(0)), signatures);

        guard.scheduleTransaction(address(safe), nonce, params, signatures);
        assertEq(
            guard.getTransactionExecutableAt(address(safe), targetHash), block.timestamp + 24 hours, "ticket scheduled"
        );

        // Scheduled + Before the delay elapses => Revert
        vm.expectRevert(Timelock.TimelockNotElapsed.selector);
        safe.execTransaction(TARGET, 0, "", Enum.Operation.Call, 0, 0, 0, address(0), payable(address(0)), signatures);

        // wait
        vm.warp(block.timestamp + 24 hours + 1);

        // Scheduled + After the delay elapses => Executes through normal Safe UX.
        assertTrue(
            safe.execTransaction(
                TARGET, 0, "", Enum.Operation.Call, 0, 0, 0, address(0), payable(address(0)), signatures
            ),
            "scheduled tx executes"
        );
        assertEq(guard.getTransactionExecutableAt(address(safe), targetHash), 0, "ticket consumed");
    }

    function test_timelock_schedule_preservesSafeNonceAndUsesNormalSafeExecution() public {
        _enableTimelock(safe, 24 hours);

        uint256 nonce = safe.nonce();
        bytes memory signatures = _signTx(safe, OWNER_PK, TARGET, 0, "", Enum.Operation.Call);
        bytes32 targetHash =
            safe.getTransactionHash(TARGET, 0, "", Enum.Operation.Call, 0, 0, 0, address(0), address(0), nonce);

        Timelock.ExecTransactionParams memory params = Timelock.ExecTransactionParams({
            to: TARGET,
            value: 0,
            data: "",
            operation: Enum.Operation.Call,
            safeTxGas: 0,
            baseGas: 0,
            gasPrice: 0,
            gasToken: address(0),
            refundReceiver: payable(address(0))
        });

        vm.expectRevert(Timelock.TicketNotFound.selector);
        safe.execTransaction(TARGET, 0, "", Enum.Operation.Call, 0, 0, 0, address(0), payable(address(0)), signatures);
        assertEq(safe.nonce(), nonce, "failed execution did not consume nonce");

        vm.prank(address(0x515C));
        guard.scheduleTransaction(address(safe), nonce, params, signatures);
        assertEq(safe.nonce(), nonce, "schedule does not consume Safe nonce");
        assertEq(guard.getTransactionExecutableAt(address(safe), targetHash), block.timestamp + 24 hours, "scheduled");

        vm.expectRevert(Timelock.TimelockNotElapsed.selector);
        safe.execTransaction(TARGET, 0, "", Enum.Operation.Call, 0, 0, 0, address(0), payable(address(0)), signatures);
        assertEq(safe.nonce(), nonce, "early execution did not consume nonce");

        vm.warp(block.timestamp + 24 hours + 1);
        assertTrue(
            safe.execTransaction(
                TARGET, 0, "", Enum.Operation.Call, 0, 0, 0, address(0), payable(address(0)), signatures
            ),
            "normal Safe execution succeeds after delay"
        );
        assertEq(safe.nonce(), nonce + 1, "target tx consumed nonce");
        assertEq(guard.getTransactionExecutableAt(address(safe), targetHash), 0, "ticket consumed");

        vm.expectRevert(Timelock.StaleSafeNonce.selector);
        guard.scheduleTransaction(address(safe), nonce, params, signatures);
        assertEq(guard.getTransactionExecutableAt(address(safe), targetHash), 0, "stale signature did not reschedule");
    }

    function test_timelock_schedule_rejectsApprovedHashShortcutWithoutPreapproval() public {
        _enableTimelock(safe, 24 hours);

        uint256 nonce = safe.nonce();
        bytes32 targetHash =
            safe.getTransactionHash(TARGET, 0, "", Enum.Operation.Call, 0, 0, 0, address(0), address(0), nonce);
        bytes memory approvedHashSignature =
            abi.encodePacked(bytes32(uint256(uint160(owner))), bytes32(0), bytes1(uint8(1)));

        Timelock.ExecTransactionParams memory params = Timelock.ExecTransactionParams({
            to: TARGET,
            value: 0,
            data: "",
            operation: Enum.Operation.Call,
            safeTxGas: 0,
            baseGas: 0,
            gasPrice: 0,
            gasToken: address(0),
            refundReceiver: payable(address(0))
        });

        vm.expectRevert();
        guard.scheduleTransaction(address(safe), nonce, params, approvedHashSignature);
        assertEq(guard.getTransactionExecutableAt(address(safe), targetHash), 0, "approved-hash shortcut rejected");
    }

    function test_timelock_schedule_acceptsApprovedHashAfterPreapproval() public {
        _enableTimelock(safe, 24 hours);

        uint256 nonce = safe.nonce();
        bytes32 targetHash =
            safe.getTransactionHash(TARGET, 0, "", Enum.Operation.Call, 0, 0, 0, address(0), address(0), nonce);
        bytes memory approvedHashSignature =
            abi.encodePacked(bytes32(uint256(uint160(owner))), bytes32(0), bytes1(uint8(1)));
        Timelock.ExecTransactionParams memory params = _ownerParams(TARGET, 0, "", Enum.Operation.Call);

        vm.prank(owner);
        safe.approveHash(targetHash);

        guard.scheduleTransaction(address(safe), nonce, params, approvedHashSignature);
        assertEq(guard.getTransactionExecutableAt(address(safe), targetHash), block.timestamp + 24 hours, "scheduled");

        vm.warp(block.timestamp + 24 hours + 1);
        assertTrue(
            safe.execTransaction(
                TARGET, 0, "", Enum.Operation.Call, 0, 0, 0, address(0), payable(address(0)), approvedHashSignature
            ),
            "approved-hash signature executes after delay"
        );
        assertEq(guard.getTransactionExecutableAt(address(safe), targetHash), 0, "ticket consumed");
    }

    function test_timelock_schedule_futureNonce_endToEnd() public {
        _enableTimelock(safe, 24 hours);

        uint256 currentNonce = safe.nonce();
        uint256 futureNonce = currentNonce + 1;
        bytes memory fillerData = hex"f111";
        bytes memory targetData = hex"f222";

        bytes memory fillerSig =
            _signTxAtNonce(safe, OWNER_PK, TARGET, 0, fillerData, Enum.Operation.Call, currentNonce);
        bytes memory targetSig = _signTxAtNonce(safe, OWNER_PK, TARGET, 0, targetData, Enum.Operation.Call, futureNonce);
        bytes32 fillerHash = safe.getTransactionHash(
            TARGET, 0, fillerData, Enum.Operation.Call, 0, 0, 0, address(0), address(0), currentNonce
        );
        bytes32 targetHash = safe.getTransactionHash(
            TARGET, 0, targetData, Enum.Operation.Call, 0, 0, 0, address(0), address(0), futureNonce
        );

        guard.scheduleTransaction(
            address(safe), currentNonce, _ownerParams(TARGET, 0, fillerData, Enum.Operation.Call), fillerSig
        );
        guard.scheduleTransaction(
            address(safe), futureNonce, _ownerParams(TARGET, 0, targetData, Enum.Operation.Call), targetSig
        );
        assertEq(safe.nonce(), currentNonce, "scheduling preserves nonce");

        vm.warp(block.timestamp + 24 hours + 1);

        assertTrue(
            safe.execTransaction(
                TARGET, 0, fillerData, Enum.Operation.Call, 0, 0, 0, address(0), payable(address(0)), fillerSig
            ),
            "filler executes"
        );
        assertEq(safe.nonce(), futureNonce, "future nonce reached");
        assertEq(guard.getTransactionExecutableAt(address(safe), fillerHash), 0, "filler consumed");

        assertTrue(
            safe.execTransaction(
                TARGET, 0, targetData, Enum.Operation.Call, 0, 0, 0, address(0), payable(address(0)), targetSig
            ),
            "future tx executes"
        );
        assertEq(guard.getTransactionExecutableAt(address(safe), targetHash), 0, "future ticket consumed");
    }

    function test_timelock_schedule_multiOwnerThreshold() public {
        Safe multiOwnerSafe = _createTwoOwnerSafe(99);

        vm.startPrank(address(multiOwnerSafe));
        multiOwnerSafe.setGuard(address(guard));
        multiOwnerSafe.setModuleGuard(address(guard));
        multiOwnerSafe.setFallbackHandler(address(handler));
        address[] memory recoveryOwners = new address[](1);
        recoveryOwners[0] = recovery;
        guard.initialize(48 hours, 4 hours, recoveryOwners, new bytes[](0));
        guard.setTimelockDelay(24 hours);
        vm.stopPrank();

        uint256 nonce = multiOwnerSafe.nonce();
        bytes memory data = hex"2f2f";
        Timelock.ExecTransactionParams memory params = _ownerParams(TARGET, 0, data, Enum.Operation.Call);
        bytes memory ownerSig = _signTxAtNonce(multiOwnerSafe, OWNER_PK, TARGET, 0, data, Enum.Operation.Call, nonce);
        bytes memory otherSig = _signTxAtNonce(multiOwnerSafe, OTHER_PK, TARGET, 0, data, Enum.Operation.Call, nonce);
        bytes memory thresholdSigs = _packSortedSignatures(ownerSig, otherSig);

        vm.expectRevert();
        guard.scheduleTransaction(address(multiOwnerSafe), nonce, params, ownerSig);

        guard.scheduleTransaction(address(multiOwnerSafe), nonce, params, thresholdSigs);
        vm.warp(block.timestamp + 24 hours + 1);

        assertTrue(
            multiOwnerSafe.execTransaction(
                TARGET, 0, data, Enum.Operation.Call, 0, 0, 0, address(0), payable(address(0)), thresholdSigs
            ),
            "2-of-2 Safe tx executes after delay"
        );
    }

    function test_timelock_bypasser_executesWithoutWait() public {
        // Register the HSM bypasser BEFORE enabling the timelock, so its own
        // owner-path self-call is not itself timelocked.
        _execAsOwner(
            safe,
            address(guard),
            0,
            abi.encodeCall(LockdownTimelock.setTimelockBypasser, (HSM, true)),
            Enum.Operation.Call
        );
        _enableTimelock(safe, 24 hours);

        // The bypasser writes executableAt = now directly; no prior schedule and
        // no wait. The target is the next owner tx at the current nonce.
        bytes32 targetHash =
            safe.getTransactionHash(TARGET, 0, "", Enum.Operation.Call, 0, 0, 0, address(0), address(0), safe.nonce());
        vm.prank(HSM);
        guard.bypassTimelock(address(safe), targetHash);

        _execAsOwner(safe, TARGET, 0, "", Enum.Operation.Call);
    }

    function test_timelock_bypasser_executesWithoutWait_noBypassCall() public {
        // Register the HSM bypasser BEFORE enabling the timelock, so its own
        // owner-path self-call is not itself timelocked.
        _execAsOwner(
            safe,
            address(guard),
            0,
            abi.encodeCall(LockdownTimelock.setTimelockBypasser, (HSM, true)),
            Enum.Operation.Call
        );
        _enableTimelock(safe, 24 hours);

        // The bypasser relays the Safe call directly, so no executableAt write,
        // prior schedule, or wait is needed.
        bytes memory signature = _signTx(safe, OWNER_PK, TARGET, 0, "", Enum.Operation.Call);
        vm.prank(HSM);
        safe.execTransaction(TARGET, 0, "", Enum.Operation.Call, 0, 0, 0, address(0), payable(address(0)), signature);
    }

    // -------------------------------------------------------------------
    // Module path
    // -------------------------------------------------------------------

    function test_module_normal_allowsModuleTransaction() public {
        _moduleCall(module, safe, TARGET, 0, "", Enum.Operation.Call);
    }

    function test_module_lockdown_blocksModuleTransaction() public {
        _triggerLockdown(safe, keccak256("wrench"));
        _moduleCall_Revert(module, safe, TARGET, 0, "", Enum.Operation.Call, Lockdown.LockedDown.selector);
    }

    function test_module_recovery_blocksModuleTransaction() public {
        _triggerLockdown(safe, keccak256("wrench"));
        vm.warp(block.timestamp + 48 hours + 1);
        _moduleCall_Revert(module, safe, TARGET, 0, "", Enum.Operation.Call, Lockdown.RecoveryActive.selector);
    }

    function test_module_delegateCall_rejected() public {
        _moduleCall_Revert(
            module, safe, TARGET, 0, "", Enum.Operation.DelegateCall, Lockdown.DelegateCallDenied.selector
        );
    }

    function test_module_callToSingleton_denied() public {
        // A module can never reach the singleton, in any state.
        _moduleCall_Revert(
            module, safe, address(guard), 0, "", Enum.Operation.Call, Lockdown.ModuleCallToSingletonDenied.selector
        );
    }

    // -------------------------------------------------------------------
    // Module path timelock
    // -------------------------------------------------------------------

    function test_timelock_module_schedule_wait_execute() public {
        _enableTimelock(safe, 24 hours);

        // Unscheduled => Revert
        _moduleCall_Revert(module, safe, TARGET, 0, "", Enum.Operation.Call, Timelock.TicketNotFound.selector);

        // Schedule (consumes nonce, so we must regenerate the signature)
        _execAsOwner(
            safe,
            address(guard),
            0,
            abi.encodeCall(LockdownTimelock.scheduleModuleTransaction, (module, TARGET, 0, "", Enum.Operation.Call)),
            Enum.Operation.Call
        );

        bytes32 moduleHash = guard.getModuleTransactionHash(address(safe), module, TARGET, 0, "", Enum.Operation.Call);

        assertEq(
            guard.getModuleTransactionExecutableAt(address(safe), moduleHash),
            block.timestamp + 24 hours,
            "ticket consumed"
        );

        // Scheduled + Before the delay elapses => Revert
        _moduleCall_Revert(module, safe, TARGET, 0, "", Enum.Operation.Call, Timelock.TimelockNotElapsed.selector);

        // wait
        vm.warp(block.timestamp + 24 hours + 1);

        // Scheduled + After the delay elapses => Executes
        _moduleCall(module, safe, TARGET, 0, "", Enum.Operation.Call);
        assertEq(guard.getModuleTransactionExecutableAt(address(safe), moduleHash), 0, "ticket consumed");
    }

    // -------------------------------------------------------------------
    // Fallback handler
    // -------------------------------------------------------------------

    // -------------------------------------------------------------------
    // Normal state: handler behaves like CompatibilityFallbackHandler
    // -------------------------------------------------------------------

    function test_normal_validSignatureReturnsMagic() public view {
        bytes32 hash = keccak256("authorise something");
        bytes memory signature = _signMessage(safe, OWNER_PK, hash);
        assertTrue(
            SignatureChecker.isValidERC1271SignatureNow(address(safe), hash, signature),
            "valid ERC-1271 signature accepted in Normal"
        );
    }

    function test_normal_wrongSignerReverts() public {
        bytes32 hash = keccak256("authorise something");
        bytes memory signature = _signMessage(safe, PANIC_PK, hash); // not an owner
        vm.expectRevert();
        IERC1271(address(safe)).isValidSignature(hash, signature);
    }

    function test_fallbackHandler_getMessageHashUsesCallingSafe() public {
        bytes memory message = "operator-message";
        vm.prank(address(safe));
        bytes32 viaCaller = handler.getMessageHash(message);
        assertEq(viaCaller, handler.getMessageHashForSafe(safe, message), "caller-safe hash parity");
    }

    function test_fallbackHandler_getModulesReturnsEnabledModule() public {
        vm.prank(address(safe));
        address[] memory modules = handler.getModules();
        assertEq(modules.length, 1, "one enabled test module");
        assertEq(modules[0], module, "module returned");
    }

    function test_fallbackHandler_encodeTransactionDataMatchesSafeHash() public {
        bytes memory payload = hex"123456";
        uint256 nonce = safe.nonce();
        vm.prank(address(safe));
        bytes memory encoded = handler.encodeTransactionData(
            TARGET, 0, payload, Enum.Operation.Call, 0, 0, 0, address(0), address(0), nonce
        );
        assertEq(
            keccak256(encoded),
            safe.getTransactionHash(TARGET, 0, payload, Enum.Operation.Call, 0, 0, 0, address(0), address(0), nonce),
            "handler hash preimage matches Safe"
        );
    }

    // -------------------------------------------------------------------
    // Incident: ERC-1271 frozen across LockedDown / Recovering
    // -------------------------------------------------------------------

    function test_lockedDown_signatureFrozen() public {
        _triggerLockdown(safe, keccak256("wrench"));

        bytes32 hash = keccak256("authorise something");
        bytes memory signature = _signMessage(safe, OWNER_PK, hash); // a fully valid owner signature
        vm.expectRevert(LockdownFallbackHandler.SignaturesFrozenDuringLockdown.selector);
        IERC1271(address(safe)).isValidSignature(hash, signature);
    }

    function test_recovering_signatureFrozen() public {
        _triggerLockdown(safe, keccak256("wrench"));
        vm.warp(block.timestamp + 48 hours + 1); // past lockdownUntil -> Recovering

        bytes32 hash = keccak256("authorise something");
        bytes memory signature = _signMessage(safe, OWNER_PK, hash);
        vm.expectRevert(LockdownFallbackHandler.SignaturesFrozenDuringLockdown.selector);
        IERC1271(address(safe)).isValidSignature(hash, signature);
    }

    function test_afterResume_signatureUnfrozen() public {
        _triggerLockdown(safe, keccak256("wrench"));
        vm.warp(block.timestamp + 48 hours + 4 hours + 1); // past resumeDelay -> auto-resumed to Normal

        bytes32 hash = keccak256("authorise something");
        bytes memory signature = _signMessage(safe, OWNER_PK, hash);
        assertTrue(
            SignatureChecker.isValidERC1271SignatureNow(address(safe), hash, signature),
            "ERC-1271 works again after resume"
        );
    }

    function _ownerParams(address to, uint256 value, bytes memory data, Enum.Operation op)
        private
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

    function _signTxAtNonce(
        Safe instance,
        uint256 privateKey,
        address to,
        uint256 value,
        bytes memory data,
        Enum.Operation op,
        uint256 nonce
    ) private view returns (bytes memory sig) {
        bytes32 safeTxHash = instance.getTransactionHash(to, value, data, op, 0, 0, 0, address(0), address(0), nonce);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, safeTxHash);
        return abi.encodePacked(r, s, v);
    }

    function _createTwoOwnerSafe(uint256 nonce) private returns (Safe) {
        address[] memory owners = new address[](2);
        owners[0] = owner;
        owners[1] = other;

        return Safe(
            payable(factory.createProxyWithNonce(
                    address(singleton),
                    abi.encodeCall(
                        Safe.setup, (owners, 2, address(0), "", address(0), address(0), 0, payable(address(0)))
                    ),
                    nonce
                ))
        );
    }

    function _packSortedSignatures(bytes memory ownerSig, bytes memory otherSig) private view returns (bytes memory) {
        return owner < other ? bytes.concat(ownerSig, otherSig) : bytes.concat(otherSig, ownerSig);
    }
}
