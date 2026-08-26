// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";

import {Enum} from "@safe-global/safe-smart-account/interfaces/ISafe.sol";

import {LockdownTimelock, Lockdown} from "../../src/LockdownTimelock.sol";
import {StateMachine} from "../../src/base/StateMachine.sol";
import {MockSecretVerifier} from "../mocks/MockSecretVerifier.sol";
import {
    MockSelectiveRevertingVerifier,
    MockWrongMagicVerifier,
    MockSelectiveMagicVerifier
} from "../mocks/MockAdversarialVerifiers.sol";

/// @title OtherSafe - represents SAFE_B in cross-key isolation tests.
/// @notice Initialised once via `init()`, called by the harness right after
///         deployment. The fuzzer has no entry point that locks down SAFE_B,
///         so isLockedDown(SAFE_B) becoming true is a singleton cross-key
///         leak.
contract OtherSafe {
    LockdownTimelock private immutable _guard;
    MockSecretVerifier private immutable _secret;

    /// @dev H.19: the singleton staticcalls `isOwner` on the caller during
    ///      recovery-owner validation. This harness Safe has no owners.
    function isOwner(address) external pure returns (bool) {
        return false;
    }

    constructor(LockdownTimelock g, MockSecretVerifier secret) {
        _guard = g;
        _secret = secret;
    }

    /// @dev H.19 made `initialize` staticcall `isOwner` on the caller, so
    ///      OtherSafe cannot initialize inside its own constructor (it has
    ///      no runtime code at that point). The harness calls this once,
    ///      post-deployment; a second call reverts in the singleton.
    function init() external {
        address[] memory backups = new address[](1);
        backups[0] = address(0xB0BB);
        bytes[] memory signers = new bytes[](1);
        // Commitment with NO known keccak preimage: producing a signature
        // that triggers SAFE_B is keccak-hard, so SAFE_B can never be
        // legitimately locked and the isolation invariants are sound.
        // (A string-literal secret here is NOT safe: echidna constant-mines
        // source literals and once legitimately triggered SAFE_B with it.)
        signers[0] = abi.encodePacked(address(_secret), bytes32(uint256(1)));
        _guard.initialize(24 hours, 8 hours, backups, signers);
    }
}

/// @title EchidnaLockdown (V1, post-hardening)
/// @notice Stateful property-based fuzz harness for the V1 singleton.
/// @dev The harness IS SAFE_A. A separate OtherSafe is SAFE_B. The fuzzer
///      drives state on SAFE_A. Invariants assert cross-key isolation,
///      single-use burn correctness, lifecycle gates, recovery whitelist
///      tightening (including the V1 removeLockdownSigner-during-Recovering
///      carve-out), trigger-time verifier normalisation, the
///      ModuleCallToSingletonDenied guard, and burn permanence.
contract EchidnaLockdown is Test {
    /// @dev H.19: the singleton staticcalls `isOwner` on the caller during
    ///      recovery-owner validation. The harness Safe has no owners.
    function isOwner(address) external pure returns (bool) {
        return false;
    }

    LockdownTimelock public guard;
    MockSecretVerifier public secretVerifier;
    MockSelectiveMagicVerifier public selectiveMagicVerifier;
    MockSelectiveRevertingVerifier public selectiveRevertingVerifier;
    MockWrongMagicVerifier public wrongMagicVerifier;
    OtherSafe public safeB;

    address private constant MULTI_SEND_CALL_ONLY = address(0xA83C);

    bytes private constant HARNESS_PASSWORD = "harness-secret";
    bytes32 private immutable HARNESS_COMMITMENT;

    // Witnesses for invariant failures.
    bool private _saw_owner_path_during_lockdown;
    bool private _saw_module_path_during_recovery;
    bool private _saw_module_call_to_singleton_succeeded;
    bool private _saw_burnt_signer_resurrected;
    bool private _saw_removed_signer_trigger_success;
    bool private _saw_recovery_admin_succeeded;
    bool private _saw_resume_delay_reopen_incident;
    bool private _saw_bypass_succeeded_during_incident;
    bool private _saw_sweep_left_owner_ticket_slot_nonzero;
    bool private _saw_unscheduled_disarm_passed;

    bool private _initDone;

    constructor() {
        HARNESS_COMMITMENT = keccak256(HARNESS_PASSWORD);

        secretVerifier = new MockSecretVerifier();
        selectiveMagicVerifier = new MockSelectiveMagicVerifier();
        selectiveRevertingVerifier = new MockSelectiveRevertingVerifier();
        wrongMagicVerifier = new MockWrongMagicVerifier();

        guard = new LockdownTimelock(MULTI_SEND_CALL_ONLY);

        // SAFE_B = OtherSafe with its own secret. Deployed here, initialised
        // lazily in _ensureInit (see below).
        safeB = new OtherSafe(guard, secretVerifier);
    }

    /// @dev H.19 made `initialize` staticcall `isOwner` on the caller, so the
    ///      harness cannot initialize inside its own constructor (no runtime
    ///      code at that point: the staticcall returns empty and the decode
    ///      reverts). Every fuzz entry point lazily initializes both Safes
    ///      instead; invariants that read initialised state return true until
    ///      the first fuzz call.
    function _ensureInit() private {
        if (_initDone) return;
        _initDone = true;

        // SAFE_A = this harness.
        address[] memory backups = new address[](1);
        backups[0] = address(0xA0A0);
        bytes[] memory signers = new bytes[](1);
        signers[0] = _verifierSigner(address(secretVerifier), abi.encodePacked(HARNESS_COMMITMENT));
        guard.initialize(48 hours, 4 hours, backups, signers);

        safeB.init();
    }

    // -------------------------------------------------------------------
    // Time advancement
    // -------------------------------------------------------------------

    /// @notice Jump forward by `dt` seconds (capped to ~30 days per jump).
    ///         Lets the fuzzer reach Recovering and post-resume Normal
    ///         within a reasonable sequence length.
    function fuzzWarp(uint64 dt) public {
        _ensureInit();
        if (dt > 30 days) dt = uint64(30 days);
        try vm.warp(block.timestamp + dt) {} catch {}
    }

    // -------------------------------------------------------------------
    // Fuzz: signer + verifier management
    // -------------------------------------------------------------------

    function fuzzAddPasswordSigner(bytes32 commitment) public {
        _ensureInit();
        bytes memory key = abi.encodePacked(commitment);
        try guard.addLockdownSigner(_verifierSigner(address(secretVerifier), key)) {} catch {}
    }

    function fuzzAddECDSASigner(address addr) public {
        _ensureInit();
        try guard.addLockdownSigner(_eoaSigner(addr)) {} catch {}
    }

    function fuzzRemovePasswordSigner(bytes32 commitment) public {
        _ensureInit();
        bytes memory key = abi.encodePacked(commitment);
        try guard.removeLockdownSigner(_verifierSigner(address(secretVerifier), key)) {} catch {}
    }

    // -------------------------------------------------------------------
    // Fuzz: adversarial verifiers (removal / normalization)
    // -------------------------------------------------------------------

    /// @notice Add a signer under a selective always-magic verifier.
    ///         Used to subsequently verify explicit removal neutralises it
    ///         (echidna_removedSelectiveMagicSignerCannotTrigger).
    function fuzzAddSelectiveMagicSigner(bytes32 keyMaterial) public {
        _ensureInit();
        try guard.addLockdownSigner(_verifierSigner(address(selectiveMagicVerifier), abi.encodePacked(keyMaterial))) {}
            catch {}
    }

    /// @notice Attempt to trigger via an added-then-removed selective-magic
    ///         signer. Must always revert NotLockdownSigner. If it succeeds,
    ///         the invariant fails.
    function fuzzTriggerSelectiveMagicAfterRemove(bytes32 keyMaterial, bytes32 reasonHash) public {
        _ensureInit();
        // Best effort: register then remove; ignore failures of either.
        try guard.addLockdownSigner(_verifierSigner(address(selectiveMagicVerifier), abi.encodePacked(keyMaterial))) {}
            catch {}
        try guard.removeLockdownSigner(
            _verifierSigner(address(selectiveMagicVerifier), abi.encodePacked(keyMaterial))
        ) {}
            catch {}

        bytes memory key = abi.encodePacked(keyMaterial);
        try guard.triggerLockdown(
            address(this), reasonHash, _verifierSigner(address(selectiveMagicVerifier), key), hex""
        ) {
            _saw_removed_signer_trigger_success = true;
        } catch {}
    }

    /// @notice Trigger via a reverting / wrong-magic verifier must always
    ///         revert with BadSignature (normalization). If the call
    ///         succeeds AT ALL, something is very wrong.
    function fuzzTriggerRevertingVerifier(bytes32 keyMaterial, bytes32 reasonHash) public {
        _ensureInit();
        // Register (best effort).
        try guard.addLockdownSigner(
            _verifierSigner(address(selectiveRevertingVerifier), abi.encodePacked(keyMaterial))
        ) {}
            catch {}

        bytes memory key = abi.encodePacked(keyMaterial);
        try guard.triggerLockdown(
            address(this), reasonHash, _verifierSigner(address(selectiveRevertingVerifier), key), hex""
        ) {
            revert("reverting verifier produced successful trigger");
        } catch {}
    }

    function fuzzTriggerWrongMagicVerifier(bytes32 keyMaterial, bytes32 reasonHash) public {
        _ensureInit();
        try guard.addLockdownSigner(_verifierSigner(address(wrongMagicVerifier), abi.encodePacked(keyMaterial))) {}
            catch {}

        bytes memory key = abi.encodePacked(keyMaterial);
        try guard.triggerLockdown(address(this), reasonHash, _verifierSigner(address(wrongMagicVerifier), key), hex"") {
            revert("wrong-magic verifier produced successful trigger");
        } catch {}
    }

    // -------------------------------------------------------------------
    // Fuzz: trigger path on SAFE_A and SAFE_B
    // -------------------------------------------------------------------

    /// @notice Succeeds only if the signer for HARNESS_COMMITMENT exists AND
    ///         lockdownUntil == 0.
    function fuzzTriggerWithKnownPassword(bytes32 reasonHash) public {
        _ensureInit();
        bytes memory key = abi.encodePacked(HARNESS_COMMITMENT);
        bytes memory signer = _verifierSigner(address(secretVerifier), key);
        bool wasSigner = guard.isLockdownSigner(address(this), signer);

        try guard.triggerLockdown(address(this), reasonHash, signer, HARNESS_PASSWORD) {
            // After a successful trigger the entry must be burnt
            // (INV-SIGN-1). If it isn't, the burn-before-lock invariant
            // is broken.
            if (wasSigner && guard.isLockdownSigner(address(this), signer)) {
                _saw_burnt_signer_resurrected = true;
            }
        } catch {}
    }

    function fuzzTriggerWithWrongPassword(bytes32 reasonHash, bytes calldata wrongPreimage) public {
        _ensureInit();
        bytes memory key = abi.encodePacked(HARNESS_COMMITMENT);
        bytes memory signer = _verifierSigner(address(secretVerifier), key);
        try guard.triggerLockdown(address(this), reasonHash, signer, wrongPreimage) {
            if (keccak256(wrongPreimage) != HARNESS_COMMITMENT) {
                revert("trigger accepted wrong preimage");
            }
        } catch {}
    }

    /// @notice Cross-Safe trigger attempt against SAFE_B. SAFE_B's only
    ///         signer commitment is `bytes32(1)`, which has no known keccak
    ///         preimage, so ANY success here is an isolation/auth break
    ///         (also caught by echidna_safeBNeverLockedDown).
    function fuzzTryTriggerSafeB(bytes32 reasonHash, bytes calldata anyPreimage) public {
        _ensureInit();
        bytes memory key = abi.encodePacked(bytes32(uint256(1)));
        try guard.triggerLockdown(
            address(safeB), reasonHash, _verifierSigner(address(secretVerifier), key), anyPreimage
        ) {
            revert("safeB triggered: keccak preimage of bytes32(1) found?!");
        } catch {}
    }

    // -------------------------------------------------------------------
    // Fuzz: lifecycle (resume, hook probing)
    // -------------------------------------------------------------------

    function fuzzCheckOwnerPath(address to, uint256 value, bytes calldata data, Enum.Operation op) public {
        _ensureInit();
        try guard.checkTransaction(to, value, data, op, 0, 0, 0, address(0), payable(address(0)), hex"", address(0)) {
            if (_isLockedDown(address(this))) {
                _saw_owner_path_during_lockdown = true;
            }
        } catch {}
    }

    function fuzzCheckModulePath(address to, uint256 value, bytes calldata data, Enum.Operation op, address mod)
        public
    {
        _ensureInit();
        try guard.checkModuleTransaction(to, value, data, op, mod) returns (bytes32) {
            if (_isRecovering(address(this))) {
                _saw_module_path_during_recovery = true;
            }
            // ModuleCallToSingletonDenied invariant: a successful
            // checkModuleTransaction with to == singleton would mean the
            // hook missed the guard introduced in H.5.
            if (to == address(guard)) {
                _saw_module_call_to_singleton_succeeded = true;
            }
        } catch {}
    }

    /// @notice Drive the recovery whitelist test path. During Recovering,
    ///         removeLockdownSigner self-call MUST be accepted by the
    ///         hook. All other singleton admin selectors MUST be rejected.
    function fuzzCheckRecoveryAdminSelector(uint8 which, bytes calldata payload) public {
        _ensureInit();
        if (!_isRecovering(address(this))) return;

        bytes memory data;
        if (which % 4 == 0) {
            // setResumeDelay(uint64)
            data = abi.encodeWithSelector(guard.setResumeDelay.selector, uint64(5 hours));
        } else if (which % 4 == 1) {
            // addLockdownSigner(bytes)
            data = abi.encodeWithSelector(
                guard.addLockdownSigner.selector, _verifierSigner(address(secretVerifier), payload)
            );
        } else if (which % 4 == 2) {
            // setLockdownDuration(uint64)
            data = abi.encodeWithSelector(guard.setLockdownDuration.selector, uint64(1 hours));
        } else {
            // rotateLockdownSigner(bytes,bytes)
            data = abi.encodeWithSelector(
                guard.rotateLockdownSigner.selector,
                _verifierSigner(address(secretVerifier), payload),
                _eoaSigner(address(uint160(uint256(keccak256(payload)))))
            );
        }
        try guard.checkTransaction(
            address(guard), 0, data, Enum.Operation.Call, 0, 0, 0, address(0), payable(address(0)), hex"", address(0)
        ) {
            _saw_recovery_admin_succeeded = true;
        } catch {}
    }

    /// @notice INV-LIFE-1 / F-M2-01: changing resumeDelay from Normal must
    ///         apply prospectively. In particular, it must not make an elapsed
    ///         incident's stale lockdownUntil live again.
    function fuzzSetResumeDelay(uint64 newDelay) public {
        _ensureInit();
        if (newDelay < guard.RESUME_DELAY_MIN()) newDelay = guard.RESUME_DELAY_MIN();
        if (newDelay > guard.RESUME_DELAY_MAX()) newDelay = guard.RESUME_DELAY_MAX();

        (StateMachine.State before_,) = guard.getState(address(this));
        try guard.setResumeDelay(newDelay) {
            if (before_ != StateMachine.State.Normal) return;
            (StateMachine.State after_,) = guard.getState(address(this));
            if (
                after_ != StateMachine.State.Normal || guard.getLockdownUntil(address(this)) != 0
                    || guard.lastReasonHash(address(this)) != bytes32(0)
            ) {
                _saw_resume_delay_reopen_incident = true;
            }
        } catch {}
    }

    // -------------------------------------------------------------------
    // Fuzz: timelock (SPEC §V1 + External review review 2 fix)
    // -------------------------------------------------------------------

    /// @notice Drive setTimelockDelay; only succeeds in Normal mode. The
    ///         interesting state is "timelock active during an incident",
    ///         covered by fuzzBypassTimelockDuringIncident below.
    function fuzzSetTimelockDelay(uint32 delay) public {
        _ensureInit();
        if (delay < 1 hours) delay = 1 hours;
        if (delay > 30 days) delay = uint32(30 days);
        try guard.setTimelockDelay(uint64(delay)) {} catch {}
    }

    function fuzzSetTimelockBypasserSelf(bool allowed) public {
        _ensureInit();
        try guard.setTimelockBypasser(address(this), allowed) {} catch {}
    }

    /// @notice INV-TIME-7: bypassTimelock MUST revert during LockedDown
    ///         and Recovering (the `onlyNormal` lifecycle gate).
    ///         If it ever succeeds while the Safe is in either incident
    ///         state, the recovery-shielding guarantee is broken.
    function fuzzBypassTimelockDuringIncident(bytes32 anyHash) public {
        _ensureInit();
        bool inIncident = _isLockedDown(address(this)) || _isRecovering(address(this));
        try guard.bypassTimelock(address(this), anyHash) {
            if (inIncident) {
                _saw_bypass_succeeded_during_incident = true;
            }
        } catch {}
    }

    /// @notice After sweepExpired*Ticket the slot MUST read back as
    ///         zero. We cannot easily fuzz "past TTL" without time control
    ///         beyond fuzzWarp, so we drive the most realistic path: the
    ///         fuzzer chooses a hash, creates a bypass ticket, jumps past TTL,
    ///         then sweeps. Any non-zero post-sweep value is a leak.
    function fuzzOwnerTicketWarpSweep(bytes32 h) public {
        _ensureInit();
        try guard.setTimelockDelay(uint64(1 hours)) {} catch {}
        try guard.setTimelockBypasser(address(this), true) {} catch {}
        try guard.bypassTimelock(address(this), h) {}
        catch {
            return;
        }
        try vm.warp(block.timestamp + 1 hours + 91 days) {}
        catch {
            return;
        }
        try guard.sweepExpiredOwnerTicket(address(this), h) {
            uint64 after_ = guard.getTransactionExecutableAt(address(this), h);
            if (after_ != 0) _saw_sweep_left_owner_ticket_slot_nonzero = true;
        } catch {}
    }

    /// @notice INV-LIVE-1 (§14.2) regression tripwire. In Normal mode with
    ///         timelockDelay > 0, every owner-path op that NEUTRALISES
    ///         protection (setGuard(0), removeLockdownSigner,
    ///         setTimelockBypasser, setTimelockDelay(0)) must NOT pass the hook without a matured
    ///         scheduled ticket. None of these selectors is in the
    ///         _isTimelockBypassedSelfCall free-pass set, so the hook either
    ///         reverts in _verifyOwnerTimelock (no ticket) or earlier.
    ///         A success here means a neutralisation selector slipped into the
    ///         bypass set - the exact failure INV-LIVE-1 forbids. The harness
    ///         never schedules these hashes, so a correct hook always reverts.
    function fuzzDisarmInNormalTimelock(uint8 which) public {
        _ensureInit();
        if (guard.getTimelockDelay(address(this)) == 0) return;
        if (_isLockedDown(address(this)) || _isRecovering(address(this))) return;
        address to = address(guard);
        bytes memory data;
        uint8 k = which % 4;
        if (k == 0) {
            to = address(this); // setGuard(address) self-call to the Safe
            data = abi.encodeWithSelector(bytes4(0xe19a9dd9), address(0));
        } else if (k == 1) {
            data =
                abi.encodeWithSelector(guard.removeLockdownSigner.selector, address(secretVerifier), HARNESS_PASSWORD);
        } else if (k == 2) {
            data = abi.encodeWithSelector(guard.setTimelockBypasser.selector, address(0x1234), true);
        } else {
            data = abi.encodeWithSelector(guard.setTimelockDelay.selector, uint64(0));
        }
        try guard.checkTransaction(
            to, 0, data, Enum.Operation.Call, 0, 0, 0, address(0), payable(address(0)), hex"", address(0)
        ) {
            _saw_unscheduled_disarm_passed = true;
        } catch {}
    }

    // -------------------------------------------------------------------
    // Invariants
    // -------------------------------------------------------------------

    function echidna_signersCountAtMost32() public view returns (bool) {
        (,,, uint256 cnt,) = guard.getConfigSnapshot(address(this));
        return cnt <= 32;
    }

    function echidna_noOwnerPathDuringLockdown() public view returns (bool) {
        return !_saw_owner_path_during_lockdown;
    }

    function echidna_noModulePathDuringRecovery() public view returns (bool) {
        return !_saw_module_path_during_recovery;
    }

    function echidna_allowlistCountNeverZero() public view returns (bool) {
        if (!_initDone) return true;
        return guard.getRecoveryOwners(address(this)).length >= 1;
    }

    function echidna_safeBNeverLockedDown() public view returns (bool) {
        return !_isLockedDown(address(safeB)) && !_isRecovering(address(safeB));
    }

    function echidna_safeBConfigUntouched() public view returns (bool) {
        if (!_initDone) return true;
        (uint64 d, uint64 r, uint64 u, uint256 cnt, uint256 backupCnt) = guard.getConfigSnapshot(address(safeB));
        return d == 24 hours && r == 8 hours && u == 0 && cnt == 1 && backupCnt == 1;
    }

    /// @notice H.5: the module path must never produce a successful
    ///         checkModuleTransaction with `to == address(singleton)`.
    function echidna_modulePathCannotReachSingleton() public view returns (bool) {
        return !_saw_module_call_to_singleton_succeeded;
    }

    /// @notice INV-SIGN-1: a successful triggerLockdown must atomically
    ///         delete the signer entry. A non-empty pre-image followed by
    ///         a non-empty post-image is a burn-before-lock
    ///         violation.
    function echidna_burntSignerNeverResurrects() public view returns (bool) {
        return !_saw_burnt_signer_resurrected;
    }

    /// @notice Explicitly removing a signer under a selective-magic verifier
    ///         must neutralize that exact signer tuple.
    function echidna_removedSelectiveMagicSignerCannotTrigger() public view returns (bool) {
        return !_saw_removed_signer_trigger_success;
    }

    /// @notice §7.4: during Recovering, only resume and removeLockdownSigner
    ///         self-calls are accepted. All other admin self-calls must be
    ///         rejected by the hook.
    function echidna_recoveryAdminSelectorsRejected() public view returns (bool) {
        return !_saw_recovery_admin_succeeded;
    }

    /// @notice INV-LIFE-1 / F-M2-01: a successful Normal-state resumeDelay
    ///         update cannot resurrect an elapsed incident.
    function echidna_resumeDelayCannotReopenIncident() public view returns (bool) {
        return !_saw_resume_delay_reopen_incident;
    }

    /// @notice INV-TIME-7: `bypassTimelock` MUST revert whenever getState is
    ///         LockedDown or Recovering. Combined with the hook branches
    ///         (INV-TIME-6), an attacker who only controls a bypasser key
    ///         cannot interact with a Safe during an active incident.
    function echidna_bypassRejectedDuringIncident() public view returns (bool) {
        return !_saw_bypass_succeeded_during_incident;
    }

    /// @notice INV-TIME-8 slot-clearing scope: a successful owner-ticket sweep
    ///         MUST leave the slot reading back as 0. This does not assert that
    ///         the underlying Safe authorisation cannot be scheduled again.
    function echidna_sweepClearsExpiredOwnerTicketSlot() public view returns (bool) {
        return !_saw_sweep_left_owner_ticket_slot_nonzero;
    }

    /// @notice INV-LIVE-1 (§14.2): with timelockDelay > 0 in Normal mode, no
    ///         protection-neutralising owner-path op may pass the hook
    ///         unscheduled. A failure means a disarm selector reached the
    ///         _isTimelockBypassedSelfCall free-pass set.
    function echidna_disarmGatedByTimelock() public view returns (bool) {
        return !_saw_unscheduled_disarm_passed;
    }

    /// @notice INV-LIVE-3 / T-LIVE-2 (§14.2 / §17): the hard-freeze phase must
    ///         never be shorter than the timelock delay it backs, i.e.
    ///         lockdownDuration >= timelockDelay holds across every setter
    ///         sequence. If it broke, a coerced quorum could self-induce a
    ///         short lockdown to reach the un-timelocked Recovering disarm
    ///         faster than the timelock would allow. fuzzSetTimelockDelay can
    ///         drive timelockDelay up to 30d > the 48h init duration, so this
    ///         invariant is non-vacuous: removing the setter guard would let it
    ///         fire.
    function echidna_lockdownCoversTimelock() public view returns (bool) {
        (uint64 dur,,,,) = guard.getConfigSnapshot(address(this));
        if (dur == 0) return true; // uninitialised
        return dur >= guard.getTimelockDelay(address(this));
    }

    function _eoaSigner(address signer) private pure returns (bytes memory) {
        return abi.encodePacked(signer);
    }

    function _verifierSigner(address verifier, bytes memory key) private pure returns (bytes memory) {
        return abi.encodePacked(verifier, key);
    }

    // isLockedDown / isRecovering were removed from the contract in favour of
    // getState(); these local mirrors preserve the semantics for the invariants
    // below. isRecovering covers only the Recovering state: the Resumable state
    // was removed, so after the recovery window the Safe auto-resumes to Normal.
    function _isLockedDown(address safe) private view returns (bool) {
        (StateMachine.State state,) = guard.getState(safe);
        return state == StateMachine.State.LockedDown;
    }

    function _isRecovering(address safe) private view returns (bool) {
        (StateMachine.State state,) = guard.getState(safe);
        return state == StateMachine.State.Recovering;
    }
}
