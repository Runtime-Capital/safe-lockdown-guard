// SPDX-License-Identifier: MIT
pragma solidity 0.8.35;

// Safe
import {ISafe, Enum} from "@safe-global/safe-smart-account/interfaces/ISafe.sol";
// OpenZeppelin
import {TransientSlot} from "@openzeppelin/contracts/utils/TransientSlot.sol";
// Lockdown
import {Lockdown} from "./Lockdown.sol";
import {Timelock} from "./base/Timelock.sol";
import {LockdownLib} from "./utils/LockdownLib.sol";

/// @title Lockdown (V1 singleton with EIP-7913 signer dispatch)
/// @notice Dual transaction guard + module guard for Safe v1.5.0 multi-sigs,
///         providing an anti-coercion panic primitive. A single deployed
///         contract serves an unbounded number of Safes; each Safe registers
///         a list of ERC-7913 signer identities.
/// @dev Install the same contract as both Safe transaction guard
///      (`setGuard(address)`) and Safe module guard (`setModuleGuard(address)`).
///
///      Authorisation model (V1):
///      - No implicit equivalence: Safe owners are NOT automatically lockdown
///        signers. They must register their 20-byte EOA / ERC-1271 address
///        if they want that role.
///      - Every signer is single-use: a successful `triggerLockdown(...)`
///        deletes the signer entry that authorised the call.
///      - Replay across re-registrations is prevented by permanently burning
///        every signer identity that has been removed, rotated away, or used.
///      - Verifier trust is attached to each explicit ERC-7913 identity
///        (`verifier || key`). There is no verifier-class allowlist or bulk
///        revocation switch.
///
///      Anti-brick:
///      - Hooks pass through silently for an uninitialised Safe
///        (`cfg.lockdownDuration == 0`).
///      - Initialise via `initialize(...)`, optionally with initial signers
///        in a single atomic MultiSend.
///
///      Cross-key isolation:
///      - All admin functions key off `msg.sender`.
///      - `triggerLockdown` and views take `safe` as an explicit parameter.
///      - Hooks read `_timelockConfigs[msg.sender]` only.
///      - There is no path that mutates `_timelockConfigs[other]` from a call
///        identifying `safe = msg.sender = self`.
/// @custom:security-contact contact@runtime.capital
contract LockdownTimelock is Lockdown, Timelock {
    using LockdownLib for bytes32;
    using TransientSlot for *;

    // -------------------------------------------------------------------
    // Errors
    // -------------------------------------------------------------------

    /// @notice A schedule/cancel meta-call to the singleton tried to use
    ///         non-zero Safe refund fields. The bypassed meta-call path
    ///         MUST NOT carry refund instructions, otherwise a coerced
    ///         quorum could drain via `gasToken`/`refundReceiver` while
    ///         sidestepping the timelock (review C1).
    error TimelockBypassRefundDenied();
    /// @notice Thrown by `checkModuleTransaction` when the timelock branch
    ///         detects that another module-path timelocked execution is
    ///         already in-flight on this Safe (`_inFlightModuleTicket(safe).tload() != 0`).
    ///         Closes the V1 review round 3 reentrancy window where Safe
    ///         v1.5.0 module-path reentrancy could double-spend a single
    ///         scheduled ticket (INV-TIME-11).
    error ReentrantModuleTimelockExecution();
    error TimelockExceedsLockdownDuration();

    // -------------------------------------------------------------------
    // Construction
    // -------------------------------------------------------------------

    constructor(address multiSendCallOnly) Lockdown(multiSendCallOnly) {}

    // -------------------------------------------------------------------
    // Overrides
    // -------------------------------------------------------------------

    /// @notice Override Lockdown.setLockdownDuration to enforce T-LIVE-2 (§14.2 / §17):
    function setLockdownDuration(uint64 newDuration) public virtual override {
        // Run the base validation first (the onlyNormal state gate inherited
        // from Lockdown, then the min/max bounds) so a below-min duration still
        // reverts LockdownDurationTooLow; only then enforce the timelock coupling.
        super.setLockdownDuration(newDuration);
        require(newDuration >= getTimelockDelay(msg.sender), TimelockExceedsLockdownDuration());
    }

    /// @dev The stateless `Timelock` component has no view of the lockdown
    ///      state machine, so the per-Safe state gates that these mutators
    ///      carried before the component extraction are re-applied here.
    ///      `schedule*` / `set*` / `bypass*` are `onlyNormal` (no scheduling
    ///      new work mid-incident); `cancel*` / `sweep*` are `onlyInitialized`
    ///      (cleanup is allowed in any non-uninitialised state).

    function setTimelockDelay(uint64 newDelay) public virtual override onlyNormal(msg.sender) {
        super.setTimelockDelay(newDelay);
        require(newDelay == 0 || newDelay <= getLockdownDuration(msg.sender), TimelockExceedsLockdownDuration());
    }

    function setTimelockBypasser(address bypasser, bool allowed) public virtual override onlyNormal(msg.sender) {
        super.setTimelockBypasser(bypasser, allowed);
    }

    function scheduleTransaction(
        address safe,
        uint256 nonce,
        ExecTransactionParams calldata params,
        bytes calldata signatures
    ) public virtual override onlyNormal(safe) returns (bytes32) {
        return super.scheduleTransaction(safe, nonce, params, signatures);
    }

    function scheduleModuleTransaction(
        address module,
        address to,
        uint256 value,
        bytes calldata data,
        Enum.Operation operation
    ) public virtual override onlyNormal(msg.sender) returns (bytes32) {
        return super.scheduleModuleTransaction(module, to, value, data, operation);
    }

    function cancelTransaction(bytes32 safeTxHash) public virtual override onlyInitialized(msg.sender) {
        super.cancelTransaction(safeTxHash);
    }

    function cancelModuleTransaction(bytes32 moduleTxHash) public virtual override onlyInitialized(msg.sender) {
        super.cancelModuleTransaction(moduleTxHash);
    }

    function bypassTimelock(address safe, bytes32 safeTxHash) public virtual override onlyNormal(safe) {
        super.bypassTimelock(safe, safeTxHash);
    }

    function sweepExpiredOwnerTicket(address safe, bytes32 safeTxHash) public virtual override onlyInitialized(safe) {
        super.sweepExpiredOwnerTicket(safe, safeTxHash);
    }

    function sweepExpiredModuleTicket(address safe, bytes32 moduleTxHash)
        public
        virtual
        override
        onlyInitialized(safe)
    {
        super.sweepExpiredModuleTicket(safe, moduleTxHash);
    }

    // -------------------------------------------------------------------
    // Guard hooks - Transactions guard
    // -------------------------------------------------------------------

    function checkTransaction(
        address to,
        uint256 value,
        bytes calldata data,
        Enum.Operation operation,
        uint256 safeTxGas,
        uint256 baseGas,
        uint256 gasPrice,
        address gasToken,
        address payable refundReceiver,
        bytes calldata signatures,
        address msgSender
    ) public virtual override {
        (State state,) = getState(msg.sender);

        super.checkTransaction(
            to, value, data, operation, safeTxGas, baseGas, gasPrice, gasToken, refundReceiver, signatures, msgSender
        );

        // Fail-open for uninitialised configs (anti-brick on install order).
        if (state == State.Uninitialised) return;
        require(state != State.LockedDown, LockedDown());

        if (state == State.Normal && operation == Enum.Operation.Call) {
            // If timelock is active, verify the scheduled ticket and delay, except for the cancel / module
            // management meta-operations themselves (which bypass the timelock). The bypass is necessary so the
            // user can clean up tickets and manage module scheduling without a meta-timelock.
            if (getTimelockDelay(msg.sender) > 0) {
                // Bypass timelock for cancel / module management meta-operations
                // so the user can manage tickets without a meta-timelock. The
                // bypass MUST reject non-zero Safe refund fields, otherwise a
                // coerced quorum could drain via gasToken/refundReceiver while
                // sidestepping the timelock (review C1).
                if (_isTimelockManagementCall(to, value, data)) {
                    require(
                        safeTxGas == 0 && baseGas == 0 && gasPrice == 0 && gasToken == address(0)
                            && refundReceiver == address(0),
                        TimelockBypassRefundDenied()
                    );
                    // Otherwise enforce the timelock, UNLESS a registered
                    // bypasser is the one submitting this execTransaction
                    // (msgSender == bypasser). That is the HSM-as-relayer form
                    // of bypassTimelock: the delay is skipped inline, no ticket,
                    // no schedule. Owner signatures are still enforced by the
                    // Safe; this is Normal-state + owner-path only (it cannot
                    // accelerate a LockedDown/Recovering tx); and unlike the
                    // meta-call carve-out above it does NOT re-check refund
                    // fields, consistent with the bypasser's full owner-path
                    // authority (SPEC_V1 "Bypass model").
                } else if (!isTimelockBypasser(msg.sender, msgSender)) {
                    _verifyOwnerTimelock(
                        msg.sender, to, value, data, operation, safeTxGas, baseGas, gasPrice, gasToken, refundReceiver
                    );
                }
            }
        } else if (state == State.Normal && operation == Enum.Operation.DelegateCall) {
            // MultiSend DELEGATECALL is one Safe tx with one safeTxHash;
            // it is timelocked as a unit (the user schedules the bundle). A
            // registered bypasser submitting this bundle (msgSender == bypasser)
            // skips the delay inline, same as the Call path above.
            if (getTimelockDelay(msg.sender) > 0 && !isTimelockBypasser(msg.sender, msgSender)) {
                _verifyOwnerTimelock(
                    msg.sender, to, value, data, operation, safeTxGas, baseGas, gasPrice, gasToken, refundReceiver
                );
            }
        }
    }

    /// @notice Post-hook for owner-path tx execution. Consumes the timelock
    ///         ticket associated with `safeTxHash` if and only if:
    ///         (a) `success == true` (the inner call did not revert), AND
    ///         (b) a ticket exists for this Safe at `_ownerTicketKey(safeTxHash)`.
    ///
    ///         Otherwise the call is a no-op: bypass-meta self-calls, no-
    ///         timelock paths, uninit Safes, and recovery-whitelisted calls
    ///         all produce a `safeTxHash` that does not map to a stored
    ///         ticket, so the early-return branches fire and nothing is
    ///         deleted. Failure paths (`success == false`) leave the ticket
    ///         in storage so the operator can retry without re-scheduling
    ///         (subject to the Safe nonce having advanced for `safeTxGas > 0`
    ///         outer-success cases - see `_verifyTicket` NatSpec).
    ///
    ///         INV-TIME-4 hardening (V1 review round 3 / Safe v1.5.0
    ///         execution-semantics fix): replaces the pre-hook delete that
    ///         could silently burn a ticket when the outer Safe tx
    ///         committed with a failed inner call.
    /// @dev    Anyone can call this externally; cross-Safe damage is bounded
    ///         by the `msg.sender` binding (only `_timelockConfigs[msg.sender]` is
    ///         mutated). A non-Safe caller has no `_timelockConfigs` entry, so the
    ///         existence guard short-circuits.
    function checkAfterExecution(bytes32 safeTxHash, bool success) public virtual override {
        if (success) {
            _consumeTicket(msg.sender, safeTxHash.ownerTicketKey());
        }
    }

    // Transaction guard helpers

    function _isTimelockManagementCall(address to, uint256 value, bytes calldata data) private view returns (bool) {
        return value == 0 && to == address(this)
            && ((data.length == 0x24 && bytes4(data) == this.cancelTransaction.selector)
                || (data.length >= 0x04 && bytes4(data) == this.scheduleModuleTransaction.selector)
                || (data.length >= 0x04 && bytes4(data) == this.cancelModuleTransaction.selector));
    }

    /// @dev Owner-path timelock pre-hook verification (V1 review round 3).
    ///      Recomputes the in-flight `safeTxHash` via
    ///      `ISafe.getTransactionHash(...)` with the pre-incremented nonce
    ///      (`nonce() - 1`, see Safe v1.5.0 order: compute hash → check
    ///      sigs → increment nonce → call guard). Reverts on
    ///      missing/expired/early ticket. Does NOT delete - actual
    ///      consumption happens in `checkAfterExecution` gated on
    ///      `success == true` so that a failed inner execution does not
    ///      burn the ticket (see `_verifyTicket` for the Safe v1.5.0
    ///      execution-semantics rationale).
    function _verifyOwnerTimelock(
        address safe,
        address to,
        uint256 value,
        bytes calldata data,
        Enum.Operation operation,
        uint256 safeTxGas,
        uint256 baseGas,
        uint256 gasPrice,
        address gasToken,
        address payable refundReceiver
    ) private view {
        _verifyTicket(
            safe,
            ISafe(payable(safe))
                .getTransactionHash(
                    to,
                    value,
                    data,
                    operation,
                    safeTxGas,
                    baseGas,
                    gasPrice,
                    gasToken,
                    refundReceiver,
                    ISafe(payable(safe)).nonce() - 1
                ).ownerTicketKey()
        );
    }

    // -------------------------------------------------------------------
    // Guard hooks - Module transactions guard
    // -------------------------------------------------------------------

    function checkModuleTransaction(
        address to,
        uint256 value,
        bytes calldata data,
        Enum.Operation operation,
        address module
    ) public virtual override returns (bytes32 moduleTxHash) {
        bytes32 result = super.checkModuleTransaction(to, value, data, operation, module);

        (State state,) = getState(msg.sender);
        if (state == State.Normal && getTimelockDelay(msg.sender) > 0) {
            // Store in transient storage so the post-hook can cross-check and consume it if the module call succeeded.
            TransientSlot.Bytes32Slot inFlightTicket = _inFlightModuleTicket(msg.sender);
            require(inFlightTicket.tload() == bytes32(0), ReentrantModuleTimelockExecution());
            bytes32 ticketKey =
                getModuleTransactionHash(msg.sender, module, to, value, data, operation).moduleTicketKey();
            _verifyTicket(msg.sender, ticketKey);
            inFlightTicket.tstore(ticketKey);
        }

        return result;
    }

    /// @notice Post-hook for module-path tx execution. Reads the in-flight
    ///         ticket key set by the pre-hook (V1 review round 3 INV-TIME-11
    ///         reentrancy guard) and consumes it if and only if:
    ///         (a) `success == true` (module call did not revert), AND
    ///         (b) a ticket exists for this Safe at the in-flight key.
    ///
    ///         The in-flight slot is cleared regardless of `success` so the
    ///         next module-path timelocked tx can begin. A failure path
    ///         (`success == false`, i.e. Safe v1.5.0 emitted
    ///         `ExecutionFromModuleFailure`) leaves the ticket in storage
    ///         so the operator can retry the SAME module tx (identical
    ///         params) without re-scheduling. The single-use INV-TIME-4
    ///         semantic is preserved: exactly one successful execution per
    ///         scheduled ticket.
    /// @dev    `txHash` is the value our pre-hook returned and Safe v1.5.0
    ///         relays it back here verbatim. We DO NOT use `txHash` for the
    ///         storage key (the in-flight slot is authoritative); the
    ///         parameter is kept for the Safe v1.5.0 interface contract.
    ///         Cross-Safe damage is bounded by the `msg.sender` binding:
    ///         a non-Safe caller (or a Safe with no in-flight tx) hits
    ///         `pending == 0` and returns early.
    function checkAfterModuleExecution(
        bytes32,
        /* txHash */
        bool success
    )
        public
        virtual
        override
    {
        TransientSlot.Bytes32Slot inFlightTicket = _inFlightModuleTicket(msg.sender);
        bytes32 pending = inFlightTicket.tload();
        inFlightTicket.tstore(0); // cleanup

        // Defence in depth against Safe v1.5.0 quirks: still guard against
        // a missing ticket entry (would otherwise emit a spurious
        // TimelockConsumed for an already-cleared entry).
        if (success && pending != bytes32(0)) {
            _consumeTicket(msg.sender, pending);
        }
    }
}
