// SPDX-License-Identifier: MIT
pragma solidity 0.8.35;

// Safe
import {ISafe, Enum} from "@safe-global/safe-smart-account/interfaces/ISafe.sol";
// Lockdown
import {LockdownLib} from "../utils/LockdownLib.sol";

/// @custom:security-contact contact@runtime.capital
contract Timelock {
    using LockdownLib for bytes32;

    /// @notice Smallest non-zero `timelockDelay`. Below this, the timelock
    ///         is meaningless (1h = the practical minimum to give an
    ///         offline incident-response chain a chance to react).
    uint64 public constant TIMELOCK_DELAY_MIN = 1 hours;
    /// @notice Largest `timelockDelay`. 30 days mirrors `LOCKDOWN_DURATION_MAX`
    ///         and matches the high-defense cold-storage target.
    uint64 public constant TIMELOCK_DELAY_MAX = 30 days;
    /// @notice TTL after which a ticket (or bypass) expires
    ///         automatically. Recommended by external review (V1
    ///         /TTL: 90 days) as the sweet spot between operational
    ///         flexibility for multi-week treasury planning and storage
    ///         hygiene. The check is "now > executableAt + TTL", and the
    ///         entry is auto-deleted on the expired-check path. An
    ///         explicit `cancelTransaction(...)` bypass is provided for
    ///         immediate cleanup (independent of TTL).
    uint64 public constant TICKET_TTL = 90 days;

    struct SafeTimelockConfig {
        /// @dev 0 means timelock disabled (default after initialize).
        ///      When > 0, every owner-path AND module-path tx that is not
        ///      a `cancel*` self-call (owner-path) or module-management
        ///      self-call goes through schedule + wait + execute.
        ///      See `setTimelockDelay`.
        uint64 timelockDelay;
        /// @dev ticketKey => executableAt. ticketKey is namespace-prefixed
        ///      (see OWNER_TX_TIMELOCK_TYPEHASH / MODULE_TX_TIMELOCK_TYPEHASH)
        ///      so owner-path and module-path tickets share storage but
        ///      cannot collide. Single-use: deleted on consumption inside the
        ///      guard hooks (owner-path: post-hook, on success; module-path:
        ///      pre-hook, re-created by the post-hook on failure).
        mapping(bytes32 ticketKey => uint64 executableAt) ticketExecutableAt;
        /// @dev Allowlist of HSM-style addresses that can call
        ///      `bypassTimelock(safe, safeTxHash)` to set executableAt = now
        ///      for a specific owner-path tx (no module-path bypass per Q5).
        ///      Off-chain trust model: the bypasser receives ONLY the hash
        ///      and writes executableAt = now; on-chain enforcement of
        ///      "what is bypassable" is NOT possible. The bypasser
        ///      service is expected to apply policy off-chain (refuse to
        ///      sign bypasses for admin txs). HSM compromise =
        ///      full bypass authority including timelock disable. The
        ///      operator accepts this SPOF in exchange for the simpler
        ///      design (gap-analysis Q-Bypass-1 option A).
        mapping(address bypasser => bool) timelockBypassers;
    }

    struct ExecTransactionParams {
        address to;
        uint256 value;
        bytes data;
        Enum.Operation operation;
        uint256 safeTxGas;
        uint256 baseGas;
        uint256 gasPrice;
        address gasToken;
        address payable refundReceiver;
    }

    mapping(address safe => SafeTimelockConfig) private _timelockConfigs;

    // -------------------------------------------------------------------
    // Events
    // -------------------------------------------------------------------

    event TimelockDelayChanged(address indexed safe, uint64 newDelay);
    event TimelockBypasserChanged(address indexed safe, address indexed bypasser, bool allowed);
    event TransactionScheduled(address indexed safe, bytes32 indexed safeTxHash, uint64 executableAt);
    event ModuleTransactionScheduled(
        address indexed safe,
        address indexed module,
        bytes32 indexed moduleTxHash,
        address to,
        uint256 value,
        bytes data,
        Enum.Operation operation,
        uint64 executableAt
    );
    event TicketCancelled(address indexed safe, bytes32 indexed ticketKey);
    /// @notice Emitted on permissionless cleanup of a ticket past TTL
    ///         (via `sweepExpiredOwnerTicket` /
    ///         `sweepExpiredModuleTicket`). Distinguishes governance
    ///         cancellation (`TicketCancelled`) from janitor-style
    ///         sweep so off-chain indexers can tell them apart.
    event TicketSwept(address indexed safe, bytes32 indexed ticketKey, address indexed sweeper);
    event TimelockBypassed(address indexed safe, bytes32 indexed safeTxHash, address indexed bypasser);
    event TimelockConsumed(address indexed safe, bytes32 indexed ticketKey);
    /// @notice Emitted when the module post-hook re-creates a ticket that its
    ///         pre-hook consumed, because the module call failed. The ticket
    ///         is re-created with `executableAt = block.timestamp` (see
    ///         `_restoreTicket`).
    event TicketRestored(address indexed safe, bytes32 indexed ticketKey, uint64 executableAt);

    // -------------------------------------------------------------------
    // Errors
    // -------------------------------------------------------------------

    /// @notice `bypassTimelock` / `scheduleTransaction` /
    ///         `scheduleModuleTransaction` called while `timelockDelay == 0`.
    error TimelockDisabled();
    error TimelockDelayTooLow();
    error TimelockDelayTooHigh();
    /// @notice A ticket for this key already exists. Cancel
    ///         the prior ticket before re-registering (idempotent
    ///         self-overwrite would otherwise be a footgun).
    error TicketAlreadyExists();
    /// @notice Guard hook saw a tx that requires timelock authorisation
    ///         (`timelockDelay > 0`) but no matching `executableAt` exists.
    ///         Either the tx was never scheduled, was cancelled, or was
    ///         consumed by a prior execution.
    error TicketNotFound();
    /// @notice Guard hook reached before `executableAt`. Wait or bypass.
    error TimelockNotElapsed();
    /// @notice Guard hook reached after `executableAt + TICKET_TTL`.
    ///         The entry STAYS in storage because the revert rolls back any
    ///         in-function `delete` (Solidity atomic-tx semantics). The Safe
    ///         quorum reclaims the slot via `cancelTransaction(...)`; anyone
    ///         may reclaim it via `sweepExpiredOwnerTicket(...)`.
    error TicketExpired();
    /// @notice `sweepExpired*Ticket(...)` called on an entry still
    ///         within its TTL window. Use `cancelTransaction(...)` from the
    ///         Safe quorum instead.
    error TicketNotExpired();
    /// @notice `bypassTimelock` caller is not in `timelockBypassers`.
    error NotTimelockBypasser();
    /// @notice `setTimelockBypasser` called with `address(0)`.
    error BypasserZeroAddress();
    /// @notice `scheduleTransaction` called for a Safe nonce that has
    ///         already been consumed. Old quorum signatures are public after
    ///         execution, so accepting stale nonces would let anyone recreate
    ///         useless tickets until TTL expiry.
    error StaleSafeNonce();

    // -------------------------------------------------------------------
    // Public mutators
    // -------------------------------------------------------------------

    /// @notice Set the per-Safe owner+module timelock delay. `0` disables.
    ///         Once active (delay > 0), every subsequent owner-path tx must
    ///         be scheduled with its full Safe transaction and signatures,
    ///         and every module-path tx must be scheduled first. Both paths
    ///         wait at least `delay` before execution. `cancelTransaction`
    ///         self-calls and module scheduling/cancellation self-calls
    ///         bypass the timelock; the bypass is necessary so the user can
    ///         clean up owner-path tickets and manage module scheduling
    ///         without a meta-timelock.
    /// @dev    Calling this is itself subject to the CURRENT delay (it is
    ///         a normal owner-path self-call to the singleton). The only
    ///         "free" change is the first activation `0 → N` because the
    ///         current delay is 0 at hook time, so the hook skips its
    ///         timelock check. Subsequent changes (including back to 0)
    ///         must be scheduled and waited.
    function setTimelockDelay(uint64 newDelay) public virtual {
        SafeTimelockConfig storage cfg = _timelockConfigs[msg.sender];
        if (newDelay != 0) {
            require(newDelay >= TIMELOCK_DELAY_MIN, TimelockDelayTooLow());
            require(newDelay <= TIMELOCK_DELAY_MAX, TimelockDelayTooHigh());
        }
        cfg.timelockDelay = newDelay;
        emit TimelockDelayChanged(msg.sender, newDelay);
    }

    /// @notice Add / remove a timelock bypasser for the calling Safe.
    /// @dev    The bypasser (typically an operator-run HSM service) can
    ///         later call `bypassTimelock(safe, safeTxHash)` directly to
    ///         set `executableAt = now` for a specific owner-path tx.
    ///         No on-chain enforcement of WHAT can be bypassed: the
    ///         bypasser service is expected to apply policy off-chain.
    ///         HSM compromise = full bypass authority.
    ///         The event is emitted on every call (even idempotent no-ops)
    ///         so off-chain indexers see every governance-level intent.
    function setTimelockBypasser(address bypasser, bool allowed) public virtual {
        require(bypasser != address(0), BypasserZeroAddress());
        _timelockConfigs[msg.sender].timelockBypassers[bypasser] = allowed;
        emit TimelockBypasserChanged(msg.sender, bypasser, allowed);
    }

    /// @notice Optimism-style scheduler. Anyone can submit a fully signed
    ///         Safe transaction for scheduling without consuming the Safe
    ///         nonce. The same Safe signatures remain usable for execution
    ///         after `timelockDelay`.
    function scheduleTransaction(
        address safe,
        uint256 nonce,
        ExecTransactionParams calldata params,
        bytes calldata signatures
    ) public virtual returns (bytes32 safeTxHash) {
        ISafe safe_ = ISafe(payable(safe));

        SafeTimelockConfig storage cfg = _timelockConfigs[safe];
        require(cfg.timelockDelay != 0, TimelockDisabled());
        require(nonce >= safe_.nonce(), StaleSafeNonce());

        // Hash transaction and verify signatures.
        safeTxHash = safe_.getTransactionHash(
            params.to,
            params.value,
            params.data,
            params.operation,
            params.safeTxGas,
            params.baseGas,
            params.gasPrice,
            params.gasToken,
            params.refundReceiver,
            nonce
        );
        safe_.checkSignatures(address(0), safeTxHash, signatures);

        // Schedule the ticket. Revert if already scheduled.
        bytes32 ticketKey = safeTxHash.ownerTicketKey();
        require(cfg.ticketExecutableAt[ticketKey] == 0, TicketAlreadyExists());
        uint64 executableAt = cfg.ticketExecutableAt[ticketKey] = uint64(block.timestamp) + cfg.timelockDelay;

        // Emit event for off-chain indexers
        emit TransactionScheduled(safe, safeTxHash, executableAt);
    }

    /// @notice Module-path scheduling primitive. msg.sender is the Safe.
    ///         The Safe's owner quorum schedules an upcoming module call;
    ///         the module guard hook checks the same ticket at
    ///         execution time and consumes it. No bypass exists for
    ///         module-path (Q-Bypass-5: out of V1 scope).
    function scheduleModuleTransaction(
        address module,
        address to,
        uint256 value,
        bytes calldata data,
        Enum.Operation operation
    ) public virtual returns (bytes32 moduleTxHash) {
        SafeTimelockConfig storage cfg = _timelockConfigs[msg.sender];
        require(cfg.timelockDelay != 0, TimelockDisabled());

        // Hash module call
        moduleTxHash = getModuleTransactionHash(msg.sender, module, to, value, data, operation);

        // Schedule the ticket. Revert if already scheduled.
        bytes32 ticketKey = moduleTxHash.moduleTicketKey();
        require(cfg.ticketExecutableAt[ticketKey] == 0, TicketAlreadyExists());
        uint64 executableAt = cfg.ticketExecutableAt[ticketKey] = uint64(block.timestamp) + cfg.timelockDelay;

        // Emit event for off-chain indexers. The module path has no Safe
        // Transaction Service as an observability source, so the event carries
        // the full call (to, value, data, operation) - not just the hash - so
        // monitoring can reconstruct the scheduled module call.
        emit ModuleTransactionScheduled(msg.sender, module, moduleTxHash, to, value, data, operation, executableAt);
    }

    /// @notice Cancel an owner-path ticket. msg.sender is the Safe.
    /// @dev    Allowed regardless of `timelockDelay` (the user may have
    ///         disabled the timelock but still want to clean up old
    ///         entries). Forbidden during LockedDown and Recovering by
    ///         the hook layer (recovery whitelist), so cleanup must be
    ///         scheduled before incident or after resume.
    function cancelTransaction(bytes32 safeTxHash) public virtual {
        _cancelTicket(msg.sender, safeTxHash.ownerTicketKey());
    }

    /// @notice Cancel a module-path scheduled ticket. msg.sender is the Safe.
    function cancelModuleTransaction(bytes32 moduleTxHash) public virtual {
        _cancelTicket(msg.sender, moduleTxHash.moduleTicketKey());
    }

    /// @notice HSM-side: an allowlisted bypasser writes `executableAt = now`
    ///         for a specific owner-path `safeTxHash`. After this call, the
    ///         Safe owners can execute the transaction immediately without
    ///         waiting `timelockDelay`.
    /// @dev    Direct call by `msg.sender` (the bypasser EOA / contract).
    ///         The bypasser only sees the hash, so it cannot enforce
    ///         policy on-chain about WHAT is bypassable. The bypasser
    ///         off-chain service is expected to refuse bypasses for
    ///         policy-sensitive operations (admin self-calls,
    ///         setTimelockBypasser, setGuard, etc.). Operator accepts
    ///         this trust model (gap analysis Q-Bypass-1 option A).
    function bypassTimelock(address safe, bytes32 safeTxHash) public virtual {
        SafeTimelockConfig storage cfg = _timelockConfigs[safe];
        require(cfg.timelockDelay != 0, TimelockDisabled());
        require(cfg.timelockBypassers[msg.sender], NotTimelockBypasser());
        bytes32 ticketKey = safeTxHash.ownerTicketKey();
        cfg.ticketExecutableAt[ticketKey] = uint64(block.timestamp);
        emit TimelockBypassed(safe, safeTxHash, msg.sender);
    }

    /// @notice Permissionless cleanup of an owner-path ticket that has
    ///         already passed its TTL. Anyone may call this; the only effect
    ///         is to delete the storage slot for an entry that is already
    ///         unreachable (the hook would revert `TicketExpired` if
    ///         the Safe tried to execute it). State-gate free: callable in
    ///         Normal, LockedDown, and Recovering, because cleaning an
    ///         expired ticket cannot affect any reachable execution path.
    /// @dev    Reverts `TicketNotFound` if no entry exists.
    ///         Reverts `TicketNotExpired` if the entry is still within
    ///         its TTL window (cancel via the Safe quorum instead).
    function sweepExpiredOwnerTicket(address safe, bytes32 safeTxHash) public virtual {
        _sweepTicket(safe, safeTxHash.ownerTicketKey());
    }

    /// @notice Permissionless cleanup of a module-path scheduled ticket past TTL.
    ///         Same semantics as `sweepExpiredOwnerTicket` for the
    ///         module ticket key.
    function sweepExpiredModuleTicket(address safe, bytes32 moduleTxHash) public virtual {
        _sweepTicket(safe, moduleTxHash.moduleTicketKey());
    }

    // -------------------------------------------------------------------
    // Public accessors
    // -------------------------------------------------------------------

    /// @notice The Safe's current timelock delay. 0 means timelock disabled.
    function getTimelockDelay(address safe) public view returns (uint64) {
        return _timelockConfigs[safe].timelockDelay;
    }

    function isTimelockBypasser(address safe, address bypasser) public view virtual returns (bool) {
        return _timelockConfigs[safe].timelockBypassers[bypasser];
    }

    /// @notice Returns the `executableAt` timestamp for an owner-path
    ///         scheduled ticket, or 0 if none is pending.
    function getTransactionExecutableAt(address safe, bytes32 safeTxHash) public view virtual returns (uint64) {
        return _timelockConfigs[safe].ticketExecutableAt[safeTxHash.ownerTicketKey()];
    }

    /// @notice Returns the `executableAt` timestamp for a module-path
    ///         scheduled ticket, or 0 if none is pending. Computes the module
    ///         hash internally so callers do not have to reimplement the
    ///         packing.
    function getModuleTransactionExecutableAt(address safe, bytes32 moduleTxHash) public view virtual returns (uint64) {
        return _timelockConfigs[safe].ticketExecutableAt[moduleTxHash.moduleTicketKey()];
    }

    /// @notice Off-chain helper: returns the module-path scheduling hash
    ///         for the given parameters. Indexers can match this against
    ///         `ModuleTransactionScheduled.moduleTxHash`.
    function getModuleTransactionHash(
        address safe,
        address module,
        address to,
        uint256 value,
        bytes calldata data,
        Enum.Operation operation
    ) public view virtual returns (bytes32) {
        return LockdownLib.moduleTxHash(safe, module, to, value, data, operation);
    }

    //--------------------------------------------------------------------
    // Helpers
    //--------------------------------------------------------------------

    /// @dev Read-only ticket validity check (V1 review round 3, INV-TIME-4
    ///      hardening). A failed inner execution under Safe v1.5.0
    ///      semantics must NOT silently burn a scheduled ticket.
    ///
    ///      Safe v1.5.0 module path: `execTransactionFromModule` catches
    ///      inner reverts (emits `ExecutionFromModuleFailure`) and the outer
    ///      tx commits. The module pre-hook verifies then consumes the
    ///      ticket (so a nested re-execution of the same module tx finds no
    ///      ticket), and `checkAfterModuleExecution` re-creates it on
    ///      failure (see `_restoreTicket`) so the operator can retry.
    ///
    ///      Safe v1.5.0 owner path: when `safeTxGas == 0 && gasPrice == 0`,
    ///      an inner revert rolls back the entire tx including any pre-hook
    ///      writes (no semantic difference). When either is non-zero, Safe
    ///      v1.5.0 may commit the outer tx despite the inner revert (the
    ///      `safeTxGas` try/catch pattern); the nonce advances but the
    ///      ticket now survives until the operator cancels or the TTL
    ///      expires (residual grief surface: a same-params replay requires
    ///      a new ticket at the new nonce).
    ///
    ///      Reverts: `TicketNotFound` if no entry, `TicketExpired` if
    ///      past TTL (the entry stays in storage because the revert rolls
    ///      back any `delete`; the Safe quorum may `cancelTransaction(...)`
    ///      to reclaim the slot), `TimelockNotElapsed` if before
    ///      `executableAt`.
    function _verifyTicket(address safe, bytes32 ticketKey) internal view {
        uint64 executableAt = _timelockConfigs[safe].ticketExecutableAt[ticketKey];
        require(executableAt != 0, TicketNotFound());
        require(block.timestamp <= uint256(executableAt) + TICKET_TTL, TicketExpired());
        require(block.timestamp >= executableAt, TimelockNotElapsed());
    }

    function _consumeTicket(address safe, bytes32 ticketKey) internal returns (bool consumed) {
        SafeTimelockConfig storage cfg = _timelockConfigs[safe];
        if (cfg.ticketExecutableAt[ticketKey] != 0) {
            delete cfg.ticketExecutableAt[ticketKey];
            emit TimelockConsumed(safe, ticketKey);
            return true;
        } else {
            return false;
        }
    }

    /// @dev Re-create a module ticket consumed by the pre-hook of a module call
    ///      that failed. Only called while `timelockDelay > 0`, where the
    ///      pre-hook verified the ticket was executable: `executableAt = now`
    ///      therefore never makes it executable earlier. It does restart the
    ///      `TICKET_TTL` window, so every failed attempt extends the ticket's
    ///      lifetime (room for retries; the quorum can still cancel it).
    function _restoreTicket(address safe, bytes32 ticketKey) internal {
        uint64 executableAt = uint64(block.timestamp);
        _timelockConfigs[safe].ticketExecutableAt[ticketKey] = executableAt;
        emit TicketRestored(safe, ticketKey, executableAt);
    }

    function _cancelTicket(address safe, bytes32 ticketKey) private {
        SafeTimelockConfig storage cfg = _timelockConfigs[safe];
        require(cfg.ticketExecutableAt[ticketKey] != 0, TicketNotFound());
        delete cfg.ticketExecutableAt[ticketKey];
        emit TicketCancelled(safe, ticketKey);
    }

    function _sweepTicket(address safe, bytes32 ticketKey) private {
        SafeTimelockConfig storage cfg = _timelockConfigs[safe];
        uint64 executableAt = cfg.ticketExecutableAt[ticketKey];
        require(executableAt != 0, TicketNotFound());
        require(block.timestamp > uint256(executableAt) + TICKET_TTL, TicketNotExpired());
        delete cfg.ticketExecutableAt[ticketKey];
        emit TicketSwept(safe, ticketKey, msg.sender);
    }
}
