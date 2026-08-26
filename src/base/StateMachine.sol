// SPDX-License-Identifier: MIT
pragma solidity 0.8.35;

/// @custom:security-contact contact@runtime.capital
abstract contract StateMachine {
    /// @notice Smallest `lockdownDuration`. Two roles: (1) anti-fat-finger
    ///         floor so a panic freeze is operationally meaningful, and
    ///         (2) the absolute term of the T-LIVE-2 invariant
    ///         `lockdownDuration >= max(LOCKDOWN_DURATION_MIN, timelockDelay)`,
    ///         which guarantees the hard-freeze phase is never shorter than
    ///         the timelock delay it is meant to back (SPEC_V1 §14.2 / §17).
    uint64 public constant LOCKDOWN_DURATION_MIN = 1 hours;
    uint64 public constant LOCKDOWN_DURATION_MAX = 30 days;
    uint64 public constant RESUME_DELAY_MIN = 4 hours;
    uint64 public constant RESUME_DELAY_MAX = 7 days;

    bytes32 public constant LOCKDOWN_TYPEHASH = keccak256("Lockdown(address safe,bytes32 reasonHash)");

    enum State {
        Uninitialised,
        Normal,
        LockedDown,
        Recovering
    }

    struct SafeConfig {
        uint64 resumeDelay;
        uint64 lockdownDuration; // 0 ⟹ uninitialised
        uint64 lockdownUntil; // 0 ⟹ Normal state
        bytes32 lockdownReasonHash; // 0 ⟹ no reason
    }

    mapping(address safe => SafeConfig) private _configs;

    // -------------------------------------------------------------------
    // Events
    // -------------------------------------------------------------------

    event LockdownDurationChanged(address indexed safe, uint64 newDuration);
    event ResumeDelayChanged(address indexed safe, uint64 newDelay);
    /// @notice Emitted by a successful `triggerLockdown`. The trailing
    ///         signer bytes are the forensic trail: a watcher who missed the
    ///         original `LockdownSignerAdded` event can still resolve which
    ///         exact identity fired this trigger from this single event.
    event SafeLockedDown(address indexed safe, uint64 lockdownUntil, bytes32 reasonHash, bytes signer);

    // -------------------------------------------------------------------
    // Errors
    // -------------------------------------------------------------------

    error InvalidState(State state, uint256 expectedStates);
    error LockdownDurationTooHigh();
    error LockdownDurationTooLow();
    error ResumeDelayTooHigh();
    error ResumeDelayTooLow();

    // -------------------------------------------------------------------
    // Modifiers
    // -------------------------------------------------------------------

    modifier onlyUninitialised(address safe) {
        (State state,) = getState(safe);
        require(state == State.Uninitialised, InvalidState(state, 1 << uint256(State.Uninitialised)));
        _;
    }

    modifier onlyInitialized(address safe) {
        (State state,) = getState(safe);
        require(state != State.Uninitialised, InvalidState(state, ~(1 << uint256(State.Uninitialised))));
        _;
    }

    modifier onlyNormal(address safe) {
        (State state,) = getState(safe);
        require(state == State.Normal, InvalidState(state, 1 << uint256(State.Normal)));
        _;
    }

    /// @dev Permits every initialised state except the LockedDown hard-freeze
    ///      (Normal, Recovering). Uninitialised is also rejected, so
    ///      the gated function still reverts InvalidState before init.
    modifier onlyNotLockedDown(address safe) {
        (State state,) = getState(safe);
        require(
            state == State.Normal || state == State.Recovering,
            InvalidState(state, (1 << uint256(State.Normal)) | (1 << uint256(State.Recovering)))
        );
        _;
    }

    // -------------------------------------------------------------------
    // Accessors
    // -------------------------------------------------------------------

    function getState(address safe) public view returns (State state, uint64 secondsRemaining) {
        // all read at once from one slot
        uint64 lockdownDuration = _configs[safe].lockdownDuration;
        uint64 resumeDelay = _configs[safe].resumeDelay;
        uint64 lockdownUntil = _configs[safe].lockdownUntil;
        if (lockdownDuration == 0) {
            return (State.Uninitialised, 0);
        } else if (lockdownUntil == 0) {
            return (State.Normal, 0);
        } else if (block.timestamp < lockdownUntil) {
            return (State.LockedDown, lockdownUntil - uint64(block.timestamp));
        } else if (block.timestamp < lockdownUntil + resumeDelay) {
            // secondsRemaining is the countdown to the end of the freeze and is
            // reported only during LockedDown. During Recovering it is 0 by
            // design: the recovery-window end is derivable from getConfigSnapshot
            // (lockdownUntil + resumeDelay).
            return (State.Recovering, 0);
        } else {
            // Recovery window elapsed: auto-resume to Normal, purely time-based
            // (no resume tx, no event). NOTE: lockdownUntil / lockdownReasonHash
            // are NOT cleared here, so a stale non-zero lockdownUntil can coexist
            // with Normal. The `lockdownUntil == 0 => Normal` shortcut above is
            // one-directional; always derive the state from getState, never from
            // the raw scalars. The stale values are overwritten by the next
            // `_lock`, or zeroed by `_setResumeDelay` once the window has elapsed
            // (so a later resumeDelay increase cannot re-open this dead window).
            return (State.Normal, 0);
        }
    }

    function getLockdownDuration(address safe) public view returns (uint64) {
        return _configs[safe].lockdownDuration;
    }

    function getResumeDelay(address safe) public view returns (uint64) {
        return _configs[safe].resumeDelay;
    }

    function getLockdownUntil(address safe) public view returns (uint64) {
        uint64 until = _configs[safe].lockdownUntil;
        return uint64(block.timestamp) < until + _configs[safe].resumeDelay ? until : 0;
    }

    function lastReasonHash(address safe) public view returns (bytes32) {
        uint64 until = _configs[safe].lockdownUntil;
        return
            uint64(block.timestamp) < until + _configs[safe].resumeDelay
                ? _configs[safe].lockdownReasonHash
                : bytes32(0);
    }

    // -------------------------------------------------------------------
    // Public setters
    // -------------------------------------------------------------------

    function setLockdownDuration(uint64 newDuration) public virtual {
        _setLockdownDuration(msg.sender, newDuration);
    }

    function setResumeDelay(uint64 newDelay) public virtual {
        _setResumeDelay(msg.sender, newDelay);
    }

    // -------------------------------------------------------------------
    // Internal setters
    // -------------------------------------------------------------------

    function _setLockdownDuration(address safe, uint64 newDuration) internal virtual {
        require(newDuration >= LOCKDOWN_DURATION_MIN, LockdownDurationTooLow());
        require(newDuration <= LOCKDOWN_DURATION_MAX, LockdownDurationTooHigh());
        _configs[safe].lockdownDuration = newDuration;
        emit LockdownDurationChanged(safe, newDuration);
    }

    function _setResumeDelay(address safe, uint64 newDelay) internal virtual {
        require(newDelay >= RESUME_DELAY_MIN, ResumeDelayTooLow());
        require(newDelay <= RESUME_DELAY_MAX, ResumeDelayTooHigh());
        // getState derives the recovery-window end live as `lockdownUntil +
        // resumeDelay`, and `_lock` never zeroes `lockdownUntil`, so a stale
        // non-zero scalar from an already auto-resumed incident lingers. Raising
        // `resumeDelay` would then retroactively re-open that dead window and
        // force the Safe back into Recovering with the closed incident's reason
        // hash. Clear the elapsed incident before writing the new delay. The
        // elapsed guard means an active LockedDown/Recovering window is never
        // cleared here (defence-in-depth; the public setter is `onlyNormal`).
        SafeConfig storage config = _configs[safe];
        uint64 lockdownUntil = config.lockdownUntil;
        if (lockdownUntil != 0 && block.timestamp >= uint256(lockdownUntil) + config.resumeDelay) {
            config.lockdownUntil = 0;
            config.lockdownReasonHash = bytes32(0);
        }
        config.resumeDelay = newDelay;
        emit ResumeDelayChanged(safe, newDelay);
    }

    function _lock(address safe, bytes32 reasonHash, bytes memory signer) internal virtual {
        uint64 until = uint64(block.timestamp) + _configs[safe].lockdownDuration;
        _configs[safe].lockdownUntil = until;
        _configs[safe].lockdownReasonHash = reasonHash;
        emit SafeLockedDown(safe, until, reasonHash, signer);
    }
}
