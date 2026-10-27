// SPDX-License-Identifier: MIT
// NM-1060 6.1 (High): `LockdownFallbackHandler.isValidSignature` read only the incident
// state. In Normal it validated owner signatures (inline via `checkSignatures`, or an
// empty signature via `safe.signedMessages`) and never read the timelock, so a coerced
// quorum could sign an EIP-3009 `transferWithAuthorization` / EIP-2612-style permit on a
// token that verifies through ERC-1271 (USDC, EURC, PYUSD use SignatureChecker), or a
// Permit2 / CoW / Seaport order, and the attacker settled it immediately: zero reaction
// window despite `timelockDelay > 0`.
//
// Fix (SPEC_V1 H.27): ERC-1271 is an explicit per-Safe operator choice stored on the
// singleton (`erc1271Allowed`, default `false` = disabled). The handler reverts
// `Erc1271Disabled` unless the Safe opted in, on both branches, after the unchanged
// incident gate. Opting in is an owner-path, `onlyNormal`, timelocked config call.
pragma solidity ^0.8.24;

import {TestEnvironment} from "../TestEnvironment.sol";

import {ISafe} from "@safe-global/safe-smart-account/interfaces/ISafe.sol";
import {Safe, Enum} from "@safe-global/safe-smart-account/Safe.sol";
import {MultiSendCallOnly} from "@safe-global/safe-smart-account/libraries/MultiSendCallOnly.sol";
import {SignMessageLib} from "@safe-global/safe-smart-account/libraries/SignMessageLib.sol";
import {SignatureChecker} from "@openzeppelin/contracts/utils/cryptography/SignatureChecker.sol";

import {Lockdown} from "../../src/Lockdown.sol";
import {Timelock} from "../../src/base/Timelock.sol";
import {StateMachine} from "../../src/base/StateMachine.sol";
import {LockdownFallbackHandler} from "../../src/handlers/LockdownFallbackHandler.sol";

/// @dev USDC-v2.2-style token: EIP-3009 `transferWithAuthorization(..., bytes signature)`
///      verified with OpenZeppelin `SignatureChecker`, i.e. ERC-1271 for contract
///      wallets. The digest is opaque to the Safe; the token settles with no Safe tx.
contract MockEip3009Token {
    bytes32 public constant TYPEHASH = keccak256(
        "TransferWithAuthorization(address from,address to,uint256 value,uint256 validAfter,uint256 validBefore,bytes32 nonce)"
    );
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(bytes32 => bool)) public authorizationState;

    function mint(address to, uint256 amount) external {
        balanceOf[to] += amount;
    }

    function digest(address from, address to, uint256 value, bytes32 nonce) public view returns (bytes32) {
        return keccak256(
            abi.encodePacked(
                "\x19\x01",
                keccak256(abi.encode(block.chainid, address(this))),
                keccak256(abi.encode(TYPEHASH, from, to, value, 0, type(uint256).max, nonce))
            )
        );
    }

    function transferWithAuthorization(address from, address to, uint256 value, bytes32 nonce, bytes memory sig)
        external
    {
        require(!authorizationState[from][nonce], "used");
        require(SignatureChecker.isValidSignatureNow(from, digest(from, to, value, nonce), sig), "invalid sig");
        authorizationState[from][nonce] = true;
        balanceOf[from] -= value;
        balanceOf[to] += value;
    }
}

contract Erc1271OptInPoC is TestEnvironment {
    bytes4 private constant ERC1271_MAGIC = 0x1626ba7e;
    uint64 private constant DELAY = 1 days;
    address private constant ATTACKER = address(0xBAD);
    uint256 private constant AMOUNT = 1_000_000e6;

    event Erc1271AllowedChanged(address indexed safe, bool allowed);

    MockEip3009Token private token;
    Safe private safe;

    function setUp() public override {
        super.setUp();
        token = new MockEip3009Token();
        safe = _createConfigureAndInitialise(611);
        token.mint(address(safe), AMOUNT);
    }

    // ------------------------------------------------------------------
    // Helpers
    // ------------------------------------------------------------------

    function _coercedAuthorization(ISafe instance, bytes32 nonce) private view returns (bytes memory) {
        return _signMessage(instance, OWNER_PK, token.digest(address(instance), ATTACKER, AMOUNT, nonce));
    }

    function _settle(ISafe instance, bytes32 nonce, bytes memory sig) private returns (bool ok) {
        vm.prank(ATTACKER);
        (ok,) = address(token)
            .call(
                abi.encodeCall(
                    MockEip3009Token.transferWithAuthorization, (address(instance), ATTACKER, AMOUNT, nonce, sig)
                )
            );
    }

    function _isValidSignature(ISafe instance, bytes32 hash, bytes memory sig)
        private
        returns (bool ok, bytes memory ret)
    {
        (ok, ret) = address(instance)
            .call(abi.encodeWithSelector(LockdownFallbackHandler.isValidSignature.selector, hash, sig));
    }

    function _assertValid(ISafe instance, bytes32 hash, bytes memory sig, string memory why) private {
        (bool ok, bytes memory ret) = _isValidSignature(instance, hash, sig);
        assertTrue(ok, why);
        assertEq(abi.decode(ret, (bytes4)), ERC1271_MAGIC, why);
    }

    function _assertReverts(ISafe instance, bytes32 hash, bytes memory sig, bytes4 err, string memory why) private {
        (bool ok, bytes memory ret) = _isValidSignature(instance, hash, sig);
        assertFalse(ok, why);
        assertEq(bytes4(ret), err, why);
    }

    function _assertDisabled(ISafe instance, bytes32 hash, bytes memory sig, string memory why) private {
        _assertReverts(instance, hash, sig, LockdownFallbackHandler.Erc1271Disabled.selector, why);
    }

    function _assertFrozen(ISafe instance, bytes32 hash, bytes memory sig, string memory why) private {
        _assertReverts(instance, hash, sig, LockdownFallbackHandler.SignaturesFrozenDuringLockdown.selector, why);
    }

    function _setAllowed(ISafe instance, address singleton, bool allowed) private {
        _execAsOwner(instance, singleton, 0, abi.encodeCall(Lockdown.setErc1271Allowed, (allowed)), Enum.Operation.Call);
    }

    function _schedule(ISafe instance, address to, bytes memory data) private {
        guard.scheduleTransaction(
            address(instance),
            instance.nonce(),
            Timelock.ExecTransactionParams({
                to: to,
                value: 0,
                data: data,
                operation: Enum.Operation.Call,
                safeTxGas: 0,
                baseGas: 0,
                gasPrice: 0,
                gasToken: address(0),
                refundReceiver: payable(address(0))
            }),
            _signTx(instance, OWNER_PK, to, 0, data, Enum.Operation.Call)
        );
    }

    /// @dev Writes a permanent `signedMessages` entry via SignMessageLib DELEGATECALL,
    ///      which is only possible BEFORE the Lockdown guard is installed.
    function _preInstallSignedMessage(Safe fresh, bytes32 d) private {
        SignMessageLib lib = new SignMessageLib();
        _execAsOwner(
            fresh,
            address(lib),
            0,
            abi.encodeCall(SignMessageLib.signMessage, (abi.encode(d))),
            Enum.Operation.DelegateCall
        );
        assertTrue(fresh.signedMessages(handler.getMessageHashForSafe(fresh, abi.encode(d))) != 0, "entry written");
    }

    function _install(Safe instance, Lockdown singleton, LockdownFallbackHandler h) private {
        vm.startPrank(address(instance));
        instance.setGuard(address(singleton));
        instance.setModuleGuard(address(singleton));
        instance.setFallbackHandler(address(h));
        vm.stopPrank();
        _execAsOwner(instance, address(singleton), 0, _initCall(), Enum.Operation.Call);
    }

    function _initCall() private view returns (bytes memory) {
        address[] memory recoveryOwners = new address[](1);
        recoveryOwners[0] = recovery;
        bytes[] memory signers = new bytes[](1);
        signers[0] = abi.encodePacked(panicKey);
        return abi.encodeCall(Lockdown.initialize, (48 hours, 4 hours, recoveryOwners, signers));
    }

    // ------------------------------------------------------------------
    // Default: disabled (fail-closed)
    // ------------------------------------------------------------------

    /// @dev NM-1060 6.1: after a plain install the coerced authorization no longer
    ///      settles, at delay 0 as well as under a timelock.
    function test_default_disabledAfterInstall() public {
        assertFalse(guard.isErc1271Allowed(address(safe)), "default false");
        bytes32 nonce = keccak256("n0");
        bytes memory sig = _coercedAuthorization(safe, nonce);
        _assertDisabled(safe, token.digest(address(safe), ATTACKER, AMOUNT, nonce), sig, "inline, delay 0");
        assertFalse(_settle(safe, nonce, sig), "no settlement at delay 0");

        _enableTimelock(safe, DELAY);
        _assertDisabled(safe, token.digest(address(safe), ATTACKER, AMOUNT, nonce), sig, "inline, delay N");
        assertFalse(_settle(safe, nonce, sig), "no settlement at delay N");
        assertEq(token.balanceOf(address(safe)), AMOUNT, "funds stay");
    }

    /// @dev `signedMessages` is a permanent Safe boolean. An entry written BEFORE the
    ///      Lockdown install is refused by default and only honoured after an opt-in.
    function test_default_preInstallSignedMessageRejected() public {
        Safe fresh = _createSafe(612);
        bytes32 nonce = keccak256("pre-install");
        bytes32 d = token.digest(address(fresh), ATTACKER, AMOUNT, nonce);
        _preInstallSignedMessage(fresh, d);
        _install(fresh, guard, handler);
        token.mint(address(fresh), AMOUNT);

        _assertDisabled(fresh, d, "", "signedMessages branch gated by default");
        assertFalse(_settle(fresh, nonce, ""), "pre-install approval cannot settle");
        assertEq(token.balanceOf(address(fresh)), AMOUNT, "funds stay");

        _setAllowed(fresh, address(guard), true);
        _assertValid(fresh, d, "", "signedMessages honoured once opted in");
    }

    /// @dev Handler installed but `initialize` not run yet: the flag reads `false`, and
    ///      the setter is `onlyNormal` so it cannot be flipped before `initialize`.
    function test_default_uninitialisedSafeDisabledAndSetterRejected() public {
        Safe fresh = _createAndConfigure(614);
        bytes32 h = keccak256("order");
        _assertDisabled(fresh, h, _signMessage(fresh, OWNER_PK, h), "uninitialised");

        vm.prank(address(fresh));
        vm.expectRevert(
            abi.encodeWithSelector(
                StateMachine.InvalidState.selector,
                StateMachine.State.Uninitialised,
                1 << uint256(StateMachine.State.Normal)
            )
        );
        guard.setErc1271Allowed(true);
    }

    /// @dev The atomic install MultiSend may carry `setErc1271Allowed(true)` right after
    ///      `initialize` (state is already Normal for the second leaf).
    function test_install_multiSendInitializeThenAllow() public {
        Safe fresh = _createAndConfigure(615);
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
        assertTrue(guard.isErc1271Allowed(address(fresh)), "allowed in install batch");
        bytes32 h = keccak256("order");
        _assertValid(fresh, h, _signMessage(fresh, OWNER_PK, h), "valid after opt-in install");
    }

    // ------------------------------------------------------------------
    // Opt-in via the owner path
    // ------------------------------------------------------------------

    function test_enable_ownerPathEmitsAndAcceptsInNormal() public {
        vm.expectEmit(true, false, false, true, address(guard));
        emit Erc1271AllowedChanged(address(safe), true);
        _setAllowed(safe, address(guard), true);
        assertTrue(guard.isErc1271Allowed(address(safe)), "allowed");

        // Stored in the independent policy mapping: lifecycle fields are untouched.
        assertEq(guard.getLockdownDuration(address(safe)), 48 hours, "duration intact");
        assertEq(guard.getResumeDelay(address(safe)), 4 hours, "resume delay intact");
        assertEq(guard.getLockdownUntil(address(safe)), 0, "until intact");

        bytes32 h = keccak256("order");
        _assertValid(safe, h, _signMessage(safe, OWNER_PK, h), "inline valid");
        bytes32 nonce = keccak256("n1");
        assertTrue(_settle(safe, nonce, _coercedAuthorization(safe, nonce)), "accepted residual at delay 0");
    }

    /// @dev The incident gate runs first and keeps its own error whatever the flag; the
    ///      flag survives the incident (it is not cleared by `_lock`).
    function test_enabled_stillFrozenInLockedDownAndRecovering() public {
        _setAllowed(safe, address(guard), true);
        bytes32 h = keccak256("order");
        bytes memory sig = _signMessage(safe, OWNER_PK, h);
        _triggerLockdown(safe, bytes32("wrench"));
        _assertFrozen(safe, h, sig, "LockedDown");
        vm.warp(block.timestamp + 48 hours + 1);
        _assertFrozen(safe, h, sig, "Recovering");
        vm.warp(block.timestamp + 4 hours + 1);
        assertTrue(guard.isErc1271Allowed(address(safe)), "flag survives the incident");
        _assertValid(safe, h, sig, "auto-resumed, opted in");
    }

    /// @dev Disabled and allowed Safes alike see the incident error first.
    function test_disabled_incidentErrorTakesPrecedence() public {
        bytes32 h = keccak256("order");
        bytes memory sig = _signMessage(safe, OWNER_PK, h);
        _triggerLockdown(safe, bytes32("wrench"));
        _assertFrozen(safe, h, sig, "LockedDown");
        vm.warp(block.timestamp + 48 hours + 1);
        _assertFrozen(safe, h, sig, "Recovering");
        vm.warp(block.timestamp + 4 hours + 1);
        _assertDisabled(safe, h, sig, "Normal again: disabled");
    }

    /// @dev The flag cannot be flipped mid-incident: `onlyNormal`, and not on the
    ///      recovery whitelist.
    function test_setter_rejectedDuringIncident() public {
        bytes memory data = abi.encodeCall(Lockdown.setErc1271Allowed, (true));
        _triggerLockdown(safe, bytes32("wrench"));
        _execAsOwner_Revert(safe, address(guard), 0, data, Enum.Operation.Call, Lockdown.LockedDown.selector);
        vm.warp(block.timestamp + 48 hours + 1);
        _execAsOwner_Revert(safe, address(guard), 0, data, Enum.Operation.Call, Lockdown.RecoveryActive.selector);
        assertFalse(guard.isErc1271Allowed(address(safe)), "still disabled");
    }

    function test_disable_again() public {
        _setAllowed(safe, address(guard), true);
        bytes32 h = keccak256("order");
        bytes memory sig = _signMessage(safe, OWNER_PK, h);
        _assertValid(safe, h, sig, "enabled");

        vm.expectEmit(true, false, false, true, address(guard));
        emit Erc1271AllowedChanged(address(safe), false);
        _setAllowed(safe, address(guard), false);
        assertFalse(guard.isErc1271Allowed(address(safe)), "disabled");
        _assertDisabled(safe, h, sig, "disabled again");
    }

    // ------------------------------------------------------------------
    // Timelock interaction
    // ------------------------------------------------------------------

    /// @dev `setErc1271Allowed` is not a timelock meta-call: under `timelockDelay > 0`
    ///      it must be scheduled and wait the full delay.
    function test_timelock_enablingWaitsTheDelay() public {
        _enableTimelock(safe, DELAY);
        bytes memory data = abi.encodeCall(Lockdown.setErc1271Allowed, (true));

        _execAsOwner_Revert(safe, address(guard), 0, data, Enum.Operation.Call, Timelock.TicketNotFound.selector);

        _schedule(safe, address(guard), data);
        _execAsOwner_Revert(safe, address(guard), 0, data, Enum.Operation.Call, Timelock.TimelockNotElapsed.selector);
        vm.warp(block.timestamp + DELAY - 1);
        _execAsOwner_Revert(safe, address(guard), 0, data, Enum.Operation.Call, Timelock.TimelockNotElapsed.selector);
        assertFalse(guard.isErc1271Allowed(address(safe)), "still disabled during the window");

        vm.warp(block.timestamp + 1);
        _execAsOwner(safe, address(guard), 0, data, Enum.Operation.Call);
        assertTrue(guard.isErc1271Allowed(address(safe)), "allowed after the delay");

        // Operator-accepted residual: allowed AND delay > 0 re-opens NM-1060 6.1.
        bytes32 nonce = keccak256("residual");
        assertTrue(_settle(safe, nonce, _coercedAuthorization(safe, nonce)), "residual by operator choice");
    }

    /// @dev Disabling is equally timelocked (same setter, same path). A `cancel*`-only
    ///      meta-call carve-out does not cover it.
    function test_timelock_disablingAlsoWaitsTheDelay() public {
        _setAllowed(safe, address(guard), true);
        _enableTimelock(safe, DELAY);
        bytes memory data = abi.encodeCall(Lockdown.setErc1271Allowed, (false));
        _execAsOwner_Revert(safe, address(guard), 0, data, Enum.Operation.Call, Timelock.TicketNotFound.selector);
        _schedule(safe, address(guard), data);
        vm.warp(block.timestamp + DELAY);
        _execAsOwner(safe, address(guard), 0, data, Enum.Operation.Call);
        assertFalse(guard.isErc1271Allowed(address(safe)), "disabled after the delay");
    }

    // ------------------------------------------------------------------
    // Access control
    // ------------------------------------------------------------------

    function test_module_cannotCallSetter() public {
        bytes memory data = abi.encodeCall(Lockdown.setErc1271Allowed, (true));
        _moduleCall_Revert(
            module, safe, address(guard), 0, data, Enum.Operation.Call, Lockdown.ModuleCallToSingletonDenied.selector
        );
        bytes memory batch = _multiSendItem(Enum.Operation.Call, address(guard), 0, data);
        _moduleCall_Revert(
            module,
            safe,
            address(multiSendCallOnly),
            0,
            abi.encodeCall(MultiSendCallOnly.multiSend, (batch)),
            Enum.Operation.DelegateCall,
            Lockdown.ModuleCallToSingletonDenied.selector
        );
        assertFalse(guard.isErc1271Allowed(address(safe)), "still disabled");
    }

    /// @dev The setter keys off `msg.sender`: a third party only ever writes its own
    ///      (uninitialised, hence rejected) slot, and Safes are isolated from each other.
    function test_crossSafe_callerCannotFlipAnotherSafe() public {
        vm.prank(ATTACKER);
        vm.expectRevert(
            abi.encodeWithSelector(
                StateMachine.InvalidState.selector,
                StateMachine.State.Uninitialised,
                1 << uint256(StateMachine.State.Normal)
            )
        );
        guard.setErc1271Allowed(true);
        assertFalse(guard.isErc1271Allowed(address(safe)), "victim untouched");

        Safe b = _createConfigureAndInitialise(616);
        _setAllowed(b, address(guard), true);
        assertTrue(guard.isErc1271Allowed(address(b)), "B allowed");
        assertFalse(guard.isErc1271Allowed(address(safe)), "A still disabled");
        bytes32 h = keccak256("order");
        _assertDisabled(safe, h, _signMessage(safe, OWNER_PK, h), "A refuses");
        _assertValid(b, h, _signMessage(b, OWNER_PK, h), "B accepts");
    }

    // ------------------------------------------------------------------
    // Base flavour
    // ------------------------------------------------------------------

    /// @dev The flag lives in the base `Lockdown`, so the non-timelocked flavour behaves
    ///      the same: disabled by default, opt-in via the owner path, frozen in incidents.
    function test_baseFlavour_sameRule() public {
        Lockdown base = new Lockdown(address(multiSendCallOnly));
        LockdownFallbackHandler baseHandler = new LockdownFallbackHandler(base);
        Safe b = _createSafe(613);
        _install(b, base, baseHandler);
        token.mint(address(b), AMOUNT);

        bytes32 nonce = keccak256("base");
        bytes memory sig = _coercedAuthorization(b, nonce);
        bytes32 d = token.digest(address(b), ATTACKER, AMOUNT, nonce);
        _assertDisabled(b, d, sig, "base: disabled by default");
        assertFalse(_settle(b, nonce, sig), "base: no settlement by default");

        vm.expectEmit(true, false, false, true, address(base));
        emit Erc1271AllowedChanged(address(b), true);
        _setAllowed(b, address(base), true);
        _assertValid(b, d, sig, "base: valid once allowed");

        _triggerLockdownOn(base, b);
        _assertFrozen(b, d, sig, "base: frozen in LockedDown");
    }

    function _triggerLockdownOn(Lockdown singleton, ISafe instance) private {
        bytes32 reason = bytes32("wrench");
        bytes memory signer = abi.encodePacked(panicKey);
        bytes32 structHash =
            keccak256(abi.encode(singleton.LOCKDOWN_TYPEHASH(), address(instance), keccak256(signer), reason));
        (, string memory name, string memory version, uint256 chainId, address verifying,,) = singleton.eip712Domain();
        bytes32 domain = keccak256(
            abi.encode(
                keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
                keccak256(bytes(name)),
                keccak256(bytes(version)),
                chainId,
                verifying
            )
        );
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(PANIC_PK, keccak256(abi.encodePacked("\x19\x01", domain, structHash)));
        singleton.triggerLockdown(address(instance), reason, signer, abi.encodePacked(r, s, v));
    }

    // ------------------------------------------------------------------
    // Unchanged behaviour
    // ------------------------------------------------------------------

    /// @dev Token callbacks and the other handler views are untouched by the gate.
    function test_unchanged_tokenCallbacksWhileDisabled() public {
        (bool ok, bytes memory ret) = address(safe)
            .call(abi.encodeWithSignature("onERC721Received(address,address,uint256,bytes)", other, other, 1, ""));
        assertTrue(ok, "ERC721 callback");
        assertEq(bytes4(ret), bytes4(0x150b7a02));
        (ok,) = address(safe).call(abi.encodeWithSignature("getModules()"));
        assertTrue(ok, "getModules");
    }
}
