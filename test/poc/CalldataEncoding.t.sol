// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {TestEnvironment} from "../TestEnvironment.sol";

import {Safe, Enum} from "@safe-global/safe-smart-account/Safe.sol";
import {MultiSendCallOnly} from "@safe-global/safe-smart-account/libraries/MultiSendCallOnly.sol";
import {IGuardManager} from "@safe-global/safe-smart-account/interfaces/IGuardManager.sol";
import {IModuleManager} from "@safe-global/safe-smart-account/interfaces/IModuleManager.sol";
import {IFallbackManager} from "@safe-global/safe-smart-account/interfaces/IFallbackManager.sol";
import {IOwnerManager} from "@safe-global/safe-smart-account/interfaces/IOwnerManager.sol";

import {Lockdown} from "../../src/Lockdown.sol";
import {StateMachine} from "../../src/base/StateMachine.sol";

contract CalldataTarget {
    uint256 public calls;

    function mark() external {
        ++calls;
    }
}

/// @dev A fallback handler that answers `LOCKDOWN()` with the wrong singleton.
contract WrongBoundHandler {
    function LOCKDOWN() external pure returns (address) {
        return address(0xBAD);
    }
}

/// @notice Calldata / encoding adversarial surface for the V1 guard.
/// @dev    Every candidate is decided by execution, never by reading. Names:
///         `test_confirmed_*`  - the divergence is real,
///         `test_refuted_*`    - the candidate is stopped by a named check,
///         `test_limitation_*` - real but accepted / non-exploitable behaviour.
contract CalldataEncodingPoC is TestEnvironment {
    // Panic(uint256) codes.
    uint256 private constant PANIC_ENUM_CONVERSION = 0x21;

    address private constant SENTINEL_OWNERS = address(0x1);

    Safe private pocSafe;
    CalldataTarget private target;

    function setUp() public override {
        super.setUp();
        pocSafe = _createConfigureAndInitialise(91);
        target = new CalldataTarget();
        vm.deal(address(pocSafe), 10 ether);
    }

    // ------------------------------------------------------------------
    // Helpers
    // ------------------------------------------------------------------

    function _multiSend(bytes memory transactions) private pure returns (bytes memory) {
        return abi.encodeCall(MultiSendCallOnly.multiSend, (transactions));
    }

    /// @dev Direct guard pre-hook call, impersonating the Safe, so a payload
    ///      that the Safe's own ABI decoder would reject can still be pushed
    ///      through `_checkCall`.
    function _pokeGuard(address to, uint256 value, bytes memory data, Enum.Operation op) private {
        vm.prank(address(pocSafe));
        guard.checkTransaction(to, value, data, op, 0, 0, 0, address(0), payable(address(0)), "", address(0));
    }

    function _pokeGuard_Revert(address to, uint256 value, bytes memory data, Enum.Operation op, bytes memory err)
        private
    {
        vm.prank(address(pocSafe));
        vm.expectRevert(err);
        guard.checkTransaction(to, value, data, op, 0, 0, 0, address(0), payable(address(0)), "", address(0));
    }

    /// @dev Raw `execTransaction` so an empty (data-less) revert can be observed
    ///      without a bare `vm.expectRevert()`.
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

    function _enterRecovery() private {
        _triggerLockdown(pocSafe, keccak256("calldata-poc"));
        vm.warp(block.timestamp + 48 hours + 1);
        (StateMachine.State state,) = guard.getState(address(pocSafe));
        assertEq(uint256(state), uint256(StateMachine.State.Recovering), "recovering");
    }

    // ==================================================================
    // C1 - `_decodeCalldataBytes` bounds arithmetic (Lockdown.sol:538-546).
    // Both tests below were CONFIRMED defects; the bounds are now checked by
    // subtraction against `input.length` and both tests pin the fix.
    // ==================================================================

    /// REGRESSION PIN. `_decodeCalldataBytes` used to compute its bounds check with
    /// wrapping `add`, so an offset of -0xA4 made `transactions` point at the guard's
    /// OWN checkTransaction calldata (the zero `gasToken` head word) and the guard
    /// validated a fabricated EMPTY batch instead of the caller's payload. Nothing in
    /// `Lockdown.sol` rejected it; the payload only died later inside
    /// MultiSendCallOnly's ABI decoder, so the guard was not self-sufficient.
    /// The offset is now bounded by subtraction against `input.length`, and the guard
    /// rejects the payload itself with its own selector.
    function test_regression_decodeCalldataBytesOffsetWraparoundRejectedByGuard() public {
        // Head layout of checkTransaction(...): 4 + 11 words. `data` tail content
        // starts at 388, so data[4:] starts at 392; 392 - 0xA4 = 228 = the
        // `gasToken` head word, which is zero on both the direct and the Safe path.
        bytes memory data = abi.encodePacked(MultiSendCallOnly.multiSend.selector, bytes32(type(uint256).max - 0xA3));
        assertEq(data.length, 36, "offset word only");

        // The guard now rejects it, with its own error selector.
        _pokeGuard_Revert(
            address(multiSendCallOnly),
            0,
            data,
            Enum.Operation.DelegateCall,
            abi.encodeWithSelector(Lockdown.BadMultiSendCallOnlyPayload.selector)
        );

        // Same payload through a real Safe: the rejection comes from the guard, so
        // the revert carries the guard's selector rather than the empty revert data
        // MultiSendCallOnly's ABI decoder used to produce.
        (bool ok, bytes memory ret) = _rawExec(address(multiSendCallOnly), 0, data, Enum.Operation.DelegateCall);
        assertFalse(ok, "execution reverts");
        assertEq(bytes4(ret), Lockdown.BadMultiSendCallOnlyPayload.selector, "rejected by the guard, not by MSCO");
    }

    /// REGRESSION PIN, second manifestation of the same unchecked `add`: declaring
    /// `transactions.length = type(uint256).max` used to wrap
    /// `output.offset + output.length` BELOW the slice end, so the bounds check passed
    /// and `_checkCall` walked a ~2^250-record batch, reading past the end of calldata
    /// until it ran out of gas. Fail-closed, but only by gas exhaustion.
    /// The declared length is now bounded by subtraction, so the payload is rejected
    /// immediately, cheaply, and with a named error.
    function test_regression_declaredLengthOverflowRejectedByGuard() public {
        bytes memory data =
            abi.encodePacked(MultiSendCallOnly.multiSend.selector, bytes32(uint256(0x20)), bytes32(type(uint256).max));

        uint256 gasBefore = gasleft();
        vm.prank(address(pocSafe));
        (bool ok, bytes memory ret) = address(guard).call{gas: 5_000_000}(
            abi.encodeCall(
                guard.checkTransaction,
                (
                    address(multiSendCallOnly),
                    0,
                    data,
                    Enum.Operation.DelegateCall,
                    0,
                    0,
                    0,
                    address(0),
                    payable(address(0)),
                    "",
                    address(0)
                )
            )
        );
        assertFalse(ok, "does not return");
        // Rejected by a real check: the named error, not an out-of-gas empty revert.
        assertEq(bytes4(ret), Lockdown.BadMultiSendCallOnlyPayload.selector, "BadMultiSendCallOnlyPayload");
        assertLt(gasBefore - gasleft(), 1_000_000, "rejected cheaply, not by burning the budget");
    }

    /// Corollary: a canonical payload cannot be pointed outside `data`. Offset = 0x40
    /// (one word past the length word) already fails. This case was always rejected,
    /// including before the bounds fix, because it does not wrap.
    function test_refuted_forwardOutOfRangeOffsetRejected() public {
        bytes memory data = abi.encodePacked(MultiSendCallOnly.multiSend.selector, bytes32(uint256(0x40)));
        _pokeGuard_Revert(
            address(multiSendCallOnly),
            0,
            data,
            Enum.Operation.DelegateCall,
            abi.encodeWithSelector(Lockdown.BadMultiSendCallOnlyPayload.selector)
        );
    }

    /// A 4-byte `data` (selector only) leaves a zero-length slice. Before the bounds
    /// fix, `_decodeCalldataBytes` calldataload'ed PAST its own slice (into the
    /// caller's checkTransaction calldata) and then failed closed on the success
    /// check. It now rejects on the `input.length >= 0x20` precondition, so the
    /// out-of-slice read no longer happens at all.
    function test_refuted_selectorOnlyPayloadRejectedBeforeAnyOutOfSliceRead() public {
        bytes memory data = abi.encodePacked(MultiSendCallOnly.multiSend.selector);
        _pokeGuard_Revert(
            address(multiSendCallOnly),
            0,
            data,
            Enum.Operation.DelegateCall,
            abi.encodeWithSelector(Lockdown.BadMultiSendCallOnlyPayload.selector)
        );
    }

    // ==================================================================
    // C2 - trailing garbage / the `offset == transactions.length` check (:473)
    // ==================================================================

    /// Trailing bytes shorter than one record are caught by the IN-LOOP bound at
    /// Lockdown.sol:444, not by :473.
    function test_refuted_trailingGarbageShorterThanRecordRejectedInLoop() public {
        bytes memory batch = abi.encodePacked(
            _multiSendItem(Enum.Operation.Call, address(target), 0, abi.encodeCall(CalldataTarget.mark, ())), hex"00"
        );
        _pokeGuard_Revert(
            address(multiSendCallOnly),
            0,
            _multiSend(batch),
            Enum.Operation.DelegateCall,
            abi.encodeWithSelector(Lockdown.BadMultiSendCallOnlyPayload.selector)
        );
    }

    /// Trailing bytes of at least one record size are simply parsed as another
    /// record (here: 0x55 zero bytes = a zero-value, empty-data self-call, which
    /// the owner path allows). So garbage is either consumed by the loop or
    /// rejected in-loop; `offset` can never overshoot `transactions.length`, and
    /// the final `require(offset == transactions.length)` at Lockdown.sol:473 is
    /// UNREACHABLE. (Confirms the mutation-testing result.)
    function test_refuted_finalLengthCheckUnreachableBecauseLoopIsExact() public {
        bytes memory batch = abi.encodePacked(
            _multiSendItem(Enum.Operation.Call, address(target), 0, abi.encodeCall(CalldataTarget.mark, ())),
            new bytes(0x55)
        );
        // Accepted: the 0x55 trailing zeros decode as a second, benign record.
        _pokeGuard(address(multiSendCallOnly), 0, _multiSend(batch), Enum.Operation.DelegateCall);

        // And the loop bound is exact for every prefix length below one record.
        for (uint256 extra = 1; extra < 0x55; extra += 0x14) {
            bytes memory ragged =
                abi.encodePacked(_multiSendItem(Enum.Operation.Call, address(target), 0, ""), new bytes(extra));
            _pokeGuard_Revert(
                address(multiSendCallOnly),
                0,
                _multiSend(ragged),
                Enum.Operation.DelegateCall,
                abi.encodeWithSelector(Lockdown.BadMultiSendCallOnlyPayload.selector)
            );
        }
    }

    /// The declared `dataLength` at Lockdown.sol:455 is never trusted: :457
    /// re-derives the remaining space before the slice is taken.
    function test_refuted_forgedInnerDataLengthRejected() public {
        bytes memory record =
            abi.encodePacked(uint8(Enum.Operation.Call), address(target), uint256(0), type(uint256).max, hex"deadbeef");
        _pokeGuard_Revert(
            address(multiSendCallOnly),
            0,
            _multiSend(record),
            Enum.Operation.DelegateCall,
            abi.encodeWithSelector(Lockdown.BadMultiSendCallOnlyPayload.selector)
        );
    }

    // ==================================================================
    // C3 - `revert InvalidOperation` (:475) vs the enum conversion (:448)
    // ==================================================================

    /// An inner operation byte > 1 panics on the `Enum.Operation` conversion at
    /// Lockdown.sol:448 (Panic 0x21) BEFORE control can ever reach the
    /// `InvalidOperation` branch at :475.
    function test_refuted_innerOperationByteTwoPanicsBeforeInvalidOperation() public {
        bytes memory record = abi.encodePacked(uint8(2), address(target), uint256(0), uint256(0));
        _pokeGuard_Revert(
            address(multiSendCallOnly),
            0,
            _multiSend(record),
            Enum.Operation.DelegateCall,
            abi.encodeWithSignature("Panic(uint256)", PANIC_ENUM_CONVERSION)
        );
    }

    /// The top-level operation cannot reach :475 either: the ABI decoder of
    /// `checkTransaction` (and of `execTransaction`) rejects the out-of-range
    /// enum first, with an empty revert.
    function test_refuted_topLevelOperationByteTwoRejectedByAbiDecoder() public {
        bytes memory payload = abi.encodeWithSelector(
            guard.checkTransaction.selector,
            address(target),
            uint256(0),
            bytes(""),
            uint256(2), // out-of-range Enum.Operation
            uint256(0),
            uint256(0),
            uint256(0),
            address(0),
            address(0),
            bytes(""),
            address(0)
        );
        vm.prank(address(pocSafe));
        (bool ok, bytes memory ret) = address(guard).call(payload);
        assertFalse(ok, "out-of-range operation rejected");
        assertEq(ret.length, 0, "rejected by the ABI decoder, so InvalidOperation is unreachable");
    }

    // ==================================================================
    // C4 - address(0) aliasing in the leaf parser (Lockdown.sol:462)
    // ==================================================================

    /// MultiSendCallOnly aliases `to == address(0)` to the Safe. The guard mirrors
    /// that at :462, so a module cannot smuggle a guard-disabling self-call by
    /// writing address(0) instead of the Safe address.
    function test_refuted_zeroAddressAliasBlocksModuleGuardDisable() public {
        bytes memory record =
            _multiSendItem(Enum.Operation.Call, address(0), 0, abi.encodeCall(IGuardManager.setGuard, (address(0))));
        _moduleCall_Revert(
            module,
            pocSafe,
            address(multiSendCallOnly),
            0,
            _multiSend(record),
            Enum.Operation.DelegateCall,
            Lockdown.ModuleSafeSelfCallDenied.selector
        );
    }

    /// Same alias on the owner path routes into the fallback-handler binding
    /// check, so a non-lockdown handler cannot be installed via address(0).
    function test_refuted_zeroAddressAliasStillBindsFallbackHandler() public {
        bytes memory record = _multiSendItem(
            Enum.Operation.Call,
            address(0),
            0,
            abi.encodeCall(IFallbackManager.setFallbackHandler, (address(new WrongBoundHandler())))
        );
        _execAsOwner_Revert(
            pocSafe,
            address(multiSendCallOnly),
            0,
            _multiSend(record),
            Enum.Operation.DelegateCall,
            Lockdown.InvalidFallbackHandler.selector
        );
    }

    // ==================================================================
    // C5 - nested MultiSend
    // ==================================================================

    /// Privilege is threaded through every recursion level: a singleton call
    /// buried two MultiSend levels deep is still denied on the module path.
    function test_refuted_nestedMultiSendCarriesModulePrivilege() public {
        bytes memory inner = _multiSend(
            _multiSendItem(Enum.Operation.Call, address(guard), 0, abi.encodeCall(Lockdown.setResumeDelay, (7 days)))
        );
        bytes memory outer =
            _multiSend(_multiSendItem(Enum.Operation.DelegateCall, address(multiSendCallOnly), 0, inner));
        _moduleCall_Revert(
            module,
            pocSafe,
            address(multiSendCallOnly),
            0,
            outer,
            Enum.Operation.DelegateCall,
            Lockdown.ModuleCallToSingletonDenied.selector
        );
    }

    /// The inner-DelegateCall recursion branch is defensive only: the guard
    /// happily validates a nested batch that MultiSendCallOnly can never execute
    /// (its `case 1` reverts). Guard-accept + execution-revert, no bypass.
    function test_limitation_nestedMultiSendPassesGuardButCannotExecute() public {
        bytes memory inner = _multiSend(
            _multiSendItem(Enum.Operation.Call, address(target), 0, abi.encodeCall(CalldataTarget.mark, ()))
        );
        bytes memory outer =
            _multiSend(_multiSendItem(Enum.Operation.DelegateCall, address(multiSendCallOnly), 0, inner));

        _pokeGuard(address(multiSendCallOnly), 0, outer, Enum.Operation.DelegateCall);

        (bool ok, bytes memory ret) = _rawExec(address(multiSendCallOnly), 0, outer, Enum.Operation.DelegateCall);
        assertFalse(ok, "nested delegatecall cannot execute");
        assertEq(ret.length, 0, "MultiSendCallOnly rejects the inner DELEGATECALL");
        assertEq(target.calls(), 0, "nothing executed");
    }

    // ==================================================================
    // C6 - recovery whitelist: exact lengths and dirty padding
    // ==================================================================

    /// A MultiSend bundle does not escape the recovery whitelist: every leaf is
    /// re-checked with Privilege.Recovery.
    function test_refuted_recoveryMultiSendCannotEscapeWhitelist() public {
        _enterRecovery();
        bytes memory record =
            _multiSendItem(Enum.Operation.Call, address(target), 0, abi.encodeCall(CalldataTarget.mark, ()));
        _execAsOwner_Revert(
            pocSafe,
            address(multiSendCallOnly),
            0,
            _multiSend(record),
            Enum.Operation.DelegateCall,
            Lockdown.RecoveryActive.selector
        );
    }

    /// The zero-address alias cannot forge a value transfer during recovery: the
    /// nonce-burn arm additionally requires `value == 0`.
    function test_refuted_recoveryZeroAddressAliasCannotMoveValue() public {
        _enterRecovery();
        bytes memory record = _multiSendItem(Enum.Operation.Call, address(0), 1 ether, "");
        _execAsOwner_Revert(
            pocSafe,
            address(multiSendCallOnly),
            0,
            _multiSend(record),
            Enum.Operation.DelegateCall,
            Lockdown.RecoveryActive.selector
        );
    }

    /// `disableModule` is length-pinned to 0x44: appending a single trailing byte
    /// (which the Safe's ABI decoder would happily ignore) is rejected.
    function test_refuted_recoveryExactLengthChecksRejectTrailingBytes() public {
        _enterRecovery();
        bytes memory padded =
            abi.encodePacked(abi.encodeCall(IModuleManager.disableModule, (SENTINEL_OWNERS, module)), hex"00");
        _execAsOwner_Revert(pocSafe, address(pocSafe), 0, padded, Enum.Operation.Call, Lockdown.RecoveryActive.selector);
    }

    /// `_readAddressCalldata(data, 0x50)` reads only the LOW 20 bytes of the
    /// `newOwner` word, so the upper 12 bytes are unvalidated by the guard. The
    /// guard accepts the dirty word; the Safe's own ABI decoder is what rejects
    /// it. Divergence, but strictly fail-closed (no extra owner is installed).
    function test_refuted_swapOwnerDirtyUpperBytesAreMaskedConsistently() public {
        _enterRecovery();
        bytes memory dirty = abi.encodePacked(
            IOwnerManager.swapOwner.selector,
            bytes32(uint256(uint160(SENTINEL_OWNERS))),
            bytes32(uint256(uint160(owner))),
            bytes32((uint256(0xdead) << 232) | uint256(uint160(recovery)))
        );
        assertEq(dirty.length, 0x64, "exact swapOwner length");

        // The guard's whitelist accepts it...
        _pokeGuard(address(pocSafe), 0, dirty, Enum.Operation.Call);

        // ...and the Safe masks the same low 20 bytes the guard read, so the
        // owner actually installed is exactly the one the whitelist authorised.
        // No divergence: dirty padding buys the attacker nothing.
        (bool ok,) = _rawExec(address(pocSafe), 0, dirty, Enum.Operation.Call);
        assertTrue(ok, "dirty word tolerated by the Safe too");
        assertTrue(pocSafe.isOwner(recovery), "the guard-authorised recovery owner is the one installed");
        assertFalse(pocSafe.isOwner(owner), "old owner swapped out");
    }

    // ==================================================================
    // C7 - short `setFallbackHandler` self-call (Lockdown.sol:405)
    // ==================================================================

    /// `bytes4(data)` matches on a 4-byte payload but `_readAddressCalldata(data,
    /// 0x10)` then slices bytes [0x10,0x24) of a 4-byte array. It fails closed,
    /// but with a bare data-less revert: no named error, and not even a
    /// Panic(0x32), so an operator cannot tell which check stopped the call.
    function test_limitation_shortSetFallbackHandlerSelfCallRevertsWithoutData() public {
        for (uint256 len = 4; len < 0x24; len += 0x10) {
            bytes memory truncated = new bytes(len);
            bytes4 selector = IFallbackManager.setFallbackHandler.selector;
            for (uint256 i = 0; i < 4; ++i) {
                truncated[i] = selector[i];
            }

            vm.prank(address(pocSafe));
            (bool ok, bytes memory ret) = address(guard)
                .call(
                    abi.encodeCall(
                        guard.checkTransaction,
                        (
                            address(pocSafe),
                            0,
                            truncated,
                            Enum.Operation.Call,
                            0,
                            0,
                            0,
                            address(0),
                            payable(address(0)),
                            "",
                            address(0)
                        )
                    )
                );
            assertFalse(ok, "short setFallbackHandler self-call fails closed");
            assertEq(ret.length, 0, "but with no revert data at all");
        }
    }

    /// Below 4 bytes the `bytes4` zero-padding cannot synthesise any guarded
    /// selector (none of them ends in a zero byte), so the unguarded slice at
    /// :405 is never reached and the call passes through as an ordinary
    /// self-call.
    function test_refuted_subSelectorPayloadCannotForgeGuardedSelector() public {
        bytes memory stub = hex"f08a03"; // setFallbackHandler minus its last byte
        _pokeGuard(address(pocSafe), 0, stub, Enum.Operation.Call);
    }

    // ==================================================================
    // C8 - module ticket hash encoding (LockdownLib.moduleTxHash)
    // ==================================================================

    /// `moduleTxHash` is a fixed-width `abi.encode` with `keccak256(data)`, not a
    /// packed encoding, so no re-split of (to, value, data, operation) collides.
    /// A one-byte change of `data`, or the operation byte alone, yields a
    /// different ticket, so a scheduled module ticket cannot be spent by a
    /// different payload.
    function test_refuted_moduleTicketHashHasNoPackedEncodingCollision() public view {
        bytes32 a = guard.getModuleTransactionHash(
            address(pocSafe), module, address(target), 0, hex"0011", Enum.Operation.Call
        );
        bytes32 b = guard.getModuleTransactionHash(
            address(pocSafe), module, address(target), 0, hex"1100", Enum.Operation.Call
        );
        bytes32 c = guard.getModuleTransactionHash(
            address(pocSafe), module, address(target), 0, hex"0011", Enum.Operation.DelegateCall
        );
        bytes32 d = guard.getModuleTransactionHash(
            address(pocSafe), module, address(target), 1, hex"0011", Enum.Operation.Call
        );
        assertTrue(a != b && a != c && a != d && b != c && b != d && c != d, "no collision");
    }
}
