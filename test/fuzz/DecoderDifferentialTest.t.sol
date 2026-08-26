// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {TestEnvironment} from "../TestEnvironment.sol";

import {Safe, Enum} from "@safe-global/safe-smart-account/Safe.sol";
import {IFallbackManager} from "@safe-global/safe-smart-account/interfaces/IFallbackManager.sol";
import {MultiSendCallOnly} from "@safe-global/safe-smart-account/libraries/MultiSendCallOnly.sol";

import {Lockdown} from "../../src/Lockdown.sol";
import {LockdownFallbackHandler} from "../../src/handlers/LockdownFallbackHandler.sol";
import {StateMachine} from "../../src/base/StateMachine.sol";

/// @title Differential test: `_decodeCalldataBytes` vs Solidity `abi.decode`.
/// @notice The guard validates a MultiSend batch by decoding the `bytes`
///         argument of `multiSend(bytes)` with a hand-rolled calldata decoder
///         (`_decodeCalldataBytes`). The Safe, at execution, decodes the SAME
///         argument with Solidity `abi.decode` (inside `MultiSendCallOnly`). If
///         the two decoders ever disagreed, the guard would validate one batch
///         while the Safe executes another - a guard-vs-executor bypass.
///
///         ABI allows a `bytes` argument to sit at any in-bounds offset, not
///         just the canonical 0x20 immediately after the head word. An attacker
///         can therefore "hide" the real batch behind filler ("bytes caché au
///         milieu"). A decoder that assumed offset == 0x20 would read the filler
///         and miss the real batch.
///
///         This suite compares the hand-rolled decoder with an internal
///         `abi.decode` oracle and fuzzes non-canonical encodings of a batch
///         that hides an inner `setFallbackHandler(foreign)` self-call. The
///         separate adversarial PoC calls the real MultiSendCallOnly entrypoint;
///         an internal decode is not a complete oracle for external dispatcher
///         behaviour on every non-canonical encoding.
///         The guard MUST reach the same verdict (revert `InvalidFallbackHandler`)
///         for every encoding `abi.decode` accepts, and must reject every
///         encoding `abi.decode` rejects.
contract DecoderDifferentialTest is TestEnvironment {
    event GotCall();

    Safe private SAFE_A;
    LockdownFallbackHandler private foreignHandler;

    function setUp() public override {
        super.setUp();

        // Fully configured + initialised so the guard is in Normal state and
        // actually validates (an uninitialised config fails open).
        SAFE_A = _createConfigureAndInitialise(0);
        // A handler bound to a different singleton: rebinding to it must revert.
        foreignHandler = new LockdownFallbackHandler(StateMachine(address(0xBEEF)));
    }

    // -------------------------------------------------------------------
    // Ground-truth sanity: the non-canonical encoding really hides the batch,
    // and `abi.decode` (the executor's view) recovers it.
    // -------------------------------------------------------------------

    function test_nonCanonicalEncodingDecodesToInner(bytes memory inner, uint16 fillerWords) public pure {
        assertEq(
            abi.decode(_encodeArgs(inner, fillerWords), (bytes)), inner, "abi.decode must follow the offset to inner"
        );
    }

    // -------------------------------------------------------------------
    // The guard reaches the SAME verdict as `abi.decode` for accepted encodings:
    // the hidden setFallbackHandler is caught regardless of the offset.
    // -------------------------------------------------------------------

    function test_guardCatchesHiddenFallbackHandler(uint16 fillerWords) public {
        bytes memory args = _encodeArgs(_maliciousInner(), fillerWords);

        vm.prank(address(SAFE_A));
        vm.expectRevert(Lockdown.InvalidFallbackHandler.selector);
        guard.checkTransaction(
            address(multiSendCallOnly),
            0,
            bytes.concat(MultiSendCallOnly.multiSend.selector, args),
            Enum.Operation.DelegateCall,
            0,
            0,
            0,
            address(0),
            payable(address(0)),
            "",
            address(0)
        );
    }

    // -------------------------------------------------------------------
    // Conversely: a benign batch encoded non-canonically is ACCEPTED, matching
    // `abi.decode` (no spurious rejection of valid encodings the Safe executes).
    // -------------------------------------------------------------------

    function test_guardAcceptsBenignNonCanonical(uint16 fillerWords) public {
        bytes memory args = _encodeArgs(_benignInner(), fillerWords);

        vm.prank(address(SAFE_A));
        guard.checkTransaction(
            address(multiSendCallOnly),
            0,
            bytes.concat(MultiSendCallOnly.multiSend.selector, args),
            Enum.Operation.DelegateCall,
            0,
            0,
            0,
            address(0),
            payable(address(0)),
            "",
            address(0)
        );
    }

    // -------------------------------------------------------------------
    // Rejection side of the differential: an out-of-bounds offset that
    // `abi.decode` rejects must also be rejected by the guard.
    // -------------------------------------------------------------------

    function test_guardRejectsOutOfBoundsOffset() public {
        // offset points past the end of the args: no length word there.
        bytes memory args = abi.encodePacked(uint256(0x1000));
        // abi.decode rejects it too.
        vm.expectRevert();
        this.decodeExternally(args);

        vm.prank(address(SAFE_A));
        vm.expectRevert(Lockdown.BadMultiSendCallOnlyPayload.selector);
        guard.checkTransaction(
            address(multiSendCallOnly),
            0,
            bytes.concat(MultiSendCallOnly.multiSend.selector, args),
            Enum.Operation.DelegateCall,
            0,
            0,
            0,
            address(0),
            payable(address(0)),
            "",
            address(0)
        );
    }

    function test_guardRejectsOutOfBoundsOffset_2(uint16 length) public {
        // offset points past the end of the args: no length word there.
        bytes memory args = abi.encodePacked(uint256(0x20), uint256(length) + 1, new bytes(length));
        // abi.decode rejects it too.
        vm.expectRevert();
        this.decodeExternally(args);

        vm.prank(address(SAFE_A));
        vm.expectRevert(Lockdown.BadMultiSendCallOnlyPayload.selector);
        guard.checkTransaction(
            address(multiSendCallOnly),
            0,
            bytes.concat(MultiSendCallOnly.multiSend.selector, args),
            Enum.Operation.DelegateCall,
            0,
            0,
            0,
            address(0),
            payable(address(0)),
            "",
            address(0)
        );
    }

    /// @dev `abi.decode` must be invoked from an external call so its revert is
    ///      catchable by `vm.expectRevert`.
    function decodeExternally(bytes calldata args) external pure returns (bytes memory) {
        return abi.decode(args, (bytes));
    }

    //--------------------------------------------------------------------
    // Helpers for constructing the non-canonical encodings.
    //--------------------------------------------------------------------

    function _benignInner() private pure returns (bytes memory) {
        return _multiSendItem(Enum.Operation.Call, address(0xBEEF), 0, hex"12345678");
    }

    // A single-item batch whose inner CALL rebinds the Safe's fallback handler
    // to a non-lockdown-aware handler - the operation the guard must always catch.
    function _maliciousInner() private view returns (bytes memory) {
        return _multiSendItem(
            Enum.Operation.Call,
            address(SAFE_A),
            0,
            abi.encodeCall(IFallbackManager.setFallbackHandler, (address(foreignHandler)))
        );
    }

    // ABI-encode the `bytes` argument of `multiSend(bytes)` with a NON-canonical
    // offset = 0x20 + 0x20 * fillerWords, i.e. `fillerWords` zero words inserted
    // between the head pointer and the length+content. `abi.decode` follows the
    // pointer, so it recovers `inner` for any fillerWords; the canonical form is
    // fillerWords == 0.
    function _encodeArgs(bytes memory inner, uint256 fillerWords) private pure returns (bytes memory) {
        return bytes.concat(
            abi.encode(0x20 + 0x20 * fillerWords), // offset pointer to the length word
            new bytes(0x20 * fillerWords), // filler the decoder must skip over
            abi.encode(inner.length),
            _padTo32(inner)
        );
    }

    function _padTo32(bytes memory b) private pure returns (bytes memory) {
        return bytes.concat(b, new bytes(32 - (b.length % 32)));
    }
}
