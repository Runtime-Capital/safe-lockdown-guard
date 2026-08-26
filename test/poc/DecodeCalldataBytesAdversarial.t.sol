// SPDX-License-Identifier: MIT
pragma solidity 0.8.35;

import {TestEnvironment} from "../TestEnvironment.sol";

import {Safe, Enum} from "@safe-global/safe-smart-account/Safe.sol";
import {MultiSendCallOnly} from "@safe-global/safe-smart-account/libraries/MultiSendCallOnly.sol";

import {Lockdown} from "../../src/Lockdown.sol";

contract DecodeAdversarialTarget {
    uint256 public calls;

    function mark() external {
        ++calls;
    }
}

/// @notice Adversarial boundary matrix for the private `_decodeCalldataBytes` path.
/// @dev The guard verdict is obtained by executing `checkTransaction`; the executor
///      verdict is obtained by calling the real Safe v1.5.0 `MultiSendCallOnly` ABI
///      entry point with the same argument bytes. The suite pins the two overflow
///      fixes from PR #75 and records agreement or divergence only when execution
///      demonstrates it.
contract DecodeCalldataBytesAdversarialPoC is TestEnvironment {
    Safe private safe;
    DecodeAdversarialTarget private target;

    function setUp() public override {
        super.setUp();
        safe = _createConfigureAndInitialise(0xDEC0DE);
        target = new DecodeAdversarialTarget();
    }

    function _guardVerdict(bytes memory args) private returns (bool ok, bytes memory ret) {
        bytes memory data = bytes.concat(MultiSendCallOnly.multiSend.selector, args);
        vm.prank(address(safe));
        (ok, ret) = address(guard)
            .call(
                abi.encodeCall(
                    Lockdown.checkTransaction,
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
                        bytes(""),
                        address(0)
                    )
                )
            );
    }

    function _executorVerdict(bytes memory args) private returns (bool ok, bytes memory ret) {
        (ok, ret) = address(multiSendCallOnly).call(bytes.concat(MultiSendCallOnly.multiSend.selector, args));
    }

    function _assertGuardRejectsNamed(bytes memory args) private {
        (bool ok, bytes memory ret) = _guardVerdict(args);
        assertFalse(ok, "guard rejects");
        assertEq(bytes4(ret), Lockdown.BadMultiSendCallOnlyPayload.selector, "named guard rejection");
    }

    function _record(bytes memory data) private view returns (bytes memory) {
        return _multiSendItem(Enum.Operation.Call, address(target), 0, data);
    }

    function _argsAtOffset(bytes memory inner, uint256 fillerWords) private pure returns (bytes memory) {
        uint256 padding = (32 - (inner.length % 32)) % 32;
        return bytes.concat(
            abi.encode(0x20 + 0x20 * fillerWords),
            new bytes(0x20 * fillerWords),
            abi.encode(inner.length),
            inner,
            new bytes(padding)
        );
    }

    function test_control_canonicalEmptyBatchAcceptedByGuardAndExecutor() public {
        bytes memory args = abi.encode(bytes(""));
        (bool guardOk,) = _guardVerdict(args);
        (bool executorOk,) = _executorVerdict(args);
        assertTrue(guardOk, "guard accepts");
        assertTrue(executorOk, "executor accepts");
    }

    function test_control_canonicalSingleRecordAcceptedByGuardAndExecutor() public {
        bytes memory args = abi.encode(_record(abi.encodeCall(DecodeAdversarialTarget.mark, ())));
        (bool guardOk,) = _guardVerdict(args);
        (bool executorOk,) = _executorVerdict(args);
        assertTrue(guardOk, "guard accepts");
        assertTrue(executorOk, "executor accepts");
        assertEq(target.calls(), 1, "real executor ran the record");
    }

    function test_control_nonCanonicalForwardOffsetAcceptedByBothDecoders() public {
        bytes memory args = _argsAtOffset(_record(abi.encodeCall(DecodeAdversarialTarget.mark, ())), 1);
        (bool guardOk,) = _guardVerdict(args);
        (bool executorOk,) = _executorVerdict(args);
        assertTrue(guardOk, "guard follows forward offset");
        assertTrue(executorOk, "Solidity decoder follows forward offset");
    }

    function test_control_largeInBoundsForwardOffsetAcceptedByBothDecoders() public {
        bytes memory args = _argsAtOffset(_record(abi.encodeCall(DecodeAdversarialTarget.mark, ())), 8);
        (bool guardOk,) = _guardVerdict(args);
        (bool executorOk,) = _executorVerdict(args);
        assertTrue(guardOk, "guard accepts in-bounds offset");
        assertTrue(executorOk, "executor accepts in-bounds offset");
    }

    function test_control_trailingWordsAfterDeclaredBytesAcceptedByBothDecoders() public {
        bytes memory args = bytes.concat(abi.encode(bytes("")), bytes32("ignored-tail"));
        (bool guardOk,) = _guardVerdict(args);
        (bool executorOk,) = _executorVerdict(args);
        assertTrue(guardOk, "guard ignores external tail");
        assertTrue(executorOk, "Solidity ABI decoder ignores external tail");
    }

    function test_control_zeroOffsetEmptySliceAcceptedByGuardAndExecutor() public {
        bytes memory args = abi.encode(uint256(0));
        (bool guardOk,) = _guardVerdict(args);
        (bool executorOk,) = _executorVerdict(args);
        assertTrue(guardOk, "guard accepts overlapping zero-length slice");
        assertTrue(executorOk, "Safe v1.5.0 decoder also accepts the empty overlap");
    }

    function test_control_unpaddedRecordAcceptedByGuardAndExecutor() public {
        bytes memory inner = _record(abi.encodeCall(DecodeAdversarialTarget.mark, ()));
        bytes memory args = bytes.concat(abi.encode(uint256(0x20)), abi.encode(inner.length), inner);
        assertEq(inner.length, 0x59, "one exact four-byte-data record");

        (bool guardOk,) = _guardVerdict(args);
        (bool executorOk,) = _executorVerdict(args);
        assertTrue(guardOk, "guard needs only the declared bytes");
        assertTrue(executorOk, "Safe v1.5.0 decoder also accepts the unpadded tail");
        assertEq(target.calls(), 1, "executor ran the unpadded record");
    }

    function test_refuted_missingHeadRejectedByGuardAndExecutor() public {
        bytes memory args = "";
        _assertGuardRejectsNamed(args);
        (bool executorOk,) = _executorVerdict(args);
        assertFalse(executorOk, "executor rejects missing head");
    }

    function test_refuted_shortHeadRejectedByGuardAndExecutor() public {
        bytes memory args = new bytes(31);
        _assertGuardRejectsNamed(args);
        (bool executorOk,) = _executorVerdict(args);
        assertFalse(executorOk, "executor rejects short head");
    }

    function test_refuted_offsetAtInputEndHasNoLengthWord() public {
        bytes memory args = abi.encode(uint256(0x20));
        _assertGuardRejectsNamed(args);
        (bool executorOk,) = _executorVerdict(args);
        assertFalse(executorOk, "executor rejects missing length word");
    }

    function test_regression_typeMaxOffsetRejectedByNamedGuardCheck() public {
        bytes memory args = abi.encode(type(uint256).max);
        _assertGuardRejectsNamed(args);
        (bool executorOk,) = _executorVerdict(args);
        assertFalse(executorOk, "executor also rejects huge offset");
    }

    function test_regression_reviewExploitOffsetWrapRejectedByNamedGuardCheck() public {
        bytes memory args = abi.encode(type(uint256).max - 0xA3);
        _assertGuardRejectsNamed(args);
        (bool executorOk,) = _executorVerdict(args);
        assertFalse(executorOk, "executor rejects review payload too");
    }

    function test_regression_offsetAdditionBoundaryRejectedWithoutWrapping() public {
        bytes memory args = abi.encode(type(uint256).max - 0x1F);
        _assertGuardRejectsNamed(args);
        (bool executorOk,) = _executorVerdict(args);
        assertFalse(executorOk, "executor rejects overflow boundary");
    }

    function test_regression_typeMaxDeclaredLengthRejectedByNamedGuardCheck() public {
        bytes memory args = bytes.concat(abi.encode(uint256(0x20)), abi.encode(type(uint256).max));
        _assertGuardRejectsNamed(args);
        (bool executorOk,) = _executorVerdict(args);
        assertFalse(executorOk, "executor rejects huge length");
    }

    function test_refuted_declaredLengthOneBytePastAvailableTailRejectedByBoth() public {
        bytes memory args = bytes.concat(abi.encode(uint256(0x20)), abi.encode(uint256(1)));
        _assertGuardRejectsNamed(args);
        (bool executorOk,) = _executorVerdict(args);
        assertFalse(executorOk, "executor rejects short tail");
    }

    function test_control_declaredLengthExactlyConsumesAvailableTail() public {
        bytes memory inner = _multiSendItem(Enum.Operation.Call, address(0xBEEF), 0, "");
        bytes memory args = bytes.concat(abi.encode(uint256(0x20)), abi.encode(inner.length), inner);
        (bool guardOk,) = _guardVerdict(args);
        (bool executorOk,) = _executorVerdict(args);
        assertTrue(guardOk, "subtraction bound accepts exact endpoint");
        assertTrue(executorOk, "executor accepts the same exact endpoint");
    }
}
