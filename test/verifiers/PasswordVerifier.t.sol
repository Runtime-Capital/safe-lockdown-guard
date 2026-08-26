// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {PasswordVerifier} from "../../src/verifiers/PasswordVerifier.sol";
import {IERC7913SignatureVerifier} from "@openzeppelin/contracts/interfaces/IERC7913.sol";

contract PasswordVerifierTest {
    bytes4 private constant MAGIC = IERC7913SignatureVerifier.verify.selector;

    PasswordVerifier private verifier;

    function setUp() public {
        verifier = new PasswordVerifier();
    }

    // -------------------------------------------------------------------
    // verify
    // -------------------------------------------------------------------

    function test_verify_acceptsValidPreimage() public view {
        bytes memory password = "diceware-six-word-correct-horse-battery";
        bytes32 commitment = keccak256(password);
        bytes memory key = abi.encodePacked(commitment);
        assertEq(verifier.verify(key, bytes32(0), password), MAGIC, "correct preimage accepted");
    }

    function test_verify_rejectsWrongPreimage() public view {
        bytes memory password = "correct-password";
        bytes32 commitment = keccak256(password);
        bytes memory key = abi.encodePacked(commitment);
        assertEq(verifier.verify(key, bytes32(0), "wrong-password"), bytes4(0), "wrong preimage rejected");
    }

    function test_verify_rejectsShortKey() public view {
        bytes memory key = hex"1234"; // < 32 bytes
        assertEq(verifier.verify(key, bytes32(0), "anything"), bytes4(0), "short key rejected");
    }

    function test_verify_rejectsLongKey() public view {
        bytes memory key = new bytes(33);
        assertEq(verifier.verify(key, bytes32(0), "anything"), bytes4(0), "long key rejected");
    }

    function test_verify_rejectsEmptySignature() public view {
        bytes32 commitment = keccak256("password");
        bytes memory key = abi.encodePacked(commitment);
        assertEq(verifier.verify(key, bytes32(0), hex""), bytes4(0), "empty signature rejected");
    }

    function test_verify_rejectsZeroCommitment() public view {
        // A zero commitment can never match a non-empty password (keccak256
        // output is never zero), so it is unreachable.
        bytes memory key = new bytes(32); // all zeros
        assertEq(verifier.verify(key, bytes32(0), "anything"), bytes4(0), "zero commitment rejected");
    }

    function test_verify_rejectsEmptyPasswordCommitment() public view {
        // The footgun: registering keccak256("") as the commitment. Without
        // the empty-signature guard, anyone could trigger it with an empty
        // password (keccak256(hex"") == keccak256("")). The guard rejects it.
        bytes memory key = abi.encodePacked(keccak256(""));
        assertEq(verifier.verify(key, bytes32(0), hex""), bytes4(0), "empty-password commitment unusable");
    }

    function test_verify_ignoresHash() public view {
        // The verifier IS DESIGNED to ignore `hash`. This test pins that
        // behavior so future changes that break it are loud.
        bytes memory password = "any";
        bytes32 commitment = keccak256(password);
        bytes memory key = abi.encodePacked(commitment);
        bytes4 r1 = verifier.verify(key, bytes32(uint256(1)), password);
        bytes4 r2 = verifier.verify(key, bytes32(uint256(2)), password);
        assertEq(r1, MAGIC, "h=1 accepts");
        assertEq(r2, MAGIC, "h=2 accepts (hash ignored)");
    }

    function test_verify_magicValueIsSelector() public pure {
        assertEq(MAGIC, IERC7913SignatureVerifier.verify.selector, "magic = verify selector");
    }

    function testFuzz_verify_consistentWithCommitment(bytes calldata password) public view {
        if (password.length == 0) return; // verifier rejects empty signature, ok
        bytes32 commitment = keccak256(password);
        if (commitment == bytes32(0)) return; // astronomically unlikely but guarded
        bytes memory key = abi.encodePacked(commitment);
        assertEq(verifier.verify(key, bytes32(0), password), MAGIC, "preimage matches");
    }

    // -------------------------------------------------------------------
    // Minimal assert helpers
    // -------------------------------------------------------------------

    function assertEq(bytes4 actual, bytes4 expected, string memory message) internal pure {
        if (actual != expected) revert(message);
    }
}
