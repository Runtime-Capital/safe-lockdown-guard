// SPDX-License-Identifier: MIT
// External audit NM-1060, Low: "Trigger signatures can be replayed against a second
// identity that wraps the same key".
//
// The trigger message used to be `Lockdown(address safe,bytes32 reasonHash)`. It did not
// name the signer, and the burnt register is keyed by exact identity bytes, so the same
// key material registered under two identities produced two identities that accepted
// the same signature. Once the first one triggered, its signature sat in public calldata
// and ANY address could replay it through the second identity: an extra freeze, one
// burnt panic identity, and a trigger by an address with no signer role.
//
// Fix (SPEC_V1 §5.2, H.23): the message is `Lockdown(address safe,bytes signer,bytes32
// reasonHash)`, so each signature is bound to the identity it was produced for.
//
// Residual: a verifier that ignores the digest cannot be bound by any message field.
// The bundled `PasswordVerifier` is one; its commitment must never be registered under
// more than one identity.
pragma solidity ^0.8.24;

import {TestEnvironment} from "../TestEnvironment.sol";

import {Safe} from "@safe-global/safe-smart-account/Safe.sol";
import {Base64} from "@openzeppelin/contracts/utils/Base64.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";

import {Lockdown} from "../../src/Lockdown.sol";
import {StateMachine} from "../../src/base/StateMachine.sol";
import {PasswordVerifier} from "../../src/verifiers/PasswordVerifier.sol";
import {WebAuthnVerifier, WebAuthnVerifierNoUV} from "../../src/verifiers/WebAuthnVerifier.sol";
import {Mock1271Wallet} from "../mocks/Mock1271Wallet.sol";

contract TriggerIdentityBindingPoC is TestEnvironment {
    uint256 private constant P256_PRIVATE_KEY = 0x5EC12E7;
    uint256 private constant P256_N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551;
    uint256 private constant P256_HALF_N = 0x7fffffff800000007fffffffffffffffde737d56d38bcf4279dce5617e3192a8;

    bytes32 private constant REASON = keccak256("nm-1060");

    /// @dev An address with no signer role, replaying public calldata.
    address private constant OBSERVER = address(0x0B5E7);

    Safe private safe;

    function setUp() public override {
        super.setUp();
        safe = _createConfigureAndInitialise(0x1060);
    }

    // -------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------

    function _register(bytes memory signer) private {
        vm.prank(address(safe));
        guard.addLockdownSigner(signer);
    }

    function _digest(bytes memory signer) private view returns (bytes32) {
        (
            bytes1 fields,
            string memory name,
            string memory version,
            uint256 chainId,
            address verifyingContract,
            bytes32 salt,
        ) = guard.eip712Domain();
        return MessageHashUtils.toTypedDataHash(
            MessageHashUtils.toDomainSeparator(fields, name, version, chainId, verifyingContract, salt),
            keccak256(abi.encode(guard.LOCKDOWN_TYPEHASH(), address(safe), keccak256(signer), REASON))
        );
    }

    function _passkey() private pure returns (bytes memory) {
        (uint256 qx, uint256 qy) = vm.publicKeyP256(P256_PRIVATE_KEY);
        return abi.encodePacked(bytes32(qx), bytes32(qy));
    }

    /// @dev UP+UV assertion over `digest`: valid under BOTH WebAuthn verifier variants.
    function _assertion(bytes32 digest) private pure returns (bytes memory) {
        string memory clientDataJSON = string.concat(
            '{"type":"webauthn.get","challenge":"',
            Base64.encodeURL(abi.encodePacked(digest)),
            '","origin":"https://runtime.capital"}'
        );
        bytes memory authenticatorData = abi.encodePacked(bytes32(0), bytes1(0x05), bytes4(0));
        bytes32 message = sha256(abi.encodePacked(authenticatorData, sha256(bytes(clientDataJSON))));
        (bytes32 r, bytes32 s) = vm.signP256(P256_PRIVATE_KEY, message);
        if (uint256(s) > P256_HALF_N) s = bytes32(P256_N - uint256(s));
        return abi.encode(r, s, uint256(23), uint256(1), authenticatorData, clientDataJSON);
    }

    /// @dev First identity triggers, then OBSERVER replays the public signature through
    ///      the second identity from Recovering - the state in which the finding re-locks.
    function _assertReplayRejected(bytes memory first, bytes memory second, bytes memory signature) private {
        guard.triggerLockdown(address(safe), REASON, first, signature);
        vm.warp(block.timestamp + guard.getLockdownDuration(address(safe)));
        (StateMachine.State s,) = guard.getState(address(safe));
        assertEq(uint256(s), uint256(StateMachine.State.Recovering), "in Recovering");

        vm.prank(OBSERVER);
        vm.expectRevert(Lockdown.BadSignature.selector);
        guard.triggerLockdown(address(safe), REASON, second, signature);

        (s,) = guard.getState(address(safe));
        assertEq(uint256(s), uint256(StateMachine.State.Recovering), "not re-locked");
        assertTrue(guard.isLockdownSigner(address(safe), second), "second identity not burnt");
    }

    // -------------------------------------------------------------------
    // Fixed: every digest-binding identity pairing from the finding
    // -------------------------------------------------------------------

    /// @notice The finding's headline: one passkey under both shipped WebAuthn policies.
    function test_regression_passkeyUnderBothWebAuthnPoliciesCannotBeReplayed() public {
        bytes memory uv = abi.encodePacked(address(new WebAuthnVerifier()), _passkey());
        bytes memory noUv = abi.encodePacked(address(new WebAuthnVerifierNoUV()), _passkey());
        _register(uv);
        _register(noUv);

        _assertReplayRejected(uv, noUv, _assertion(_digest(uv)));
    }

    function test_regression_keyUnderTwoVerifierDeploymentsCannotBeReplayed() public {
        bytes memory a = abi.encodePacked(address(new WebAuthnVerifier()), _passkey());
        bytes memory b = abi.encodePacked(address(new WebAuthnVerifier()), _passkey());
        _register(a);
        _register(b);

        _assertReplayRejected(a, b, _assertion(_digest(a)));
    }

    function test_regression_eoaSignatureCannotBeReplayedThroughWrapping1271Wallet() public {
        bytes memory eoa = abi.encodePacked(panicKey); // registered by the fixture
        bytes memory wallet = abi.encodePacked(address(new Mock1271Wallet(panicKey)));
        _register(wallet);

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(PANIC_PK, _digest(eoa));
        _assertReplayRejected(eoa, wallet, abi.encodePacked(r, s, v));
    }

    /// @notice Positive control: each identity still triggers with its own signature.
    function test_control_eachIdentityTriggersWithItsOwnSignature() public {
        bytes memory uv = abi.encodePacked(address(new WebAuthnVerifier()), _passkey());
        bytes memory noUv = abi.encodePacked(address(new WebAuthnVerifierNoUV()), _passkey());
        _register(uv);
        _register(noUv);

        guard.triggerLockdown(address(safe), REASON, uv, _assertion(_digest(uv)));
        guard.triggerLockdown(address(safe), REASON, noUv, _assertion(_digest(noUv)));
        assertTrue(guard.isSignerBurntPermanently(address(safe), noUv), "second identity fired");
    }

    // -------------------------------------------------------------------
    // Accepted residual: digest-ignoring verifiers
    // -------------------------------------------------------------------

    /// @notice `PasswordVerifier` ignores the digest, so no message field can bind it: one
    ///         commitment under two identities stays replayable by anyone who saw the
    ///         first trigger's calldata. Operator rule: never register a commitment under
    ///         more than one identity (SPEC_V1 H.23).
    function test_limitation_passwordCommitmentUnderTwoIdentitiesIsReplayable() public {
        bytes memory password = "correct horse battery staple";
        bytes32 commitment = keccak256(password);
        bytes memory a = abi.encodePacked(address(new PasswordVerifier()), commitment);
        bytes memory b = abi.encodePacked(address(new PasswordVerifier()), commitment);
        _register(a);
        _register(b);

        guard.triggerLockdown(address(safe), REASON, a, password);
        vm.warp(block.timestamp + guard.getLockdownDuration(address(safe)));

        vm.prank(OBSERVER);
        guard.triggerLockdown(address(safe), REASON, b, password);

        (StateMachine.State s,) = guard.getState(address(safe));
        assertEq(uint256(s), uint256(StateMachine.State.LockedDown), "replay re-locked the Safe");
    }
}
