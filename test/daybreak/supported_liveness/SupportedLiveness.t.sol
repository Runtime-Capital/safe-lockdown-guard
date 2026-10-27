// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {TestEnvironment} from "../../TestEnvironment.sol";
import {Safe} from "@safe-global/safe-smart-account/Safe.sol";
import {Enum} from "@safe-global/safe-smart-account/libraries/Enum.sol";
import {IERC7913SignatureVerifier} from "@openzeppelin/contracts/interfaces/IERC7913.sol";
import {Base64} from "@openzeppelin/contracts/utils/Base64.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";

import {Lockdown} from "../../../src/Lockdown.sol";
import {StateMachine} from "../../../src/base/StateMachine.sol";
import {WebAuthnVerifier} from "../../../src/verifiers/WebAuthnVerifier.sol";
import {DrillSigner} from "../../../script/DrillSigner.s.sol";

contract SupportedLivenessDaybreakTest is TestEnvironment {
    uint256 private constant P256_PRIVATE_KEY = 0x123456789;
    uint256 private constant P256_N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551;
    uint256 private constant P256_HALF_N = 0x7fffffff800000007fffffffffffffffde737d56d38bcf4279dce5617e3192a8;

    DrillSigner private drill = new DrillSigner();

    function test_control_webAuthnFlatTuplePreflightAndRealSafeTriggerAgree() public {
        WebAuthnVerifier verifier = new WebAuthnVerifier();
        (uint256 qx, uint256 qy) = vm.publicKeyP256(P256_PRIVATE_KEY);
        bytes memory key = abi.encodePacked(bytes32(qx), bytes32(qy));
        bytes memory identity = abi.encodePacked(address(verifier), key);
        Safe target = _createConfigureAndInitialiseWithSigner(1001, identity);

        bytes32 reasonHash = keccak256("supported-web-authn-real-trigger");
        bytes32 digest = _triggerDigest(address(target), identity, reasonHash);
        bytes memory signature = _webAuthnSignature(digest, true);

        assertEq(
            verifier.verify(key, digest, signature),
            IERC7913SignatureVerifier.verify.selector,
            "shipped verifier must accept the vector"
        );
        assertTrue(
            drill.isValid(guard, address(target), reasonHash, identity, signature), "off-chain drill must accept"
        );

        guard.triggerLockdown(address(target), reasonHash, identity, signature);

        (StateMachine.State state,) = guard.getState(address(target));
        assertEq(uint256(state), uint256(StateMachine.State.LockedDown), "genuine Safe must be locked");
        assertEq(guard.getLockdownSignerCount(address(target)), 0, "signer must be burned");
        assertEq(guard.lastReasonHash(address(target)), reasonHash, "reason must be recorded");
    }

    function test_limitation_nativeSafeSignerPassesNormalButCannotTriggerWhileSignerSafeIsLockedOrRecovering() public {
        Safe signerSafe = _createConfigureAndInitialise(2001);
        // A Safe used as a lockdown signer identity answers through ERC-1271, so it
        // must opt in (SPEC_V1 H.27): disabled by default.
        _allowErc1271(signerSafe);
        bytes memory signerIdentity = abi.encodePacked(address(signerSafe));
        Safe target = _createConfigureAndInitialiseWithSigner(2002, signerIdentity);

        bytes32 reasonHash = keccak256("correlated-incident-target");
        bytes32 digest = _triggerDigest(address(target), signerIdentity, reasonHash);
        bytes memory signature = _signMessage(signerSafe, OWNER_PK, digest);

        assertTrue(
            drill.isValid(guard, address(target), reasonHash, signerIdentity, signature),
            "normal ERC-1271 preflight must pass"
        );

        _triggerLockdown(signerSafe, keccak256("signer-safe-incident"));
        (StateMachine.State signerState,) = guard.getState(address(signerSafe));
        assertEq(uint256(signerState), uint256(StateMachine.State.LockedDown));
        assertFalse(
            drill.isValid(guard, address(target), reasonHash, signerIdentity, signature),
            "locked signer Safe must reject ERC-1271"
        );
        vm.expectRevert(Lockdown.BadSignature.selector);
        guard.triggerLockdown(address(target), reasonHash, signerIdentity, signature);
        assertEq(guard.getLockdownSignerCount(address(target)), 1, "failed trigger must not burn signer");

        vm.warp(block.timestamp + 48 hours);
        (signerState,) = guard.getState(address(signerSafe));
        assertEq(uint256(signerState), uint256(StateMachine.State.Recovering));
        assertFalse(
            drill.isValid(guard, address(target), reasonHash, signerIdentity, signature),
            "recovering signer Safe must reject ERC-1271"
        );
        vm.expectRevert(Lockdown.BadSignature.selector);
        guard.triggerLockdown(address(target), reasonHash, signerIdentity, signature);

        (StateMachine.State targetState,) = guard.getState(address(target));
        assertEq(uint256(targetState), uint256(StateMachine.State.Normal), "target remains unprotected");
        assertEq(guard.getLockdownSignerCount(address(target)), 1, "identity remains registered but unusable");
    }

    function _createConfigureAndInitialiseWithSigner(uint256 nonce, bytes memory signer)
        private
        returns (Safe instance)
    {
        instance = _createAndConfigure(nonce);
        address[] memory recoveryOwners = new address[](1);
        recoveryOwners[0] = recovery;
        bytes[] memory signers = new bytes[](1);
        signers[0] = signer;
        _execAsOwner(
            instance,
            address(guard),
            0,
            abi.encodeCall(Lockdown.initialize, (48 hours, 4 hours, recoveryOwners, signers)),
            Enum.Operation.Call
        );
    }

    function _triggerDigest(address safe, bytes memory signer, bytes32 reasonHash) private view returns (bytes32) {
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
            keccak256(abi.encode(guard.LOCKDOWN_TYPEHASH(), safe, keccak256(signer), reasonHash))
        );
    }

    function _webAuthnSignature(bytes32 digest, bool uv) private returns (bytes memory) {
        string memory challenge = Base64.encodeURL(abi.encodePacked(digest));
        string memory clientDataJSON =
            string.concat('{"type":"webauthn.get","challenge":"', challenge, '","origin":"https://runtime.capital"}');
        bytes1 flags = uv ? bytes1(0x05) : bytes1(0x01);
        bytes memory authenticatorData = abi.encodePacked(bytes32(0), flags, bytes4(0));
        bytes32 message = sha256(abi.encodePacked(authenticatorData, sha256(bytes(clientDataJSON))));
        (bytes32 r, bytes32 s) = vm.signP256(P256_PRIVATE_KEY, message);
        if (uint256(s) > P256_HALF_N) s = bytes32(P256_N - uint256(s));
        return abi.encode(r, s, uint256(23), uint256(1), authenticatorData, clientDataJSON);
    }
}
