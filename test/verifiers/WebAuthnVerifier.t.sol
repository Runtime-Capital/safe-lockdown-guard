// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {WebAuthnVerifier, WebAuthnVerifierNoUV} from "../../src/verifiers/WebAuthnVerifier.sol";
import {IERC7913SignatureVerifier} from "@openzeppelin/contracts/interfaces/IERC7913.sol";
import {WebAuthn} from "@openzeppelin/contracts/utils/cryptography/WebAuthn.sol";

/// @notice End-to-end tests for `WebAuthnVerifier`. The fixture is a REAL
///         secp256r1 WebAuthn assertion generated off-chain (Python
///         `cryptography`), so the positive path exercises OZ's audited
///         `WebAuthn.verify` + `P256.verifySolidity` (the test EVM has no
///         RIP-7212 precompile, so `P256.verify` falls back to Solidity).
///
///         Fixture parameters (see deploy notes):
///           private key seed : 0x0c0ffee...0c0ffee1 (mod n)
///           digest (challenge): 0x1111...11
///           flags            : 0x05 (UP | UV)
contract WebAuthnVerifierTest {
    bytes4 constant MAGIC = IERC7913SignatureVerifier.verify.selector;

    // ---- real P-256 / WebAuthn fixture ----
    bytes32 constant QX = 0x932d6a8e55fa12f467b8abdd67bec872e73f55e92038dd66705c00ffe4897882;
    bytes32 constant QY = 0x3cb55a5de09aec868a5664946ea65c14f18bc33c82fc80466ffebb7bdc333c83;
    bytes32 constant R = 0x19485f8d4b3c058130c6f400385a4876751409ecd940d9dd77d209dcc54b11fa;
    bytes32 constant S = 0x50aa6e1b0ad9ac0c6f37ff327f4ec2ddf0f74e421a352ede82c73efb829887ce;
    bytes32 constant S_HIGH = 0xAF5591E3F52653F490C800CD80B13D21CBEFAC6B8CE26FA670F28BC779CA9D83;
    bytes32 constant DIGEST = 0x1111111111111111111111111111111111111111111111111111111111111111;
    uint256 constant CHALLENGE_INDEX = 23;
    uint256 constant TYPE_INDEX = 1;
    bytes constant AUTH_DATA = hex"d1f393a0b240d51b1bf76a511c09f653cb5414e5ec0bcfabe045c0cba6a578d70500000000";
    // flags byte (index 32) = 0x01 (UP only, no UV)
    bytes constant AUTH_DATA_UP_ONLY = hex"d1f393a0b240d51b1bf76a511c09f653cb5414e5ec0bcfabe045c0cba6a578d70100000000";
    // flags byte = 0x00 (no UP)
    bytes constant AUTH_DATA_NO_UP = hex"d1f393a0b240d51b1bf76a511c09f653cb5414e5ec0bcfabe045c0cba6a578d70000000000";
    string constant CLIENT_DATA =
        "{\"type\":\"webauthn.get\",\"challenge\":\"ERERERERERERERERERERERERERERERERERERERERERE\",\"origin\":\"https://lockdown.runtime.capital\",\"crossOrigin\":false}";

    IERC7913SignatureVerifier vUV = new WebAuthnVerifier(); // REQUIRE_UV = true
    IERC7913SignatureVerifier vNoUV = new WebAuthnVerifierNoUV(); // REQUIRE_UV = false

    function _key() internal pure returns (bytes memory) {
        return abi.encodePacked(QX, QY);
    }

    /// @dev Flat tuple encoding (NOT `abi.encode(structInstance)`, which would
    ///      prepend a 0x20 outer offset that `WebAuthn.tryDecodeAuth` does not
    ///      expect). The 6 fields encode directly to the head||tail layout the
    ///      decoder reads. The frontend MUST produce the same flat encoding.
    function _sig(bytes32 r, bytes32 s, bytes memory authData, string memory clientData)
        internal
        pure
        returns (bytes memory)
    {
        return abi.encode(r, s, CHALLENGE_INDEX, TYPE_INDEX, authData, clientData);
    }

    function _assert(bool cond, string memory what) internal pure {
        require(cond, what);
    }

    // ---------------------------------------------------------------
    // Positive
    // ---------------------------------------------------------------

    function test_verify_validAssertion_returnsMagic_uvRequired() public view {
        bytes memory sig = _sig(R, S, AUTH_DATA, CLIENT_DATA);
        _assert(vUV.verify(_key(), DIGEST, sig) == MAGIC, "uv-required positive");
    }

    function test_verify_validAssertion_returnsMagic_uvNotRequired() public view {
        bytes memory sig = _sig(R, S, AUTH_DATA, CLIENT_DATA);
        _assert(vNoUV.verify(_key(), DIGEST, sig) == MAGIC, "no-uv positive");
    }

    // ---------------------------------------------------------------
    // Challenge binding
    // ---------------------------------------------------------------

    function test_verify_wrongDigest_fails() public view {
        bytes memory sig = _sig(R, S, AUTH_DATA, CLIENT_DATA);
        bytes32 otherDigest = 0x2222222222222222222222222222222222222222222222222222222222222222;
        _assert(vUV.verify(_key(), otherDigest, sig) != MAGIC, "wrong digest must fail");
    }

    // ---------------------------------------------------------------
    // Flag policy
    // ---------------------------------------------------------------

    function test_verify_upMissing_fails() public view {
        bytes memory sig = _sig(R, S, AUTH_DATA_NO_UP, CLIENT_DATA);
        _assert(vNoUV.verify(_key(), DIGEST, sig) != MAGIC, "UP missing must fail");
    }

    function test_verify_uvMissing_failsWhenRequired() public view {
        bytes memory sig = _sig(R, S, AUTH_DATA_UP_ONLY, CLIENT_DATA);
        _assert(vUV.verify(_key(), DIGEST, sig) != MAGIC, "UV required but missing");
    }

    // ---------------------------------------------------------------
    // Signature integrity
    // ---------------------------------------------------------------

    function test_verify_tamperedAuthData_fails() public view {
        // UP set (0x01) so the flag gate passes, but the message hash now
        // differs from what was signed -> P256 rejects.
        bytes memory sig = _sig(R, S, AUTH_DATA_UP_ONLY, CLIENT_DATA);
        _assert(vNoUV.verify(_key(), DIGEST, sig) != MAGIC, "tampered authData must fail");
    }

    function test_verify_highS_fails() public view {
        // OZ WebAuthn.verify -> P256.verify rejects the malleable high-s form.
        bytes memory sig = _sig(R, S_HIGH, AUTH_DATA, CLIENT_DATA);
        _assert(vUV.verify(_key(), DIGEST, sig) != MAGIC, "high-s must fail");
    }

    // ---------------------------------------------------------------
    // Malformed-input safety
    // ---------------------------------------------------------------

    function test_verify_emptyInput_isNotMagic() public view {
        // Malformed (empty) input must not revert and must not be magic.
        _assert(vUV.verify("", bytes32(0), "") != MAGIC, "empty must not be magic");
    }

    function test_verify_garbageSignature_isNotMagicNoRevert() public view {
        _assert(vUV.verify(_key(), DIGEST, hex"deadbeef") != MAGIC, "garbage sig must not be magic");
    }

    function test_verify_structEncodedSignature_isNotMagic() public view {
        WebAuthn.WebAuthnAuth memory auth = WebAuthn.WebAuthnAuth({
            r: R,
            s: S,
            challengeIndex: CHALLENGE_INDEX,
            typeIndex: TYPE_INDEX,
            authenticatorData: AUTH_DATA,
            clientDataJSON: CLIENT_DATA
        });
        _assert(vUV.verify(_key(), DIGEST, abi.encode(auth)) != MAGIC, "struct encoding has outer offset");
    }
}
