// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {console2} from "forge-std/Script.sol";

import {TestEnvironment} from "../test/TestEnvironment.sol";

import {Safe} from "@safe-global/safe-smart-account/Safe.sol";
import {Base64} from "@openzeppelin/contracts/utils/Base64.sol";
import {IERC7913SignatureVerifier} from "@openzeppelin/contracts/interfaces/IERC7913.sol";

import {Lockdown} from "../src/Lockdown.sol";
import {StateMachine} from "../src/base/StateMachine.sol";
import {WebAuthnVerifier, WebAuthnVerifierNoUV} from "../src/verifiers/WebAuthnVerifier.sol";

/// @title WebAuthn gas-envelope characterisation
/// @notice Measures what a WebAuthn (passkey) panic identity actually costs, so
///         the ERC-7913 verifier gas ceiling of issue #79 point A can be chosen
///         against numbers instead of a guess. It CHOOSES NOTHING: it reports a
///         minimum, a maximum observed, and the margin those imply.
///
/// @dev Deliberately a `forge script`, not a test. A test file would change the
///      483-test count that the audit brief, the scope sheet and the RFQ answers
///      all state, forcing a documentation round-trip for a measurement harness.
///      Nothing under `src/` is modified.
///
///      Fallback run (the repository's Prague target):
///        forge script script/WebAuthnGasEnvelope.s.sol --sig 'measure()' -v
///      Current-mainnet run, while preserving the exact Prague-compiled
///      verifier runtime:
///        export WEBAUTHN_UV_PRAGUE_RUNTIME="$(forge inspect \
///          src/verifiers/WebAuthnVerifier.sol:WebAuthnVerifier deployedBytecode)"
///        export WEBAUTHN_NOUV_PRAGUE_RUNTIME="$(forge inspect \
///          src/verifiers/WebAuthnVerifier.sol:WebAuthnVerifierNoUV deployedBytecode)"
///        forge script script/WebAuthnGasEnvelope.s.sol \
///          --sig 'measurePragueVerifierOnCurrentEvm()' \
///          --evm-version osaka --out out-osaka -v
///
///      READ THE NUMBERS WITH THESE CAVEATS:
///        - The default Prague EVM has no P-256 precompile, so it measures OZ's
///          Solidity fallback. Ethereum mainnet has EIP-7951 since Fusaka; the
///          second entry point executes the exact Prague-compiled verifier
///          runtime under Osaka to measure that production path as well.
///        - Cost varies with the clientDataJSON length, which varies by vendor
///          (origin string, extension fields). The captured fixtures cover real
///          Chrome/Google-Password-Manager and Chrome/YubiKey blobs; a longer
///          one costs more. This is a measured range, not a proven worst case.
contract WebAuthnGasEnvelope is TestEnvironment {
    bytes4 internal constant MAGIC = IERC7913SignatureVerifier.verify.selector;

    // secp256r1 group order, for low-s normalisation.
    uint256 internal constant P256_N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551;

    uint256 internal constant PASSKEY_PK = 0x0c0ffee0c0ffee0c0ffee0c0ffee0c0ffee0c0ffee0c0ffee0c0ffee0c0ffee1;

    bytes32 internal constant RP_ID_HASH = sha256("lockdown.runtime.capital");
    bytes32 internal constant REASON = keccak256("gas-envelope");

    WebAuthnVerifier internal vUV;
    WebAuthnVerifierNoUV internal vNoUV;

    uint256 internal minVerify = type(uint256).max;
    uint256 internal maxVerify;
    uint256 internal minTrigger = type(uint256).max;
    uint256 internal maxTrigger;

    // ------------------------------------------------------------------
    // Assertion construction
    // ------------------------------------------------------------------

    /// @dev authenticatorData = rpIdHash(32) || flags(1) || signCount(4).
    ///      flags: 0x01 = UP, 0x04 = UV.
    function _authData(bytes1 flags) internal pure returns (bytes memory) {
        return abi.encodePacked(RP_ID_HASH, flags, bytes4(0));
    }

    /// @dev The challenge is the raw 32-byte digest, base64url-encoded, exactly
    ///      as a browser would place it. typeIndex 1 and challengeIndex 23 are
    ///      the offsets of `"type":"` and `"challenge":"` in this layout.
    function _clientData(bytes32 challenge) internal pure returns (string memory) {
        return string.concat(
            '{"type":"webauthn.get","challenge":"',
            Base64.encodeURL(abi.encodePacked(challenge)),
            '","origin":"https://lockdown.runtime.capital","crossOrigin":false}'
        );
    }

    /// @dev Produces a genuine assertion over `challenge`, in the flat tuple
    ///      encoding OZ's `WebAuthn.tryDecodeAuth` expects (NOT
    ///      `abi.encode(struct)`, which prepends an outer offset).
    function _assertion(bytes32 challenge, bytes1 flags) internal pure returns (bytes memory) {
        bytes memory authData = _authData(flags);
        string memory clientData = _clientData(challenge);
        bytes32 message = sha256(abi.encodePacked(authData, sha256(bytes(clientData))));

        (bytes32 r, bytes32 s) = vm.signP256(PASSKEY_PK, message);
        // OZ rejects s > N/2 as malleable; browsers normalise, so do the same.
        if (uint256(s) > P256_N / 2) s = bytes32(P256_N - uint256(s));

        return abi.encode(r, s, uint256(23), uint256(1), authData, clientData);
    }

    function _passkey() internal view returns (bytes memory) {
        (uint256 qx, uint256 qy) = vm.publicKeyP256(PASSKEY_PK);
        return abi.encodePacked(bytes32(qx), bytes32(qy));
    }

    // ------------------------------------------------------------------
    // Measurement primitives
    // ------------------------------------------------------------------

    function _measureVerify(
        string memory label,
        IERC7913SignatureVerifier verifier,
        bytes memory key,
        bytes32 hash,
        bytes memory sig,
        bool expectMagic
    ) internal {
        // P256.verify calls 0x100 before falling back. Access lists are
        // transaction-wide, so without this reset later cases would inherit a
        // warm precompile and understate the per-transaction gas requirement.
        vm.cool(address(0x100));
        uint256 before = gasleft();
        bytes4 got = verifier.verify(key, hash, sig);
        uint256 cost = before - gasleft();

        require((got == MAGIC) == expectMagic, string.concat("unexpected verify() outcome for: ", label));
        // Only ACCEPTING paths bound the cap: a rejection that short-circuits
        // early is cheap and says nothing about the ceiling a real panic needs.
        if (expectMagic) {
            if (cost < minVerify) minVerify = cost;
            if (cost > maxVerify) maxVerify = cost;
        }
        console2.log(string.concat("  verify() ", expectMagic ? "ACCEPT  " : "reject  ", label), cost);
    }

    function _measureTrigger(string memory label, address verifier, bytes1 flags) internal {
        Safe safe = _createConfigureAndInitialise(uint256(keccak256(bytes(label))) % 1e6);
        bytes memory signer = abi.encodePacked(verifier, _passkey());

        vm.prank(address(safe));
        guard.addLockdownSigner(signer);

        bytes32 digest = _triggerDigest(safe, REASON);
        bytes memory sig = _assertion(digest, flags);

        // A real trigger transaction begins with both addresses cold. The
        // verifier access is paid by Lockdown outside the bounded STATICCALL;
        // the nested 0x100 access is paid from the verifier's forwarded gas.
        vm.cool(verifier);
        vm.cool(address(0x100));
        uint256 before = gasleft();
        guard.triggerLockdown(address(safe), REASON, signer, sig);
        uint256 cost = before - gasleft();

        (StateMachine.State state,) = guard.getState(address(safe));
        require(state == StateMachine.State.LockedDown, string.concat("trigger failed: ", label));
        require(guard.isSignerBurntPermanently(address(safe), signer), "identity not burnt");

        if (cost < minTrigger) minTrigger = cost;
        if (cost > maxTrigger) maxTrigger = cost;
        console2.log(string.concat("  triggerLockdown ACCEPT  ", label), cost);
    }

    /// @dev The EIP-712 digest `triggerLockdown` will check, so the WebAuthn
    ///      challenge is bound to the real `(safe, reasonHash)` rather than to a
    ///      fixed test challenge.
    function _triggerDigest(Safe safe, bytes32 reasonHash) internal view returns (bytes32) {
        (, string memory name, string memory version, uint256 chainId, address verifying, bytes32 salt,) =
            guard.eip712Domain();
        bytes32 domainSeparator = keccak256(
            abi.encode(
                keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
                keccak256(bytes(name)),
                keccak256(bytes(version)),
                chainId,
                verifying
            )
        );
        salt; // unused in this domain shape
        return keccak256(
            abi.encodePacked(
                hex"1901", domainSeparator, keccak256(abi.encode(guard.LOCKDOWN_TYPEHASH(), safe, reasonHash))
            )
        );
    }

    // ------------------------------------------------------------------
    // Entry point
    // ------------------------------------------------------------------

    function _deployVerifiers() internal {
        vUV = new WebAuthnVerifier();
        vNoUV = new WebAuthnVerifierNoUV();
    }

    function _measureDirectCases() internal {
        console2.log("-- A. generated assertions bound to the real EIP-712 trigger digest --");

        bytes memory key = _passkey();
        bytes32 probe = keccak256("probe-digest");

        bytes memory sigUV = _assertion(probe, 0x05); // UP | UV
        bytes memory sigUP = _assertion(probe, 0x01); // UP only

        _measureVerify("UV-required verifier, UV assertion", vUV, key, probe, sigUV, true);
        _measureVerify("UP-only verifier,     UV assertion", vNoUV, key, probe, sigUV, true);
        _measureVerify("UP-only verifier,     UP assertion", vNoUV, key, probe, sigUP, true);
        _measureVerify("UV-required verifier, UP assertion", vUV, key, probe, sigUP, false);
        _measureVerify("UV-required verifier, wrong digest ", vUV, key, keccak256("other"), sigUV, false);
        _measureVerify("UV-required verifier, garbage sig  ", vUV, key, probe, hex"deadbeef", false);
        _measureVerify("UV-required verifier, empty sig    ", vUV, key, probe, hex"", false);

        console2.log("");
        console2.log("-- B. captured vendor fixtures (real browser/authenticator blobs) --");
        _capturedFixtures();
    }

    function _printVerifyEnvelope() internal view {
        console2.log("accepting verify()        min", minVerify);
        console2.log("accepting verify()        max", maxVerify);
        console2.log("verifier-only max + 100%  ", maxVerify * 2);
    }

    function _hasP256Precompile() internal view returns (bool) {
        // Known-valid vector also used by OZ to distinguish an absent 0x100
        // from a precompile returning empty bytes for an invalid signature.
        bytes memory input = abi.encodePacked(
            bytes32(0xbb5a52f42f9c9261ed4361f59422a1e30036e7c32b270c8807a419feca605023),
            bytes32(uint256(5)),
            bytes32(uint256(1)),
            bytes32(0xa71af64de5126a4a4e02b7922d66ce9415ce88a4c9d25514d91082c8725ac957),
            bytes32(0x5d47723c8fbe580bb369fec9c2665d8e30a435b9932645482e7c9f11e872296b)
        );
        (bool ok, bytes memory result) = address(0x100).staticcall(input);
        return ok && result.length == 32 && abi.decode(result, (uint256)) == 1;
    }

    function measure() public {
        _deployVerifiers();

        console2.log("=== WebAuthn gas envelope (configured EVM) ===");
        console2.log("");
        _measureDirectCases();

        console2.log("");
        console2.log("-- C. full triggerLockdown, end to end --");
        _measureTrigger("UP-only verifier,     UP assertion", address(vNoUV), 0x01);
        _measureTrigger("UV-required verifier, UV assertion", address(vUV), 0x05);

        console2.log("");
        console2.log("=== ENVELOPE ===");
        console2.log("P-256 precompile present  ", _hasP256Precompile());
        _printVerifyEnvelope();
        console2.log("full triggerLockdown      min", minTrigger);
        console2.log("full triggerLockdown      max", maxTrigger);
        console2.log("");
        console2.log("A verifier gas cap must clear the verify() maximum, not the trigger");
        console2.log("maximum: the cap bounds only the STATICCALL into the verifier.");
        console2.log("This is a measured range over the fixtures above, NOT a proven");
        console2.log("worst case: a longer clientDataJSON costs more. Choosing the");
        console2.log("constant remains issue #79 point A.");
    }

    /// @notice Measure the exact verifier runtime produced by the repository's
    ///         Prague build while executing it under an Osaka/EIP-7951 EVM.
    /// @dev Export both default-build runtimes first as shown above. Only direct
    ///      verify() is reported: TestEnvironment's guard would be
    ///      recompiled for Osaka, so calling that an exact production
    ///      triggerLockdown measurement would be misleading.
    function measurePragueVerifierOnCurrentEvm() public {
        _deployVerifiers();
        require(_hasP256Precompile(), "current EVM has no P-256 precompile");
        vm.etch(address(vUV), vm.envBytes("WEBAUTHN_UV_PRAGUE_RUNTIME"));
        vm.etch(address(vNoUV), vm.envBytes("WEBAUTHN_NOUV_PRAGUE_RUNTIME"));

        console2.log("=== Prague verifier runtime on current EIP-7951 EVM ===");
        _measureDirectCases();
        console2.log("");
        console2.log("=== DIRECT VERIFY ENVELOPE ===");
        _printVerifyEnvelope();
    }

    function _capturedFixtures() internal {
        // Chrome desktop + Google Password Manager (Android), UP only.
        _measureVerify(
            "chrome/google-password-manager (UP-only verifier)",
            vNoUV,
            hex"4fa1748c33463cc3c3efbac38fbdca562bb6f3f189e558bff2ac5d69694a08b09ef6a5ba1be24cf649683e923e8a6e1389f2fe6e1d974cadf9737be7090a3cfc",
            0x1111111111111111111111111111111111111111111111111111111111111111,
            hex"dfc55fad6b43b2488be6d180bacb5c433186a96872c43ade6e39a6d8c347f81f5dab298d95eea7cffa9adcb76441d631910a312546e81133337fe60835f689210000000000000000000000000000000000000000000000000000000000000017000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000c00000000000000000000000000000000000000000000000000000000000000120000000000000000000000000000000000000000000000000000000000000002549960de5880e8c687434170f6476605b8fe4aeb9a28632c7995cf3ba831d9763190000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000867b2274797065223a22776562617574686e2e676574222c226368616c6c656e6765223a2245524552455245524552455245524552455245524552455245524552455245524552455245524552455245222c226f726967696e223a22687474703a2f2f6c6f63616c686f73743a38373635222c2263726f73734f726967696e223a66616c73657d0000000000000000000000000000000000000000000000000000",
            true
        );
        // Chrome desktop + YubiKey. UP only (no UV flag), and a notably longer
        // clientDataJSON carrying an extra JSON field - the expensive shape.
        _measureVerify(
            "chrome/yubikey, long clientDataJSON (UP-only verifier)",
            vNoUV,
            hex"fb86c9b927347d9ce8c92c3a09ed2cceb4a5a1131f84a7871464b55a3b74c360a3d473145d494960651fdb832771c9e6f7a20fcf959decbeef4dd451e9b01767",
            0x1111111111111111111111111111111111111111111111111111111111111111,
            hex"8963e432f879a861926e16b497ec80589aa774fb3dc0a93284a3e9067674a55d59a622915991ce12db8ec08765cf29ec756a8390a2b357e540ed7be23d92c36c0000000000000000000000000000000000000000000000000000000000000017000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000c00000000000000000000000000000000000000000000000000000000000000120000000000000000000000000000000000000000000000000000000000000002549960de5880e8c687434170f6476605b8fe4aeb9a28632c7995cf3ba831d9763010000000100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000f37b2274797065223a22776562617574686e2e676574222c226368616c6c656e6765223a2245524552455245524552455245524552455245524552455245524552455245524552455245524552455245222c226f726967696e223a22687474703a2f2f6c6f63616c686f73743a38373635222c2263726f73734f726967696e223a66616c73652c226f746865725f6b6579735f63616e5f62655f61646465645f68657265223a22646f206e6f7420636f6d7061726520636c69656e74446174614a534f4e20616761696e737420612074656d706c6174652e205365652068747470733a2f2f676f6f2e676c2f796162506578227d00000000000000000000000000",
            true
        );
    }
}
