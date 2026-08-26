// SPDX-License-Identifier: MIT
pragma solidity 0.8.35;

import {IERC7913SignatureVerifier} from "@openzeppelin/contracts/interfaces/IERC7913.sol";

// TEST-ONLY adversarial verifiers used to validate the trigger's
// normalisation of misbehaving verifier returns at execution time.
// **None of these MUST ever be approved on a production Safe.**
//
// Naming convention:
//   - Mock<X>Verifier         : always misbehaves. Smoke test REJECTS.
//   - MockSelective<X>Verifier: passes the smoke test (returns non-magic
//                               on empty input) but misbehaves on real
//                               input. Used to exercise explicit signer
//                               removal and trigger-time normalisation.

bytes4 constant ERC7913_MAGIC = IERC7913SignatureVerifier.verify.selector;

/* ------------------------- always-misbehaving ------------------------- */

/// @notice Always reverts. Smoke test rejects.
contract MockRevertingVerifier is IERC7913SignatureVerifier {
    error VerifierBoom(bytes32 reason);

    function verify(bytes calldata, bytes32, bytes calldata) external pure override returns (bytes4) {
        revert VerifierBoom(bytes32("boom"));
    }
}

/// @notice Returns a wrong bytes4 (not magic). Smoke test ACCEPTS (no
///         security issue at approval time; verifier is merely useless).
///         At trigger time, the L.3 normalisation reverts BadSignature.
contract MockWrongMagicVerifier is IERC7913SignatureVerifier {
    function verify(bytes calldata, bytes32, bytes calldata) external pure override returns (bytes4) {
        return bytes4(0xDEADBEEF);
    }
}

/// @notice Returns empty bytes (no abi-encoded bytes4). Smoke test rejects.
contract MockEmptyReturnVerifier {
    fallback() external {
        assembly {
            return(0, 0)
        }
    }
}

/// @notice Always returns the magic value regardless of input.
///         Smoke test REJECTS at approval time - this is the always-magic
///         class the smoke test exists to neutralise.
contract MockAlwaysMagicVerifier is IERC7913SignatureVerifier {
    function verify(bytes calldata, bytes32, bytes calldata) external pure override returns (bytes4) {
        return ERC7913_MAGIC;
    }
}

/* -------------------------- selective ones ---------------------------- */

/// @notice Selective attacker: returns non-magic on empty input but returns
///         the magic value for any non-empty input. Models a malicious
///         verifier that looks inert under a shallow drill then activates.
///         Used to confirm explicit `removeLockdownSigner` still
///         neutralises the registered tuple.
contract MockSelectiveMagicVerifier is IERC7913SignatureVerifier {
    function verify(bytes calldata key, bytes32, bytes calldata) external pure override returns (bytes4) {
        if (key.length == 0) return bytes4(0); // pass smoke
        return ERC7913_MAGIC; // accept any signer post-approval
    }
}

/// @notice Buggy verifier: returns non-magic on empty input but reverts on
///         any non-empty input. Used to assert that the L.3 trigger-time
///         normalisation produces a clean `BadSignature()` instead of
///         bubbling arbitrary revert data.
contract MockSelectiveRevertingVerifier is IERC7913SignatureVerifier {
    error LateBoom();

    function verify(bytes calldata key, bytes32, bytes calldata) external pure override returns (bytes4) {
        if (key.length == 0) return bytes4(0); // pass smoke
        revert LateBoom(); // L.3 normalises this
    }
}

/// @notice Stateful verifier that can be flipped from "reject" to "accept".
///         Used to prove a failed trigger attempt leaves no burnt state behind:
///         the same registered identity can succeed once the verifier accepts.
contract MockToggleVerifier is IERC7913SignatureVerifier {
    bool public accepts;

    function setAccepts(bool value) external {
        accepts = value;
    }

    function verify(bytes calldata, bytes32, bytes calldata) external view override returns (bytes4) {
        return accepts ? ERC7913_MAGIC : bytes4(0);
    }
}
