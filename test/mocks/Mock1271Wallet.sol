// SPDX-License-Identifier: MIT
pragma solidity 0.8.35;

import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {IERC1271} from "@openzeppelin/contracts/interfaces/IERC1271.sol";
import {SignatureChecker} from "@openzeppelin/contracts/utils/cryptography/SignatureChecker.sol";

/// @dev Minimal ERC-1271 smart-contract wallet: approves a signature iff it is
///      a 65-byte ECDSA signature from the configured OWNER over the hash.
///      Exercises SignatureChecker's 20-byte 1271 branch (a contract identity).
contract Mock1271Wallet is Ownable, IERC1271 {
    constructor(address owner) Ownable(owner) {}

    function isValidSignature(bytes32 hash, bytes calldata sig) external view returns (bytes4) {
        return SignatureChecker.isValidSignatureNow(owner(), hash, sig)
            ? IERC1271.isValidSignature.selector
            : bytes4(0xffffffff);
    }
}
