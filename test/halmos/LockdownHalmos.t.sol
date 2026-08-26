// SPDX-License-Identifier: MIT
pragma solidity 0.8.35;

import {Test} from "forge-std/Test.sol";

import {Enum} from "@safe-global/safe-smart-account/interfaces/ISafe.sol";

import {Lockdown} from "../../src/Lockdown.sol";
import {LockdownFallbackHandler} from "../../src/handlers/LockdownFallbackHandler.sol";
import {PasswordVerifier} from "../../src/verifiers/PasswordVerifier.sol";
import {MockToggleVerifier} from "../mocks/MockAdversarialVerifiers.sol";

/// @dev Minimal stand-in for the Safe surface used by Lockdown initialization.
contract HalmosMockSafe {
    uint256 private constant GUARD_STORAGE_SLOT = 0x4a204f620c8c5ccdca3fd54d003badd85ba500436a431f0cbda4f558c93c34c8;
    uint256 private constant MODULE_GUARD_STORAGE_SLOT =
        0xb104e0b93118902c651344349b610029d694cfdec91c589c91ebafbcd0289947;
    uint256 private constant FALLBACK_HANDLER_STORAGE_SLOT =
        0x6c9a6c4a39284e37ed1cf53d337577d14212a4870fb976a4366c693b939918d5;

    mapping(address => bool) private _owners;
    address private _guard;
    address private _moduleGuard;
    address private _fallbackHandler;

    function setOwner(address owner, bool isOwner_) external {
        _owners[owner] = isOwner_;
    }

    function setInstalledGuards(address guard, address moduleGuard, address fallbackHandler) external {
        _guard = guard;
        _moduleGuard = moduleGuard;
        _fallbackHandler = fallbackHandler;
    }

    function isOwner(address owner) external view returns (bool) {
        return _owners[owner];
    }

    function getStorageAt(uint256 slot, uint256 length) external view returns (bytes memory) {
        if (length != 1) return "";
        if (slot == GUARD_STORAGE_SLOT) return abi.encode(_guard);
        if (slot == MODULE_GUARD_STORAGE_SLOT) return abi.encode(_moduleGuard);
        if (slot == FALLBACK_HANDLER_STORAGE_SLOT) return abi.encode(_fallbackHandler);
        return abi.encode(bytes32(0));
    }
}

/// @notice Focused Halmos entrypoints for parser and auth rollback checks.
/// @dev These checks intentionally avoid `vm.expectRevert`, which Halmos 0.3.3
///      does not support. Reverts are observed through low-level calls.
contract LockdownHalmosTest is Test {
    address private constant SAFE_A = address(0xCAFE);
    address private constant MULTI_SEND_CALL_ONLY = address(0xA83C);
    address private constant BACKUP_OWNER = address(0xC003);
    bytes private constant PASSWORD = "halmos-password";

    Lockdown private guard;
    bytes private passwordIdentity;

    function setUp() public {
        HalmosMockSafe template = new HalmosMockSafe();
        vm.etch(SAFE_A, address(template).code);

        PasswordVerifier passwordVerifier = new PasswordVerifier();
        guard = new Lockdown(MULTI_SEND_CALL_ONLY);
        LockdownFallbackHandler handler = new LockdownFallbackHandler(guard);
        HalmosMockSafe(SAFE_A).setInstalledGuards(address(guard), address(guard), address(handler));
        passwordIdentity = abi.encodePacked(address(passwordVerifier), keccak256(PASSWORD));

        address[] memory backups = new address[](1);
        backups[0] = BACKUP_OWNER;
        bytes[] memory signers = new bytes[](1);
        signers[0] = passwordIdentity;

        vm.prank(SAFE_A);
        guard.initialize(48 hours, 4 hours, backups, signers);
    }

    function check_recoveryRejectsAddSigner() public {
        _enterRecovery();

        bytes memory addCall = abi.encodeWithSelector(guard.addLockdownSigner.selector, passwordIdentity);

        assert(!_ownerHookAccepts(address(guard), addCall));
    }

    function check_triggerFailedVerifierCanRetry() public {
        MockToggleVerifier verifier = new MockToggleVerifier();
        bytes memory identity = abi.encodePacked(address(verifier), bytes32("retry-key"));

        vm.prank(SAFE_A);
        guard.addLockdownSigner(identity);

        verifier.setAccepts(false);
        (bool failed,) =
            address(guard).call(abi.encodeCall(guard.triggerLockdown, (SAFE_A, bytes32("first"), identity, hex"01")));
        assert(!failed);
        assert(guard.isLockdownSigner(SAFE_A, identity));
        assert(!guard.isSignerBurntPermanently(SAFE_A, identity));

        verifier.setAccepts(true);
        guard.triggerLockdown(SAFE_A, bytes32("retry"), identity, hex"01");
        assert(!guard.isLockdownSigner(SAFE_A, identity));
        assert(guard.isSignerBurntPermanently(SAFE_A, identity));
    }

    function _enterRecovery() private {
        guard.triggerLockdown(SAFE_A, bytes32("panic"), passwordIdentity, PASSWORD);
        vm.warp(block.timestamp + 48 hours + 1);
    }

    function _ownerHookAccepts(address to, bytes memory data) private returns (bool) {
        vm.prank(SAFE_A);
        (bool ok,) = address(guard)
            .call(
                abi.encodeCall(
                    guard.checkTransaction,
                    (to, 0, data, Enum.Operation.Call, 0, 0, 0, address(0), payable(address(0)), hex"", address(0))
                )
            );
        return ok;
    }
}
