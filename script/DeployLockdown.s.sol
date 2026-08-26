// SPDX-License-Identifier: MIT
pragma solidity 0.8.35;

import {Script, console} from "forge-std/Script.sol";
import {ArachnidFactoryDeployer, SafeSingletonFactoryDeployer} from "./helpers/FactoryDeployers.sol";
import {LockdownTimelock} from "../src/LockdownTimelock.sol";
import {LockdownFallbackHandler} from "../src/handlers/LockdownFallbackHandler.sol";

import {SafeDeployer} from "./helpers/SafeDeployer.sol";

/// @title DeployLockdown
/// @notice Deterministic CREATE2 deployment of the V1 `LockdownTimelock`
///         singleton through the canonical Arachnid / Foundry deterministic
///         deployment proxy. A fixed salt gives the singleton the SAME address
///         on every chain where the constructor init code is identical, which
///         is what the legacy in-place-upgrade story (preserve the Safe's
///         address) relies on.
/// @dev    The singleton bakes `MULTI_SEND_CALL_ONLY` as an immutable
///         constructor argument, so it is part of the CREATE2 init code:
///         cross-chain address parity therefore holds only where the canonical
///         Safe `MultiSendCallOnly` sits at the same address (true for standard
///         EVM chains; chains where it differs carry EVM differences that would
///         block this design anyway).
///
///         Usage (dry run):
///           MULTI_SEND_CALL_ONLY=0x... forge script script/DeployLockdown.s.sol
///         Broadcast:
///           MULTI_SEND_CALL_ONLY=0x... LOCKDOWN_SALT=0x... \
///             forge script script/DeployLockdown.s.sol \
///             --rpc-url <url> --broadcast --verify
///
///         After deploy, paste the printed EXTCODEHASH into
///         `deploy/manifest.json` (`.chains[<chainId>].singletonCodehash`) and
///         confirm the install with `scripts/verify-install-v1.sh`.
contract DeployLockdown is Script {
    function run() public returns (LockdownTimelock guard, LockdownFallbackHandler handler) {
        // ===================================================================
        // Fetch environment variables
        // ===================================================================
        bytes32 salt = vm.envOr("LOCKDOWN_SALT", bytes32(0));
        address multiSendCallOnly = vm.envOr("MULTI_SEND_CALL_ONLY", address(SafeDeployer.MULTI_SEND_CALL_ONLY));

        // ===================================================================
        // Check environment
        // ===================================================================
        if (CREATE2_FACTORY.code.length == 0) {
            require(CREATE2_FACTORY == ArachnidFactoryDeployer.FACTORY_ADDR, "Cannot deploy custom CREATE2 factory");
            ArachnidFactoryDeployer.deployFactory();
            require(CREATE2_FACTORY.code.length != 0, "CREATE2 factory deployment failed");
        } else {
            console.log("CREATE2 factory already present:", CREATE2_FACTORY);
        }
        if (multiSendCallOnly.code.length == 0) {
            require(
                multiSendCallOnly == address(SafeDeployer.MULTI_SEND_CALL_ONLY),
                "Cannot deploy custom MultiSendCallOnly"
            );
            SafeDeployer.deployMultiSendCallOnly();
        } else {
            console.log("MultiSendCallOnly already present:", multiSendCallOnly);
        }

        // ===================================================================
        // Predict deployment address
        // ===================================================================
        guard = LockdownTimelock(
            vm.computeCreate2Address(
                salt,
                keccak256(abi.encodePacked(type(LockdownTimelock).creationCode, abi.encode(multiSendCallOnly))),
                CREATE2_FACTORY
            )
        );
        handler = LockdownFallbackHandler(
            vm.computeCreate2Address(
                salt,
                keccak256(abi.encodePacked(type(LockdownFallbackHandler).creationCode, abi.encode(guard))),
                CREATE2_FACTORY
            )
        );
        // ===================================================================
        // Summary
        // ===================================================================
        console.log("MultiSendCallOnly:", multiSendCallOnly);
        console.log("Salt:");
        console.logBytes32(salt);
        console.log("Predicted guard:", address(guard));
        console.log("Predicted handler:", address(handler));
        // Idempotent: re-running with the same salt on a chain that already has
        // the singleton is a no-op, so a multi-chain rollout is replayable.
        if (address(guard).code.length == 0) {
            vm.startBroadcast();
            LockdownTimelock deployed = new LockdownTimelock{salt: salt}(multiSendCallOnly);
            vm.stopBroadcast();

            require(address(guard) == address(deployed), "deployed address != predicted (CREATE2 routing)");
            console.log("Deployed guard:", address(guard));
        } else {
            console.log("Singleton already deployed at predicted address, skipping.");
        }

        if (address(handler).code.length == 0) {
            vm.startBroadcast();
            LockdownFallbackHandler deployed = new LockdownFallbackHandler{salt: salt}(guard);
            vm.stopBroadcast();

            require(address(handler) == address(deployed), "deployed address != predicted (CREATE2 routing)");
            console.log("Deployed handler:", address(handler));
        } else {
            console.log("Handler already deployed at predicted address, skipping.");
        }
    }
}
