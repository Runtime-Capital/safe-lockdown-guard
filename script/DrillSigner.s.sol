// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Script, console2} from "forge-std/Script.sol";

import {SignatureChecker} from "@openzeppelin/contracts/utils/cryptography/SignatureChecker.sol";

import {Lockdown} from "../src/Lockdown.sol";
import {StateMachine} from "../src/base/StateMachine.sol";

/// @title Off-chain lockdown signer drill
/// @notice Checks that a panic identity and a signature would pass
///         `triggerLockdown`, without consuming the identity and without sending
///         the signature anywhere.
///
/// @dev A trigger signature is a bearer credential: whoever holds it can call
///      `triggerLockdown` with it. `Lockdown` therefore has no on-chain drill
///      view, and this script must never be pointed at a remote node with
///      `cast call` or `eth_call`. Run it against a LOCAL fork: forge executes
///      the verification in its own EVM and only fetches public state (code and
///      storage) from the RPC. The script never broadcasts.
///
///      A signature that passes this drill IS a valid trigger, and stays one
///      until the identity is burnt or removed (SPEC_V1 §H.25). Do not store or
///      share it; if it may have leaked, rotate the identity in Normal.
///
///      Pass inputs through the environment so the signature stays out of shell
///      history (e.g. `read -rs SIGNATURE && export SIGNATURE`):
///        LOCKDOWN     singleton address
///        SAFE         Safe address
///        REASON_HASH  bytes32 reason hash that was signed
///        SIGNER       ERC-7913 signer identity bytes
///        SIGNATURE    signature bytes (for PasswordVerifier: the cleartext)
///
///        forge script script/DrillSigner.s.sol --fork-url "$RPC"
///
///      The check mirrors `triggerLockdown` exactly: the EIP-712 digest is taken
///      from the singleton's `hashLockdownTrigger` view, which shares its encoding
///      with `triggerLockdown` (it binds `safe`, the `signer` identity and
///      `reasonHash`; SPEC_V1 §H.29), and the signature goes through the same
///      `SignatureChecker.isValidSignatureNow` call, against the forked state.
///      It cannot account for state that changes between the drill and the real
///      trigger (e.g. an EOA that later gains code through EIP-7702).
contract DrillSigner is Script {
    struct Report {
        StateMachine.State state;
        bool registered;
        bool burnt;
        bool valid;
    }

    function run() external view {
        Lockdown lockdown = Lockdown(vm.envAddress("LOCKDOWN"));
        address safe = vm.envAddress("SAFE");
        bytes32 reasonHash = vm.envBytes32("REASON_HASH");
        bytes memory signer = vm.envBytes("SIGNER");
        bytes memory signature = vm.envBytes("SIGNATURE");

        require(address(lockdown).code.length != 0, "no code at LOCKDOWN: run against a fork (--fork-url)");

        Report memory r = check(lockdown, safe, reasonHash, signer, signature);
        console2.log("state      ", _stateName(r.state));
        console2.log("registered ", r.registered);
        console2.log("burnt      ", r.burnt);
        console2.log("signature  ", r.valid ? "VALID" : "INVALID");
        require(r.registered && r.valid, "drill failed: triggerLockdown would revert");
    }

    /// @notice The EIP-712 digest `triggerLockdown` verifies for `(safe, signer, reasonHash)`.
    /// @dev Read from the singleton rather than re-encoded here, so the drill
    ///      cannot drift from the trigger. The view takes no signature.
    function digest(Lockdown lockdown, address safe, bytes memory signer, bytes32 reasonHash)
        public
        view
        returns (bytes32)
    {
        return lockdown.hashLockdownTrigger(safe, signer, reasonHash);
    }

    /// @notice Whether `signature` from `signer` verifies over the trigger digest.
    function isValid(Lockdown lockdown, address safe, bytes32 reasonHash, bytes memory signer, bytes memory signature)
        public
        view
        returns (bool)
    {
        return SignatureChecker.isValidSignatureNow(signer, digest(lockdown, safe, signer, reasonHash), signature);
    }

    function check(Lockdown lockdown, address safe, bytes32 reasonHash, bytes memory signer, bytes memory signature)
        public
        view
        returns (Report memory r)
    {
        (r.state,) = lockdown.getState(safe);
        r.registered = lockdown.isLockdownSigner(safe, signer);
        r.burnt = lockdown.isSignerBurntPermanently(safe, signer);
        r.valid = isValid(lockdown, safe, reasonHash, signer, signature);
    }

    function _stateName(StateMachine.State s) private pure returns (string memory) {
        if (s == StateMachine.State.Normal) return "Normal";
        if (s == StateMachine.State.LockedDown) return "LockedDown";
        if (s == StateMachine.State.Recovering) return "Recovering";
        return "Uninitialised";
    }
}
