// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, Vm} from "forge-std/Test.sol";

import {ISafe} from "@safe-global/safe-smart-account/interfaces/ISafe.sol";
import {Safe, Enum} from "@safe-global/safe-smart-account/Safe.sol";
import {SafeProxyFactory} from "@safe-global/safe-smart-account/proxies/SafeProxyFactory.sol";
import {MultiSendCallOnly} from "@safe-global/safe-smart-account/libraries/MultiSendCallOnly.sol";
import {IGuardManager} from "@safe-global/safe-smart-account/interfaces/IGuardManager.sol";
import {IModuleManager} from "@safe-global/safe-smart-account/interfaces/IModuleManager.sol";
import {IFallbackManager} from "@safe-global/safe-smart-account/interfaces/IFallbackManager.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";

import {Lockdown} from "../src/Lockdown.sol";
import {LockdownTimelock} from "../src/LockdownTimelock.sol";
import {LockdownFallbackHandler} from "../src/handlers/LockdownFallbackHandler.sol";

import {SafeDeployer} from "../script/helpers/SafeDeployer.sol";
import {DeployLockdown} from "../script/DeployLockdown.s.sol";

abstract contract TestEnvironment is Test, DeployLockdown {
    // Contracts (see deploy scripts and helpers)
    Safe internal singleton;
    SafeProxyFactory internal factory;
    MultiSendCallOnly internal multiSendCallOnly;
    LockdownTimelock internal guard;
    LockdownFallbackHandler internal handler;

    // EOA keys
    uint256 internal constant OWNER_PK = 0xB0B;
    uint256 internal constant PANIC_PK = 0xA11CE;
    uint256 internal constant RECOVERY_PK = 0xBACC;
    uint256 internal constant OTHER_PK = 0xC0DE;

    address internal owner = vm.addr(OWNER_PK);
    address internal panicKey = vm.addr(PANIC_PK);
    address internal recovery = vm.addr(RECOVERY_PK);
    address internal other = vm.addr(OTHER_PK);
    address internal module = address(0x80D3);

    // Platform
    function setUp() public virtual {
        singleton = SafeDeployer.deploySafe();
        factory = SafeDeployer.deploySafeProxyFactory();
        multiSendCallOnly = SafeDeployer.deployMultiSendCallOnly();
        (guard, handler) = run();
    }

    function _createSafe(uint256 nonce) internal virtual returns (Safe) {
        address[] memory owners = new address[](1);
        owners[0] = owner;

        return Safe(
            payable(factory.createProxyWithNonce(
                    address(singleton),
                    abi.encodeCall(
                        Safe.setup, (owners, 1, address(0), "", address(0), address(0), 0, payable(address(0)))
                    ),
                    nonce
                ))
        );
    }

    function _createAndConfigure(uint256 nonce) internal virtual returns (Safe) {
        Safe instance = _createSafe(nonce);
        vm.startPrank(address(instance));
        instance.setGuard(address(guard));
        instance.setModuleGuard(address(guard));
        instance.setFallbackHandler(address(handler));
        instance.enableModule(module);
        vm.stopPrank();
        return instance;
    }

    function _createConfigureAndInitialise(uint256 nonce) internal virtual returns (Safe) {
        Safe instance = _createAndConfigure(nonce);
        address[] memory recoveryOwners = new address[](1);
        recoveryOwners[0] = recovery;
        bytes[] memory signers = new bytes[](1);
        signers[0] = abi.encodePacked(panicKey);
        _execAsOwner(
            instance,
            address(guard),
            0,
            abi.encodeCall(Lockdown.initialize, (48 hours, 4 hours, recoveryOwners, signers)),
            Enum.Operation.Call
        );
        return instance;
    }

    // -------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------

    function _enableModule(ISafe instance, address module_) internal {
        _execAsOwner(
            instance, address(instance), 0, abi.encodeCall(IModuleManager.enableModule, (module_)), Enum.Operation.Call
        );
    }

    function _enableTimelock(ISafe instance, uint64 delay) internal {
        _execAsOwner(
            instance, address(guard), 0, abi.encodeCall(LockdownTimelock.setTimelockDelay, (delay)), Enum.Operation.Call
        );
    }

    function _triggerLockdown(ISafe instance, bytes32 reasonHash) internal {
        guard.triggerLockdown(
            address(instance), reasonHash, abi.encodePacked(panicKey), _signTrigger(instance, PANIC_PK, reasonHash)
        );
    }

    function _safeTxHash(ISafe instance, address to, uint256 value, bytes memory data, Enum.Operation op)
        internal
        view
        returns (bytes32)
    {
        return _safeTxHash(instance, to, value, data, op, instance.nonce());
    }

    function _safeTxHash(ISafe instance, address to, uint256 value, bytes memory data, Enum.Operation op, uint256 nonce)
        internal
        view
        returns (bytes32)
    {
        return instance.getTransactionHash(to, value, data, op, 0, 0, 0, address(0), address(0), nonce);
    }

    function _multiSendItem(Enum.Operation operation, address to, uint256 value, bytes memory data)
        internal
        pure
        returns (bytes memory)
    {
        return abi.encodePacked(operation, to, value, data.length, data);
    }

    function _signTx(
        ISafe instance,
        uint256 privateKey,
        address to,
        uint256 value,
        bytes memory data,
        Enum.Operation op
    ) internal view returns (bytes memory sig) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, _safeTxHash(instance, to, value, data, op));
        return abi.encodePacked(r, s, v);
    }

    function _signMessage(ISafe instance, uint256 privateKey, bytes32 hash) internal view returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, handler.getMessageHashForSafe(instance, abi.encode(hash)));
        return abi.encodePacked(r, s, v);
    }

    function _signTrigger(ISafe instance, uint256 privateKey, bytes32 reasonHash) internal view returns (bytes memory) {
        (
            bytes1 fields,
            string memory name,
            string memory version,
            uint256 chainId,
            address verifyingContract,
            bytes32 salt,
        ) = guard.eip712Domain();
        bytes32 digest = MessageHashUtils.toTypedDataHash(
            MessageHashUtils.toDomainSeparator(fields, name, version, chainId, verifyingContract, salt),
            keccak256(abi.encode(guard.LOCKDOWN_TYPEHASH(), instance, reasonHash))
        );
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, digest);
        return abi.encodePacked(r, s, v);
    }

    function _execAsOwner(ISafe instance, address to, uint256 value, bytes memory data, Enum.Operation op) internal {
        require(
            instance.execTransaction(
                to,
                value,
                data,
                op,
                0,
                0,
                0,
                address(0),
                payable(address(0)),
                _signTx(instance, OWNER_PK, to, value, data, op)
            )
        );
    }

    function _execAsOwner_Revert(
        ISafe instance,
        address to,
        uint256 value,
        bytes memory data,
        Enum.Operation op,
        bytes4 expectedRevert
    ) internal {
        bytes memory sig = _signTx(instance, OWNER_PK, to, value, data, op);
        vm.expectRevert(expectedRevert);
        instance.execTransaction(to, value, data, op, 0, 0, 0, address(0), payable(address(0)), sig);
    }

    function _execAsOwner_Revert(
        ISafe instance,
        address to,
        uint256 value,
        bytes memory data,
        Enum.Operation op,
        bytes memory expectedRevert
    ) internal {
        bytes memory sig = _signTx(instance, OWNER_PK, to, value, data, op);
        vm.expectRevert(expectedRevert);
        instance.execTransaction(to, value, data, op, 0, 0, 0, address(0), payable(address(0)), sig);
    }

    function _moduleCall(
        address module_,
        ISafe instance,
        address to,
        uint256 value,
        bytes memory data,
        Enum.Operation op
    ) internal {
        vm.prank(module_);
        require(instance.execTransactionFromModule(to, value, data, op));
    }

    function _moduleCall_Revert(
        address module_,
        ISafe instance,
        address to,
        uint256 value,
        bytes memory data,
        Enum.Operation op,
        bytes4 expectedRevert
    ) internal {
        vm.prank(module_);
        vm.expectRevert(expectedRevert);
        instance.execTransactionFromModule(to, value, data, op);
    }

    function _moduleCall_Revert(
        address module_,
        ISafe instance,
        address to,
        uint256 value,
        bytes memory data,
        Enum.Operation op,
        bytes memory expectedRevert
    ) internal {
        vm.prank(module_);
        vm.expectRevert(expectedRevert);
        instance.execTransactionFromModule(to, value, data, op);
    }

    function _burnNonce(ISafe instance) internal {
        _execAsOwner(instance, address(0), 0, "", Enum.Operation.Call);
    }
}
