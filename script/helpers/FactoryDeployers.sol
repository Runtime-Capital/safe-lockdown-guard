// SPDX-License-Identifier: MIT
pragma solidity 0.8.35;

import {console} from "forge-std/console.sol";
import {Vm} from "forge-std/Vm.sol";

library ArachnidFactoryDeployer {
    Vm internal constant vm = Vm(0x7109709ECfa91a80626fF3989D68f67F5b1DD12D);

    address internal constant FACTORY_ADDR = 0x4e59b44847b379578588920cA78FbF26c0B4956C;
    address internal constant FACTORY_DEPLOYER = 0x3fAB184622Dc19b6109349B94811493BF2a45362;
    uint256 internal constant FACTORY_GAS_COST = 0.01 ether;
    bytes internal constant FACTORY_RAW_TX =
        hex"f8a58085174876e800830186a08080b853604580600e600039806000f350fe7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe03601600081602082378035828234f58015156039578182fd5b8082525050506014600cf31ba02222222222222222222222222222222222222222222222222222222222222222a02222222222222222222222222222222222222222222222222222222222222222";

    function deployFactory() internal returns (address) {
        if (FACTORY_ADDR.code.length == 0) {
            console.log("Arachnid factory absent; bootstrapping via Nick's method...");
            (bool funded,) = FACTORY_DEPLOYER.call{value: FACTORY_GAS_COST}("");
            require(funded, "funding the Arachnid deployer EOA failed");
            vm.broadcastRawTransaction(FACTORY_RAW_TX);
            require(FACTORY_ADDR.code.length != 0, "Arachnid factory bootstrap failed");
            console.log("Arachnid factory deployed:", FACTORY_ADDR);
        } else {
            console.log("Arachnid factory already present:", FACTORY_ADDR);
        }
        return FACTORY_ADDR;
    }
}

library SafeSingletonFactoryDeployer {
    Vm internal constant vm = Vm(0x7109709ECfa91a80626fF3989D68f67F5b1DD12D);

    address internal constant FACTORY_ADDR = 0x914d7Fec6aaC8cd542e72Bca78B30650d45643d7;
    address internal constant FACTORY_DEPLOYER = 0xE1CB04A0fA36DdD16a06ea828007E35e1a3cBC37;
    uint256 internal constant FACTORY_GAS_COST = 0.01 ether;
    // ChainID specifid (1)
    bytes internal constant FACTORY_RAW_TX =
        hex"f8a58085174876e800830186a08080b853604580600e600039806000f350fe7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe03601600081602082378035828234f58015156039578182fd5b8082525050506014600cf326a0b1fd9f4102283a663738983f1aac789e979e220a1b649faa74033f507b911af5a061dd0f2f6f2341ee95913cf94b3b8a49cac9fdd7be6310da7acd7a96e31958d7";
    bytes internal constant FACTORY_BYTECODE =
        hex"7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe03601600081602082378035828234f58015156039578182fd5b8082525050506014600cf3";

    function deployFactory() internal returns (address) {
        if (FACTORY_ADDR.code.length == 0) {
            // console.log("Safe Singleton factory absent; bootstrapping via Nick's method...");
            // (bool funded,) = FACTORY_DEPLOYER.call{value: FACTORY_GAS_COST}("");
            // require(funded, "funding the Safe Singleton deployer EOA failed");
            // vm.broadcastRawTransaction(FACTORY_RAW_TX);
            console.log("Safe Singleton factory absent; bootstrapping using cheatcode...");
            vm.etch(FACTORY_ADDR, FACTORY_BYTECODE);
            require(FACTORY_ADDR.code.length != 0, "Safe Singleton factory bootstrap failed");
            console.log("Safe Singleton factory deployed:", FACTORY_ADDR);
        } else {
            console.log("Safe Singleton factory already present:", FACTORY_ADDR);
        }
        return FACTORY_ADDR;
    }
}
