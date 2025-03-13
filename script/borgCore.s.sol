// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

import {Script, console} from "forge-std/Script.sol";
import "../test/libraries/safe.t.sol";
import "../src/borgCore.sol";
import "../src/libs/auth.sol";
import "../src/implants/failSafeImplant.sol";

contract borgScript is Script {
    function setUp() public {}

    function run() public {
        vm.startBroadcast();

        vm.stopBroadcast();
    }

}