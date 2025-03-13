// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

import {Script, console} from "forge-std/Script.sol";
import "../test/libraries/safe.t.sol";
import "../src/borgCore.sol";
import "../src/libs/auth.sol";
import "../src/implants/failSafeImplant.sol";

contract borgScript is Script {
    borgCore public core;
    BorgAuth public auth;
    failSafeImplant failSafe;
    IGnosisSafe public safe = IGnosisSafe(0x9a72ec2F0FF9e8c1e640e8F163B45A6f8E31F764);
    address public weth = 0x4200000000000000000000000000000000000006;
    address public executor = 0x400e942A08DCA906349d59957A5E6AA2856D3603;
    function setUp() public {}

    function run() public {
        vm.startBroadcast();

        borgCore.borgModes _mode = borgCore.borgModes(0); // Whitelist BORG
        string memory _identifier = "Submission Dev BORG";
        bytes32[] memory matches = new bytes32[](1);
        matches[0] = keccak256(abi.encodePacked(address(0x341Da9fb8F9bD9a775f6bD641091b24Dd9aA459B)));

        auth = new BorgAuth(); 
        core = new borgCore(auth, 0x3, _mode, _identifier, address(safe));

        // Whitelist WETH contract methods
        // TODO: Combine into updatePolicy()
        // Add two unsigned integer range parameter constraints for approve and transfer, and two exact matches for the address parameter
        core.addUnsignedRangeParameterConstraint(
            weth,
            "approve(address,uint256)",
            borgCore.ParamType.UINT,
            0,
            999999999999999999, // Maximum < 1 Ether
            36,
            32
        );

        core.addUnsignedRangeParameterConstraint(
            weth,
            "transfer(address,uint256)",
            borgCore.ParamType.UINT,
            0,
            999999999999999999, // Maximum < 1 Ether
            36,
            32
        );

        core.addExactMatchParameterConstraint(
            weth, 
            "approve(address,uint256)",
            borgCore.ParamType.ADDRESS,
            matches,
            16,
            20
        );

        core.addExactMatchParameterConstraint(
            weth, 
            "transfer(address,uint256)",
            borgCore.ParamType.ADDRESS,
            matches,
            16,
            20
        );

        core.updateMethodCooldown(
            weth,
            "approve(address,uint256)",
            604800 // 1 week
        );

        core.updateMethodCooldown(
            weth,
            "transfer(address,uint256)",
            604800 // 1 week
        );

        vm.stopBroadcast();
    }

}