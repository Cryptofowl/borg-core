// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

import {Script} from "forge-std/Script.sol";
import "../test/libraries/safe.t.sol";
import "../src/borgCore.sol";
import "../src/libs/auth.sol";
import "../src/implants/failSafeImplant.sol";

contract borgScript is Script {
    borgCore public core;
    BorgAuth public auth;
    SignatureHelper public helper;
    failSafeImplant public failSafe;
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
        helper = new SignatureHelper();

        core.setSignatureHelper(helper);

        // Implant recovery module
        failSafe = new failSafeImplant(auth, address(safe), 0x68Ab3F79622cBe74C9683aA54D7E1BBdCAE8003C);
        bytes memory failsafeData = abi.encodeWithSignature("enableModule(address)", address(failSafe));
        GnosisTransaction memory failsafeTxData = GnosisTransaction({to: address(safe), value: 0, data: failsafeData}); 
        executeData(failsafeTxData.to, 0, failsafeTxData.data);

        // Set guard to assimilate safe
        bytes memory guardData = abi.encodeWithSignature("setGuard(address)", address(core));
        GnosisTransaction memory guardTxData = GnosisTransaction({to: address(safe), value: 0, data: guardData}); 
        executeData(guardTxData.to, 0, guardTxData.data);

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

        // Update cooldowns
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

        // Transfer ownership to executor
        auth.updateRole(executor, 99);
        auth.zeroOwner();

        vm.stopBroadcast();
    }

    function executeData(
        address to,
        uint8 operation,
        bytes memory data
    ) public {
        uint256 value = 0;
        uint256 safeTxGas = 0;
        uint256 baseGas = 0;
        uint256 gasPrice = 0;
        address gasToken = address(0);
        address refundReceiver = address(0);
        uint256 nonce = safe.nonce();
        bytes memory signature = getSignature(
            to,
            value,
            data,
            operation,
            safeTxGas,
            baseGas,
            gasPrice,
            gasToken,
            refundReceiver,
            nonce
        );
        safe.execTransaction(
            to,
            value,
            data,
            operation,
            safeTxGas,
            baseGas,
            gasPrice,
            gasToken,
            refundReceiver,
            signature
        );
    }

    function getSignature(
        address to,
        uint256 value,
        bytes memory data,
        uint8 operation,
        uint256 safeTxGas,
        uint256 baseGas,
        uint256 gasPrice,
        address gasToken,
        address refundReceiver,
        uint256 nonce
    ) public view returns (bytes memory) {
        bytes memory txHashData = safe.encodeTransactionData(
            to,
            value,
            data,
            operation,
            safeTxGas,
            baseGas,
            gasPrice,
            gasToken,
            refundReceiver,
            nonce
        );

        uint256 deployerPrivateKey = vm.envUint("PRIVATE_KEY");
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(deployerPrivateKey, keccak256(txHashData));
        bytes memory signature = abi.encodePacked(r, s, v);
        return signature;
    }

}