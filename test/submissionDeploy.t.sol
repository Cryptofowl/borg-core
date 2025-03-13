// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity 0.8.20;

import "forge-std/Test.sol";
import "../scripts/submissionDeploy.sol";

contract borgCoreScriptTest is Test {
    borgScript public script;
    borgCore public core;
    BorgAuth public auth;
    failSafeImplant failSafe;
    SignatureHelper helper;
    IGnosisSafe public safe = IGnosisSafe(0x9a72ec2F0FF9e8c1e640e8F163B45A6f8E31F764);
    address public weth = 0x4200000000000000000000000000000000000006;
    address public executor = 0x400e942A08DCA906349d59957A5E6AA2856D3603;

    function setUp() public {
        script = new borgScript();
        script.run();
        core = script.core();
        auth = script.auth();
        helper = script.helper();
        failSafe = script.failSafe();
        safe = script.safe();
    }

    /*
        The script should:
            - Deploy failsafe, auth, core, and helper contracts
            - Set the signature helper on the core contract
            - Enable the failsafe module on the safe
            - Set the guard to the core contract
            - The core should be owned by the executor address, have the correct name, and be in the correct mode

        The safe should:
            - Only be able to interact with the whitelisted WETH contract
            - Only be able to use the two whitelisted methods of the WETH contract
            - Only be able to transfer or approve to the whitelisted address
            - Only be able to transfer or approve the whitelisted amount
            - Only allow the owner to change access controls
            - Be able to eject to the failsafe address
    */
    function test_deployment() public {
        assertFalse(address(core) == address(0));
        assertFalse(address(auth) == address(0));
        assertFalse(address(helper) == address(0));
        assertFalse(address(failSafe) == address(0));
    }
    function test_core() public {
        assertEq(auth.userRoles(executor), 99);
        assertEq(core.id(), "Submission Dev BORG");
        assertEq(uint256(core.borgMode()), uint256(borgCore.borgModes.whitelist));
        assertEq(address(core.helper()), address(helper));
    }

    function test_transfer() public {

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
        vm.prank(owner);
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