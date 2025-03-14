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
    address public guy = 0x341Da9fb8F9bD9a775f6bD641091b24Dd9aA459B;
    address public dai = 0x50c5725949A6F0c72E6C4a641F24049A917DB0Cb;

    function setUp() public {
        script = new borgScript();
        script.run();
        core = script.core();
        auth = script.auth();
        helper = script.helper();
        failSafe = script.failSafe();
        safe = script.safe();
        vm.deal(address(safe), 115792089237316195423570985008687907853269984665640564039457584007913129639935);
        vm.prank(address(safe));
        (bool success, ) = weth.call{value: 115792089237316195423570985008687907853269984665640563039457584007913129639935}(abi.encodeWithSignature("deposit()"));
        require(success, "WETH deposit failed");
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
            - Only be able to approve or transfer after the cooldown period
            - Be able to eject to the failsafe address
    */

    function testDeployment() public {
        assertFalse(address(core) == address(0));
        assertFalse(address(auth) == address(0));
        assertFalse(address(helper) == address(0));
        assertFalse(address(failSafe) == address(0));
    }
    function testCore() public {
        assertEq(auth.userRoles(executor), 99);
        assertEq(core.id(), "Submission Dev BORG");
        assertEq(uint256(core.borgMode()), uint256(borgCore.borgModes.whitelist));
        assertEq(address(core.helper()), address(helper));
    }

    function testApprove(uint256 amount) public {
        vm.assume(amount < 1 ether);
        vm.warp(block.timestamp + 604800);
        GnosisTransaction memory approveTx = getApproveData(weth, guy, amount);
        executeData(approveTx.to, 0, approveTx.data);
        assertEq(IERC20(weth).allowance(address(safe), guy), amount);
    }

    function testRevertApprove(uint256 amount) public {
        vm.assume(amount > 1 ether);
        GnosisTransaction memory approveTx = getApproveData(weth, guy, amount);
        executeRevertData(approveTx.to, 0, approveTx.data);
    }

    function testApproveCooldown(uint256 amount) public {
        vm.assume(amount < 1 ether - 1);
        vm.warp(block.timestamp + 604800);
        GnosisTransaction memory approveTx = getApproveData(weth, guy, amount);
        executeData(approveTx.to, 0, approveTx.data);
        assertEq(IERC20(weth).allowance(address(safe), guy), amount);
        vm.warp(block.timestamp + 1209600);
        approveTx = getApproveData(weth, guy, amount + 1);
        executeData(approveTx.to, 0, approveTx.data);
        assertEq(IERC20(weth).allowance(address(safe), guy), amount + 1);
    }

    function testRevertApproveCooldown(uint256 amount) public {
        vm.assume(amount < 1 ether);
        vm.warp(block.timestamp + 604800);
        GnosisTransaction memory approveTx = getApproveData(weth, guy, amount);
        executeData(approveTx.to, 0, approveTx.data);
        assertEq(IERC20(weth).allowance(address(safe), guy), amount);
        approveTx = getApproveData(weth, guy, amount); 
        executeRevertData(approveTx.to, 0, approveTx.data);
    }

    function testTransfer(uint256 amount) public {
        vm.assume(amount < 1 ether);
        vm.assume(IERC20(weth).balanceOf(address(safe)) > amount);
        vm.warp(block.timestamp + 604800);
        GnosisTransaction memory approveTx = getApproveData(weth, guy, amount);
        executeData(approveTx.to, 0, approveTx.data);
        GnosisTransaction memory transferTx = getTransferData(weth, guy, amount);
        executeData(transferTx.to, 0, transferTx.data);
        assertEq(IERC20(weth).balanceOf(guy), amount);
    }

    function testRevertTransfer(uint256 amount) public {
        vm.assume(amount > 1 ether);
        GnosisTransaction memory transferTx = getTransferData(weth, guy, amount);
        executeRevertData(transferTx.to, 0, transferTx.data);
    }

    function testTransferCooldown(uint256 amount) public {
        vm.assume(amount < 1 ether);
        vm.assume(IERC20(weth).balanceOf(address(safe)) > amount * 2);
        vm.warp(block.timestamp + 604800);
        GnosisTransaction memory approveTx = getApproveData(weth, guy, amount);
        executeData(approveTx.to, 0, approveTx.data);
        GnosisTransaction memory transferTx = getTransferData(weth, guy, amount);
        executeData(transferTx.to, 0, transferTx.data);
        vm.warp(block.timestamp + 1209600);
        approveTx = getApproveData(weth, guy, amount);
        executeData(approveTx.to, 0, approveTx.data);
        transferTx = getTransferData(weth, guy, amount);
        executeData(transferTx.to, 0, transferTx.data);
        assertEq(IERC20(weth).balanceOf(guy), amount + amount);
    }

    function testRevertTransferCooldown(uint256 amount) public {
        vm.assume(amount < 1 ether);
        vm.warp(block.timestamp + 604800);
        GnosisTransaction memory approveTx = getApproveData(weth, guy, amount);
        executeData(approveTx.to, 0, approveTx.data);
        GnosisTransaction memory transferTx = getTransferData(weth, guy, amount);
        executeData(transferTx.to, 0, transferTx.data);
        assertEq(IERC20(weth).balanceOf(guy), amount);
        transferTx = getTransferData(weth, guy, amount); 
        executeRevertData(transferTx.to, 0, transferTx.data);
    }

    function testRevertUnauthorizedContract() public {
        vm.warp(block.timestamp + 604800);
        GnosisTransaction memory approveTx = getApproveData(dai, guy, 1 ether);
        executeRevertData(approveTx.to, 0, approveTx.data);
    }

    function testSafeModule() public {
        // Normally I would add the method to the interface, but for the purposes of the assessment I will avoid altering other files
        (bool success, bytes memory data) = address(safe).call(
            abi.encodeWithSignature("isModuleEnabled(address)", address(failSafe))); 
        bool module = abi.decode(data, (bool));
        assertTrue(module);
        assertTrue(success);
    }

    function testOwner() public {
        assertEq(auth.userRoles(executor), 99);
        assertEq(auth.userRoles(msg.sender), 0);
    }

    function getTransferData(address token, address to, uint256 amount) public pure returns (GnosisTransaction memory) {
        bytes memory transferData = abi.encodeWithSignature(
            "transfer(address,uint256)",
            to,
            amount
        );
        GnosisTransaction memory txData = GnosisTransaction({to: token, value: 0, data: transferData});
        return txData;
    }

    function getApproveData(address token, address to, uint256 amount) public pure returns (GnosisTransaction memory) {
        bytes memory transferData = abi.encodeWithSignature(
            "approve(address,uint256)",
            to,
            amount
        );
        GnosisTransaction memory txData = GnosisTransaction({to: token, value: 0, data: transferData});
        return txData;
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
        vm.prank(executor);
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

    function executeRevertData(
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
        vm.prank(executor);
        vm.expectRevert();
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