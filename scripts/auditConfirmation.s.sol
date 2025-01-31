// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity 0.8.20;

import {Script} from "forge-std/Script.sol";
import "../src/borgCore.sol";
import "../src/implants/ejectImplant.sol";
import "../src/implants/optimisticGrantImplant.sol";
import "../src/implants/daoVoteGrantImplant.sol";
import "../src/implants/daoVetoGrantImplant.sol";
import "../src/implants/daoVetoImplant.sol";
import "../src/implants/daoVoteImplant.sol";
import "../src/libs/conditions/signatureCondition.sol";
import "../src/libs/conditions/multiUseSignCondition.sol";
import "../src/libs/conditions/balanceCondition.sol";
import "../src/libs/conditions/deadManSwitchCondition.sol";
import "../src/libs/conditions/timeCondition.sol";
import "../src/libs/conditions/chainlinkOracleCondition.sol";
import "../src/libs/conditions/API3OracleCondition.sol";
import "../src/implants/failSafeImplant.sol";
import "../test/libraries/mocks/MockGovToken.sol";
import "../test/libraries/mocks/FlexGov.sol";
import "metavest/MetaVesTController.sol";
import "../src/libs/governance/flexGovernanceAdapater.sol";
import "../test/libraries/safe.t.sol";
import {console} from "forge-std/console.sol";
import "metavest/VestingAllocationFactory.sol";
import "metavest/TokenOptionFactory.sol";
import "metavest/RestrictedTokenFactory.sol";

contract BaseScript is Script {
  address deployerAddress;
  
  address MULTISIG = 0x5604C974C1bea9adC59AA01F769D77A0a1aB03f8;//eth:0x5604C974C1bea9adC59AA01F769D77A0a1aB03f8//0xA52ccdee6105D758964ee55155Ced6c012eA0e89;//0xC92Bc86Ae8E0561A57d1FBA63B58447b0E24c58F;//0x201308B728ACb48413CD27EC60B4FfaC074c2D01; //change this to the deployed Safe address
  address owner = 0x5Dd10e6b3622921481d56d8CB6456f22173dd4D4;
  IGnosisSafe safe;
  borgCore core;
  ejectImplant eject;
  BorgAuth auth;
  optimisticGrantImplant opGrant;
  daoVoteGrantImplant voteGrant;
  daoVetoGrantImplant vetoGrant;
  daoVoteImplant voteImplant;
  daoVetoImplant vetoImplant;
  SignatureCondition sigCondition;
  failSafeImplant failSafe;
  MockERC20Votes govToken;
  FlexGov mockDao;
  metavestController metaVesTController;
  FlexGovernanceAdapter governanceAdapter;
  MultiUseSignCondition multiSignCondition;

     function run() public {
            deployerAddress = vm.addr(vm.envUint("PRIVATE_KEY_MAIN"));
            uint256 deployerPrivateKey = vm.envUint("PRIVATE_KEY_MAIN");
            vm.startBroadcast(deployerPrivateKey);
           // multiSignCondition = new MultiUseSignCondition(MULTISIG, 1);
            auth = new BorgAuth();
            //auth.updateRole(owner, 98);
            govToken = new MockERC20Votes("OnlyBORGs", "oBORG");
            mockDao = new FlexGov(govToken, auth);
            govToken.delegate(address(this));

            vm.stopBroadcast();
            safe = IGnosisSafe(MULTISIG);
            vm.startBroadcast(deployerPrivateKey);
            governanceAdapter = new FlexGovernanceAdapter(auth, address(mockDao));
            auth.updateRole(address(governanceAdapter), 98);

            VestingAllocationFactory vestingFactory = new VestingAllocationFactory();
            TokenOptionFactory tokenOptionFactory = new TokenOptionFactory();
            RestrictedTokenFactory restrictedTokenFactory = new RestrictedTokenFactory();

            metaVesTController = new metavestController(MULTISIG, MULTISIG, address(vestingFactory), address(tokenOptionFactory), address(restrictedTokenFactory));
            vm.stopBroadcast();
            address controllerAddr = address(metaVesTController);
            vm.startBroadcast(deployerPrivateKey);

            //(BorgAuth _auth, uint256 _borgType, borgModes _mode, string memory _identifier, address _safe)
            core = new borgCore(auth, 0x1, borgCore.borgModes.whitelist, "", address(safe));
            failSafe = new failSafeImplant(auth, address(safe), deployerAddress);
            eject = new ejectImplant(auth, MULTISIG, address(failSafe), false, true);
            opGrant = new optimisticGrantImplant(auth, MULTISIG, address(metaVesTController));
            auth.updateRole(address(opGrant), 98);

            voteGrant = new daoVoteGrantImplant(auth, MULTISIG, 10, 10, 40, address(governanceAdapter), address(mockDao), address(metaVesTController));
            auth.updateRole(address(voteGrant), 98);

            //constructor(BorgAuth _auth, address _borgSafe, uint256 _duration, uint _quorum, uint256 _threshold, uint _waitingPeriod, address _governanceAdapter, address _governanceExecutor, address _metaVesT, address _metaVesTController) BaseImplant(_auth, _borgSafe) {
            vetoGrant = new daoVetoGrantImplant(auth, MULTISIG, 600, 5, 10, 600, address(governanceAdapter), address(mockDao), address(metaVesTController));
            auth.updateRole(address(vetoGrant), 98);

    /*        BorgAuth _auth,
        address _borgSafe,
        uint256 _duration,
        uint256 _quorum,
        uint256 _threshold,
        address _governanceAdapter,
        address _governanceExecutor*/
            voteImplant = new daoVoteImplant(auth, MULTISIG, 10, 10, 40, address(governanceAdapter), address(mockDao));
              //(BorgAuth _auth, address _borgSafe, uint256 _duration, uint256 _quorum, uint256 _threshold, uint256 _cooldown, address _governanceAdapter, address _governanceExecutor) 
            vetoImplant = new daoVetoImplant(auth, MULTISIG, 600, 5, 10, 600, address(governanceAdapter), address(mockDao));

            auth.updateRole(address(governanceAdapter), 98);
            auth.updateRole(address(mockDao), 99);
            auth.updateRole(address(eject), 99);
            
            executeSingle(getAddModule(address(opGrant)));
            executeSingle(getAddModule(address(vetoGrant)));
            executeSingle(getAddModule(address(voteGrant)));
            executeSingle(getAddModule(address(voteImplant)));
            executeSingle(getAddModule(address(vetoImplant)));
            executeSingle(getAddModule(address(eject)));
            executeSingle(getAddModule(address(failSafe)));

            //dao deploys the core, with the dao as the owner.
            core.addFullAccessOrBlockContract(address(core));
            core.addFullAccessOrBlockContract(address(safe));
            core.addFullAccessOrBlockContract(address(opGrant));
            core.addFullAccessOrBlockContract(address(vetoGrant));
            core.addFullAccessOrBlockContract(address(voteGrant));
            core.addFullAccessOrBlockContract(address(voteImplant));
            core.addFullAccessOrBlockContract(address(vetoImplant));
            core.addFullAccessOrBlockContract(address(govToken));
                                         
            govToken.transfer(MULTISIG, 100000000000 * 10**18);
            govToken.transfer(owner,      10000000000 * 10**18);
            opGrant.setGrantLimits(10, 1728380215);
            opGrant.addApprovedGrantToken(address(govToken), 1000000000 * 10**18, 50000000000 * 10**18);
            vetoGrant.addApprovedGrantToken(address(govToken), 50000000000 * 10**18);
            vetoGrant.updateDuration(1 hours);

            //Set the core as the guard for the safe
            executeSingle(getSetGuardData(address(MULTISIG)));
            vm.stopBroadcast();
            console.log("Deployed");
            console.log("Addresses:");
            console.log("Safe: ", MULTISIG);
            console.log("Core: ", address(core));
            console.log("Optimistic Grant: ", address(opGrant));
            console.log("Vote Grant: ", address(voteGrant));
            console.log("Veto Grant: ", address(vetoGrant));
            console.log("Vote: ", address(voteImplant));
            console.log("Veto: ", address(vetoImplant));
            console.log("Eject: ", address(eject));
            console.log("FailSafe: ", address(failSafe));
            console.log("Auth: ", address(auth));
            console.log("Governance Adapter: ", address(governanceAdapter));
            console.log("MetaVesT Controller: ", address(metaVesTController));
            console.log("Mock DAO: ", address(mockDao));
            console.log("Mock Gov Token: ", address(govToken));


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

        uint256 deployerPrivateKey = vm.envUint("PRIVATE_KEY_MAIN");
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(deployerPrivateKey, keccak256(txHashData));
        bytes memory signature = abi.encodePacked(r, s, v);
        return signature;
    }


    function executeSingle(GnosisTransaction memory tx) public {
        executeData(tx.to, 0, tx.data);
    }

    function executeSingle(GnosisTransaction memory tx, uint256 value) public {
        executeData(tx.to, 0, tx.data, value);
    }

    function getAddModule(address to) public view returns (GnosisTransaction memory) {
    bytes4 addContractMethod = bytes4(
        keccak256("enableModule(address)")
    );

    bytes memory guardData = abi.encodeWithSelector(
        addContractMethod,
        to
    );
    GnosisTransaction memory txData = GnosisTransaction({to: address(safe), value: 0, data: guardData}); 
    return txData;
    }
    
    function getSetGuardData(address to) public view returns (GnosisTransaction memory) {
    bytes4 setGuardFunctionSignature = bytes4(
        keccak256("setGuard(address)")
    );

     bytes memory guardData = abi.encodeWithSelector(
        setGuardFunctionSignature,
        address(core)
    );
    GnosisTransaction memory txData = GnosisTransaction({to: to, value: 0, data: guardData});
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

    function executeData(
        address to,
        uint8 operation,
        bytes memory data, 
        uint256 _value
    ) public {
        uint256 value = _value;
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

}