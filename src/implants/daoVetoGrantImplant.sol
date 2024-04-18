// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity ^0.8.19;

import "../interfaces/ISafe.sol";
import "../libs/auth.sol";
import "forge-std/interfaces/IERC20.sol";
import "../interfaces/IGovernanceAdapter.sol";
import "../libs/conditions/conditionManager.sol";

contract daoVetoGrantImplant is GlobalACL, ConditionManager { //is baseImplant

    address public immutable BORG_SAFE;
    address public immutable governanceToken;
    uint256 public duration;
    uint256 public objectionsThreshold;
    uint256 public lastMotionId;
    address public governanceAdapter;
    address public governanceExecutor;

    struct Proposal {
        uint256 id;
        uint256 duration;
        uint256 startTime;
        bytes cdata;
    }

    struct approvedGrantToken { 
        address token;
        uint256 grantLimit;
    }

    error daoVetoGrantImplant_NotAuthorized();

    Proposal[] public currentProposals;
    approvedGrantToken[] public approvedGrantTokens;
    mapping(uint256 => uint256) internal proposalIndicesByProposalId;
    uint256 internal constant PERC_SCALE = 10000;

    constructor(Auth _auth, address _borgSafe, address _governanceToken, uint256 _duration, uint256 _objectionsThreshold, address _governanceAdapter) ConditionManager(_auth) {
        BORG_SAFE = _borgSafe;
        governanceToken = _governanceToken;
        duration = _duration;
        objectionsThreshold = _objectionsThreshold;
        lastMotionId=0;
        governanceAdapter = _governanceAdapter;
    }

    function updateDuration(uint256 _duration) external onlyOwner {
        duration = _duration;
    }

    function addApprovedGrantToken(address _token, uint256 _spendingLimit) external onlyOwner {
        approvedGrantTokens.push(approvedGrantToken(_token, _spendingLimit));
    }

    function removeApprovedGrantToken(address _token) external onlyOwner {
        for (uint256 i = 0; i < approvedGrantTokens.length; i++) {
            if (approvedGrantTokens[i].token == _token) {
                approvedGrantTokens[i] = approvedGrantTokens[approvedGrantTokens.length - 1];
                approvedGrantTokens.pop();
                break;
            }
        }
    }

    function setGovernanceAdapter(address _governanceAdapter) external onlyOwner {
        governanceAdapter = _governanceAdapter;
    }

    function updateObjectionsThreshold(uint256 _objectionsThreshold) external onlyOwner {
        objectionsThreshold = _objectionsThreshold;
    }

    function getApprovedGrantTokenByAddress(address _token) internal view returns (approvedGrantToken storage) {
        for (uint256 i = 0; i < approvedGrantTokens.length; i++) {
            if (approvedGrantTokens[i].token == _token) {
                return approvedGrantTokens[i];
            }
        }
        return approvedGrantTokens[0];
    }

    function _isTokenApproved(address _token) internal view returns (bool) {
        for (uint256 i = 0; i < approvedGrantTokens.length; i++) {
            if (approvedGrantTokens[i].token == _token) {
                return true;
            }
        }
        return false;
    }

    function createProposal(address _token, address _recipient, uint256 _amount, address _votingAuthority) external 
        returns (uint256 _newProposalId)
    {
        require(ISafe(BORG_SAFE).isOwner(msg.sender), "Caller is not an owner of the BORG");
        require(_isTokenApproved(_token), "Token not approved for grants");
        approvedGrantToken storage approvedToken = getApprovedGrantTokenByAddress(_token);


        Proposal storage newProposal = currentProposals.push();
        _newProposalId = ++lastMotionId;
        newProposal.id = _newProposalId;
        newProposal.startTime = block.timestamp;
        proposalIndicesByProposalId[_newProposalId] = currentProposals.length;
    }

    // should only be executed by a BORG owner/member
    function executeProposal(uint256 _proposalId)
        external
    {
        Proposal storage proposal = _getProposal(_proposalId);
        require(proposal.startTime + proposal.duration <= block.timestamp, "Proposal is not ready to be executed");

    }

    function _getProposal(uint256 _proposalId) internal view returns (Proposal storage) {
        uint256 proposalIndex = proposalIndicesByProposalId[_proposalId];
        require(proposalIndex > 0, "Proposal not found");
        return currentProposals[proposalIndex - 1];
    }

    function _deleteProposal(uint256 _proposalId) public {
        uint256 proposalIndex = proposalIndicesByProposalId[_proposalId];
        require(proposalIndex > 0, "Proposal not found");
        uint256 lastProposalIndex = currentProposals.length - 1;
        if (proposalIndex != lastProposalIndex) {
            currentProposals[proposalIndex - 1] = currentProposals[lastProposalIndex];
            proposalIndicesByProposalId[currentProposals[lastProposalIndex].id] = proposalIndex;
        }
        currentProposals.pop();
        delete proposalIndicesByProposalId[_proposalId];
    }
}
