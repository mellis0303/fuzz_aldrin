// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

interface ITaskMailbox {
    function submitAuditResult(uint256 taskId, bytes calldata report, bytes[] calldata signatures) external;
}

contract AVSTaskHook {
    struct OperatorResult {
        address operator;
        uint256 score;
        uint256 findingsCount;
        bytes signature;
    }
    
    address public owner;
    address public aggregator;
    ITaskMailbox public taskMailbox;
    
    mapping(address => uint256) public operatorStakes;
    mapping(address => uint256) public operatorPerformance;
    mapping(uint256 => OperatorResult[]) public taskResults;
    
    uint256 public constant CONSENSUS_THRESHOLD = 67; // 67%
    uint256 public constant MAX_SCORE_VARIANCE = 15;
    uint256 public constant SLASHING_PENALTY = 5; // 5%
    
    event ResultProcessed(uint256 taskId, uint256 consensusScore);
    event OperatorSlashed(address operator, uint256 amount);
    event RewardsDistributed(uint256 taskId, uint256 totalRewards);
    
    modifier onlyAggregator() {
        require(msg.sender == aggregator, "Only aggregator");
        _;
    }
    
    modifier onlyOwner() {
        require(msg.sender == owner, "Only owner");
        _;
    }
    
    constructor(address _taskMailbox) {
        owner = msg.sender;
        taskMailbox = ITaskMailbox(_taskMailbox);
    }
    
    function setAggregator(address _aggregator) external onlyOwner {
        aggregator = _aggregator;
    }
    
    function processAuditResult(
        uint256 taskId,
        bytes calldata auditReport,
        bytes[] calldata signatures,
        OperatorResult[] calldata results
    ) external onlyAggregator {
        require(signatures.length == results.length, "Mismatched signatures");
        
        // Store operator results
        for (uint i = 0; i < results.length; i++) {
            taskResults[taskId].push(results[i]);
        }
        
        // Calculate consensus
        (uint256 consensusScore, address[] memory outliers) = calculateConsensus(results);
        
        // Slash outliers
        for (uint i = 0; i < outliers.length; i++) {
            if (outliers[i] != address(0)) {
                slashOperator(outliers[i]);
            }
        }
        
        // Submit to TaskMailbox
        taskMailbox.submitAuditResult(taskId, auditReport, signatures);
        
        emit ResultProcessed(taskId, consensusScore);
    }
    
    function calculateConsensus(
        OperatorResult[] calldata results
    ) internal pure returns (uint256 consensusScore, address[] memory outliers) {
        if (results.length == 0) return (0, new address[](0));
        
        // Calculate average score
        uint256 totalScore = 0;
        for (uint i = 0; i < results.length; i++) {
            totalScore += results[i].score;
        }
        consensusScore = totalScore / results.length;
        
        // Find outliers
        outliers = new address[](results.length);
        uint256 outlierCount = 0;
        
        for (uint i = 0; i < results.length; i++) {
            uint256 variance = results[i].score > consensusScore 
                ? results[i].score - consensusScore 
                : consensusScore - results[i].score;
                
            if (variance > MAX_SCORE_VARIANCE) {
                outliers[outlierCount++] = results[i].operator;
            }
        }
        
        return (consensusScore, outliers);
    }
    
    function slashOperator(address operator) internal {
        uint256 stake = operatorStakes[operator];
        uint256 penalty = (stake * SLASHING_PENALTY) / 100;
        
        operatorStakes[operator] -= penalty;
        operatorPerformance[operator] = (operatorPerformance[operator] * 95) / 100;
        
        emit OperatorSlashed(operator, penalty);
    }
    
    function distributeRewards(uint256 taskId, uint256 totalRewards) external onlyAggregator {
        OperatorResult[] memory results = taskResults[taskId];
        require(results.length > 0, "No results");
        
        // Calculate rewards based on stake and performance
        uint256[] memory rewards = new uint256[](results.length);
        uint256 totalWeight = 0;
        
        for (uint i = 0; i < results.length; i++) {
            uint256 weight = operatorStakes[results[i].operator] * 
                           operatorPerformance[results[i].operator] / 100;
            rewards[i] = weight;
            totalWeight += weight;
        }
        
        // Distribute proportionally
        for (uint i = 0; i < results.length; i++) {
            uint256 reward = (totalRewards * rewards[i]) / totalWeight;
            payable(results[i].operator).transfer(reward);
        }
        
        emit RewardsDistributed(taskId, totalRewards);
    }
    
    receive() external payable {}
} 