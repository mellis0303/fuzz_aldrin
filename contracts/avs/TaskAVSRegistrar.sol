// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

contract TaskAVSRegistrar {
    struct Operator {
        bytes publicKey;
        uint256 stake;
        bool isActive;
        uint256 performanceScore;
        uint256 registeredAt;
    }
    
    mapping(address => Operator) public operators;
    address[] public operatorList;
    
    address public owner;
    uint256 public constant MIN_STAKE = 32 ether;
    uint256 public constant INITIAL_PERFORMANCE = 100;
    
    event OperatorRegistered(address indexed operator, bytes publicKey, uint256 stake);
    event OperatorDeregistered(address indexed operator);
    event OperatorSlashed(address indexed operator, uint256 penalty);
    event StakeUpdated(address indexed operator, uint256 newStake);
    
    modifier onlyOwner() {
        require(msg.sender == owner, "Only owner");
        _;
    }
    
    modifier onlyRegistered() {
        require(operators[msg.sender].isActive, "Not registered");
        _;
    }
    
    constructor() {
        owner = msg.sender;
    }
    
    function registerOperator(bytes calldata operatorKey) external payable {
        require(msg.value >= MIN_STAKE, "Insufficient stake");
        require(!operators[msg.sender].isActive, "Already registered");
        require(operatorKey.length > 0, "Invalid key");
        
        operators[msg.sender] = Operator({
            publicKey: operatorKey,
            stake: msg.value,
            isActive: true,
            performanceScore: INITIAL_PERFORMANCE,
            registeredAt: block.timestamp
        });
        
        operatorList.push(msg.sender);
        
        emit OperatorRegistered(msg.sender, operatorKey, msg.value);
    }
    
    function deregisterOperator() external onlyRegistered {
        operators[msg.sender].isActive = false;
        
        // Return stake
        uint256 stake = operators[msg.sender].stake;
        operators[msg.sender].stake = 0;
        
        if (stake > 0) {
            payable(msg.sender).transfer(stake);
        }
        
        emit OperatorDeregistered(msg.sender);
    }
    
    function addStake() external payable onlyRegistered {
        operators[msg.sender].stake += msg.value;
        emit StakeUpdated(msg.sender, operators[msg.sender].stake);
    }
    
    function withdrawStake(uint256 amount) external onlyRegistered {
        require(operators[msg.sender].stake - amount >= MIN_STAKE, "Below minimum stake");
        
        operators[msg.sender].stake -= amount;
        payable(msg.sender).transfer(amount);
        
        emit StakeUpdated(msg.sender, operators[msg.sender].stake);
    }
    
    function slashOperator(address operator, uint256 penalty) external onlyOwner {
        require(operators[operator].isActive, "Operator not active");
        require(penalty <= operators[operator].stake, "Penalty exceeds stake");
        
        operators[operator].stake -= penalty;
        operators[operator].performanceScore = (operators[operator].performanceScore * 95) / 100;
        
        // Deregister if below minimum
        if (operators[operator].stake < MIN_STAKE) {
            operators[operator].isActive = false;
            emit OperatorDeregistered(operator);
        }
        
        emit OperatorSlashed(operator, penalty);
    }
    
    function updatePerformanceScore(address operator, uint256 score) external onlyOwner {
        require(score <= 100, "Invalid score");
        operators[operator].performanceScore = score;
    }
    
    function getActiveOperators() external view returns (address[] memory) {
        uint256 count = 0;
        for (uint i = 0; i < operatorList.length; i++) {
            if (operators[operatorList[i]].isActive) {
                count++;
            }
        }
        
        address[] memory active = new address[](count);
        uint256 index = 0;
        for (uint i = 0; i < operatorList.length; i++) {
            if (operators[operatorList[i]].isActive) {
                active[index++] = operatorList[i];
            }
        }
        
        return active;
    }
    
    function getOperatorStake(address operator) external view returns (uint256) {
        return operators[operator].stake;
    }
    
    function getOperatorPerformance(address operator) external view returns (uint256) {
        return operators[operator].performanceScore;
    }
} 