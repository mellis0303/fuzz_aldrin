// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

contract TaskMailbox {
    enum TaskStatus { PENDING, PROCESSING, COMPLETED, FAILED }
    
    struct Task {
        address submitter;
        address contractAddress;
        uint256 payment;
        TaskStatus status;
        uint256 timestamp;
        bytes requirements;
    }
    
    struct AuditResult {
        bytes report;
        bytes[] operatorSignatures;
        uint256 timestamp;
        bool isValid;
    }
    
    uint256 public nextTaskId;
    mapping(uint256 => Task) public tasks;
    mapping(uint256 => AuditResult) public auditResults;
    mapping(address => bool) public authorizedAggregators;
    
    address public owner;
    address public taskHook;
    uint256 public constant MIN_PAYMENT = 0.01 ether;
    
    event TaskSubmitted(uint256 indexed taskId, address contractAddress, uint256 payment);
    event TaskCompleted(uint256 indexed taskId, bytes32 resultHash);
    event AggregatorAuthorized(address aggregator);
    
    modifier onlyOwner() {
        require(msg.sender == owner, "Only owner");
        _;
    }
    
    modifier onlyAuthorized() {
        require(authorizedAggregators[msg.sender] || msg.sender == taskHook, "Unauthorized");
        _;
    }
    
    constructor() {
        owner = msg.sender;
        nextTaskId = 1;
    }
    
    function setTaskHook(address _taskHook) external onlyOwner {
        taskHook = _taskHook;
    }
    
    function authorizeAggregator(address aggregator) external onlyOwner {
        authorizedAggregators[aggregator] = true;
        emit AggregatorAuthorized(aggregator);
    }
    
    function submitAuditTask(
        address contractToAudit,
        bytes calldata requirements
    ) external payable returns (uint256) {
        require(msg.value >= MIN_PAYMENT, "Insufficient payment");
        require(contractToAudit != address(0), "Invalid contract address");
        
        uint256 taskId = nextTaskId++;
        tasks[taskId] = Task({
            submitter: msg.sender,
            contractAddress: contractToAudit,
            payment: msg.value,
            status: TaskStatus.PENDING,
            timestamp: block.timestamp,
            requirements: requirements
        });
        
        emit TaskSubmitted(taskId, contractToAudit, msg.value);
        return taskId;
    }
    
    function submitAuditResult(
        uint256 taskId,
        bytes calldata auditReport,
        bytes[] calldata signatures
    ) external onlyAuthorized {
        require(tasks[taskId].status == TaskStatus.PENDING, "Invalid task status");
        
        tasks[taskId].status = TaskStatus.COMPLETED;
        auditResults[taskId] = AuditResult({
            report: auditReport,
            operatorSignatures: signatures,
            timestamp: block.timestamp,
            isValid: true
        });
        
        // Transfer payment to aggregator for distribution
        if (tasks[taskId].payment > 0) {
            payable(msg.sender).transfer(tasks[taskId].payment);
        }
        
        emit TaskCompleted(taskId, keccak256(auditReport));
    }
    
    function getTask(uint256 taskId) external view returns (Task memory) {
        return tasks[taskId];
    }
    
    function getAuditResult(uint256 taskId) external view returns (AuditResult memory) {
        return auditResults[taskId];
    }
} 