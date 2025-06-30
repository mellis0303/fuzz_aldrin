// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "forge-std/Script.sol";

contract AVSRegistry {
    struct OperatorInfo {
        address operator;
        bytes32 pubkeyHash;
        uint256 stake;
        string socket;
        bool isActive;
        uint256 blsX;
        uint256 blsY;
    }
    
    mapping(address => OperatorInfo) public operators;
    address[] public operatorList;
    
    event OperatorRegistered(address indexed operator, uint256 stake, string socket);
    
    function registerOperator(
        bytes32 pubkeyHash,
        uint256 blsX,
        uint256 blsY,
        string memory socket
    ) external payable {
        require(msg.value > 0, "Stake required");
        require(!operators[msg.sender].isActive, "Already registered");
        
        operators[msg.sender] = OperatorInfo({
            operator: msg.sender,
            pubkeyHash: pubkeyHash,
            stake: msg.value,
            socket: socket,
            isActive: true,
            blsX: blsX,
            blsY: blsY
        });
        
        operatorList.push(msg.sender);
        emit OperatorRegistered(msg.sender, msg.value, socket);
    }
    
    function getOperatorCount() external view returns (uint256) {
        return operatorList.length;
    }
    
    function getOperatorAtIndex(uint256 index) external view returns (address) {
        require(index < operatorList.length, "Index out of bounds");
        return operatorList[index];
    }
    
    function getOperatorInfo(address operator) external view returns (
        bytes32 pubkeyHash,
        uint256 stake,
        string memory socket,
        bool isActive
    ) {
        OperatorInfo memory info = operators[operator];
        return (info.pubkeyHash, info.stake, info.socket, info.isActive);
    }
    
    function getOperatorBLSPublicKey(address operator) external view returns (uint256 x, uint256 y) {
        OperatorInfo memory info = operators[operator];
        return (info.blsX, info.blsY);
    }
}

contract TaskMailbox {
    struct AuditTask {
        uint256 taskId;
        address contractToAudit;
        uint256 payment;
        address requester;
        uint256 deadline;
        bool completed;
    }
    
    mapping(uint256 => AuditTask) public tasks;
    uint256 public nextTaskId = 1;
    
    event TaskSubmitted(uint256 indexed taskId, address contractAddress, uint256 payment);
    event TaskCompleted(uint256 indexed taskId, bytes auditReport);
    
    function submitAuditTask(address contractAddress, uint256 deadline) external payable returns (uint256) {
        uint256 taskId = nextTaskId++;
        
        tasks[taskId] = AuditTask({
            taskId: taskId,
            contractToAudit: contractAddress,
            payment: msg.value,
            requester: msg.sender,
            deadline: deadline,
            completed: false
        });
        
        emit TaskSubmitted(taskId, contractAddress, msg.value);
        return taskId;
    }
    
    function submitAuditResult(
        uint256 taskId,
        bytes memory auditReport,
        bytes[] memory signatures
    ) external {
        require(tasks[taskId].taskId != 0, "Task not found");
        require(!tasks[taskId].completed, "Task already completed");
        require(signatures.length >= 3, "Insufficient signatures");
        
        tasks[taskId].completed = true;
        emit TaskCompleted(taskId, auditReport);
    }
}

contract TaskResponse {
    mapping(uint256 => bytes) public taskResponses;
    
    function submitResponse(uint256 taskId, bytes memory response) external {
        taskResponses[taskId] = response;
    }
}

contract DeployAVS is Script {
    function run() external {
        uint256 deployerPrivateKey = vm.envUint("PRIVATE_KEY");
        vm.startBroadcast(deployerPrivateKey);

        // Deploy contracts
        AVSRegistry registry = new AVSRegistry();
        TaskMailbox mailbox = new TaskMailbox();
        TaskResponse response = new TaskResponse();

        vm.stopBroadcast();

        // Log deployment addresses (we'll get them from broadcast files)
        
        console.log("AVS Registry deployed at:", address(registry));
        console.log("Task Mailbox deployed at:", address(mailbox));
        console.log("Task Response deployed at:", address(response));
    }
} 