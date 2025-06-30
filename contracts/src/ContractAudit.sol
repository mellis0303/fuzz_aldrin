// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

import {ITaskMailbox, ITaskMailboxTypes} from "@hourglass-monorepo/src/interfaces/core/ITaskMailbox.sol";
import {OperatorSet} from "@eigenlayer-contracts/src/contracts/libraries/OperatorSetLib.sol";
import {AccessControl} from "@openzeppelin/contracts/access/AccessControl.sol";


contract ContractAudit is AccessControl {
    ITaskMailbox public immutable taskMailbox;
    address public immutable avs;
    uint32 public executorOperatorSetId;
    
    // Access control roles
    bytes32 public constant OPERATOR_ROLE = keccak256("OPERATOR_ROLE");
    bytes32 public constant ADMIN_ROLE = keccak256("ADMIN_ROLE");
    bytes32 public constant FEE_COLLECTOR_ROLE = keccak256("FEE_COLLECTOR_ROLE");
    
    enum AuditType {
        SOURCE_CODE,
        CONTRACT_ADDRESS
    }
    
    struct AuditRequest {
        AuditType auditType;
        string data;  // Either source code or contract address
        string network;  // For contract address audits
        address requester;
        uint256 timestamp;
        bytes32 taskId;
    }
    
    struct AuditResult {
        bytes32 requestId;
        uint256 securityScore;
        uint256 totalFindings;
        uint256 criticalCount;
        uint256 highCount;
        uint256 mediumCount;
        uint256 lowCount;
        string reportUri;  // IPFS or other storage URI for full report
        uint256 timestamp;
        address operator;  // Track which operator submitted the result
    }
    
    mapping(bytes32 => AuditRequest) public auditRequests;
    mapping(bytes32 => AuditResult) public auditResults;
    mapping(address => bytes32[]) public userAudits;
    mapping(address => bool) public registeredOperators;
    
    uint256 public totalAudits;
    uint256 public constant MIN_AUDIT_FEE = 0.01 ether;
    
    event AuditRequested(
        bytes32 indexed requestId,
        address indexed requester,
        AuditType auditType,
        bytes32 indexed taskId
    );
    
    event AuditCompleted(
        bytes32 indexed requestId,
        uint256 securityScore,
        uint256 totalFindings,
        string reportUri,
        address operator
    );
    
    event AuditFailed(
        bytes32 indexed requestId,
        string reason,
        address operator
    );
    
    event OperatorRegistered(address indexed operator);
    event OperatorDeregistered(address indexed operator);
    
    struct ContractAuditPayload {
        bytes32 requestId;
        string auditType;  // "source" or "address"
        string data;       // Contract source code or address
        string network;    // Network for address-based audits
        string etherscanKey; // Optional API key for fetching contracts
    }
    
    modifier onlyRegisteredOperator() {
        require(
            hasRole(OPERATOR_ROLE, msg.sender) && registeredOperators[msg.sender],
            "Not a registered operator"
        );
        _;
    }
    
    constructor(address _taskMailbox, address _avs, uint32 _executorOperatorSetId) {
        taskMailbox = ITaskMailbox(_taskMailbox);
        avs = _avs;
        executorOperatorSetId = _executorOperatorSetId;
        
        // Set up initial roles
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(ADMIN_ROLE, msg.sender);
        _grantRole(FEE_COLLECTOR_ROLE, msg.sender);
    }
    
    // Operator management functions
    function registerOperator(address operator) external onlyRole(ADMIN_ROLE) {
        require(operator != address(0), "Invalid operator address");
        require(!registeredOperators[operator], "Operator already registered");
        
        registeredOperators[operator] = true;
        _grantRole(OPERATOR_ROLE, operator);
        
        emit OperatorRegistered(operator);
    }
    
    function deregisterOperator(address operator) external onlyRole(ADMIN_ROLE) {
        require(registeredOperators[operator], "Operator not registered");
        
        registeredOperators[operator] = false;
        _revokeRole(OPERATOR_ROLE, operator);
        
        emit OperatorDeregistered(operator);
    }
    
    function requestSourceCodeAudit(string memory sourceCode) external payable returns (bytes32) {
        require(msg.value >= MIN_AUDIT_FEE, "Insufficient audit fee");
        require(bytes(sourceCode).length > 0, "Source code cannot be empty");
        
        bytes32 requestId = keccak256(abi.encodePacked(msg.sender, sourceCode, block.timestamp, totalAudits));
        
        AuditRequest memory request = AuditRequest({
            auditType: AuditType.SOURCE_CODE,
            data: sourceCode,
            network: "",
            requester: msg.sender,
            timestamp: block.timestamp,
            taskId: bytes32(0)
        });
        
        ContractAuditPayload memory payload = ContractAuditPayload({
            requestId: requestId,
            auditType: "source",
            data: sourceCode,
            network: "",
            etherscanKey: ""
        });
        
        bytes32 taskId = _createAuditTask(payload);
        request.taskId = taskId;
        
        auditRequests[requestId] = request;
        userAudits[msg.sender].push(requestId);
        totalAudits++;
        
        emit AuditRequested(requestId, msg.sender, AuditType.SOURCE_CODE, taskId);
        return requestId;
    }
    
    function requestContractAddressAudit(
        string memory contractAddress,
        string memory network,
        string memory etherscanKey
    ) external payable returns (bytes32) {
        require(msg.value >= MIN_AUDIT_FEE, "Insufficient audit fee");
        require(bytes(contractAddress).length == 42, "Invalid contract address");
        require(bytes(network).length > 0, "Network cannot be empty");
        
        bytes32 requestId = keccak256(
            abi.encodePacked(msg.sender, contractAddress, network, block.timestamp, totalAudits)
        );
        
        AuditRequest memory request = AuditRequest({
            auditType: AuditType.CONTRACT_ADDRESS,
            data: contractAddress,
            network: network,
            requester: msg.sender,
            timestamp: block.timestamp,
            taskId: bytes32(0)
        });
        
        ContractAuditPayload memory payload = ContractAuditPayload({
            requestId: requestId,
            auditType: "address",
            data: contractAddress,
            network: network,
            etherscanKey: etherscanKey
        });
        
        bytes32 taskId = _createAuditTask(payload);
        request.taskId = taskId;
        
        auditRequests[requestId] = request;
        userAudits[msg.sender].push(requestId);
        totalAudits++;
        
        emit AuditRequested(requestId, msg.sender, AuditType.CONTRACT_ADDRESS, taskId);
        return requestId;
    }
    
    function _createAuditTask(ContractAuditPayload memory payload) private returns (bytes32) {
        bytes memory encodedPayload = abi.encode(payload);
        
        OperatorSet memory executorOperatorSet = OperatorSet({
            avs: avs,
            id: executorOperatorSetId
        });
        
        ITaskMailboxTypes.TaskParams memory taskParams = ITaskMailboxTypes.TaskParams({
            refundCollector: msg.sender,
            avsFee: uint96(msg.value),
            executorOperatorSet: executorOperatorSet,
            payload: encodedPayload
        });
        
        bytes32 taskHash = taskMailbox.createTask(taskParams);
        return taskHash;
    }
    
    function submitAuditResult(
        bytes32 requestId,
        uint256 securityScore,
        uint256 totalFindings,
        uint256 criticalCount,
        uint256 highCount,
        uint256 mediumCount,
        uint256 lowCount,
        string memory reportUri
    ) external onlyRegisteredOperator {
        require(auditRequests[requestId].requester != address(0), "Invalid request ID");
        require(auditResults[requestId].timestamp == 0, "Result already submitted");
        require(securityScore <= 100, "Invalid security score");
        
        AuditResult memory result = AuditResult({
            requestId: requestId,
            securityScore: securityScore,
            totalFindings: totalFindings,
            criticalCount: criticalCount,
            highCount: highCount,
            mediumCount: mediumCount,
            lowCount: lowCount,
            reportUri: reportUri,
            timestamp: block.timestamp,
            operator: msg.sender
        });
        
        auditResults[requestId] = result;
        
        emit AuditCompleted(requestId, securityScore, totalFindings, reportUri, msg.sender);
    }
    
    function reportAuditFailure(bytes32 requestId, string memory reason) external onlyRegisteredOperator {
        require(auditRequests[requestId].requester != address(0), "Invalid request ID");
        require(bytes(reason).length > 0, "Reason cannot be empty");
        
        emit AuditFailed(requestId, reason, msg.sender);
    }
    
    // View functions
    function getAuditRequest(bytes32 requestId) external view returns (AuditRequest memory) {
        return auditRequests[requestId];
    }
    
    function getAuditResult(bytes32 requestId) external view returns (AuditResult memory) {
        return auditResults[requestId];
    }
    
    function getUserAudits(address user) external view returns (bytes32[] memory) {
        return userAudits[user];
    }
    
    function getAuditFee() external pure returns (uint256) {
        return MIN_AUDIT_FEE;
    }
    
    function isOperatorRegistered(address operator) external view returns (bool) {
        return registeredOperators[operator];
    }
    
    // Admin functions
    function withdrawFees(address payable recipient) external onlyRole(FEE_COLLECTOR_ROLE) {
        require(recipient != address(0), "Invalid recipient address");
        require(address(this).balance > 0, "No fees to withdraw");
        
        uint256 amount = address(this).balance;
        recipient.transfer(amount);
    }
    
    function updateExecutorOperatorSetId(uint32 newOperatorSetId) external onlyRole(ADMIN_ROLE) {
        executorOperatorSetId = newOperatorSetId;
    }
    
    // Emergency functions
    function pause() external onlyRole(ADMIN_ROLE) {
        // Implementation would depend on OpenZeppelin Pausable if needed
    }
    
    // Override required by Solidity for AccessControl
    function supportsInterface(bytes4 interfaceId) public view virtual override(AccessControl) returns (bool) {
        return super.supportsInterface(interfaceId);
    }
} 