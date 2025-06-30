// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

contract SimpleContractAudit {
    struct AuditRequest {
        address requester;
        address contractAddress;
        string network;
        uint256 timestamp;
        bool completed;
    }
    
    struct AuditResult {
        uint256 securityScore;
        uint256 totalFindings;
        uint256 criticalCount;
        uint256 highCount;
        uint256 mediumCount;
        uint256 lowCount;
        string reportUri;
        uint256 timestamp;
    }
    
    mapping(bytes32 => AuditRequest) public auditRequests;
    mapping(bytes32 => AuditResult) public auditResults;
    mapping(address => bytes32[]) public userAudits;
    
    uint256 public totalAudits;
    uint256 public constant MIN_AUDIT_FEE = 0.01 ether;
    address public immutable aggregator;
    
    event AuditRequested(
        bytes32 indexed requestId,
        address indexed requester,
        address contractAddress,
        string network
    );
    
    event AuditCompleted(
        bytes32 indexed requestId,
        uint256 securityScore,
        uint256 totalFindings,
        string reportUri
    );
    
    modifier onlyAggregator() {
        require(msg.sender == aggregator, "Only aggregator");
        _;
    }
    
    constructor(address _aggregator) {
        aggregator = _aggregator;
    }
    
    function requestAudit(
        address contractAddress,
        string memory network
    ) external payable returns (bytes32) {
        require(msg.value >= MIN_AUDIT_FEE, "Insufficient audit fee");
        require(contractAddress != address(0), "Invalid contract address");
        require(bytes(network).length > 0, "Network cannot be empty");
        
        bytes32 requestId = keccak256(
            abi.encodePacked(msg.sender, contractAddress, network, block.timestamp, totalAudits)
        );
        
        auditRequests[requestId] = AuditRequest({
            requester: msg.sender,
            contractAddress: contractAddress,
            network: network,
            timestamp: block.timestamp,
            completed: false
        });
        
        userAudits[msg.sender].push(requestId);
        totalAudits++;
        
        emit AuditRequested(requestId, msg.sender, contractAddress, network);
        return requestId;
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
    ) external onlyAggregator {
        require(auditRequests[requestId].requester != address(0), "Invalid request ID");
        require(!auditRequests[requestId].completed, "Already completed");
        require(securityScore <= 100, "Invalid security score");
        
        auditResults[requestId] = AuditResult({
            securityScore: securityScore,
            totalFindings: totalFindings,
            criticalCount: criticalCount,
            highCount: highCount,
            mediumCount: mediumCount,
            lowCount: lowCount,
            reportUri: reportUri,
            timestamp: block.timestamp
        });
        
        auditRequests[requestId].completed = true;
        
        emit AuditCompleted(requestId, securityScore, totalFindings, reportUri);
    }
    
    function getAuditRequest(bytes32 requestId) external view returns (AuditRequest memory) {
        return auditRequests[requestId];
    }
    
    function getAuditResult(bytes32 requestId) external view returns (AuditResult memory) {
        return auditResults[requestId];
    }
    
    function getUserAudits(address user) external view returns (bytes32[] memory) {
        return userAudits[user];
    }
    
    function withdrawFees() external {
        require(msg.sender == aggregator, "Only aggregator");
        payable(aggregator).transfer(address(this).balance);
    }
} 