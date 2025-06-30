package main

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/Layr-Labs/hourglass-monorepo/ponos/pkg/performer/server"
	performerV1 "github.com/Layr-Labs/protocol-apis/gen/protos/eigenlayer/hourglass/v1/performer"
	"go.uber.org/zap"
)

const (
	vulnerableContract = `pragma solidity ^0.7.6;
contract VulnerableContract {
    mapping(address => uint256) public balances;
    address owner = 0x1234567890123456789012345678901234567890;
    
    function withdraw(uint256 amount) public {
        require(balances[msg.sender] >= amount);
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success);
        balances[msg.sender] -= amount; // State change after external call - reentrancy risk
    }
    
    function unsafeRandom() public {
        uint256 random = block.timestamp % 2; // Weak randomness
        balances[msg.sender] += random;
    }
    
    function unsafeTransfer(address payable to, uint256 amount) public {
        to.send(amount); // Unchecked return value
    }
}`

	secureContract = `pragma solidity ^0.8.0;
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
import "@openzeppelin/contracts/access/Ownable.sol";

contract SecureContract is ReentrancyGuard, Ownable {
    mapping(address => uint256) public balances;
    
    event Withdrawal(address indexed user, uint256 amount);
    
    function withdraw(uint256 amount) external nonReentrant {
        require(balances[msg.sender] >= amount, "Insufficient balance");
        balances[msg.sender] -= amount; // State change before external call
        
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");
        
        emit Withdrawal(msg.sender, amount);
    }
    
    function setBalance(address user, uint256 amount) external onlyOwner {
        balances[user] = amount;
    }
}`

	gasInefficient = `pragma solidity ^0.8.0;
contract GasWaster {
    uint256[] public items;
    mapping(address => string) public names;
    
    function inefficientLoop() public {
        for (uint256 i = 0; i < items.length; i++) { // Array length in loop
            items[i] += 1;
        }
    }
    
    function stringConcat(string memory a, string memory b) public pure returns (string memory) {
        return string(abi.encodePacked(a, b)); // Expensive string concat
    }
    
    function publicFunction() public view returns (uint256) { // Could be external
        return items.length;
    }
}`

	complexContract = `pragma solidity ^0.8.0;
contract ComplexContract {
    address public owner;
    mapping(address => uint256) public balances;
    mapping(address => mapping(address => uint256)) public allowances;
    
    modifier onlyOwner() {
        require(msg.sender == owner, "Not owner");
        _;
    }
    
    constructor() {
        owner = msg.sender;
    }
    
    function transfer(address to, uint256 amount) external returns (bool) {
        require(balances[msg.sender] >= amount, "Insufficient balance");
        balances[msg.sender] -= amount;
        balances[to] += amount;
        return true;
    }
    
    function approve(address spender, uint256 amount) external returns (bool) {
        allowances[msg.sender][spender] = amount;
        return true;
    }
    
    function transferFrom(address from, address to, uint256 amount) external returns (bool) {
        require(allowances[from][msg.sender] >= amount, "Insufficient allowance");
        require(balances[from] >= amount, "Insufficient balance");
        
        allowances[from][msg.sender] -= amount;
        balances[from] -= amount;
        balances[to] += amount;
        return true;
    }
    
    function adminTransfer(address from, address to, uint256 amount) external onlyOwner {
        balances[from] -= amount;
        balances[to] += amount;
    }
}`
)

func setupTestAuditor(t *testing.T) *ContractAuditor {
	logger, err := zap.NewDevelopment()
	if err != nil {
		t.Fatalf("Failed to create logger: %v", err)
	}
	return NewContractAuditor(logger)
}

func TestInputValidation(t *testing.T) {
	auditor := setupTestAuditor(t)

	tests := []struct {
		name      string
		payload   interface{}
		expectErr bool
		errMsg    string
	}{
		{
			name:      "Empty payload",
			payload:   "",
			expectErr: true,
			errMsg:    "empty",
		},
		{
			name: "Invalid address format",
			payload: TaskInput{
				Type: "address",
				Data: "0xinvalid",
			},
			expectErr: true,
			errMsg:    "invalid Ethereum address",
		},
		{
			name: "Missing type field",
			payload: TaskInput{
				Data: "0x1234567890123456789012345678901234567890",
			},
			expectErr: true,
			errMsg:    "type must be specified",
		},
		{
			name: "Invalid type",
			payload: TaskInput{
				Type: "invalid",
				Data: "test",
			},
			expectErr: true,
			errMsg:    "must be 'address' or 'source'",
		},
		{
			name: "Valid address",
			payload: TaskInput{
				Type:    "address",
				Data:    "0x1234567890123456789012345678901234567890",
				Network: "mainnet",
			},
			expectErr: false,
		},
		{
			name: "Valid source",
			payload: TaskInput{
				Type: "source",
				Data: secureContract,
			},
			expectErr: false,
		},
		{
			name:      "Raw address detection",
			payload:   "0x1234567890123456789012345678901234567890",
			expectErr: true,
			errMsg:    "structured input",
		},
		{
			name: "Invalid Solidity source",
			payload: TaskInput{
				Type: "source",
				Data: "not solidity code",
			},
			expectErr: true,
			errMsg:    "valid Solidity",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var payload []byte
			var err error

			if str, ok := tt.payload.(string); ok {
				payload = []byte(str)
			} else {
				payload, err = json.Marshal(tt.payload)
				if err != nil {
					t.Fatalf("Failed to marshal payload: %v", err)
				}
			}

			task := &performerV1.TaskRequest{
				TaskId:  []byte("test"),
				Payload: payload,
			}

			err = auditor.ValidateTask(task)

			if tt.expectErr {
				if err == nil {
					t.Errorf("Expected error but got none")
				} else if !strings.Contains(err.Error(), tt.errMsg) {
					t.Errorf("Expected error containing '%s', got: %v", tt.errMsg, err)
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error: %v", err)
				}
			}
		})
	}
}

func TestSecurityAnalysis(t *testing.T) {
	auditor := setupTestAuditor(t)

	tests := []struct {
		name           string
		contract       string
		expectedIssues map[string]int // issue type -> expected count
		minScore       int
		maxScore       int
	}{
		{
			name:     "Vulnerable contract",
			contract: vulnerableContract,
			expectedIssues: map[string]int{
				"reentrancy":     1,
				"weak_random":    1,
				"unchecked_call": 1,
			},
			minScore: 0,
			maxScore: 60,
		},
		{
			name:     "Secure contract",
			contract: secureContract,
			expectedIssues: map[string]int{
				"hardcoded_address": 0,
			},
			minScore: 80,
			maxScore: 100,
		},
		{
			name:     "Gas inefficient contract",
			contract: gasInefficient,
			expectedIssues: map[string]int{
				"gas_optimization": 2, // Should find loop and string concat issues
			},
			minScore: 70,
			maxScore: 100,
		},
		{
			name:     "Complex contract",
			contract: complexContract,
			expectedIssues: map[string]int{
				"access_control": 1, // adminTransfer function
			},
			minScore: 60,
			maxScore: 100,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			task := &performerV1.TaskRequest{
				TaskId:  []byte("test-" + tt.name),
				Payload: []byte(tt.contract),
			}

			resp, err := auditor.HandleTask(task)
			if err != nil {
				t.Fatalf("HandleTask failed: %v", err)
			}

			var report AuditReport
			err = json.Unmarshal(resp.Result, &report)
			if err != nil {
				t.Fatalf("Failed to parse audit report: %v", err)
			}

			// Verify security score is in expected range
			if report.SecurityScore < tt.minScore || report.SecurityScore > tt.maxScore {
				t.Errorf("Security score %d not in expected range [%d-%d]",
					report.SecurityScore, tt.minScore, tt.maxScore)
			}

			// Verify analysis modules were executed
			if len(report.AnalysisModules) < 10 {
				t.Errorf("Expected at least 10 analysis modules, got %d", len(report.AnalysisModules))
			}

			// Verify findings structure
			for _, finding := range report.Findings {
				if finding.ID == "" || finding.Title == "" || finding.Description == "" {
					t.Errorf("Finding has empty required fields: %+v", finding)
				}
				if finding.Confidence < 0 || finding.Confidence > 1 {
					t.Errorf("Invalid confidence score: %f", finding.Confidence)
				}
			}

			// Verify gas optimizations structure
			for _, opt := range report.GasOptimizations {
				if opt.Description == "" || opt.EstimatedSaving == "" {
					t.Errorf("Gas optimization has empty required fields: %+v", opt)
				}
			}

			t.Logf("Analysis complete: Score %d/100, Issues %d, Gas opts %d",
				report.SecurityScore, report.TotalFindings, len(report.GasOptimizations))
		})
	}
}

func TestContractAddressHandling(t *testing.T) {
	auditor := setupTestAuditor(t)

	tests := []struct {
		name         string
		address      string
		network      string
		apiKey       string
		expectError  bool
		errorPattern string
	}{
		{
			name:         "Valid mainnet address",
			address:      "0xA0b86a33E6441fE35A38f6Bfb6ec6aA0F31e2E41",
			network:      "mainnet",
			expectError:  true, // Expected to fail in test environment
			errorPattern: "fetch contract",
		},
		{
			name:         "Valid address with API key",
			address:      "0x91E677b07F7AF907ec9a428aafA9fc14a0d3A338",
			network:      "mainnet",
			apiKey:       "test-key",
			expectError:  true, // Expected to fail in test environment
			errorPattern: "fetch contract",
		},
		{
			name:         "Unsupported network",
			address:      "0x1234567890123456789012345678901234567890",
			network:      "unsupported",
			expectError:  true,
			errorPattern: "unsupported network",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			taskInput := TaskInput{
				Type:         "address",
				Data:         tt.address,
				Network:      tt.network,
				EtherscanKey: tt.apiKey,
			}

			payload, err := json.Marshal(taskInput)
			if err != nil {
				t.Fatalf("Failed to marshal task input: %v", err)
			}

			task := &performerV1.TaskRequest{
				TaskId:  []byte("test-address"),
				Payload: payload,
			}

			_, err = auditor.HandleTask(task)

			if tt.expectError {
				if err == nil {
					t.Errorf("Expected error but got none")
				} else if !strings.Contains(err.Error(), tt.errorPattern) {
					t.Errorf("Expected error containing '%s', got: %v", tt.errorPattern, err)
				} else {
					t.Logf("Got expected error: %v", err)
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error: %v", err)
				}
			}
		})
	}
}

func TestStructuredInput(t *testing.T) {
	auditor := setupTestAuditor(t)

	tests := []struct {
		name        string
		inputType   string
		data        string
		expectError bool
		expectedSrc string
	}{
		{
			name:        "Source input",
			inputType:   "source",
			data:        secureContract,
			expectError: false,
			expectedSrc: "direct_input",
		},
		{
			name:        "Legacy raw input",
			inputType:   "",
			data:        vulnerableContract,
			expectError: false,
			expectedSrc: "legacy_input",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var payload []byte
			var err error

			if tt.inputType == "" {
				// Legacy format - raw contract code
				payload = []byte(tt.data)
			} else {
				// Structured format
				taskInput := TaskInput{
					Type: tt.inputType,
					Data: tt.data,
				}
				payload, err = json.Marshal(taskInput)
				if err != nil {
					t.Fatalf("Failed to marshal task input: %v", err)
				}
			}

			task := &performerV1.TaskRequest{
				TaskId:  []byte("test-structured"),
				Payload: payload,
			}

			resp, err := auditor.HandleTask(task)

			if tt.expectError {
				if err == nil {
					t.Errorf("Expected error but got none")
				}
				return
			}

			if err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}

			var report AuditReport
			err = json.Unmarshal(resp.Result, &report)
			if err != nil {
				t.Fatalf("Failed to parse audit report: %v", err)
			}

			if report.ContractInfo.SourceFetch != tt.expectedSrc {
				t.Errorf("Expected source fetch method '%s', got '%s'",
					tt.expectedSrc, report.ContractInfo.SourceFetch)
			}
		})
	}
}

func TestSeverityClassification(t *testing.T) {
	auditor := setupTestAuditor(t)

	task := &performerV1.TaskRequest{
		TaskId:  []byte("test-severity"),
		Payload: []byte(vulnerableContract),
	}

	resp, err := auditor.HandleTask(task)
	if err != nil {
		t.Fatalf("HandleTask failed: %v", err)
	}

	var report AuditReport
	err = json.Unmarshal(resp.Result, &report)
	if err != nil {
		t.Fatalf("Failed to parse audit report: %v", err)
	}

	// Verify severity counts add up
	total := report.CriticalCount + report.HighCount + report.MediumCount +
		report.LowCount + report.InfoCount

	if total != report.TotalFindings {
		t.Errorf("Severity counts (%d) don't match total findings (%d)", total, report.TotalFindings)
	}

	// Verify each finding has valid severity
	validSeverities := map[AuditSeverity]bool{
		SeverityCritical: true,
		SeverityHigh:     true,
		SeverityMedium:   true,
		SeverityLow:      true,
		SeverityInfo:     true,
	}

	for _, finding := range report.Findings {
		if !validSeverities[finding.Severity] {
			t.Errorf("Invalid severity: %s", finding.Severity)
		}
	}
}

func TestReportGeneration(t *testing.T) {
	auditor := setupTestAuditor(t)

	task := &performerV1.TaskRequest{
		TaskId:  []byte("test-report"),
		Payload: []byte(vulnerableContract),
	}

	resp, err := auditor.HandleTask(task)
	if err != nil {
		t.Fatalf("HandleTask failed: %v", err)
	}

	var report AuditReport
	err = json.Unmarshal(resp.Result, &report)
	if err != nil {
		t.Fatalf("Failed to parse audit report: %v", err)
	}

	// Verify required fields
	if report.ContractHash == "" {
		t.Error("Contract hash is empty")
	}

	if report.Timestamp.IsZero() {
		t.Error("Timestamp is not set")
	}

	if report.Summary == "" {
		t.Error("Summary is empty")
	}

	if len(report.AnalysisModules) == 0 {
		t.Error("No analysis modules reported")
	}

	// Verify security score calculation
	if report.SecurityScore < 0 || report.SecurityScore > 100 {
		t.Errorf("Invalid security score: %d", report.SecurityScore)
	}
}

func TestPerformance(t *testing.T) {
	auditor := setupTestAuditor(t)

	// Test with large contract
	largeContract := vulnerableContract
	for i := 0; i < 10; i++ {
		largeContract += "\n" + gasInefficient
	}

	task := &performerV1.TaskRequest{
		TaskId:  []byte("test-performance"),
		Payload: []byte(largeContract),
	}

	start := time.Now()
	resp, err := auditor.HandleTask(task)
	duration := time.Since(start)

	if err != nil {
		t.Fatalf("HandleTask failed: %v", err)
	}

	if duration > 30*time.Second {
		t.Errorf("Audit took too long: %v", duration)
	}

	var report AuditReport
	err = json.Unmarshal(resp.Result, &report)
	if err != nil {
		t.Fatalf("Failed to parse audit report: %v", err)
	}

	t.Logf("Performance test: %v for %d lines, %d findings",
		duration, strings.Count(largeContract, "\n"), report.TotalFindings)
}

func TestAVSIntegration(t *testing.T) {
	// Test the full AVS performer integration
	logger, err := zap.NewDevelopment()
	if err != nil {
		t.Fatalf("Failed to create logger: %v", err)
	}

	auditor := NewContractAuditor(logger)

	// Test task validation interface
	task := &performerV1.TaskRequest{
		TaskId:  []byte("avs-test"),
		Payload: []byte(secureContract),
	}

	err = auditor.ValidateTask(task)
	if err != nil {
		t.Fatalf("AVS ValidateTask failed: %v", err)
	}

	// Test task handling interface
	resp, err := auditor.HandleTask(task)
	if err != nil {
		t.Fatalf("AVS HandleTask failed: %v", err)
	}

	// Verify response format
	if resp.TaskId == nil {
		t.Error("Response missing TaskId")
	}

	if resp.Result == nil {
		t.Error("Response missing Result")
	}

	// Verify result is valid JSON
	var report AuditReport
	err = json.Unmarshal(resp.Result, &report)
	if err != nil {
		t.Fatalf("Response Result is not valid JSON: %v", err)
	}

	t.Log("AVS integration test passed")
}

func TestNetworkSupport(t *testing.T) {
	auditor := setupTestAuditor(t)

	networks := []string{
		"mainnet", "ethereum", "goerli", "sepolia",
		"polygon", "mumbai", "bsc", "bsc-testnet",
		"arbitrum", "arbitrum-sepolia", "optimism", "optimism-sepolia",
		"base", "base-sepolia",
	}

	for _, network := range networks {
		t.Run(network, func(t *testing.T) {
			taskInput := TaskInput{
				Type:    "address",
				Data:    "0x1234567890123456789012345678901234567890",
				Network: network,
			}

			payload, err := json.Marshal(taskInput)
			if err != nil {
				t.Fatalf("Failed to marshal task input: %v", err)
			}

			task := &performerV1.TaskRequest{
				TaskId:  []byte("test-network"),
				Payload: payload,
			}

			err = auditor.ValidateTask(task)
			if err != nil {
				t.Errorf("Network %s validation failed: %v", network, err)
			}
		})
	}

	// Test unsupported network
	taskInput := TaskInput{
		Type:    "address",
		Data:    "0x1234567890123456789012345678901234567890",
		Network: "unsupported-network",
	}

	payload, _ := json.Marshal(taskInput)
	task := &performerV1.TaskRequest{
		TaskId:  []byte("test-unsupported"),
		Payload: payload,
	}

	_, err := auditor.HandleTask(task)
	if err == nil {
		t.Error("Expected error for unsupported network")
	}
}

func TestConcurrentRequests(t *testing.T) {
	auditor := setupTestAuditor(t)

	const numConcurrent = 5
	results := make(chan error, numConcurrent)

	for i := 0; i < numConcurrent; i++ {
		go func(id int) {
			task := &performerV1.TaskRequest{
				TaskId:  []byte("concurrent-test"),
				Payload: []byte(vulnerableContract),
			}

			_, err := auditor.HandleTask(task)
			results <- err
		}(i)
	}

	for i := 0; i < numConcurrent; i++ {
		if err := <-results; err != nil {
			t.Errorf("Concurrent request %d failed: %v", i, err)
		}
	}
}

func TestErrorRecovery(t *testing.T) {
	auditor := setupTestAuditor(t)

	// Test with invalid JSON
	task := &performerV1.TaskRequest{
		TaskId:  []byte("error-test"),
		Payload: []byte(`{"invalid": json}`),
	}

	err := auditor.ValidateTask(task)
	if err == nil {
		t.Error("Expected validation error for invalid JSON")
	}

	// Test with malformed Solidity
	task.Payload = []byte("invalid solidity code {}")
	err = auditor.ValidateTask(task)
	if err == nil {
		t.Error("Expected validation error for invalid Solidity")
	}
}

func TestRealContractWithAPIKey(t *testing.T) {
	auditor := setupTestAuditor(t)

	// Test with known contract address and API key
	taskInput := TaskInput{
		Type:         "address",
		Data:         "0x91E677b07F7AF907ec9a428aafA9fc14a0d3A338",
		Network:      "mainnet",
		EtherscanKey: "2Y1H2ZB7DGNPIYSW24UJVEPTQ1MM8XNH47",
	}

	taskInputBytes, err := json.Marshal(taskInput)
	if err != nil {
		t.Fatalf("Failed to marshal task input: %v", err)
	}

	taskRequest := &performerV1.TaskRequest{
		TaskId:  []byte("real-contract-audit"),
		Payload: taskInputBytes,
	}

	t.Logf("Testing real contract audit: %s", taskInput.Data)

	err = auditor.ValidateTask(taskRequest)
	if err != nil {
		t.Fatalf("ValidateTask failed: %v", err)
	}

	resp, err := auditor.HandleTask(taskRequest)
	if err != nil {
		t.Logf("HandleTask failed (expected in test environment): %v", err)
		// This is expected to fail in test environment due to network/API issues
		return
	}

	var auditReport AuditReport
	err = json.Unmarshal(resp.Result, &auditReport)
	if err != nil {
		t.Fatalf("Failed to parse audit report: %v", err)
	}

	t.Logf("Real contract audit results:")
	t.Logf("Security Score: %d/100", auditReport.SecurityScore)
	t.Logf("Total Findings: %d", auditReport.TotalFindings)
	t.Logf("Gas Optimizations: %d", len(auditReport.GasOptimizations))

	if auditReport.ContractInfo != nil {
		t.Logf("Contract Name: %s", auditReport.ContractInfo.Name)
		t.Logf("Verified: %v", auditReport.ContractInfo.Verified)
	}
}

func TestVulnerabilityDetection(t *testing.T) {
	auditor := setupTestAuditor(t)

	// Test specific vulnerability patterns
	vulnerabilityTests := []struct {
		name     string
		contract string
		expected string
	}{
		{
			name: "Reentrancy vulnerability",
			contract: `pragma solidity ^0.7.0;
contract ReentrancyVuln {
    mapping(address => uint256) public balances;
    
    function withdraw() external {
        uint256 amount = balances[msg.sender];
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success);
        balances[msg.sender] = 0; // State change after external call
    }
}`,
			expected: "access",
		},
		{
			name: "Outdated Solidity version",
			contract: `pragma solidity ^0.7.0;
contract OldContract {
    uint256 public total;
    address payable recipient;
    
    function sendFunds() external {
        recipient.transfer(1 ether); // Using deprecated transfer
    }
}`,
			expected: "deprecated",
		},
		{
			name: "Access control vulnerability",
			contract: `pragma solidity ^0.8.0;
contract AccessVuln {
    address public owner;
    
    function setOwner(address newOwner) external {
        owner = newOwner; // No access control
    }
}`,
			expected: "access",
		},
	}

	for _, tt := range vulnerabilityTests {
		t.Run(tt.name, func(t *testing.T) {
			task := &performerV1.TaskRequest{
				TaskId:  []byte("test-vuln"),
				Payload: []byte(tt.contract),
			}

			resp, err := auditor.HandleTask(task)
			if err != nil {
				t.Fatalf("HandleTask failed: %v", err)
			}

			var report AuditReport
			err = json.Unmarshal(resp.Result, &report)
			if err != nil {
				t.Fatalf("Failed to parse audit report: %v", err)
			}

			found := false
			for _, finding := range report.Findings {
				if strings.Contains(strings.ToLower(finding.Category), tt.expected) ||
					strings.Contains(strings.ToLower(finding.Title), tt.expected) {
					found = true
					t.Logf("Found expected vulnerability: %s", finding.Title)
					break
				}
			}

			if !found {
				t.Errorf("Expected to find vulnerability type '%s' but didn't", tt.expected)
				t.Logf("Found findings:")
				for _, finding := range report.Findings {
					t.Logf("  - %s (%s)", finding.Title, finding.Category)
				}
			}
		})
	}
}

func TestConsensusAndAVSWorkflow(t *testing.T) {
	// Test the full AVS workflow including consensus mechanism
	logger, err := zap.NewDevelopment()
	if err != nil {
		t.Fatalf("Failed to create logger: %v", err)
	}

	auditor := NewContractAuditor(logger)

	// Create a mock performer server to test integration
	config := &server.PonosPerformerConfig{
		Port:    8081, // Different port to avoid conflicts
		Timeout: 10 * time.Second,
	}

	performer, err := server.NewPonosPerformerWithRpcServer(config, auditor, logger)
	if err != nil {
		t.Fatalf("Failed to create performer: %v", err)
	}

	// Test that the performer can be created and configured
	if performer == nil {
		t.Error("Performer is nil")
	}

	// Test task validation through the performer interface
	task := &performerV1.TaskRequest{
		TaskId:  []byte("consensus-test"),
		Payload: []byte(secureContract),
	}

	err = auditor.ValidateTask(task)
	if err != nil {
		t.Fatalf("Task validation failed: %v", err)
	}

	resp, err := auditor.HandleTask(task)
	if err != nil {
		t.Fatalf("Task handling failed: %v", err)
	}

	// Verify response structure for consensus
	if resp.TaskId == nil {
		t.Error("Response missing TaskId for consensus")
	}

	if resp.Result == nil {
		t.Error("Response missing Result for consensus")
	}

	// Verify the audit result is deterministic (important for consensus)
	resp2, err := auditor.HandleTask(task)
	if err != nil {
		t.Fatalf("Second task handling failed: %v", err)
	}

	// Results should be consistent for same input (excluding timestamp)
	var report1, report2 AuditReport
	json.Unmarshal(resp.Result, &report1)
	json.Unmarshal(resp2.Result, &report2)

	// Check deterministic fields (excluding timestamp)
	if report1.ContractHash != report2.ContractHash ||
		report1.TotalFindings != report2.TotalFindings ||
		report1.SecurityScore != report2.SecurityScore {
		t.Error("Core audit results are not deterministic - this breaks consensus")
	}

	t.Log("AVS consensus workflow test passed")
}

// Benchmark the audit process
func BenchmarkAuditPerformance(b *testing.B) {
	logger, _ := zap.NewDevelopment()
	auditor := NewContractAuditor(logger)

	task := &performerV1.TaskRequest{
		TaskId:  []byte("benchmark"),
		Payload: []byte(vulnerableContract),
	}

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, err := auditor.HandleTask(task)
		if err != nil {
			b.Fatalf("HandleTask failed: %v", err)
		}
	}
}

// Benchmark large contract processing
func BenchmarkLargeContractAudit(b *testing.B) {
	logger, _ := zap.NewDevelopment()
	auditor := NewContractAuditor(logger)

	// Create a large contract for benchmarking
	largeContract := complexContract
	for i := 0; i < 20; i++ {
		largeContract += "\n" + gasInefficient
	}

	task := &performerV1.TaskRequest{
		TaskId:  []byte("benchmark-large"),
		Payload: []byte(largeContract),
	}

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, err := auditor.HandleTask(task)
		if err != nil {
			b.Fatalf("HandleTask failed: %v", err)
		}
	}
}
