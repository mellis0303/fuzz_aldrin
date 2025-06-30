package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/ethclient"
	"go.uber.org/zap"
)

type AuditSeverity string

const (
	SeverityCritical AuditSeverity = "CRITICAL"
	SeverityHigh     AuditSeverity = "HIGH"
	SeverityMedium   AuditSeverity = "MEDIUM"
	SeverityLow      AuditSeverity = "LOW"
	SeverityInfo     AuditSeverity = "INFO"
)

type AuditFinding struct {
	ID          string        `json:"id"`
	Title       string        `json:"title"`
	Severity    AuditSeverity `json:"severity"`
	Description string        `json:"description"`
	LineNumber  int           `json:"line_number,omitempty"`
	CodeSnippet string        `json:"code_snippet,omitempty"`
	Suggestion  string        `json:"suggestion"`
	Category    string        `json:"category"`
	Confidence  float64       `json:"confidence"`
	GasImpact   *big.Int      `json:"gas_impact,omitempty"`
}

type AuditReport struct {
	TaskID           string         `json:"task_id"`
	ContractAddress  string         `json:"contract_address"`
	Timestamp        time.Time      `json:"timestamp"`
	TotalFindings    int            `json:"total_findings"`
	CriticalCount    int            `json:"critical_count"`
	HighCount        int            `json:"high_count"`
	MediumCount      int            `json:"medium_count"`
	LowCount         int            `json:"low_count"`
	InfoCount        int            `json:"info_count"`
	Findings         []AuditFinding `json:"findings"`
	SecurityScore    int            `json:"security_score"`
	Summary          string         `json:"summary"`
	AnalysisModules  []string       `json:"analysis_modules"`
	CodeSize         int            `json:"code_size"`
	IsVerified       bool           `json:"is_verified"`
	CompilerVersion  string         `json:"compiler_version,omitempty"`
	OptimizationUsed bool           `json:"optimization_used"`
	EstimatedGasCost *big.Int       `json:"estimated_gas_cost,omitempty"`
}

type ContractAuditor struct {
	client    *ethclient.Client
	logger    *zap.Logger
	timeout   time.Duration
	analyzers []SecurityAnalyzer
}

type SecurityAnalyzer interface {
	Name() string
	Analyze(ctx context.Context, code []byte, metadata *ContractMetadata) ([]AuditFinding, error)
}

type ContractMetadata struct {
	Address         common.Address
	Code            []byte
	CreationCode    []byte
	ABI             *abi.ABI
	CompilerVersion string
	IsVerified      bool
	SourceCode      string
}

func NewContractAuditor(client *ethclient.Client, logger *zap.Logger, timeout time.Duration) *ContractAuditor {
	auditor := &ContractAuditor{
		client:  client,
		logger:  logger,
		timeout: timeout,
	}

	auditor.analyzers = []SecurityAnalyzer{
		NewReentrancyAnalyzer(logger),
		NewAccessControlAnalyzer(logger),
		NewIntegerOverflowAnalyzer(logger),
		NewGasOptimizationAnalyzer(logger),
		NewDelegateCallAnalyzer(logger),
		NewTimestampDependencyAnalyzer(logger),
		NewUncheckedReturnAnalyzer(logger),
		NewStorageCollisionAnalyzer(logger),
	}

	return auditor
}

func (ca *ContractAuditor) AuditContract(ctx context.Context, address common.Address) (*AuditReport, error) {
	startTime := time.Now()

	ca.logger.Info("Starting contract audit",
		zap.String("address", address.Hex()))

	metadata, err := ca.fetchContractMetadata(ctx, address)
	if err != nil {
		return nil, fmt.Errorf("fetch contract metadata: %w", err)
	}

	report := &AuditReport{
		ContractAddress: address.Hex(),
		Timestamp:       startTime,
		Findings:        []AuditFinding{},
		AnalysisModules: make([]string, 0, len(ca.analyzers)),
		CodeSize:        len(metadata.Code),
		IsVerified:      metadata.IsVerified,
		CompilerVersion: metadata.CompilerVersion,
	}

	for _, analyzer := range ca.analyzers {
		report.AnalysisModules = append(report.AnalysisModules, analyzer.Name())

		findings, err := analyzer.Analyze(ctx, metadata.Code, metadata)
		if err != nil {
			ca.logger.Error("Analyzer failed",
				zap.String("analyzer", analyzer.Name()),
				zap.Error(err))
			continue
		}

		report.Findings = append(report.Findings, findings...)
	}

	ca.calculateReportMetrics(report)

	ca.logger.Info("Contract audit completed",
		zap.String("address", address.Hex()),
		zap.Int("findings", report.TotalFindings),
		zap.Int("security_score", report.SecurityScore),
		zap.Duration("duration", time.Since(startTime)))

	return report, nil
}

func (ca *ContractAuditor) fetchContractMetadata(ctx context.Context, address common.Address) (*ContractMetadata, error) {
	metadata := &ContractMetadata{
		Address: address,
	}

	code, err := ca.client.CodeAt(ctx, address, nil)
	if err != nil {
		return nil, fmt.Errorf("get contract code: %w", err)
	}

	if len(code) == 0 {
		return nil, fmt.Errorf("no code at address %s", address.Hex())
	}

	metadata.Code = code

	ca.logger.Debug("Fetched contract metadata",
		zap.String("address", address.Hex()),
		zap.Int("code_size", len(code)))

	return metadata, nil
}

func (ca *ContractAuditor) calculateReportMetrics(report *AuditReport) {
	for _, finding := range report.Findings {
		report.TotalFindings++
		switch finding.Severity {
		case SeverityCritical:
			report.CriticalCount++
		case SeverityHigh:
			report.HighCount++
		case SeverityMedium:
			report.MediumCount++
		case SeverityLow:
			report.LowCount++
		case SeverityInfo:
			report.InfoCount++
		}
	}

	// Calculate security score (100 - penalties)
	report.SecurityScore = 100
	report.SecurityScore -= report.CriticalCount * 30
	report.SecurityScore -= report.HighCount * 20
	report.SecurityScore -= report.MediumCount * 10
	report.SecurityScore -= report.LowCount * 5
	report.SecurityScore -= report.InfoCount * 2

	if report.SecurityScore < 0 {
		report.SecurityScore = 0
	}

	if report.CriticalCount > 0 {
		report.Summary = fmt.Sprintf("CRITICAL: Contract has %d critical vulnerabilities that require immediate attention. Security score: %d/100",
			report.CriticalCount, report.SecurityScore)
	} else if report.HighCount > 0 {
		report.Summary = fmt.Sprintf("HIGH RISK: Contract has %d high severity issues. Security score: %d/100",
			report.HighCount, report.SecurityScore)
	} else if report.MediumCount > 0 {
		report.Summary = fmt.Sprintf("MEDIUM RISK: Contract has %d medium severity issues. Security score: %d/100",
			report.MediumCount, report.SecurityScore)
	} else if report.LowCount > 0 {
		report.Summary = fmt.Sprintf("LOW RISK: Contract has minor issues. Security score: %d/100",
			report.SecurityScore)
	} else {
		report.Summary = fmt.Sprintf("Contract audit completed with no significant findings. Security score: %d/100",
			report.SecurityScore)
	}
}

type ReentrancyAnalyzer struct {
	logger *zap.Logger
}

func NewReentrancyAnalyzer(logger *zap.Logger) *ReentrancyAnalyzer {
	return &ReentrancyAnalyzer{logger: logger}
}

func (ra *ReentrancyAnalyzer) Name() string {
	return "Reentrancy Analyzer"
}

func (ra *ReentrancyAnalyzer) Analyze(ctx context.Context, code []byte, metadata *ContractMetadata) ([]AuditFinding, error) {
	findings := []AuditFinding{}

	// Look for patterns indicating potential reentrancy
	// This is a simplified check - production would use more sophisticated analysis
	codeHex := hex.EncodeToString(code)

	// Check for external calls followed by state changes
	// CALL opcode: 0xf1, SSTORE opcode: 0x55
	if strings.Contains(codeHex, "f1") && strings.Index(codeHex, "f1") < strings.LastIndex(codeHex, "55") {
		findings = append(findings, AuditFinding{
			ID:          "REEN_001",
			Title:       "Potential Reentrancy Vulnerability",
			Severity:    SeverityHigh,
			Description: "External calls detected before state changes. This pattern may be vulnerable to reentrancy attacks.",
			Suggestion:  "Use the Checks-Effects-Interactions pattern or implement a reentrancy guard.",
			Category:    "Security",
			Confidence:  0.7,
		})
	}

	// Check for delegatecall without proper access control
	if strings.Contains(codeHex, "f4") { // DELEGATECALL opcode
		findings = append(findings, AuditFinding{
			ID:          "REEN_002",
			Title:       "Delegatecall Usage Detected",
			Severity:    SeverityMedium,
			Description: "Contract uses delegatecall which can be dangerous if not properly restricted.",
			Suggestion:  "Ensure delegatecall targets are trusted and access is properly controlled.",
			Category:    "Security",
			Confidence:  0.8,
		})
	}

	return findings, nil
}

// AccessControlAnalyzer checks for access control issues
type AccessControlAnalyzer struct {
	logger *zap.Logger
}

func NewAccessControlAnalyzer(logger *zap.Logger) *AccessControlAnalyzer {
	return &AccessControlAnalyzer{logger: logger}
}

func (ra *AccessControlAnalyzer) Name() string {
	return "Access Control Analyzer"
}

func (ra *AccessControlAnalyzer) Analyze(ctx context.Context, code []byte, metadata *ContractMetadata) ([]AuditFinding, error) {
	findings := []AuditFinding{}

	// Look for common access control patterns
	codeHex := hex.EncodeToString(code)

	// Check for selfdestruct without access control
	if strings.Contains(codeHex, "ff") { // SELFDESTRUCT opcode
		// Check if there's a CALLER check before selfdestruct
		selfdestructIndex := strings.Index(codeHex, "ff")
		callerCheckPattern := "33" // CALLER opcode

		if !strings.Contains(codeHex[:selfdestructIndex], callerCheckPattern) {
			findings = append(findings, AuditFinding{
				ID:          "AC_001",
				Title:       "Unprotected Selfdestruct",
				Severity:    SeverityCritical,
				Description: "Contract contains selfdestruct without apparent access control.",
				Suggestion:  "Add proper access control to selfdestruct functionality.",
				Category:    "Access Control",
				Confidence:  0.9,
			})
		}
	}

	// Check for missing owner checks in critical functions
	// This is simplified - real implementation would parse function selectors
	if !strings.Contains(codeHex, "33") && len(code) > 1000 {
		findings = append(findings, AuditFinding{
			ID:          "AC_002",
			Title:       "Potential Missing Access Control",
			Severity:    SeverityMedium,
			Description: "Contract may lack proper access control mechanisms.",
			Suggestion:  "Implement role-based access control for critical functions.",
			Category:    "Access Control",
			Confidence:  0.5,
		})
	}

	return findings, nil
}

// IntegerOverflowAnalyzer checks for integer overflow/underflow vulnerabilities
type IntegerOverflowAnalyzer struct {
	logger *zap.Logger
}

func NewIntegerOverflowAnalyzer(logger *zap.Logger) *IntegerOverflowAnalyzer {
	return &IntegerOverflowAnalyzer{logger: logger}
}

func (ra *IntegerOverflowAnalyzer) Name() string {
	return "Integer Overflow Analyzer"
}

func (ra *IntegerOverflowAnalyzer) Analyze(ctx context.Context, code []byte, metadata *ContractMetadata) ([]AuditFinding, error) {
	findings := []AuditFinding{}

	codeHex := hex.EncodeToString(code)

	arithmeticOps := []string{"01", "02", "03"}
	hasArithmetic := false

	for _, op := range arithmeticOps {
		if strings.Contains(codeHex, op) {
			hasArithmetic = true
			break
		}
	}

	// Check for overflow protection patterns (simplified)
	hasOverflowCheck := strings.Contains(codeHex, "10") || // LT opcode
		strings.Contains(codeHex, "11") // GT opcode

	if hasArithmetic && !hasOverflowCheck {
		findings = append(findings, AuditFinding{
			ID:          "INT_001",
			Title:       "Potential Integer Overflow/Underflow",
			Severity:    SeverityMedium,
			Description: "Arithmetic operations detected without apparent overflow protection.",
			Suggestion:  "Use SafeMath library or Solidity 0.8+ with built-in overflow protection.",
			Category:    "Mathematics",
			Confidence:  0.6,
		})
	}

	return findings, nil
}

// GasOptimizationAnalyzer identifies gas optimization opportunities
type GasOptimizationAnalyzer struct {
	logger *zap.Logger
}

func NewGasOptimizationAnalyzer(logger *zap.Logger) *GasOptimizationAnalyzer {
	return &GasOptimizationAnalyzer{logger: logger}
}

func (ra *GasOptimizationAnalyzer) Name() string {
	return "Gas Optimization Analyzer"
}

func (ra *GasOptimizationAnalyzer) Analyze(ctx context.Context, code []byte, metadata *ContractMetadata) ([]AuditFinding, error) {
	findings := []AuditFinding{}

	codeHex := hex.EncodeToString(code)

	// Check for multiple SLOAD operations (expensive)
	sloadCount := strings.Count(codeHex, "54")
	if sloadCount > 10 {
		findings = append(findings, AuditFinding{
			ID:          "GAS_001",
			Title:       "Excessive Storage Reads",
			Severity:    SeverityLow,
			Description: fmt.Sprintf("Contract performs %d storage reads which can be expensive.", sloadCount),
			Suggestion:  "Cache frequently accessed storage variables in memory.",
			Category:    "Gas Optimization",
			Confidence:  0.8,
			GasImpact:   big.NewInt(int64(sloadCount * 2100)), // Approximate gas cost
		})
	}

	// Check for multiple SSTORE operations
	sstoreCount := strings.Count(codeHex, "55")
	if sstoreCount > 5 {
		findings = append(findings, AuditFinding{
			ID:          "GAS_002",
			Title:       "Multiple Storage Writes",
			Severity:    SeverityLow,
			Description: fmt.Sprintf("Contract performs %d storage writes which are expensive operations.", sstoreCount),
			Suggestion:  "Batch storage updates where possible to reduce gas costs.",
			Category:    "Gas Optimization",
			Confidence:  0.8,
			GasImpact:   big.NewInt(int64(sstoreCount * 20000)), // Approximate gas cost
		})
	}

	return findings, nil
}

// DelegateCallAnalyzer checks for unsafe delegatecall usage
type DelegateCallAnalyzer struct {
	logger *zap.Logger
}

func NewDelegateCallAnalyzer(logger *zap.Logger) *DelegateCallAnalyzer {
	return &DelegateCallAnalyzer{logger: logger}
}

func (ra *DelegateCallAnalyzer) Name() string {
	return "Delegatecall Analyzer"
}

func (ra *DelegateCallAnalyzer) Analyze(ctx context.Context, code []byte, metadata *ContractMetadata) ([]AuditFinding, error) {
	findings := []AuditFinding{}

	codeHex := hex.EncodeToString(code)

	// Check for DELEGATECALL opcode
	if strings.Contains(codeHex, "f4") {
		findings = append(findings, AuditFinding{
			ID:          "DELEG_001",
			Title:       "Delegatecall Usage",
			Severity:    SeverityHigh,
			Description: "Contract uses delegatecall which executes external code in the current contract's context.",
			Suggestion:  "Ensure delegatecall targets are trusted and cannot be manipulated by attackers.",
			Category:    "Security",
			Confidence:  0.9,
		})
	}

	return findings, nil
}

// TimestampDependencyAnalyzer checks for timestamp manipulation vulnerabilities
type TimestampDependencyAnalyzer struct {
	logger *zap.Logger
}

func NewTimestampDependencyAnalyzer(logger *zap.Logger) *TimestampDependencyAnalyzer {
	return &TimestampDependencyAnalyzer{logger: logger}
}

func (ra *TimestampDependencyAnalyzer) Name() string {
	return "Timestamp Dependency Analyzer"
}

func (ra *TimestampDependencyAnalyzer) Analyze(ctx context.Context, code []byte, metadata *ContractMetadata) ([]AuditFinding, error) {
	findings := []AuditFinding{}

	codeHex := hex.EncodeToString(code)

	// Check for TIMESTAMP opcode
	if strings.Contains(codeHex, "42") {
		findings = append(findings, AuditFinding{
			ID:          "TIME_001",
			Title:       "Timestamp Dependency",
			Severity:    SeverityMedium,
			Description: "Contract relies on block.timestamp which can be manipulated by miners within a 15-second window.",
			Suggestion:  "Avoid using timestamp for critical logic. Consider using block numbers or external oracles.",
			Category:    "Security",
			Confidence:  0.7,
		})
	}

	return findings, nil
}

// UncheckedReturnAnalyzer checks for unchecked return values
type UncheckedReturnAnalyzer struct {
	logger *zap.Logger
}

func NewUncheckedReturnAnalyzer(logger *zap.Logger) *UncheckedReturnAnalyzer {
	return &UncheckedReturnAnalyzer{logger: logger}
}

func (ra *UncheckedReturnAnalyzer) Name() string {
	return "Unchecked Return Analyzer"
}

func (ra *UncheckedReturnAnalyzer) Analyze(ctx context.Context, code []byte, metadata *ContractMetadata) ([]AuditFinding, error) {
	findings := []AuditFinding{}

	codeHex := hex.EncodeToString(code)

	// Check for CALL without subsequent return value check
	// This is simplified - real implementation would trace execution flow
	if strings.Contains(codeHex, "f1") { // CALL opcode
		// Check if followed by ISZERO or similar check
		callIndex := strings.Index(codeHex, "f1")
		checkPattern := "15" // ISZERO opcode

		if !strings.Contains(codeHex[callIndex:callIndex+20], checkPattern) {
			findings = append(findings, AuditFinding{
				ID:          "RETURN_001",
				Title:       "Unchecked External Call Return Value",
				Severity:    SeverityMedium,
				Description: "External call return value may not be checked, which could lead to silent failures.",
				Suggestion:  "Always check the return value of external calls and handle failures appropriately.",
				Category:    "Error Handling",
				Confidence:  0.6,
			})
		}
	}

	return findings, nil
}

// StorageCollisionAnalyzer checks for storage collision vulnerabilities
type StorageCollisionAnalyzer struct {
	logger *zap.Logger
}

func NewStorageCollisionAnalyzer(logger *zap.Logger) *StorageCollisionAnalyzer {
	return &StorageCollisionAnalyzer{logger: logger}
}

func (ra *StorageCollisionAnalyzer) Name() string {
	return "Storage Collision Analyzer"
}

func (ra *StorageCollisionAnalyzer) Analyze(ctx context.Context, code []byte, metadata *ContractMetadata) ([]AuditFinding, error) {
	findings := []AuditFinding{}

	// Check for proxy pattern indicators that might have storage collision issues
	codeHex := hex.EncodeToString(code)

	// Look for delegatecall in combination with storage access
	if strings.Contains(codeHex, "f4") && strings.Contains(codeHex, "54") {
		findings = append(findings, AuditFinding{
			ID:          "STOR_001",
			Title:       "Potential Storage Collision Risk",
			Severity:    SeverityHigh,
			Description: "Contract uses delegatecall with storage access, which may lead to storage collisions in proxy patterns.",
			Suggestion:  "Use unstructured storage or EIP-1967 standard storage slots to prevent collisions.",
			Category:    "Storage",
			Confidence:  0.7,
		})
	}

	return findings, nil
}

// Helper function to check if bytecode contains a specific pattern
func containsPattern(code []byte, pattern []byte) bool {
	return bytes.Contains(code, pattern)
}

// Helper function to count occurrences of a pattern
func countPattern(code []byte, pattern []byte) int {
	count := 0
	remaining := code
	for {
		index := bytes.Index(remaining, pattern)
		if index == -1 {
			break
		}
		count++
		remaining = remaining[index+len(pattern):]
	}
	return count
}

// isLikelyProxy checks if the contract is likely a proxy contract
func isLikelyProxy(code []byte) bool {
	// Check for common proxy patterns
	// This is a simplified check
	codeHex := hex.EncodeToString(code)

	// Check for delegatecall and minimal code size (typical of proxies)
	return strings.Contains(codeHex, "f4") && len(code) < 500
}

// extractOpcodes extracts opcodes from bytecode for analysis
func extractOpcodes(code []byte) []vm.OpCode {
	opcodes := []vm.OpCode{}
	for i := 0; i < len(code); i++ {
		op := vm.OpCode(code[i])
		opcodes = append(opcodes, op)

		// Skip push data
		if op >= vm.PUSH1 && op <= vm.PUSH32 {
			size := int(op - vm.PUSH1 + 1)
			i += size
		}
	}
	return opcodes
}
