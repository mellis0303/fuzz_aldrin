package main

import (
	"context"
	"crypto/ecdsa"
	"fmt"
	"math/big"
	"time"

	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"go.uber.org/zap"
)

// DemoOperator represents a simulated operator for demo mode
type DemoOperator struct {
	Address      common.Address
	PrivateKey   *ecdsa.PrivateKey
	BLSPublicKey *bn254.G1Affine
	Socket       string
	Stake        *big.Int
}

// EnableDemoMode configures the signature collector with demo operators
func (sc *SignatureCollector) EnableDemoMode() error {
	sc.logger.Info("Enabling demo mode with simulated operators")

	// Create 5 demo operators
	demoOperators := []struct {
		privateKeyHex string
		socket        string
		stake         int64
	}{
		{
			privateKeyHex: "281b06c35eef45e3b167d7ff603260b8c72e7a2fc5d1255cd0af17054876aa9f",
			socket:        "http://operator1.demo:9001",
			stake:         10000000000000000, // 0.01 ETH
		},
		{
			privateKeyHex: "6d1b7c2ae7b7bd2fdcda663c78b1a1deac71cce18934e2023bb5b8026b93a18d",
			socket:        "http://operator2.demo:9002",
			stake:         10000000000000000,
		},
		{
			privateKeyHex: "004a99898cc64591c5a54219dd2d56e02f4b406f6c49ad831c3df23349830c9f",
			socket:        "http://operator3.demo:9003",
			stake:         10000000000000000,
		},
		{
			privateKeyHex: "2bb7602812b6fe6cbf966e0c18ab707ee2857778f746e45f7bf0057130b73f82",
			socket:        "http://operator4.demo:9004",
			stake:         10000000000000000,
		},
		{
			privateKeyHex: "f124cc14f46aa41fae7946ebcc30d3ba1c68af2f50d13241d9583ae7444d64e6",
			socket:        "http://operator5.demo:9005",
			stake:         10000000000000000,
		},
	}

	// Load demo operators
	for i, demo := range demoOperators {
		// Parse private key
		privateKey, err := crypto.HexToECDSA(demo.privateKeyHex)
		if err != nil {
			return fmt.Errorf("parse demo operator %d private key: %w", i+1, err)
		}

		// Get address
		publicKey := privateKey.Public()
		publicKeyECDSA, ok := publicKey.(*ecdsa.PublicKey)
		if !ok {
			return fmt.Errorf("invalid public key type for operator %d", i+1)
		}
		address := crypto.PubkeyToAddress(*publicKeyECDSA)

		// Generate BLS key (simplified for demo)
		var blsPubKey bn254.G1Affine
		blsPubKey.X.SetInt64(int64(1000 + i + 1))
		blsPubKey.Y.SetInt64(int64(2000 + i + 1))

		// Create operator info
		opInfo := &OperatorInfo{
			Address:      address,
			BLSPublicKey: &blsPubKey,
			Socket:       demo.socket,
			Stake:        big.NewInt(demo.stake),
			Status:       OperatorStatusActive,
			LastSeen:     time.Now(),
			Performance: &OperatorPerformance{
				TotalTasks:      0,
				SuccessfulTasks: 0,
				FailedTasks:     0,
				AverageLatency:  0,
				LastUpdated:     time.Now(),
			},
		}

		// Store operator
		sc.mu.Lock()
		sc.operators[address] = opInfo
		if demo.socket != "" {
			sc.operatorsBySocket[demo.socket] = opInfo
		}
		sc.mu.Unlock()

		sc.logger.Info("Loaded demo operator",
			zap.Int("number", i+1),
			zap.String("address", address.Hex()),
			zap.String("socket", demo.socket))
	}

	sc.logger.Info("Demo mode enabled",
		zap.Int("operators", len(demoOperators)))

	return nil
}

// SimulateOperatorResponses simulates operator responses for demo mode
func (sc *SignatureCollector) SimulateOperatorResponses(ctx context.Context, task *TaskDistribution, reportHash common.Hash) error {
	sc.logger.Info("Simulating operator responses for demo",
		zap.String("task_id", task.TaskID.String()))

	// Simulate responses from operators
	for i, opAddr := range task.Operators {
		// Simulate processing delay
		go func(idx int, addr common.Address) {
			// Random delay between 100-500ms
			delay := time.Duration(100+idx*100) * time.Millisecond
			time.Sleep(delay)

			// Get operator info
			sc.mu.RLock()
			opInfo, exists := sc.operators[addr]
			sc.mu.RUnlock()

			if !exists {
				return
			}

			// Create simulated signature
			signature := make([]byte, 65)
			copy(signature, []byte(fmt.Sprintf("demo_signature_%d", idx)))

			// Create response
			response := &OperatorResponse{
				TaskID:       task.TaskID,
				Operator:     addr,
				ReportHash:   reportHash,
				Signature:    signature,
				BLSSignature: opInfo.BLSPublicKey,
				Timestamp:    time.Now(),
				AuditReport: &AuditReport{
					TaskID:          task.TaskID.String(),
					ContractAddress: "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48",
					Timestamp:       time.Now(),
					TotalFindings:   2,
					CriticalCount:   0,
					HighCount:       0,
					MediumCount:     1,
					LowCount:        1,
					InfoCount:       0,
					Findings: []AuditFinding{
						{
							ID:          "AC_002",
							Title:       "Missing Zero Address Check",
							Severity:    SeverityMedium,
							Description: "Function does not validate against zero address",
							Suggestion:  "Add require(to != address(0)) check",
							Category:    "Access Control",
							Confidence:  0.8,
						},
						{
							ID:          "GAS_001",
							Title:       "Storage Optimization Opportunity",
							Severity:    SeverityLow,
							Description: "Multiple storage reads can be optimized",
							Suggestion:  "Cache frequently accessed storage variables in memory",
							Category:    "Gas Optimization",
							Confidence:  0.7,
							GasImpact:   big.NewInt(2100),
						},
					},
					SecurityScore:   85,
					Summary:         "Contract audit completed successfully in demo mode",
					AnalysisModules: []string{"Demo Analyzer"},
					CodeSize:        1024,
					IsVerified:      true,
					CompilerVersion: "0.8.19",
				},
			}

			// Add response
			task.mu.Lock()
			task.Responses[addr] = response
			task.mu.Unlock()

			sc.logger.Info("Demo operator responded",
				zap.String("operator", addr.Hex()),
				zap.Int("response_count", len(task.Responses)))
		}(i, opAddr)
	}

	return nil
}
