package main

import (
	"context"
	"encoding/hex"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
	"go.uber.org/zap"
)

const SimpleContractAuditABI = `[
	{
		"anonymous": false,
		"inputs": [
			{"indexed": true, "name": "requestId", "type": "bytes32"},
			{"indexed": true, "name": "requester", "type": "address"},
			{"indexed": false, "name": "contractAddress", "type": "address"},
			{"indexed": false, "name": "network", "type": "string"}
		],
		"name": "AuditRequested",
		"type": "event"
	},
	{
		"inputs": [
			{"name": "requestId", "type": "bytes32"},
			{"name": "securityScore", "type": "uint256"},
			{"name": "totalFindings", "type": "uint256"},
			{"name": "criticalCount", "type": "uint256"},
			{"name": "highCount", "type": "uint256"},
			{"name": "mediumCount", "type": "uint256"},
			{"name": "lowCount", "type": "uint256"},
			{"name": "reportUri", "type": "string"}
		],
		"name": "submitAuditResult",
		"outputs": [],
		"type": "function"
	}
]`

type SimpleMonitor struct {
	client          *ethclient.Client
	contractAddress common.Address
	contractABI     abi.ABI
	logger          *zap.Logger
	auditor         *ContractAuditor
	privateKey      string
}

func NewSimpleMonitor(client *ethclient.Client, contractAddress common.Address, privateKey string, logger *zap.Logger) (*SimpleMonitor, error) {
	contractABI, err := abi.JSON(strings.NewReader(SimpleContractAuditABI))
	if err != nil {
		return nil, fmt.Errorf("parse ABI: %w", err)
	}

	auditor := NewContractAuditor(client, logger, 5*time.Minute)

	return &SimpleMonitor{
		client:          client,
		contractAddress: contractAddress,
		contractABI:     contractABI,
		logger:          logger,
		auditor:         auditor,
		privateKey:      privateKey,
	}, nil
}

func (sm *SimpleMonitor) Start(ctx context.Context) {
	sm.logger.Info("Starting SimpleContractAudit monitor",
		zap.String("contract", sm.contractAddress.Hex()))

	// Monitor for AuditRequested events
	eventSig := crypto.Keccak256Hash([]byte("AuditRequested(bytes32,address,address,string)"))

	query := ethereum.FilterQuery{
		Addresses: []common.Address{sm.contractAddress},
		Topics:    [][]common.Hash{{eventSig}},
	}

	// Try to subscribe to events
	logs := make(chan types.Log)
	sub, err := sm.client.SubscribeFilterLogs(ctx, query, logs)
	if err != nil {
		sm.logger.Warn("Failed to subscribe to events, using polling",
			zap.Error(err))
		// Fall back to polling
		sm.pollForEvents(ctx, query)
		return
	}

	defer sub.Unsubscribe()

	for {
		select {
		case <-ctx.Done():
			return
		case err := <-sub.Err():
			sm.logger.Error("Subscription error", zap.Error(err))
			// Restart polling
			sm.pollForEvents(ctx, query)
			return
		case vLog := <-logs:
			sm.handleAuditRequestedEvent(vLog)
		}
	}
}

func (sm *SimpleMonitor) pollForEvents(ctx context.Context, query ethereum.FilterQuery) {
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()

	lastBlock := uint64(0)

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			// Get current block
			currentBlock, err := sm.client.BlockNumber(ctx)
			if err != nil {
				sm.logger.Error("Failed to get block number", zap.Error(err))
				continue
			}

			if lastBlock == 0 {
				// Start from 100 blocks ago on first run
				if currentBlock > 100 {
					lastBlock = currentBlock - 100
				}
			}

			if currentBlock <= lastBlock {
				continue
			}

			// Query logs
			query.FromBlock = big.NewInt(int64(lastBlock + 1))
			query.ToBlock = big.NewInt(int64(currentBlock))

			logs, err := sm.client.FilterLogs(ctx, query)
			if err != nil {
				sm.logger.Error("Failed to filter logs", zap.Error(err))
				continue
			}

			for _, vLog := range logs {
				sm.handleAuditRequestedEvent(vLog)
			}

			lastBlock = currentBlock
		}
	}
}

func (sm *SimpleMonitor) handleAuditRequestedEvent(vLog types.Log) {
	sm.logger.Info("Received AuditRequested event",
		zap.String("tx", vLog.TxHash.Hex()),
		zap.Uint64("block", vLog.BlockNumber))

	// Parse event
	if len(vLog.Topics) < 3 {
		sm.logger.Error("Invalid event topics")
		return
	}

	requestId := vLog.Topics[1]
	requester := common.HexToAddress(vLog.Topics[2].Hex())

	// Decode non-indexed data
	var contractAddress common.Address
	var network string

	data := vLog.Data
	if len(data) >= 32 {
		contractAddress = common.BytesToAddress(data[12:32])
		// Network string would be decoded from remaining data
		// For simplicity, assume it's "sepolia"
		network = "sepolia"
	}

	sm.logger.Info("Processing audit request",
		zap.String("requestId", requestId.Hex()),
		zap.String("requester", requester.Hex()),
		zap.String("contract", contractAddress.Hex()),
		zap.String("network", network))

	// Perform the audit
	go sm.performAudit(requestId, contractAddress, network)
}

func (sm *SimpleMonitor) performAudit(requestId common.Hash, contractAddress common.Address, network string) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	sm.logger.Info("Starting audit",
		zap.String("requestId", requestId.Hex()),
		zap.String("contract", contractAddress.Hex()))

	// Perform the actual audit
	report, err := sm.auditor.AuditContract(ctx, contractAddress)
	if err != nil {
		sm.logger.Error("Audit failed",
			zap.String("requestId", requestId.Hex()),
			zap.Error(err))
		return
	}

	sm.logger.Info("Audit completed",
		zap.String("requestId", requestId.Hex()),
		zap.Int("securityScore", report.SecurityScore),
		zap.Int("totalFindings", len(report.Findings)))

	// Submit the result back to the contract
	if err := sm.submitAuditResult(requestId, report); err != nil {
		sm.logger.Error("Failed to submit audit result",
			zap.String("requestId", requestId.Hex()),
			zap.Error(err))
		return
	}

	sm.logger.Info("Audit result submitted successfully",
		zap.String("requestId", requestId.Hex()))
}

func (sm *SimpleMonitor) submitAuditResult(requestId common.Hash, report *AuditReport) error {
	// Count findings by severity
	var criticalCount, highCount, mediumCount, lowCount uint64
	for _, finding := range report.Findings {
		switch finding.Severity {
		case "CRITICAL":
			criticalCount++
		case "HIGH":
			highCount++
		case "MEDIUM":
			mediumCount++
		case "LOW":
			lowCount++
		}
	}

	// Create a simple report URI (in production, this would be IPFS)
	reportUri := fmt.Sprintf("audit-report-%s-%d", hex.EncodeToString(requestId[:8]), time.Now().Unix())

	// Prepare transaction data
	data, err := sm.contractABI.Pack("submitAuditResult",
		requestId,
		big.NewInt(int64(report.SecurityScore)),
		big.NewInt(int64(len(report.Findings))),
		big.NewInt(int64(criticalCount)),
		big.NewInt(int64(highCount)),
		big.NewInt(int64(mediumCount)),
		big.NewInt(int64(lowCount)),
		reportUri,
	)
	if err != nil {
		return fmt.Errorf("pack data: %w", err)
	}

	// Send transaction
	privateKey, err := crypto.HexToECDSA(strings.TrimPrefix(sm.privateKey, "0x"))
	if err != nil {
		return fmt.Errorf("parse private key: %w", err)
	}

	publicKey := crypto.PubkeyToAddress(privateKey.PublicKey)
	nonce, err := sm.client.PendingNonceAt(context.Background(), publicKey)
	if err != nil {
		return fmt.Errorf("get nonce: %w", err)
	}

	gasPrice, err := sm.client.SuggestGasPrice(context.Background())
	if err != nil {
		return fmt.Errorf("get gas price: %w", err)
	}

	tx := types.NewTransaction(nonce, sm.contractAddress, big.NewInt(0), 300000, gasPrice, data)

	chainID, err := sm.client.NetworkID(context.Background())
	if err != nil {
		return fmt.Errorf("get chain ID: %w", err)
	}

	signedTx, err := types.SignTx(tx, types.NewEIP155Signer(chainID), privateKey)
	if err != nil {
		return fmt.Errorf("sign transaction: %w", err)
	}

	if err := sm.client.SendTransaction(context.Background(), signedTx); err != nil {
		return fmt.Errorf("send transaction: %w", err)
	}

	sm.logger.Info("Submitted audit result transaction",
		zap.String("tx", signedTx.Hash().Hex()))

	return nil
}
