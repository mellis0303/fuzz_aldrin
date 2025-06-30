package main

import (
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"math/big"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
	"go.uber.org/zap"
)

type Config struct {
	RPCURL            string
	ChainID           int64
	PrivateKey        string
	ContractsFile     string
	Port              int
	LogLevel          string
	MaxConcurrentJobs int
	AuditTimeout      time.Duration
}

type Contracts struct {
	TaskMailbox      common.Address `json:"TaskMailbox"`
	AVSTaskHook      common.Address `json:"AVSTaskHook"`
	TaskAVSRegistrar common.Address `json:"TaskAVSRegistrar"`
}

type Deployment struct {
	Contracts Contracts `json:"contracts"`
}

type Aggregator struct {
	client             *ethclient.Client
	contracts          Contracts
	privateKey         *ecdsa.PrivateKey
	account            common.Address
	taskChannel        chan TaskEvent
	auditor            *ContractAuditor
	logger             *zap.Logger
	chainID            *big.Int
	taskManager        *TaskManager
	signatureCollector *SignatureCollector
	ctx                context.Context
	cancel             context.CancelFunc
	wg                 sync.WaitGroup
}

type TaskEvent struct {
	TaskID          *big.Int
	ContractAddress common.Address
	Payment         *big.Int
	BlockNumber     uint64
	TxHash          common.Hash
}

type TaskManager struct {
	maxConcurrent int
	semaphore     chan struct{}
	activeTasks   sync.Map
	metrics       *TaskMetrics
	logger        *zap.Logger
}

type TaskMetrics struct {
	mu               sync.RWMutex
	totalProcessed   uint64
	totalFailed      uint64
	totalSuccessful  uint64
	averageAuditTime time.Duration
}

const (
	TaskSubmittedEventSignature = "TaskSubmitted(uint256,address,uint256)"
	TaskMailboxABI              = `[{
		"inputs":[
			{"internalType":"uint256","name":"taskId","type":"uint256"},
			{"internalType":"bytes","name":"auditReport","type":"bytes"},
			{"internalType":"bytes[]","name":"signatures","type":"bytes[]"}
		],
		"name":"submitAuditResult",
		"outputs":[],
		"stateMutability":"nonpayable",
		"type":"function"
	}]`
)

func main() {
	var cfg Config
	var demoMode bool
	var simpleContract string
	flag.StringVar(&cfg.RPCURL, "rpc-url", "", "Ethereum RPC URL")
	flag.Int64Var(&cfg.ChainID, "chain-id", 0, "Chain ID")
	flag.StringVar(&cfg.PrivateKey, "private-key", "", "Private key")
	flag.StringVar(&cfg.ContractsFile, "contracts-file", "deployment.json", "Contracts deployment file")
	flag.IntVar(&cfg.Port, "port", 8081, "Aggregator service port")
	flag.StringVar(&cfg.LogLevel, "log-level", "info", "Log level")
	flag.IntVar(&cfg.MaxConcurrentJobs, "max-concurrent", 10, "Maximum concurrent audit jobs")
	flag.DurationVar(&cfg.AuditTimeout, "audit-timeout", 5*time.Minute, "Timeout for each audit job")
	flag.BoolVar(&demoMode, "demo", false, "Run in demo mode with simulated operators")
	flag.StringVar(&simpleContract, "simple", "", "Use SimpleContractAudit at specified address")
	flag.Parse()

	if cfg.RPCURL == "" || cfg.PrivateKey == "" || cfg.ChainID == 0 {
		log.Fatal("Required flags: --rpc-url, --private-key, --chain-id")
	}

	loggerCfg := zap.NewProductionConfig()
	if cfg.LogLevel == "debug" {
		loggerCfg.Level = zap.NewAtomicLevelAt(zap.DebugLevel)
	}
	logger, err := loggerCfg.Build()
	if err != nil {
		log.Fatalf("Failed to create logger: %v", err)
	}
	defer logger.Sync()

	// Skip loading deployment if in simple mode
	var deployment *Deployment
	if simpleContract == "" {
		deployment, err = loadDeployment(cfg.ContractsFile)
		if err != nil {
			logger.Fatal("Failed to load deployment", zap.Error(err))
		}
	}

	client, err := ethclient.Dial(cfg.RPCURL)
	if err != nil {
		logger.Fatal("Failed to connect to chain", zap.Error(err))
	}

	chainID, err := client.ChainID(context.Background())
	if err != nil {
		logger.Fatal("Failed to get chain ID", zap.Error(err))
	}
	if chainID.Cmp(big.NewInt(cfg.ChainID)) != 0 {
		logger.Fatal("Chain ID mismatch",
			zap.Int64("expected", cfg.ChainID),
			zap.String("actual", chainID.String()))
	}

	privateKey, err := crypto.HexToECDSA(strings.TrimPrefix(cfg.PrivateKey, "0x"))
	if err != nil {
		logger.Fatal("Failed to parse private key", zap.Error(err))
	}

	account := crypto.PubkeyToAddress(privateKey.PublicKey)

	// If simple mode is enabled, use SimpleMonitor instead
	if simpleContract != "" {
		simpleAddr := common.HexToAddress(simpleContract)
		monitor, err := NewSimpleMonitor(client, simpleAddr, cfg.PrivateKey, logger)
		if err != nil {
			logger.Fatal("Failed to create simple monitor", zap.Error(err))
		}

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		logger.Info("Starting in simple mode",
			zap.String("contract", simpleContract),
			zap.String("account", account.Hex()))

		go monitor.Start(ctx)

		sigChan := make(chan os.Signal, 1)
		signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
		<-sigChan

		logger.Info("Shutting down...")
		cancel()
		time.Sleep(2 * time.Second)
		return
	}

	taskManager := NewTaskManager(cfg.MaxConcurrentJobs, logger)
	auditor := NewContractAuditor(client, logger, cfg.AuditTimeout)

	// Initialize signature collector with registry address
	// In production, this should be the actual AVS registry contract address
	registryAddress := deployment.Contracts.TaskAVSRegistrar
	signatureCollector, err := NewSignatureCollector(client, registryAddress, logger)
	if err != nil {
		logger.Fatal("Failed to create signature collector", zap.Error(err))
	}

	// Initialize signature collector based on mode
	if demoMode {
		logger.Info("Demo mode enabled - using simulated operators")
		if err := signatureCollector.EnableDemoMode(); err != nil {
			logger.Fatal("Failed to enable demo mode", zap.Error(err))
		}
	} else {
		// Initialize operator client and load from registry
		signatureCollector.operatorClient = NewOperatorClient(logger)

		// Load operators from registry
		if err := signatureCollector.loadOperatorsFromRegistry(context.Background()); err != nil {
			logger.Fatal("Failed to load operators from registry", zap.Error(err))
		}

		// Start operator monitoring
		go signatureCollector.monitorOperatorHealth()
	}

	ctx, cancel := context.WithCancel(context.Background())
	aggregator := &Aggregator{
		client:             client,
		contracts:          deployment.Contracts,
		privateKey:         privateKey,
		account:            account,
		taskChannel:        make(chan TaskEvent, 100),
		auditor:            auditor,
		logger:             logger,
		chainID:            chainID,
		taskManager:        taskManager,
		signatureCollector: signatureCollector,
		ctx:                ctx,
		cancel:             cancel,
	}

	logger.Info("Fuzz-Aldrin AVS Aggregator starting",
		zap.String("account", account.Hex()),
		zap.String("task_mailbox", deployment.Contracts.TaskMailbox.Hex()),
		zap.String("avs_task_hook", deployment.Contracts.AVSTaskHook.Hex()),
		zap.String("task_avs_registrar", deployment.Contracts.TaskAVSRegistrar.Hex()),
		zap.Int("max_concurrent_jobs", cfg.MaxConcurrentJobs),
		zap.Duration("audit_timeout", cfg.AuditTimeout),
	)

	aggregator.wg.Add(2)
	go aggregator.monitorTasks()
	go aggregator.processTasks()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	<-sigChan
	logger.Info("Shutting down aggregator...")

	cancel()

	done := make(chan struct{})
	go func() {
		aggregator.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		logger.Info("Aggregator shutdown complete")
	case <-time.After(30 * time.Second):
		logger.Warn("Aggregator shutdown timeout")
	}
}

func loadDeployment(file string) (*Deployment, error) {
	data, err := os.ReadFile(file)
	if err != nil {
		return nil, fmt.Errorf("read deployment file: %w", err)
	}

	var deployment Deployment
	if err := json.Unmarshal(data, &deployment); err != nil {
		return nil, fmt.Errorf("unmarshal deployment: %w", err)
	}

	if deployment.Contracts.TaskMailbox == (common.Address{}) {
		return nil, fmt.Errorf("TaskMailbox address is zero")
	}
	if deployment.Contracts.AVSTaskHook == (common.Address{}) {
		return nil, fmt.Errorf("AVSTaskHook address is zero")
	}
	if deployment.Contracts.TaskAVSRegistrar == (common.Address{}) {
		return nil, fmt.Errorf("TaskAVSRegistrar address is zero")
	}

	return &deployment, nil
}

func (a *Aggregator) monitorTasks() {
	defer a.wg.Done()

	a.logger.Info("Starting task monitoring")

	eventSig := crypto.Keccak256Hash([]byte(TaskSubmittedEventSignature))

	query := ethereum.FilterQuery{
		Addresses: []common.Address{a.contracts.TaskMailbox},
		Topics:    [][]common.Hash{{eventSig}},
	}

	logs := make(chan types.Log)
	sub, err := a.client.SubscribeFilterLogs(a.ctx, query, logs)
	if err != nil {
		a.logger.Warn("Failed to subscribe to events, using polling", zap.Error(err))
		a.pollForTasks()
		return
	}
	defer sub.Unsubscribe()

	for {
		select {
		case <-a.ctx.Done():
			a.logger.Info("Stopping task monitoring")
			return
		case err := <-sub.Err():
			a.logger.Error("Subscription error, switching to polling", zap.Error(err))
			a.pollForTasks()
			return
		case vLog := <-logs:
			if err := a.handleTaskEvent(vLog); err != nil {
				a.logger.Error("Failed to handle task event",
					zap.Error(err),
					zap.String("tx_hash", vLog.TxHash.Hex()))
			}
		}
	}
}

func (a *Aggregator) pollForTasks() {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	currentBlock, err := a.client.BlockNumber(context.Background())
	if err != nil {
		a.logger.Error("Failed to get current block", zap.Error(err))
		currentBlock = 0
	}

	lastBlock := currentBlock
	if lastBlock > 100 {
		lastBlock = currentBlock - 100 // Start from 100 blocks ago
	}

	eventSig := crypto.Keccak256Hash([]byte(TaskSubmittedEventSignature))

	for {
		select {
		case <-a.ctx.Done():
			a.logger.Info("Stopping task polling")
			return
		case <-ticker.C:
			currentBlock, err := a.client.BlockNumber(context.Background())
			if err != nil {
				a.logger.Error("Failed to get block number", zap.Error(err))
				continue
			}

			if currentBlock <= lastBlock {
				continue
			}

			query := ethereum.FilterQuery{
				FromBlock: big.NewInt(int64(lastBlock + 1)),
				ToBlock:   big.NewInt(int64(currentBlock)),
				Addresses: []common.Address{a.contracts.TaskMailbox},
				Topics:    [][]common.Hash{{eventSig}},
			}

			logs, err := a.client.FilterLogs(context.Background(), query)
			if err != nil {
				a.logger.Error("Failed to filter logs", zap.Error(err))
				continue
			}

			for _, vLog := range logs {
				if err := a.handleTaskEvent(vLog); err != nil {
					a.logger.Error("Failed to handle task event",
						zap.Error(err),
						zap.String("tx_hash", vLog.TxHash.Hex()))
				}
			}

			lastBlock = currentBlock
		}
	}
}

func (a *Aggregator) handleTaskEvent(vLog types.Log) error {
	// Validate log structure
	if len(vLog.Topics) < 2 {
		return fmt.Errorf("invalid log: insufficient topics")
	}

	// Extract task ID from indexed topic
	taskID := new(big.Int).SetBytes(vLog.Topics[1].Bytes())

	// Parse event data (contract address and payment)
	if len(vLog.Data) < 64 {
		return fmt.Errorf("invalid log: insufficient data")
	}

	contractAddr := common.BytesToAddress(vLog.Data[:32])
	payment := new(big.Int).SetBytes(vLog.Data[32:64])

	if contractAddr == (common.Address{}) {
		return fmt.Errorf("invalid contract address")
	}

	a.logger.Info("New audit task detected",
		zap.String("task_id", taskID.String()),
		zap.String("contract", contractAddr.Hex()),
		zap.String("payment", weiToEther(payment)+" ETH"),
		zap.Uint64("block", vLog.BlockNumber),
		zap.String("tx_hash", vLog.TxHash.Hex()),
	)

	select {
	case a.taskChannel <- TaskEvent{
		TaskID:          taskID,
		ContractAddress: contractAddr,
		Payment:         payment,
		BlockNumber:     vLog.BlockNumber,
		TxHash:          vLog.TxHash,
	}:
	case <-a.ctx.Done():
		return fmt.Errorf("aggregator shutting down")
	default:
		a.logger.Warn("Task channel full, dropping task",
			zap.String("task_id", taskID.String()))
	}

	return nil
}

func (a *Aggregator) processTasks() {
	defer a.wg.Done()

	a.logger.Info("Starting task processor")

	for {
		select {
		case <-a.ctx.Done():
			a.logger.Info("Stopping task processor")
			return
		case task := <-a.taskChannel:
			if err := a.taskManager.AcquireSlot(task.TaskID); err != nil {
				a.logger.Error("Failed to acquire task slot",
					zap.Error(err),
					zap.String("task_id", task.TaskID.String()))
				continue
			}

			a.wg.Add(1)
			go func(t TaskEvent) {
				defer a.wg.Done()
				defer a.taskManager.ReleaseSlot(t.TaskID)

				if err := a.processAuditTask(t); err != nil {
					a.logger.Error("Failed to process audit task",
						zap.Error(err),
						zap.String("task_id", t.TaskID.String()))
					a.taskManager.RecordFailure()
				} else {
					a.taskManager.RecordSuccess()
				}
			}(task)
		}
	}
}

func (a *Aggregator) processAuditTask(task TaskEvent) error {
	startTime := time.Now()

	a.logger.Info("Processing audit task",
		zap.String("task_id", task.TaskID.String()),
		zap.String("contract", task.ContractAddress.Hex()))

	ctx, cancel := context.WithTimeout(a.ctx, a.auditor.timeout)
	defer cancel()

	report, err := a.auditor.AuditContract(ctx, task.ContractAddress)
	if err != nil {
		return fmt.Errorf("audit failed: %w", err)
	}

	report.TaskID = task.TaskID.String()
	report.ContractAddress = task.ContractAddress.Hex()

	reportBytes, err := json.Marshal(report)
	if err != nil {
		return fmt.Errorf("marshal report: %w", err)
	}

	signatures, err := a.signatureCollector.CollectSignatures(ctx, task.TaskID, reportBytes)
	if err != nil {
		return fmt.Errorf("collect signatures: %w", err)
	}

	if err := a.submitAuditResult(ctx, task.TaskID, reportBytes, signatures); err != nil {
		return fmt.Errorf("submit result: %w", err)
	}

	auditDuration := time.Since(startTime)
	a.taskManager.RecordAuditTime(auditDuration)

	a.logger.Info("Audit task completed",
		zap.String("task_id", task.TaskID.String()),
		zap.Int("security_score", report.SecurityScore),
		zap.Int("findings", report.TotalFindings),
		zap.Duration("duration", auditDuration),
	)

	return nil
}

func (a *Aggregator) submitAuditResult(ctx context.Context, taskID *big.Int, report []byte, signatures [][]byte) error {
	parsedABI, err := abi.JSON(strings.NewReader(TaskMailboxABI))
	if err != nil {
		return fmt.Errorf("parse ABI: %w", err)
	}

	data, err := parsedABI.Pack("submitAuditResult", taskID, report, signatures)
	if err != nil {
		return fmt.Errorf("pack data: %w", err)
	}

	auth, err := bind.NewKeyedTransactorWithChainID(a.privateKey, a.chainID)
	if err != nil {
		return fmt.Errorf("create transactor: %w", err)
	}

	// Set gas price and limit
	gasPrice, err := a.client.SuggestGasPrice(ctx)
	if err != nil {
		return fmt.Errorf("get gas price: %w", err)
	}
	auth.GasPrice = gasPrice
	auth.GasLimit = uint64(1000000) // Adjust based on contract requirements

	// Get nonce
	nonce, err := a.client.PendingNonceAt(ctx, a.account)
	if err != nil {
		return fmt.Errorf("get nonce: %w", err)
	}
	auth.Nonce = big.NewInt(int64(nonce))

	// Create transaction
	tx := types.NewTransaction(
		nonce,
		a.contracts.TaskMailbox,
		big.NewInt(0),
		auth.GasLimit,
		gasPrice,
		data,
	)

	signedTx, err := types.SignTx(tx, types.NewEIP155Signer(a.chainID), a.privateKey)
	if err != nil {
		return fmt.Errorf("sign transaction: %w", err)
	}

	if err := a.client.SendTransaction(ctx, signedTx); err != nil {
		return fmt.Errorf("send transaction: %w", err)
	}

	a.logger.Info("Submitted audit result transaction",
		zap.String("tx_hash", signedTx.Hash().Hex()),
		zap.String("task_id", taskID.String()),
	)

	receiptCtx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()

	receipt, err := bind.WaitMined(receiptCtx, a.client, signedTx)
	if err != nil {
		return fmt.Errorf("wait for transaction: %w", err)
	}

	if receipt.Status == 0 {
		return fmt.Errorf("transaction failed")
	}

	a.logger.Info("Audit result confirmed on-chain",
		zap.String("tx_hash", receipt.TxHash.Hex()),
		zap.Uint64("block", receipt.BlockNumber.Uint64()),
		zap.Uint64("gas_used", receipt.GasUsed),
	)

	return nil
}

func NewTaskManager(maxConcurrent int, logger *zap.Logger) *TaskManager {
	return &TaskManager{
		maxConcurrent: maxConcurrent,
		semaphore:     make(chan struct{}, maxConcurrent),
		metrics:       &TaskMetrics{},
		logger:        logger,
	}
}

func (tm *TaskManager) AcquireSlot(taskID *big.Int) error {
	select {
	case tm.semaphore <- struct{}{}:
		tm.activeTasks.Store(taskID.String(), time.Now())
		return nil
	default:
		return fmt.Errorf("max concurrent tasks reached")
	}
}

func (tm *TaskManager) ReleaseSlot(taskID *big.Int) {
	tm.activeTasks.Delete(taskID.String())
	<-tm.semaphore
}

func (tm *TaskManager) RecordSuccess() {
	tm.metrics.mu.Lock()
	defer tm.metrics.mu.Unlock()
	tm.metrics.totalProcessed++
	tm.metrics.totalSuccessful++
}

func (tm *TaskManager) RecordFailure() {
	tm.metrics.mu.Lock()
	defer tm.metrics.mu.Unlock()
	tm.metrics.totalProcessed++
	tm.metrics.totalFailed++
}

func (tm *TaskManager) RecordAuditTime(duration time.Duration) {
	tm.metrics.mu.Lock()
	defer tm.metrics.mu.Unlock()

	// Simple moving average
	if tm.metrics.averageAuditTime == 0 {
		tm.metrics.averageAuditTime = duration
	} else {
		tm.metrics.averageAuditTime = (tm.metrics.averageAuditTime + duration) / 2
	}
}

func weiToEther(wei *big.Int) string {
	ether := new(big.Float).SetInt(wei)
	ether.Quo(ether, big.NewFloat(1e18))
	return fmt.Sprintf("%.6f", ether)
}
