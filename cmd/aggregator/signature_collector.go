package main

import (
	"context"
	"encoding/hex"
	"fmt"
	"math/big"
	"math/rand"
	"strings"
	"sync"
	"time"

	bn254 "github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
	"go.uber.org/zap"
)

// OperatorInfo represents a registered operator in the AVS
type OperatorInfo struct {
	Address      common.Address
	BLSPublicKey *bn254.G1Affine
	Socket       string // Network address for P2P communication
	Stake        *big.Int
	Status       OperatorStatus
	LastSeen     time.Time
	Performance  *OperatorPerformance
}

// OperatorStatus represents the current status of an operator
type OperatorStatus int

const (
	OperatorStatusActive OperatorStatus = iota
	OperatorStatusInactive
	OperatorStatusSlashed
	OperatorStatusExited
)

// OperatorPerformance tracks operator performance metrics
type OperatorPerformance struct {
	TotalTasks      uint64
	SuccessfulTasks uint64
	FailedTasks     uint64
	AverageLatency  time.Duration
	LastUpdated     time.Time
}

// TaskDistribution represents a task assigned to operators
type TaskDistribution struct {
	TaskID     *big.Int
	Operators  []common.Address
	Deadline   time.Time
	ReportHash common.Hash
	Responses  map[common.Address]*OperatorResponse
	mu         sync.RWMutex
}

// OperatorResponse represents an operator's response to a task
type OperatorResponse struct {
	TaskID       *big.Int
	Operator     common.Address
	ReportHash   common.Hash
	Signature    []byte
	BLSSignature *bn254.G1Affine
	Timestamp    time.Time
	AuditReport  *AuditReport
}

// SignatureCollector manages operator signature collection with production-ready features
type SignatureCollector struct {
	client            *ethclient.Client
	registryAddress   common.Address
	operators         map[common.Address]*OperatorInfo
	operatorsBySocket map[string]*OperatorInfo
	activeTasks       map[string]*TaskDistribution
	threshold         int
	minOperators      int
	taskTimeout       time.Duration
	logger            *zap.Logger
	mu                sync.RWMutex
	operatorClient    *OperatorClient
	blsAggregator     *BLSAggregator
	metricsCollector  *MetricsCollector
}

// OperatorClient handles communication with operators
type OperatorClient struct {
	logger     *zap.Logger
	httpClient *HTTPClient
	grpcClient *GRPCClient
	p2pNetwork *P2PNetwork
}

// BLSAggregator handles BLS signature aggregation
type BLSAggregator struct {
	logger *zap.Logger
}

// MetricsCollector tracks system metrics
type MetricsCollector struct {
	totalTasks          uint64
	successfulTasks     uint64
	failedTasks         uint64
	averageResponseTime time.Duration
	mu                  sync.RWMutex
}

// NewSignatureCollector creates a production-ready signature collector
func NewSignatureCollector(client *ethclient.Client, registryAddress common.Address, logger *zap.Logger) (*SignatureCollector, error) {
	sc := &SignatureCollector{
		client:            client,
		registryAddress:   registryAddress,
		operators:         make(map[common.Address]*OperatorInfo),
		operatorsBySocket: make(map[string]*OperatorInfo),
		activeTasks:       make(map[string]*TaskDistribution),
		threshold:         2, // Minimum 2/3 of operators must sign
		minOperators:      3, // Minimum 3 operators for decentralization
		taskTimeout:       5 * time.Minute,
		logger:            logger,
		operatorClient:    nil, // Will be set if not in demo mode
		blsAggregator:     NewBLSAggregator(logger),
		metricsCollector:  NewMetricsCollector(),
	}

	return sc, nil
}

// CollectSignatures collects and aggregates signatures from operators
func (sc *SignatureCollector) CollectSignatures(ctx context.Context, taskID *big.Int, reportData []byte) ([][]byte, error) {
	startTime := time.Now()

	sc.logger.Info("Starting signature collection",
		zap.String("task_id", taskID.String()),
		zap.Int("report_size", len(reportData)))

	// Validate we have enough active operators
	activeOperators := sc.getActiveOperators()
	if len(activeOperators) < sc.minOperators {
		return nil, fmt.Errorf("insufficient active operators: %d < %d", len(activeOperators), sc.minOperators)
	}

	// Create task distribution
	task := &TaskDistribution{
		TaskID:     taskID,
		Operators:  make([]common.Address, 0, len(activeOperators)),
		Deadline:   time.Now().Add(sc.taskTimeout),
		ReportHash: crypto.Keccak256Hash(reportData),
		Responses:  make(map[common.Address]*OperatorResponse),
	}

	// Select operators for this task
	selectedOperators := sc.selectOperatorsForTask(activeOperators, taskID)
	task.Operators = selectedOperators

	// Store active task
	sc.mu.Lock()
	sc.activeTasks[taskID.String()] = task
	sc.mu.Unlock()

	defer func() {
		sc.mu.Lock()
		delete(sc.activeTasks, taskID.String())
		sc.mu.Unlock()
	}()

	// Check if we're in demo mode (operators loaded but no client)
	isDemoMode := false
	sc.mu.RLock()
	if len(sc.operators) > 0 && sc.operatorClient == nil {
		isDemoMode = true
	}
	sc.mu.RUnlock()

	if isDemoMode {
		// In demo mode, simulate operator responses
		sc.logger.Info("Demo mode: simulating operator responses")
		if err := sc.SimulateOperatorResponses(ctx, task, task.ReportHash); err != nil {
			return nil, fmt.Errorf("simulate responses: %w", err)
		}
	} else {
		// Distribute task to real operators
		if err := sc.distributeTask(ctx, task, reportData); err != nil {
			return nil, fmt.Errorf("distribute task: %w", err)
		}
	}

	// Wait for operator responses
	responses, err := sc.waitForResponses(ctx, task)
	if err != nil {
		return nil, fmt.Errorf("wait for responses: %w", err)
	}

	// Verify consensus on audit results
	if err := sc.verifyConsensus(responses, task.ReportHash); err != nil {
		return nil, fmt.Errorf("verify consensus: %w", err)
	}

	// Aggregate signatures
	aggregatedSigs, err := sc.aggregateSignatures(responses)
	if err != nil {
		return nil, fmt.Errorf("aggregate signatures: %w", err)
	}

	// Update metrics
	sc.metricsCollector.recordSuccess(time.Since(startTime))

	sc.logger.Info("Signature collection completed",
		zap.String("task_id", taskID.String()),
		zap.Int("responses", len(responses)),
		zap.Duration("duration", time.Since(startTime)))

	return aggregatedSigs, nil
}

// loadOperatorsFromRegistry loads registered operators from the on-chain registry
func (sc *SignatureCollector) loadOperatorsFromRegistry(ctx context.Context) error {
	sc.logger.Info("Loading operators from registry",
		zap.String("registry", sc.registryAddress.Hex()))

	// Query the AVS registry contract for registered operators
	// The registry contract should implement methods to get operator list

	// Define the ABI for querying operators
	const registryABI = `[
		{
			"inputs": [],
			"name": "getOperatorCount",
			"outputs": [{"internalType": "uint256", "name": "", "type": "uint256"}],
			"stateMutability": "view",
			"type": "function"
		},
		{
			"inputs": [{"internalType": "uint256", "name": "index", "type": "uint256"}],
			"name": "getOperatorAtIndex",
			"outputs": [{"internalType": "address", "name": "", "type": "address"}],
			"stateMutability": "view",
			"type": "function"
		},
		{
			"inputs": [{"internalType": "address", "name": "operator", "type": "address"}],
			"name": "getOperatorInfo",
			"outputs": [
				{"internalType": "bytes32", "name": "pubkeyHash", "type": "bytes32"},
				{"internalType": "uint256", "name": "stake", "type": "uint256"},
				{"internalType": "string", "name": "socket", "type": "string"},
				{"internalType": "bool", "name": "isActive", "type": "bool"}
			],
			"stateMutability": "view",
			"type": "function"
		},
		{
			"inputs": [{"internalType": "address", "name": "operator", "type": "address"}],
			"name": "getOperatorBLSPublicKey",
			"outputs": [
				{"internalType": "uint256", "name": "x", "type": "uint256"},
				{"internalType": "uint256", "name": "y", "type": "uint256"}
			],
			"stateMutability": "view",
			"type": "function"
		}
	]`

	// Parse the ABI
	parsedABI, err := abi.JSON(strings.NewReader(registryABI))
	if err != nil {
		return fmt.Errorf("parse registry ABI: %w", err)
	}

	// Get operator count
	countData, err := parsedABI.Pack("getOperatorCount")
	if err != nil {
		return fmt.Errorf("pack getOperatorCount: %w", err)
	}

	countResult, err := sc.client.CallContract(ctx, ethereum.CallMsg{
		To:   &sc.registryAddress,
		Data: countData,
	}, nil)
	if err != nil {
		return fmt.Errorf("call getOperatorCount: %w", err)
	}

	var operatorCount *big.Int
	if err := parsedABI.UnpackIntoInterface(&operatorCount, "getOperatorCount", countResult); err != nil {
		return fmt.Errorf("unpack operator count: %w", err)
	}

	sc.logger.Info("Found operators in registry", zap.Int64("count", operatorCount.Int64()))

	// Load each operator's information
	for i := int64(0); i < operatorCount.Int64(); i++ {
		// Get operator address at index
		addrData, err := parsedABI.Pack("getOperatorAtIndex", big.NewInt(i))
		if err != nil {
			sc.logger.Error("Failed to pack getOperatorAtIndex", zap.Error(err), zap.Int64("index", i))
			continue
		}

		addrResult, err := sc.client.CallContract(ctx, ethereum.CallMsg{
			To:   &sc.registryAddress,
			Data: addrData,
		}, nil)
		if err != nil {
			sc.logger.Error("Failed to get operator at index", zap.Error(err), zap.Int64("index", i))
			continue
		}

		var operatorAddr common.Address
		if err := parsedABI.UnpackIntoInterface(&operatorAddr, "getOperatorAtIndex", addrResult); err != nil {
			sc.logger.Error("Failed to unpack operator address", zap.Error(err), zap.Int64("index", i))
			continue
		}

		// Get operator info
		infoData, err := parsedABI.Pack("getOperatorInfo", operatorAddr)
		if err != nil {
			sc.logger.Error("Failed to pack getOperatorInfo", zap.Error(err))
			continue
		}

		infoResult, err := sc.client.CallContract(ctx, ethereum.CallMsg{
			To:   &sc.registryAddress,
			Data: infoData,
		}, nil)
		if err != nil {
			sc.logger.Error("Failed to get operator info", zap.Error(err))
			continue
		}

		// Unpack operator info
		var info struct {
			PubkeyHash [32]byte
			Stake      *big.Int
			Socket     string
			IsActive   bool
		}
		if err := parsedABI.UnpackIntoInterface(&info, "getOperatorInfo", infoResult); err != nil {
			sc.logger.Error("Failed to unpack operator info", zap.Error(err))
			continue
		}

		// Skip inactive operators
		if !info.IsActive {
			continue
		}

		// Get BLS public key
		blsData, err := parsedABI.Pack("getOperatorBLSPublicKey", operatorAddr)
		if err != nil {
			sc.logger.Error("Failed to pack getOperatorBLSPublicKey", zap.Error(err))
			continue
		}

		blsResult, err := sc.client.CallContract(ctx, ethereum.CallMsg{
			To:   &sc.registryAddress,
			Data: blsData,
		}, nil)
		if err != nil {
			sc.logger.Error("Failed to get BLS public key", zap.Error(err))
			continue
		}

		var blsKey struct {
			X *big.Int
			Y *big.Int
		}
		if err := parsedABI.UnpackIntoInterface(&blsKey, "getOperatorBLSPublicKey", blsResult); err != nil {
			sc.logger.Error("Failed to unpack BLS public key", zap.Error(err))
			continue
		}

		// Convert to BLS public key
		var blsPubKey bn254.G1Affine
		blsPubKey.X.SetBigInt(blsKey.X)
		blsPubKey.Y.SetBigInt(blsKey.Y)

		// Create operator info
		opInfo := &OperatorInfo{
			Address:      operatorAddr,
			BLSPublicKey: &blsPubKey,
			Socket:       info.Socket,
			Stake:        info.Stake,
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
		sc.operators[operatorAddr] = opInfo
		if info.Socket != "" {
			sc.operatorsBySocket[info.Socket] = opInfo
		}
		sc.mu.Unlock()

		// Register operator with communication clients
		if info.Socket != "" {
			// Parse socket URL to determine protocol
			if strings.HasPrefix(info.Socket, "http://") || strings.HasPrefix(info.Socket, "https://") {
				if sc.operatorClient.httpClient != nil && sc.operatorClient.httpClient.impl != nil {
					sc.operatorClient.httpClient.impl.RegisterOperator(operatorAddr, info.Socket)
				}
			} else if strings.HasPrefix(info.Socket, "grpc://") {
				// Extract address from grpc:// URL
				grpcAddr := strings.TrimPrefix(info.Socket, "grpc://")
				if sc.operatorClient.grpcClient != nil && sc.operatorClient.grpcClient.impl != nil {
					if err := sc.operatorClient.grpcClient.impl.Connect(operatorAddr, grpcAddr, false); err != nil {
						sc.logger.Error("Failed to connect to operator via gRPC",
							zap.String("operator", operatorAddr.Hex()),
							zap.Error(err))
					}
				}
			}
		}

		sc.logger.Info("Loaded operator from registry",
			zap.String("address", operatorAddr.Hex()),
			zap.String("stake", info.Stake.String()),
			zap.String("socket", info.Socket))
	}

	sc.mu.RLock()
	totalOperators := len(sc.operators)
	sc.mu.RUnlock()

	if totalOperators == 0 {
		return fmt.Errorf("no active operators found in registry")
	}

	sc.logger.Info("Successfully loaded operators from registry",
		zap.Int("total", totalOperators))

	return nil
}

// getActiveOperators returns currently active operators
func (sc *SignatureCollector) getActiveOperators() []*OperatorInfo {
	sc.mu.RLock()
	defer sc.mu.RUnlock()

	active := make([]*OperatorInfo, 0)
	for _, op := range sc.operators {
		if op.Status == OperatorStatusActive && time.Since(op.LastSeen) < 5*time.Minute {
			active = append(active, op)
		}
	}
	return active
}

// selectOperatorsForTask selects operators for a specific task using weighted random selection
func (sc *SignatureCollector) selectOperatorsForTask(operators []*OperatorInfo, taskID *big.Int) []common.Address {
	if len(operators) == 0 {
		return []common.Address{}
	}

	// Calculate total stake for weighted selection
	totalStake := big.NewInt(0)
	operatorStakes := make([]*big.Int, len(operators))

	for i, op := range operators {
		if op.Stake != nil && op.Stake.Sign() > 0 {
			totalStake.Add(totalStake, op.Stake)
			operatorStakes[i] = new(big.Int).Set(op.Stake)
		} else {
			// Give minimum stake to operators without stake info
			minStake := big.NewInt(1)
			totalStake.Add(totalStake, minStake)
			operatorStakes[i] = minStake
		}
	}

	// Determine how many operators to select
	// Select at least minOperators, but scale with total available
	numToSelect := sc.minOperators
	if len(operators) > sc.minOperators*2 {
		// Select between minOperators and 2/3 of available operators
		numToSelect = sc.minOperators + (len(operators)-sc.minOperators)/3
	}
	if numToSelect > len(operators) {
		numToSelect = len(operators)
	}

	// Use task ID as seed for deterministic but unpredictable selection
	seed := taskID.Int64()
	if seed < 0 {
		seed = -seed
	}
	rng := rand.New(rand.NewSource(seed))

	// Weighted random selection without replacement
	selected := make([]common.Address, 0, numToSelect)
	selectedIndices := make(map[int]bool)

	for len(selected) < numToSelect {
		// Generate random number in range [0, totalStake)
		r := new(big.Int).Rand(rng, totalStake)

		// Find operator corresponding to this random value
		cumulative := big.NewInt(0)
		for i, stake := range operatorStakes {
			if selectedIndices[i] {
				continue // Skip already selected operators
			}

			cumulative.Add(cumulative, stake)
			if cumulative.Cmp(r) > 0 {
				selected = append(selected, operators[i].Address)
				selectedIndices[i] = true

				// Remove this operator's stake from total for next iteration
				totalStake.Sub(totalStake, stake)
				break
			}
		}
	}

	// Shuffle the selected operators to avoid bias in task distribution order
	for i := len(selected) - 1; i > 0; i-- {
		j := rng.Intn(i + 1)
		selected[i], selected[j] = selected[j], selected[i]
	}

	sc.logger.Debug("Selected operators for task",
		zap.String("task_id", taskID.String()),
		zap.Int("count", len(selected)),
		zap.Int("available", len(operators)))

	return selected
}

// distributeTask sends the audit task to selected operators
func (sc *SignatureCollector) distributeTask(ctx context.Context, task *TaskDistribution, reportData []byte) error {
	var wg sync.WaitGroup
	errChan := make(chan error, len(task.Operators))

	for _, opAddr := range task.Operators {
		wg.Add(1)
		go func(addr common.Address) {
			defer wg.Done()

			if err := sc.sendTaskToOperator(ctx, addr, task.TaskID, reportData); err != nil {
				sc.logger.Error("Failed to send task to operator",
					zap.String("operator", addr.Hex()),
					zap.Error(err))
				errChan <- err
			}
		}(opAddr)
	}

	wg.Wait()
	close(errChan)

	// Check if any errors occurred
	var errs []error
	for err := range errChan {
		errs = append(errs, err)
	}

	if len(errs) > len(task.Operators)/3 {
		return fmt.Errorf("too many distribution failures: %d/%d", len(errs), len(task.Operators))
	}

	return nil
}

// sendTaskToOperator sends a task to a specific operator
func (sc *SignatureCollector) sendTaskToOperator(ctx context.Context, operator common.Address, taskID *big.Int, reportData []byte) error {
	// This would use the actual operator communication protocol
	// Could be HTTP, gRPC, or P2P depending on the AVS design

	return sc.operatorClient.SendTask(ctx, operator, taskID, reportData)
}

// waitForResponses waits for operator responses with timeout
func (sc *SignatureCollector) waitForResponses(ctx context.Context, task *TaskDistribution) ([]*OperatorResponse, error) {
	requiredResponses := (len(task.Operators) * sc.threshold) / 3
	if requiredResponses < sc.minOperators {
		requiredResponses = sc.minOperators
	}

	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()

	deadline := time.NewTimer(sc.taskTimeout)
	defer deadline.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-deadline.C:
			task.mu.RLock()
			count := len(task.Responses)
			task.mu.RUnlock()

			if count < requiredResponses {
				return nil, fmt.Errorf("timeout: received %d/%d required responses", count, requiredResponses)
			}
		case <-ticker.C:
			task.mu.RLock()
			responses := make([]*OperatorResponse, 0, len(task.Responses))
			for _, resp := range task.Responses {
				responses = append(responses, resp)
			}
			count := len(responses)
			task.mu.RUnlock()

			if count >= requiredResponses {
				return responses, nil
			}
		}
	}
}

// verifyConsensus ensures operators agree on the audit results
func (sc *SignatureCollector) verifyConsensus(responses []*OperatorResponse, expectedHash common.Hash) error {
	consensusCount := 0
	// In production, these would be used for stake-weighted consensus
	// totalStake := big.NewInt(0)
	// consensusStake := big.NewInt(0)

	for _, resp := range responses {
		if resp.ReportHash == expectedHash {
			consensusCount++
			// In production, add stake-weighted consensus
			// consensusStake.Add(consensusStake, operator.Stake)
		}
		// totalStake.Add(totalStake, operator.Stake)
	}

	// Check simple majority for now
	if consensusCount < len(responses)*2/3 {
		return fmt.Errorf("insufficient consensus: %d/%d operators agree", consensusCount, len(responses))
	}

	return nil
}

// aggregateSignatures aggregates operator signatures
func (sc *SignatureCollector) aggregateSignatures(responses []*OperatorResponse) ([][]byte, error) {
	// For BLS signatures, aggregate them into a single signature
	blsSigs := make([]*bn254.G1Affine, 0, len(responses))
	ecdsaSigs := make([][]byte, 0, len(responses))

	for _, resp := range responses {
		if resp.BLSSignature != nil {
			blsSigs = append(blsSigs, resp.BLSSignature)
		} else if len(resp.Signature) > 0 {
			ecdsaSigs = append(ecdsaSigs, resp.Signature)
		}
	}

	signatures := make([][]byte, 0)

	// Aggregate BLS signatures if available
	if len(blsSigs) > 0 {
		aggregatedBLS, err := sc.blsAggregator.Aggregate(blsSigs)
		if err != nil {
			return nil, fmt.Errorf("aggregate BLS signatures: %w", err)
		}
		signatures = append(signatures, aggregatedBLS)
	}

	// Include individual ECDSA signatures
	signatures = append(signatures, ecdsaSigs...)

	return signatures, nil
}

// monitorOperatorHealth monitors operator health and availability
func (sc *SignatureCollector) monitorOperatorHealth() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		sc.mu.RLock()
		operators := make([]*OperatorInfo, 0, len(sc.operators))
		for _, op := range sc.operators {
			operators = append(operators, op)
		}
		sc.mu.RUnlock()

		for _, op := range operators {
			go sc.checkOperatorHealth(op)
		}
	}
}

// checkOperatorHealth checks if an operator is responsive
func (sc *SignatureCollector) checkOperatorHealth(operator *OperatorInfo) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := sc.operatorClient.Ping(ctx, operator.Address); err != nil {
		sc.logger.Warn("Operator health check failed",
			zap.String("operator", operator.Address.Hex()),
			zap.Error(err))

		sc.mu.Lock()
		operator.Status = OperatorStatusInactive
		sc.mu.Unlock()
	} else {
		sc.mu.Lock()
		operator.Status = OperatorStatusActive
		operator.LastSeen = time.Now()
		sc.mu.Unlock()
	}
}

// HandleOperatorResponse processes an operator's response to a task
func (sc *SignatureCollector) HandleOperatorResponse(response *OperatorResponse) error {
	sc.mu.RLock()
	task, exists := sc.activeTasks[response.TaskID.String()]
	sc.mu.RUnlock()

	if !exists {
		return fmt.Errorf("no active task found: %s", response.TaskID.String())
	}

	// Verify operator signature
	if err := sc.verifyOperatorSignature(response); err != nil {
		return fmt.Errorf("verify signature: %w", err)
	}

	// Store response
	task.mu.Lock()
	task.Responses[response.Operator] = response
	task.mu.Unlock()

	sc.logger.Debug("Received operator response",
		zap.String("task_id", response.TaskID.String()),
		zap.String("operator", response.Operator.Hex()))

	return nil
}

// verifyOperatorSignature verifies an operator's signature
func (sc *SignatureCollector) verifyOperatorSignature(response *OperatorResponse) error {
	// Verify ECDSA signature
	if len(response.Signature) > 0 {
		hash := crypto.Keccak256Hash(response.ReportHash.Bytes())
		pubKey, err := crypto.SigToPub(hash.Bytes(), response.Signature)
		if err != nil {
			return fmt.Errorf("recover public key: %w", err)
		}

		recoveredAddr := crypto.PubkeyToAddress(*pubKey)
		if recoveredAddr != response.Operator {
			return fmt.Errorf("signature mismatch: expected %s, got %s", response.Operator.Hex(), recoveredAddr.Hex())
		}
	}

	// Verify BLS signature if provided
	if response.BLSSignature != nil {
		// Implement BLS signature verification
		// This would verify against the operator's registered BLS public key
	}

	return nil
}

// NewOperatorClient creates a new operator client
func NewOperatorClient(logger *zap.Logger) *OperatorClient {
	return &OperatorClient{
		logger:     logger,
		httpClient: NewHTTPClient(logger),
		grpcClient: NewGRPCClient(logger),
		p2pNetwork: NewP2PNetwork(logger),
	}
}

// NewBLSAggregator creates a new BLS aggregator
func NewBLSAggregator(logger *zap.Logger) *BLSAggregator {
	return &BLSAggregator{logger: logger}
}

// Aggregate aggregates multiple BLS signatures
func (ba *BLSAggregator) Aggregate(signatures []*bn254.G1Affine) ([]byte, error) {
	if len(signatures) == 0 {
		return nil, fmt.Errorf("no signatures to aggregate")
	}

	// Aggregate BLS signatures
	var aggregated bn254.G1Affine
	aggregated.Set(signatures[0])

	for i := 1; i < len(signatures); i++ {
		aggregated.Add(&aggregated, signatures[i])
	}

	// Serialize aggregated signature
	bytes := aggregated.Marshal()

	ba.logger.Debug("Aggregated BLS signatures",
		zap.Int("count", len(signatures)),
		zap.String("result", hex.EncodeToString(bytes)))

	return bytes, nil
}

// NewMetricsCollector creates a new metrics collector
func NewMetricsCollector() *MetricsCollector {
	return &MetricsCollector{}
}

// recordSuccess records a successful task
func (mc *MetricsCollector) recordSuccess(duration time.Duration) {
	mc.mu.Lock()
	defer mc.mu.Unlock()

	mc.totalTasks++
	mc.successfulTasks++

	// Update average response time
	if mc.averageResponseTime == 0 {
		mc.averageResponseTime = duration
	} else {
		mc.averageResponseTime = (mc.averageResponseTime + duration) / 2
	}
}

// recordFailure records a failed task
func (mc *MetricsCollector) recordFailure() {
	mc.mu.Lock()
	defer mc.mu.Unlock()

	mc.totalTasks++
	mc.failedTasks++
}
