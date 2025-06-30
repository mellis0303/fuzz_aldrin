package main

import (
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
	"go.uber.org/zap"
)

type Config struct {
	PrivateKey      string
	RPCURL          string
	Port            int
	RegistryAddress string
	LogLevel        string
}

type Operator struct {
	privateKey      *ecdsa.PrivateKey
	address         common.Address
	client          *ethclient.Client
	registryAddress common.Address
	blsKey          *BLSKey
	logger          *zap.Logger
	server          *http.Server
	mu              sync.RWMutex
	activeTasks     map[string]*TaskInfo
}

type BLSKey struct {
	PrivateKey *big.Int
	PublicKey  *bn254.G1Affine
}

type TaskInfo struct {
	TaskID      *big.Int
	ReportData  []byte
	ReceivedAt  time.Time
	ProcessedAt *time.Time
	Signature   []byte
}

type TaskRequest struct {
	TaskID     string `json:"task_id"`
	ReportData string `json:"report_data"`
}

type TaskResponse struct {
	TaskID       string `json:"task_id"`
	Operator     string `json:"operator"`
	Signature    string `json:"signature"`
	BLSSignature string `json:"bls_signature,omitempty"`
	Timestamp    int64  `json:"timestamp"`
	Success      bool   `json:"success"`
	Error        string `json:"error,omitempty"`
}

func main() {
	var cfg Config
	flag.StringVar(&cfg.PrivateKey, "private-key", "", "Operator private key")
	flag.StringVar(&cfg.RPCURL, "rpc-url", "https://ethereum-sepolia-rpc.publicnode.com", "Ethereum RPC URL")
	flag.IntVar(&cfg.Port, "port", 9001, "HTTP server port")
	flag.StringVar(&cfg.RegistryAddress, "registry", "", "AVS Registry contract address")
	flag.StringVar(&cfg.LogLevel, "log-level", "info", "Log level")
	flag.Parse()

	if cfg.PrivateKey == "" {
		log.Fatal("Private key is required")
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

	privateKey, err := crypto.HexToECDSA(strings.TrimPrefix(cfg.PrivateKey, "0x"))
	if err != nil {
		logger.Fatal("Failed to parse private key", zap.Error(err))
	}

	address := crypto.PubkeyToAddress(privateKey.PublicKey)

	client, err := ethclient.Dial(cfg.RPCURL)
	if err != nil {
		logger.Fatal("Failed to connect to Ethereum", zap.Error(err))
	}

	blsKey := generateBLSKey(privateKey)

	operator := &Operator{
		privateKey:      privateKey,
		address:         address,
		client:          client,
		registryAddress: common.HexToAddress(cfg.RegistryAddress),
		blsKey:          blsKey,
		logger:          logger,
		activeTasks:     make(map[string]*TaskInfo),
	}

	logger.Info("Operator node starting",
		zap.String("address", address.Hex()),
		zap.Int("port", cfg.Port),
		zap.String("registry", cfg.RegistryAddress))

	mux := http.NewServeMux()
	mux.HandleFunc("/health", operator.handleHealth)
	mux.HandleFunc("/task", operator.handleTask)
	mux.HandleFunc("/status", operator.handleStatus)

	operator.server = &http.Server{
		Addr:    fmt.Sprintf("0.0.0.0:%d", cfg.Port),
		Handler: mux,
	}

	go func() {
		logger.Info("HTTP server starting", zap.Int("port", cfg.Port))
		if err := operator.server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Fatal("HTTP server failed", zap.Error(err))
		}
	}()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	<-sigChan

	logger.Info("Shutting down operator node...")

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := operator.server.Shutdown(ctx); err != nil {
		logger.Error("Server shutdown error", zap.Error(err))
	}

	logger.Info("Operator node shutdown complete")
}

func generateBLSKey(privateKey *ecdsa.PrivateKey) *BLSKey {
	// In production, use proper BLS key generation
	// This is simplified for the demo
	privKeyInt := new(big.Int).SetBytes(privateKey.D.Bytes())

	var pubKey bn254.G1Affine
	pubKey.X.SetInt64(1000) // Simplified
	pubKey.Y.SetInt64(2000) // Simplified

	return &BLSKey{
		PrivateKey: privKeyInt,
		PublicKey:  &pubKey,
	}
}

func (o *Operator) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":   "healthy",
		"operator": o.address.Hex(),
		"time":     time.Now().Unix(),
	})
}

func (o *Operator) handleTask(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req TaskRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	taskID, ok := new(big.Int).SetString(req.TaskID, 10)
	if !ok {
		http.Error(w, "Invalid task ID", http.StatusBadRequest)
		return
	}

	reportData := common.FromHex(req.ReportData)
	if len(reportData) == 0 {
		http.Error(w, "Invalid report data", http.StatusBadRequest)
		return
	}

	o.logger.Info("Received task",
		zap.String("task_id", taskID.String()),
		zap.Int("report_size", len(reportData)))

	// Process task
	signature, err := o.processTask(taskID, reportData)
	if err != nil {
		o.logger.Error("Failed to process task", zap.Error(err))
		resp := TaskResponse{
			TaskID:    req.TaskID,
			Operator:  o.address.Hex(),
			Timestamp: time.Now().Unix(),
			Success:   false,
			Error:     err.Error(),
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
		return
	}

	o.mu.Lock()
	now := time.Now()
	o.activeTasks[taskID.String()] = &TaskInfo{
		TaskID:      taskID,
		ReportData:  reportData,
		ReceivedAt:  now,
		ProcessedAt: &now,
		Signature:   signature,
	}
	o.mu.Unlock()

	resp := TaskResponse{
		TaskID:       req.TaskID,
		Operator:     o.address.Hex(),
		Signature:    common.Bytes2Hex(signature),
		BLSSignature: o.blsKey.PublicKey.String(),
		Timestamp:    time.Now().Unix(),
		Success:      true,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func (o *Operator) processTask(taskID *big.Int, reportData []byte) ([]byte, error) {
	o.logger.Debug("Processing task",
		zap.String("task_id", taskID.String()),
		zap.Int("data_len", len(reportData)))

	var report map[string]interface{}
	if err := json.Unmarshal(reportData, &report); err != nil {
		return nil, fmt.Errorf("invalid report format: %w", err)
	}

	requiredFields := []string{"task_id", "contract_address", "security_score", "findings"}
	for _, field := range requiredFields {
		if _, ok := report[field]; !ok {
			return nil, fmt.Errorf("missing required field: %s", field)
		}
	}

	messageHash := crypto.Keccak256Hash(
		taskID.Bytes(),
		reportData,
		o.address.Bytes(),
	)

	signature, err := crypto.Sign(messageHash.Bytes(), o.privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to sign: %w", err)
	}

	o.logger.Info("Task processed and signed",
		zap.String("task_id", taskID.String()),
		zap.String("signature", common.Bytes2Hex(signature)))

	return signature, nil
}

func (o *Operator) handleStatus(w http.ResponseWriter, r *http.Request) {
	o.mu.RLock()
	taskCount := len(o.activeTasks)
	tasks := make([]map[string]interface{}, 0, taskCount)

	for id, info := range o.activeTasks {
		taskInfo := map[string]interface{}{
			"task_id":       id,
			"received_at":   info.ReceivedAt.Unix(),
			"has_signature": len(info.Signature) > 0,
		}
		if info.ProcessedAt != nil {
			taskInfo["processed_at"] = info.ProcessedAt.Unix()
		}
		tasks = append(tasks, taskInfo)
	}
	o.mu.RUnlock()

	status := map[string]interface{}{
		"operator":     o.address.Hex(),
		"active_tasks": taskCount,
		"tasks":        tasks,
		"uptime":       time.Now().Unix(),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(status)
}
