package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
)

const (
	// HTTP endpoints
	EndpointSubmitTask   = "/task"
	EndpointHealthCheck  = "/health"
	EndpointTaskResponse = "/status"
)

type TaskRequest struct {
	TaskID     string `json:"task_id"`
	ReportData string `json:"report_data"` // Base64 or hex encoded
}

type TaskResponseMessage struct {
	TaskID       string    `json:"task_id"`
	OperatorID   string    `json:"operator_id"`
	ReportHash   string    `json:"report_hash"`
	Signature    []byte    `json:"signature"`
	BLSSignature []byte    `json:"bls_signature,omitempty"`
	Timestamp    time.Time `json:"timestamp"`
	Success      bool      `json:"success"`
	Error        string    `json:"error,omitempty"`
}

type HTTPClientImpl struct {
	client  *http.Client
	logger  *zap.Logger
	baseURL map[common.Address]string
}

func NewHTTPClient(logger *zap.Logger) *HTTPClient {
	transport := &http.Transport{
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 10,
		IdleConnTimeout:     90 * time.Second,
		TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
		},
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   30 * time.Second,
	}

	impl := &HTTPClientImpl{
		client:  client,
		logger:  logger,
		baseURL: make(map[common.Address]string),
	}

	return &HTTPClient{
		logger: logger,
		impl:   impl,
	}
}

func (hc *HTTPClientImpl) RegisterOperator(operator common.Address, url string) {
	originalURL := url
	// Convert operator hostname to localhost for local testing
	if strings.Contains(url, "operator") && strings.Contains(url, ".fuzz-aldrin.sepolia:") {
		// Extract port number
		parts := strings.Split(url, ":")
		if len(parts) >= 3 {
			port := parts[len(parts)-1]
			url = fmt.Sprintf("http://localhost:%s", port)
		}
	}
	hc.baseURL[operator] = url
	hc.logger.Debug("Registered operator",
		zap.String("operator", operator.Hex()),
		zap.String("original_url", originalURL),
		zap.String("converted_url", url))
}

func (hc *HTTPClientImpl) SendTask(ctx context.Context, operator common.Address, taskID *big.Int, data []byte) error {
	url, exists := hc.baseURL[operator]
	if !exists {
		return fmt.Errorf("operator %s not registered", operator.Hex())
	}

	taskReq := TaskRequest{
		TaskID:     taskID.String(),
		ReportData: common.Bytes2Hex(data),
	}

	jsonData, err := json.Marshal(taskReq)
	if err != nil {
		return fmt.Errorf("marshal task request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", url+EndpointSubmitTask, bytes.NewReader(jsonData))
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Task-ID", taskID.String())

	resp, err := hc.client.Do(req)
	if err != nil {
		return fmt.Errorf("send request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusAccepted {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("operator returned status %d: %s", resp.StatusCode, string(body))
	}

	hc.logger.Debug("Task sent successfully",
		zap.String("operator", operator.Hex()),
		zap.String("task_id", taskID.String()),
		zap.Int("status", resp.StatusCode))

	return nil
}

func (hc *HTTPClientImpl) Ping(ctx context.Context, operator common.Address) error {
	url, exists := hc.baseURL[operator]
	if !exists {
		return fmt.Errorf("operator %s not registered", operator.Hex())
	}

	req, err := http.NewRequestWithContext(ctx, "GET", url+EndpointHealthCheck, nil)
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}

	resp, err := hc.client.Do(req)
	if err != nil {
		return fmt.Errorf("send request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("health check failed: status %d", resp.StatusCode)
	}

	return nil
}

type HTTPClient struct {
	logger *zap.Logger
	impl   *HTTPClientImpl
}

type GRPCClientImpl struct {
	logger      *zap.Logger
	connections map[common.Address]*grpc.ClientConn
}

func NewGRPCClient(logger *zap.Logger) *GRPCClient {
	impl := &GRPCClientImpl{
		logger:      logger,
		connections: make(map[common.Address]*grpc.ClientConn),
	}

	return &GRPCClient{
		logger: logger,
		impl:   impl,
	}
}

type GRPCClient struct {
	logger *zap.Logger
	impl   *GRPCClientImpl
}

func (gc *GRPCClientImpl) Connect(operator common.Address, address string, useTLS bool) error {
	var opts []grpc.DialOption

	if useTLS {
		config := &tls.Config{
			MinVersion: tls.VersionTLS12,
		}
		creds := credentials.NewTLS(config)
		opts = append(opts, grpc.WithTransportCredentials(creds))
	} else {
		opts = append(opts, grpc.WithTransportCredentials(insecure.NewCredentials()))
	}

	opts = append(opts,
		grpc.WithBlock(),
	)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	conn, err := grpc.DialContext(ctx, address, opts...)
	if err != nil {
		return fmt.Errorf("dial operator %s: %w", operator.Hex(), err)
	}

	if oldConn, exists := gc.connections[operator]; exists {
		oldConn.Close()
	}
	gc.connections[operator] = conn

	gc.logger.Info("Connected to operator via gRPC",
		zap.String("operator", operator.Hex()),
		zap.String("address", address))

	return nil
}

func (gc *GRPCClientImpl) SendTask(ctx context.Context, operator common.Address, taskID *big.Int, data []byte) error {
	conn, exists := gc.connections[operator]
	if !exists {
		return fmt.Errorf("no connection to operator %s", operator.Hex())
	}

	// Here you would use the generated gRPC client
	// For now, we'll show the interface
	_ = conn

	gc.logger.Debug("Sending task via gRPC",
		zap.String("operator", operator.Hex()),
		zap.String("task_id", taskID.String()))

	return nil
}

func (gc *GRPCClientImpl) Close() {
	for operator, conn := range gc.connections {
		if err := conn.Close(); err != nil {
			gc.logger.Error("Failed to close gRPC connection",
				zap.String("operator", operator.Hex()),
				zap.Error(err))
		}
	}
}

type P2PNetworkImpl struct {
	logger *zap.Logger
	peers  map[common.Address]string // Operator address to network address
}

func NewP2PNetwork(logger *zap.Logger) *P2PNetwork {
	impl := &P2PNetworkImpl{
		logger: logger,
		peers:  make(map[common.Address]string),
	}

	return &P2PNetwork{
		logger: logger,
		impl:   impl,
	}
}

// Add implementation field to P2PNetwork
type P2PNetwork struct {
	logger *zap.Logger
	impl   *P2PNetworkImpl
}

// RegisterPeer associates an operator address with a network address
func (p2p *P2PNetworkImpl) RegisterPeer(operator common.Address, networkAddr string) {
	p2p.peers[operator] = networkAddr
}

// SendTask sends a task to an operator via P2P
func (p2p *P2PNetworkImpl) SendTask(ctx context.Context, operator common.Address, taskID *big.Int, data []byte) error {
	networkAddr, exists := p2p.peers[operator]
	if !exists {
		return fmt.Errorf("network address not found for operator %s", operator.Hex())
	}

	// In production, this would use a P2P protocol
	// For now, we'll use HTTP as transport
	p2p.logger.Debug("Sending task via P2P",
		zap.String("operator", operator.Hex()),
		zap.String("network_addr", networkAddr),
		zap.String("task_id", taskID.String()))

	return nil
}

// OperatorClientConfig holds configuration for the operator client
type OperatorClientConfig struct {
	PreferredProtocol string // "http", "grpc", or "p2p"
	HTTPTimeout       time.Duration
	GRPCTimeout       time.Duration
}

// SendTask routes task to the appropriate protocol
func (oc *OperatorClient) SendTask(ctx context.Context, operator common.Address, taskID *big.Int, data []byte) error {
	// Try protocols in order of preference
	// In production, this would be determined by operator registration data

	// Try HTTP first
	if oc.httpClient != nil && oc.httpClient.impl != nil {
		if err := oc.httpClient.impl.SendTask(ctx, operator, taskID, data); err == nil {
			return nil
		}
	}

	// Try gRPC
	if oc.grpcClient != nil && oc.grpcClient.impl != nil {
		if err := oc.grpcClient.impl.SendTask(ctx, operator, taskID, data); err == nil {
			return nil
		}
	}

	// Try P2P
	if oc.p2pNetwork != nil && oc.p2pNetwork.impl != nil {
		if err := oc.p2pNetwork.impl.SendTask(ctx, operator, taskID, data); err == nil {
			return nil
		}
	}

	return fmt.Errorf("failed to send task via any protocol")
}

// Ping checks operator health using available protocols
func (oc *OperatorClient) Ping(ctx context.Context, operator common.Address) error {
	// Try HTTP health check
	if oc.httpClient != nil && oc.httpClient.impl != nil {
		return oc.httpClient.impl.Ping(ctx, operator)
	}

	// Could implement gRPC and P2P health checks as well
	return fmt.Errorf("operator %s not reachable", operator.Hex())
}
