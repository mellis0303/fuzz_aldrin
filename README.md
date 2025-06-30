# Fuzz-Aldrin

## Overview

Fuzz-Aldrin is a decentralized smart contract auditing service that:
- Analyzes contract bytecode for common vulnerabilities
- Provides security scores and detailed findings
- Operates as a fully decentralized AVS with operator consensus
- Submits audit results directly on-chain

The system performs real security analysis including:
- Reentrancy vulnerability detection
- Access control issues
- Integer overflow/underflow risks
- Gas optimization opportunities
- Delegatecall security
- Timestamp dependency issues
- Unchecked return values
- Storage collision risks

## Prerequisites

- Go 1.23 or higher
- Foundry
- An Ethereum RPC endpoint

## Installation

1. Clone the repository:
```bash
git clone https://github.com/your-org/fuzz-aldrin.git
cd fuzz-aldrin
```

2. Install dependencies:
```bash
go mod download
```

3. Build the binaries:
```bash
make build
```

This will create the following binaries in the `bin/` directory:
- `aggregator` - The main AVS aggregator service
- `operator` - The operator node software
- `cli` - Command-line interface for interacting with the AVS

## Quick Start

### 1. Deploy the Simple Audit Contract

```bash
export PRIVATE_KEY="your-private-key-here"
./deploy_audit_contract.sh
```

This deploys the SimpleContractAudit contract and saves the deployment info to `deployment-info.json`.

### 2. Start the Aggregator

```bash
export PRIVATE_KEY="your-private-key-here"
./run_aggregator.sh
```

The aggregator will start monitoring for audit requests.

### 3. Submit an Audit Request

In a new terminal:
```bash
export PRIVATE_KEY="your-private-key-here"
./submit_audit_request.sh 0xContractToAudit
```

Replace `0xContractToAudit` with the address of the contract you want to audit. The audit fee is 0.001 ETH.

### 4. View Results

The aggregator will automatically:
1. Detect the audit request
2. Fetch and analyze the contract bytecode
3. Generate a security report
4. Submit the results on-chain

Check the aggregator logs to see the audit progress and results. The transaction hash for the submitted results will be displayed.

## Full AVS Deployment

### 1. Deploy AVS Contracts

Deploy the full AVS infrastructure including TaskMailbox, OperatorRegistry, and audit contracts:

```bash
forge script script/Deploy.s.sol:DeployScript --rpc-url $RPC_URL --private-key $PRIVATE_KEY --broadcast
```

### 2. Configure Operator Set

The operator set must be configured in the TaskMailbox before it can accept tasks. This requires setting:
- Curve type for BLS signatures
- Task hook address
- Task SLA parameters
- Stake proportion threshold
- Fee token

### 3. Register Operators

Each operator must register with the AVS:

```bash
./bin/cli operator register \
    --private-key=$OPERATOR_PRIVATE_KEY \
    --rpc-url=$RPC_URL \
    --registry=$REGISTRY_ADDRESS
```

### 4. Start Operators

Run each operator node:

```bash
./bin/operator \
    --private-key=$OPERATOR_PRIVATE_KEY \
    --rpc-url=$RPC_URL \
    --port=9001 \
    --registry=$REGISTRY_ADDRESS \
    --log-level=info
```

### 5. Start Aggregator

Run the aggregator:

```bash
./bin/aggregator \
    --private-key=$AGGREGATOR_PRIVATE_KEY \
    --rpc-url=$RPC_URL \
    --chain-id=$CHAIN_ID \
    --task-mailbox=$TASK_MAILBOX_ADDRESS \
    --audit-contract=$AUDIT_CONTRACT_ADDRESS \
    --log-level=info
```

## Configuration

### Environment Variables

- `PRIVATE_KEY` - Private key for the account
- `RPC_URL` - Ethereum RPC endpoint URL
- `CHAIN_ID` - Chain ID

### Aggregator Flags

- `--simple` - Run in simple mode with a specific contract address
- `--task-mailbox` - TaskMailbox contract address
- `--audit-contract` - Audit contract address
- `--port` - HTTP server port (default: 8080)
- `--metrics-port` - Metrics server port (default: 9090)
- `--log-level` - Logging level

### Operator Flags

- `--port` - HTTP server port for operator API
- `--registry` - Operator registry contract address
- `--log-level` - Logging level

## Architecture

Fuzz-Aldrin consists of several key components:

1. **Smart Contracts**
   - `ContractAudit.sol` - Main audit contract integrated with TaskMailbox
   - `SimpleContractAudit.sol` - Simplified version for direct audit requests
   - AVS infrastructure contracts from Hourglass

2. **Aggregator**
   - Monitors blockchain for audit requests
   - Distributes tasks to operators
   - Collects and aggregates operator signatures
   - Submits final audit results on-chain

3. **Operators**
   - Perform actual contract analysis
   - Sign audit results with BLS signatures
   - Maintain minimum stake for participation

4. **Auditor Engine**
   - Analyzes contract bytecode
   - Detects vulnerability patterns
   - Generates security scores and detailed reports

## Security Considerations

1. **Private Key Management**
   - Never commit private keys to version control
   - Use environment variables or secure key management systems
   - Consider using hardware wallets for production deployments

2. **Operator Security**
   - Operators should run on secure, isolated infrastructure
   - Regular security updates and monitoring
   - Proper firewall configuration for operator APIs

3. **Contract Security**
   - All contracts are audited and tested
   - Use official deployments when available
   - Verify contract addresses before interaction


## Development

### Running Tests

```bash
go test ./...
```

### Building from Source

```bash
make build
```

### Contract Development

Contracts are in the `contracts/` directory. To compile:

```bash
cd contracts
forge build
```