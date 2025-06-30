#!/bin/bash

set -e

echo "Deploying SimpleContractAudit to Sepolia"

# Configuration
RPC_URL="https://ethereum-sepolia-rpc.publicnode.com"
CHAIN_ID=11155111

# Check if private key is provided
if [ -z "$PRIVATE_KEY" ]; then
    echo "Error: PRIVATE_KEY environment variable not set"
    echo "Usage: PRIVATE_KEY=0x... ./deploy_audit_contract.sh"
    exit 1
fi

# Get deployer address
DEPLOYER_ADDRESS=$(cast wallet address $PRIVATE_KEY)
echo "Deployer address: $DEPLOYER_ADDRESS"

# Check balance
BALANCE=$(cast balance --rpc-url $RPC_URL $DEPLOYER_ADDRESS)
BALANCE_ETH=$(echo "scale=6; $BALANCE / 1000000000000000000" | bc)
echo "Deployer balance: $BALANCE_ETH ETH"

# The aggregator will be the same as the deployer
AGGREGATOR_ADDRESS=$DEPLOYER_ADDRESS

# Build the contract
echo "Building contract..."
forge build --contracts contracts/src/SimpleContractAuditDemo.sol

# Deploy the contract
echo "Deploying SimpleContractAuditDemo..."
BYTECODE=$(cat out/SimpleContractAuditDemo.sol/SimpleContractAuditDemo.json | jq -r '.bytecode.object')
CONSTRUCTOR_ARGS=$(cast abi-encode "constructor(address)" $AGGREGATOR_ADDRESS)

DEPLOY_OUTPUT=$(cast send --rpc-url $RPC_URL \
    --private-key $PRIVATE_KEY \
    --create "${BYTECODE}${CONSTRUCTOR_ARGS:2}" \
    --json)

CONTRACT_ADDRESS=$(echo "$DEPLOY_OUTPUT" | jq -r '.contractAddress')
TX_HASH=$(echo "$DEPLOY_OUTPUT" | jq -r '.transactionHash')

echo "Contract deployed successfully"
echo "Contract address: $CONTRACT_ADDRESS"
echo "Transaction: https://sepolia.etherscan.io/tx/$TX_HASH"

# Save deployment info
echo "{
  \"network\": \"sepolia\",
  \"chainId\": $CHAIN_ID,
  \"contractAddress\": \"$CONTRACT_ADDRESS\",
  \"aggregator\": \"$AGGREGATOR_ADDRESS\",
  \"deploymentTx\": \"$TX_HASH\",
  \"deployedAt\": \"$(date -u +%Y-%m-%dT%H:%M:%SZ)\",
  \"minAuditFee\": \"0.001 ETH\"
}" > deployment-info.json

echo ""
echo "Deployment info saved to deployment-info.json" 