#!/bin/bash

set -e

echo "Starting Fuzz-Aldrin Aggregator"

# Check if private key is provided
if [ -z "$PRIVATE_KEY" ]; then
    echo "Error: PRIVATE_KEY environment variable not set"
    echo "Usage: PRIVATE_KEY=0x... ./run_aggregator.sh [contract_address]"
    exit 1
fi

# Get contract address from argument or deployment info
if [ -n "$1" ]; then
    CONTRACT_ADDRESS=$1
elif [ -f "deployment-info.json" ]; then
    CONTRACT_ADDRESS=$(jq -r '.contractAddress' deployment-info.json)
else
    echo "Error: No contract address provided and deployment-info.json not found"
    echo "Usage: ./run_aggregator.sh <contract_address>"
    exit 1
fi

# Configuration
RPC_URL="https://ethereum-sepolia-rpc.publicnode.com"
CHAIN_ID=11155111

# Get aggregator address
AGGREGATOR_ADDRESS=$(cast wallet address $PRIVATE_KEY)
echo "Aggregator address: $AGGREGATOR_ADDRESS"
echo "Audit contract: $CONTRACT_ADDRESS"

# Check balance
BALANCE=$(cast balance --rpc-url $RPC_URL $AGGREGATOR_ADDRESS)
BALANCE_ETH=$(echo "scale=6; $BALANCE / 1000000000000000000" | bc)
echo "Aggregator balance: $BALANCE_ETH ETH"

if (( $(echo "$BALANCE_ETH < 0.01" | bc -l) )); then
    echo "Warning: Low balance. Make sure you have enough ETH for gas fees."
fi

# Build the aggregator if needed
if [ ! -f "bin/aggregator" ]; then
    echo "Building aggregator..."
    cd cmd/aggregator && go build -buildvcs=false -o ../../bin/aggregator . && cd ../..
fi

# Run the aggregator
echo ""
echo "Starting aggregator..."
echo "Press Ctrl+C to stop"
echo ""

./bin/aggregator \
    --private-key=$PRIVATE_KEY \
    --rpc-url=$RPC_URL \
    --chain-id=$CHAIN_ID \
    --simple=$CONTRACT_ADDRESS \
    --log-level=info 