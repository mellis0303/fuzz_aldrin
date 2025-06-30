#!/bin/bash

# Run Fuzz-Aldrin Operator Nodes on Sepolia

set -e

# Check if operators file exists
if [ ! -f "operators-sepolia.json" ]; then
    echo "Error: operators-sepolia.json not found. Run deploy_sepolia.sh first."
    exit 1
fi

# Check if deployment file exists
if [ ! -f "deployment-sepolia.json" ]; then
    echo "Error: deployment-sepolia.json not found. Run deploy_sepolia.sh first."
    exit 1
fi

# Build operator if needed
if [ ! -f "./bin/operator" ]; then
    echo "Building operator..."
    go build -o ./bin/operator ./cmd/operator
fi

# Extract registry address
REGISTRY_ADDRESS=$(cat deployment-sepolia.json | jq -r '.contracts.TaskAVSRegistrar')

echo "Starting Fuzz-Aldrin Operator Nodes on Sepolia"
echo "Registry: $REGISTRY_ADDRESS"

# Read operator keys
OPERATOR_KEYS=($(cat operators-sepolia.json | jq -r '.operators[].privateKey'))

# Start operators
for i in {0..4}; do
    PORT=$((9001 + i))
    PRIVATE_KEY=${OPERATOR_KEYS[$i]}
    
    echo ""
    echo "Starting Operator $((i+1)) on port $PORT"
    
    ./bin/operator \
        --private-key="$PRIVATE_KEY" \
        --rpc-url="https://ethereum-sepolia-rpc.publicnode.com" \
        --port=$PORT \
        --registry="$REGISTRY_ADDRESS" \
        --log-level="info" > operator_$((i+1)).log 2>&1 &
    
    echo "Operator $((i+1)) started (PID: $!)"
    sleep 1
done

echo ""
echo "All operators started"
echo "Logs are being written to operator_1.log through operator_5.log"
echo "To stop all operators: pkill -f 'bin/operator'" 