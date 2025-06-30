#!/bin/bash

set -e

echo "Submitting Audit Request"

# Check if private key is provided
if [ -z "$PRIVATE_KEY" ]; then
    echo "Error: PRIVATE_KEY environment variable not set"
    echo "Usage: PRIVATE_KEY=0x... ./submit_audit_request.sh <contract_to_audit> [audit_contract_address]"
    exit 1
fi

# Check if contract to audit is provided
if [ -z "$1" ]; then
    echo "Error: No contract address to audit provided"
    echo "Usage: ./submit_audit_request.sh <contract_to_audit> [audit_contract_address]"
    echo "Example: ./submit_audit_request.sh 0xfFf9976782d46CC05630D1f6eBAb18b2324d6B14"
    exit 1
fi

CONTRACT_TO_AUDIT=$1

# Get audit contract address from argument or deployment info
if [ -n "$2" ]; then
    AUDIT_CONTRACT=$2
elif [ -f "deployment-info.json" ]; then
    AUDIT_CONTRACT=$(jq -r '.contractAddress' deployment-info.json)
else
    echo "Error: No audit contract address provided and deployment-info.json not found"
    exit 1
fi

# Configuration
RPC_URL="https://ethereum-sepolia-rpc.publicnode.com"
NETWORK="sepolia"
AUDIT_FEE="0.001ether"

# Get user address
USER_ADDRESS=$(cast wallet address $PRIVATE_KEY)
echo "User address: $USER_ADDRESS"
echo "Audit contract: $AUDIT_CONTRACT"
echo "Contract to audit: $CONTRACT_TO_AUDIT"
echo "Network: $NETWORK"
echo "Audit fee: $AUDIT_FEE"

# Check balance
BALANCE=$(cast balance --rpc-url $RPC_URL $USER_ADDRESS)
BALANCE_ETH=$(echo "scale=6; $BALANCE / 1000000000000000000" | bc)
echo "User balance: $BALANCE_ETH ETH"

# Submit audit request
echo ""
echo "Submitting audit request..."

TX_OUTPUT=$(cast send --rpc-url $RPC_URL \
    --private-key $PRIVATE_KEY \
    --value $AUDIT_FEE \
    $AUDIT_CONTRACT \
    "requestAudit(address,string)" \
    $CONTRACT_TO_AUDIT \
    "$NETWORK" \
    --json 2>&1 || echo "{}")

if echo "$TX_OUTPUT" | grep -q "transactionHash"; then
    TX_HASH=$(echo "$TX_OUTPUT" | jq -r '.transactionHash')
    echo "Audit request submitted"
    echo "Transaction hash: $TX_HASH"
    
    # Wait for confirmation
    echo ""
    echo "Waiting for confirmation..."
    sleep 5
    
    # Get receipt
    RECEIPT=$(cast receipt --rpc-url $RPC_URL $TX_HASH --json 2>/dev/null || echo "{}")
    STATUS=$(echo "$RECEIPT" | jq -r '.status // "pending"')
    
    if [ "$STATUS" == "0x1" ]; then
        echo "Transaction confirmed"
        
        # Extract request ID from logs
        if echo "$RECEIPT" | jq -e '.logs[0]' > /dev/null 2>&1; then
            REQUEST_ID=$(echo "$RECEIPT" | jq -r '.logs[0].topics[1]')
            echo "Request ID: $REQUEST_ID"
            
            # Save request info
            echo "{
              \"requestId\": \"$REQUEST_ID\",
              \"contractToAudit\": \"$CONTRACT_TO_AUDIT\",
              \"network\": \"$NETWORK\",
              \"txHash\": \"$TX_HASH\",
              \"timestamp\": \"$(date -u +%Y-%m-%dT%H:%M:%SZ)\"
            }" > last-audit-request.json
            
            echo ""
            echo "Request info saved to last-audit-request.json"
        fi
    else
        echo "Transaction failed or pending"
    fi
    
    echo ""
    echo "View on Etherscan:"
    echo "https://sepolia.etherscan.io/tx/$TX_HASH"
else
    echo "Failed to submit audit request"
    echo "$TX_OUTPUT"
fi

echo ""
echo "Next steps:"
echo "1. The aggregator will automatically detect and process this audit request"
echo "2. Check aggregator logs to see the audit progress"
echo "3. Results will be submitted back to the contract automatically" 