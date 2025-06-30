#!/bin/bash

echo "Testing Smart Contract Audit AVS"
echo ""
echo "Note: This requires grpcurl to be installed"
echo "Install with: brew install grpcurl (macOS) or download from https://github.com/fullstorydev/grpcurl"
echo ""

if ! command -v grpcurl &> /dev/null; then
    echo "grpcurl is not installed. Please install it first."
    echo "macOS: brew install grpcurl"
    echo "Linux: Download from https://github.com/fullstorydev/grpcurl/releases"
    exit 1
fi

# Test with source code
echo "Testing with Solidity source code..."

# Create the payload
PAYLOAD='{"type":"source","data":"pragma solidity ^0.8.0;\ncontract Test {\n    uint256 public value;\n    \n    function setValue(uint256 _value) public {\n        value = _value;\n    }\n}"}'

# Base64 encode the payload
ENCODED_PAYLOAD=$(echo -n "$PAYLOAD" | base64)

# Send gRPC request
grpcurl -plaintext \
  -d "{\"task_id\": \"dGVzdC0xMjM=\", \"payload\": \"$ENCODED_PAYLOAD\"}" \
  localhost:8080 \
  eigenlayer.hourglass.v1.performer.PerformerService/ExecuteTask

echo ""
echo "To test with a contract address:"
echo 'PAYLOAD='\''{"type":"address","data":"0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48","network":"mainnet","etherscan_key":"YOUR_KEY"}'\'''
echo 'ENCODED_PAYLOAD=$(echo -n "$PAYLOAD" | base64)'
echo 'grpcurl -plaintext -d "{\"task_id\": \"dGVzdC0xMjM=\", \"payload\": \"$ENCODED_PAYLOAD\"}" localhost:8080 eigenlayer.hourglass.v1.performer.PerformerService/ExecuteTask' 