// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

contract VulnerableContract {
    address public owner;
    mapping(address => uint256) public balances;
    uint256 public totalSupply;
    
    // Hardcoded address - should trigger warning
    address private constant HARDCODED_ADDR = 0x1234567890123456789012345678901234567890;
    
    modifier onlyOwner() {
        require(msg.sender == owner, "Not owner");
        _;
    }
    
    constructor() {
        owner = msg.sender;
        totalSupply = 1000000 * 10**18;
    }
    
    // Missing access control - should trigger warning
    function mintTokens(address to, uint256 amount) public {
        balances[to] += amount; // Potential overflow - should trigger warning
        totalSupply += amount;  // Potential overflow - should trigger warning
    }
    
    // Reentrancy vulnerability - should trigger warning
    function withdraw(uint256 amount) public {
        require(balances[msg.sender] >= amount, "Insufficient balance");
        
        // External call before state change - VULNERABLE
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");
        
        // State change after external call - VULNERABLE
        balances[msg.sender] -= amount;
    }
    
    // Unchecked return value - should trigger warning
    function unsafeTransfer(address to, uint256 amount) public {
        balances[msg.sender] -= amount;
        balances[to] += amount;
        
        // Not checking return value - VULNERABLE
        payable(to).send(amount);
    }
    
    // Weak randomness - should trigger warning
    function generateRandomNumber() public view returns (uint256) {
        return uint256(keccak256(abi.encodePacked(block.timestamp, block.difficulty))) % 100;
    }
    
    // Timestamp dependency for critical logic - should trigger warning
    function timeSensitiveFunction() public view returns (bool) {
        return block.timestamp % 2 == 0; // Using timestamp for logic
    }
    
    // Gas inefficient loop - should trigger optimization warning
    function inefficientLoop(address[] memory addresses) public view returns (uint256) {
        uint256 total = 0;
        for (uint256 i = 0; i < addresses.length; i++) { // addresses.length accessed each iteration
            total += balances[addresses[i]];
        }
        return total;
    }
    
    // Delegate call vulnerability - should trigger warning
    function dangerousDelegateCall(address target, bytes memory data) public returns (bool) {
        (bool success, ) = target.delegatecall(data);
        return success;
    }
    
    // Division before multiplication - should trigger precision loss warning
    function calculateFee(uint256 amount) public pure returns (uint256) {
        return (amount / 100) * 3; // Division before multiplication
    }
    
    // Magic number usage - should trigger warning
    function processLargeNumber() public pure returns (uint256) {
        return 1000000000000000000; // Magic number
    }
    
    // Function that could be external instead of public - gas optimization
    function getBalance(address account) public view returns (uint256) {
        return balances[account];
    }
    
    // Fallback function for receiving ether
    receive() external payable {
        balances[msg.sender] += msg.value;
    }
} 