// SPDX-License-Identifier: MIT
pragma solidity ^0.8.27;

/**
 * @title VulnerableExample
 * @notice This contract contains intentional vulnerabilities for testing audit tools
 * @dev DO NOT USE IN PRODUCTION - FOR TESTING ONLY
 */
contract VulnerableExample {
    mapping(address => uint256) public balances;
    address public owner;
    uint256 private seed;
    
    constructor() {
        owner = msg.sender;
        seed = block.timestamp; // Weak randomness
    }
    
    // Reentrancy vulnerability
    function withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount, "Insufficient balance");
        
        // External call before state update (reentrancy)
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");
        
        balances[msg.sender] -= amount;
    }
    
    // Integer overflow/underflow (pre-0.8.0 style)
    function transfer(address to, uint256 amount) external {
        require(balances[msg.sender] >= amount, "Insufficient balance");
        
        // Unchecked arithmetic
        unchecked {
            balances[msg.sender] = balances[msg.sender] - amount;
            balances[to] = balances[to] + amount; // Could overflow
        }
    }
    
    // Access control vulnerability
    function setOwner(address newOwner) external {
        // Missing access control
        owner = newOwner;
    }
    
    // Timestamp dependence
    function randomNumber() external returns (uint256) {
        seed = uint256(keccak256(abi.encodePacked(block.timestamp, seed)));
        return seed % 100;
    }
    
    // Uninitialized storage pointer
    struct User {
        address addr;
        uint256 amount;
    }
    
    mapping(uint256 => User) users;
    
    function addUser(uint256 id, address addr, uint256 amount) external {
        User memory user; // Changed to memory
        user.addr = addr;
        user.amount = amount;
        users[id] = user;
    }
    
    // Front-running vulnerability
    function buyToken(uint256 price) external payable {
        require(msg.value == price, "Incorrect payment");
        // Price can be front-run
        balances[msg.sender] += 1000;
    }
    
    // Denial of Service
    address[] public investors;
    
    function distributeRewards() external {
        // Unbounded loop
        for (uint i = 0; i < investors.length; i++) {
            // Gas could run out
            (bool success, ) = investors[i].call{value: 1 ether}("");
            require(success, "Transfer failed");
        }
    }
    
    // Delegate call to untrusted contract
    function delegateExecute(address target, bytes memory data) external {
        (bool success, ) = target.delegatecall(data);
        require(success, "Delegate call failed");
    }
    
    receive() external payable {
        balances[msg.sender] += msg.value;
    }
} 