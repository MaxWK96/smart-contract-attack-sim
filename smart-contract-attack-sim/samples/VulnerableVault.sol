// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * @title VulnerableVault
 * @notice This contract intentionally contains multiple vulnerabilities for testing purposes
 * @dev DO NOT USE IN PRODUCTION - This is for security testing only
 *
 * Vulnerabilities included:
 * 1. Reentrancy in withdraw() function
 * 2. Missing access control on sensitive functions
 * 3. Unchecked call return value
 */
contract VulnerableVault {
    mapping(address => uint256) public balances;
    address public owner;
    bool public paused;

    event Deposit(address indexed user, uint256 amount);
    event Withdrawal(address indexed user, uint256 amount);

    constructor() {
        owner = msg.sender;
    }

    /**
     * @notice Deposit ETH into the vault
     */
    function deposit() external payable {
        require(msg.value > 0, "Must deposit something");
        require(!paused, "Contract is paused");

        balances[msg.sender] += msg.value;
        emit Deposit(msg.sender, msg.value);
    }

    /**
     * @notice Withdraw all deposited ETH
     * @dev VULNERABLE: External call before state update (reentrancy)
     */
    function withdraw() external {
        uint256 balance = balances[msg.sender];
        require(balance > 0, "No balance to withdraw");

        // VULNERABILITY: External call BEFORE state update
        (bool success, ) = msg.sender.call{value: balance}("");
        require(success, "Transfer failed");

        // State update happens AFTER the external call - REENTRANCY!
        balances[msg.sender] = 0;

        emit Withdrawal(msg.sender, balance);
    }

    /**
     * @notice Withdraw a specific amount
     * @dev VULNERABLE: Same reentrancy pattern
     */
    function withdrawAmount(uint256 amount) external {
        require(balances[msg.sender] >= amount, "Insufficient balance");

        // VULNERABILITY: External call BEFORE state update
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");

        // State update happens AFTER the external call
        balances[msg.sender] -= amount;
    }

    /**
     * @notice Transfer funds to another user (missing access control example)
     * @dev VULNERABLE: No access control - anyone can call
     */
    function transferFunds(address to, uint256 amount) external {
        // VULNERABILITY: Missing access control - should have onlyOwner modifier
        require(address(this).balance >= amount, "Insufficient contract balance");
        payable(to).transfer(amount);
    }

    /**
     * @notice Pause the contract
     * @dev VULNERABLE: Missing access control
     */
    function pause() external {
        // VULNERABILITY: Anyone can pause the contract
        paused = true;
    }

    /**
     * @notice Unpause the contract
     * @dev VULNERABLE: Missing access control
     */
    function unpause() external {
        // VULNERABILITY: Anyone can unpause the contract
        paused = false;
    }

    /**
     * @notice Get the contract's total balance
     */
    function getContractBalance() external view returns (uint256) {
        return address(this).balance;
    }

    /**
     * @notice Get a user's balance
     */
    function getBalance(address user) external view returns (uint256) {
        return balances[user];
    }

    // Allow receiving ETH
    receive() external payable {
        balances[msg.sender] += msg.value;
    }
}
