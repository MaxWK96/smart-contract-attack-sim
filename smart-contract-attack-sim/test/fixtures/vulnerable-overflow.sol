// SPDX-License-Identifier: MIT
pragma solidity ^0.7.0;

/**
 * @title VulnerableOverflow
 * @notice Contract with integer overflow vulnerability (pre-0.8.0)
 * @dev Should detect: HIGH integer overflow/underflow
 */
contract VulnerableOverflow {
    mapping(address => uint256) public balances;
    uint256 public totalSupply;

    function deposit() external payable {
        // Potential overflow in Solidity < 0.8.0
        balances[msg.sender] += msg.value;
        totalSupply += msg.value;
    }

    function transfer(address to, uint256 amount) external {
        require(balances[msg.sender] >= amount, "Insufficient balance");

        // Potential underflow
        balances[msg.sender] -= amount;
        // Potential overflow
        balances[to] += amount;
    }

    function multiply(uint256 a, uint256 b) external pure returns (uint256) {
        // Potential overflow
        return a * b;
    }
}
