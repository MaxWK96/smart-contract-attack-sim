// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * @title MultipleVulnerabilities
 * @notice Contract with multiple vulnerability types
 * @dev Should detect: CRITICAL reentrancy, HIGH access control
 */
contract MultipleVulnerabilities {
    address public owner;
    bool public paused;
    mapping(address => uint256) public balances;

    constructor() {
        owner = msg.sender;
    }

    function deposit() external payable {
        require(!paused, "Paused");
        balances[msg.sender] += msg.value;
    }

    // VULNERABILITY 1: Reentrancy (CRITICAL)
    function withdraw() external {
        uint256 bal = balances[msg.sender];
        require(bal > 0, "No funds");

        (bool success, ) = msg.sender.call{value: bal}("");
        require(success, "Failed");

        balances[msg.sender] = 0;
    }

    // VULNERABILITY 2: Missing access control (HIGH)
    function pause() external {
        paused = true;
    }

    // VULNERABILITY 3: Missing access control (HIGH)
    function unpause() external {
        paused = false;
    }

    // VULNERABILITY 4: Missing access control (HIGH)
    function mint(address to, uint256 amount) external {
        balances[to] += amount;
    }

    function getBalance() external view returns (uint256) {
        return address(this).balance;
    }
}
