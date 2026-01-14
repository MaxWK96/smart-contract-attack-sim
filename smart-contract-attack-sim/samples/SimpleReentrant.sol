// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * @title SimpleReentrant
 * @notice Minimal reentrancy example for testing
 * @dev DO NOT USE IN PRODUCTION
 */
contract SimpleReentrant {
    mapping(address => uint256) public balances;

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    function withdraw() external {
        uint256 bal = balances[msg.sender];
        require(bal > 0, "No funds");

        // VULNERABLE: Call before state update
        (bool sent, ) = msg.sender.call{value: bal}("");
        require(sent, "Failed to send");

        balances[msg.sender] = 0;
    }

    function getBalance() external view returns (uint256) {
        return address(this).balance;
    }
}
