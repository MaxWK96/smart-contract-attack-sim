// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * @title VulnerableAccessControl
 * @notice Contract with missing access control
 * @dev Should detect: HIGH missing access control on pause/unpause/mint
 */
contract VulnerableAccessControl {
    address public owner;
    bool public paused;
    mapping(address => uint256) public balances;
    uint256 public totalSupply;

    constructor() {
        owner = msg.sender;
    }

    // Safe: has access control
    function safeWithdraw() external {
        require(msg.sender == owner, "Not owner");
        payable(owner).transfer(address(this).balance);
    }

    // VULNERABLE: No access control on pause
    function pause() external {
        paused = true;
    }

    // VULNERABLE: No access control on unpause
    function unpause() external {
        paused = false;
    }

    // VULNERABLE: No access control on mint
    function mint(address to, uint256 amount) external {
        balances[to] += amount;
        totalSupply += amount;
    }

    // Safe: users withdraw their own funds
    function withdraw() external {
        uint256 bal = balances[msg.sender];
        require(bal > 0, "No balance");
        balances[msg.sender] = 0;
        (bool success, ) = msg.sender.call{value: bal}("");
        require(success, "Failed");
    }

    receive() external payable {
        balances[msg.sender] += msg.value;
    }
}
