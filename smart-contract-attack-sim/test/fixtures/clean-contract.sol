// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * @title CleanContract
 * @notice Secure contract following best practices
 * @dev Should detect: 0 vulnerabilities (no false positives)
 */
contract CleanContract {
    address public owner;
    mapping(address => uint256) public balances;
    bool private locked;

    modifier onlyOwner() {
        require(msg.sender == owner, "Not owner");
        _;
    }

    modifier nonReentrant() {
        require(!locked, "Reentrant call");
        locked = true;
        _;
        locked = false;
    }

    constructor() {
        owner = msg.sender;
    }

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    // SAFE: State update before external call (CEI pattern)
    function withdraw() external nonReentrant {
        uint256 balance = balances[msg.sender];
        require(balance > 0, "No balance");

        // State update BEFORE external call - SAFE
        balances[msg.sender] = 0;

        (bool success, ) = msg.sender.call{value: balance}("");
        require(success, "Transfer failed");
    }

    // SAFE: Has access control
    function adminWithdraw() external onlyOwner {
        payable(owner).transfer(address(this).balance);
    }

    // SAFE: View function
    function getBalance() external view returns (uint256) {
        return address(this).balance;
    }

    // SAFE: Pure function
    function calculate(uint256 a, uint256 b) external pure returns (uint256) {
        return a + b; // Safe in 0.8.0+ (built-in overflow check)
    }
}
