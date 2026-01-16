// SPDX-License-Identifier: MIT
// SOURCE: Based on Rubixi (Etherscan 0xe82719202e5965Cf5D9B6673B7503a3b92DE20be)
// TYPE: Vulnerable
// EXPECTED: Access control detection (CRITICAL)
// DATE_ADDED: 2026-01-17
// NOTES: Famous access control bug - constructor didn't set creator, allowing takeover

pragma solidity ^0.8.0;

/**
 * @title Rubixi
 * @notice Recreation of the infamous Rubixi vulnerability
 * @dev Original bug: Contract was renamed from DynamicPyramid to Rubixi,
 *      but the constructor function name wasn't updated (pre-Solidity 0.4.22)
 *      This left the "constructor" as a public function anyone could call
 *
 * ATTACK VECTOR:
 * 1. Original contract had: function DynamicPyramid() { creator = msg.sender; }
 * 2. Contract was renamed to Rubixi, but function stayed DynamicPyramid()
 * 3. In old Solidity, constructors were named after the contract
 * 4. DynamicPyramid() became a regular public function
 * 5. Anyone could call it and become the creator
 * 6. Creator could collect all fees
 *
 * Modern equivalent: Missing access control on ownership functions
 */
contract Rubixi {
    address public creator;
    uint256 public totalInvested;
    uint256 public totalPayout;

    mapping(address => uint256) public balances;
    address[] public investors;

    event Investment(address indexed investor, uint256 amount);
    event Payout(address indexed investor, uint256 amount);
    event CreatorChanged(address indexed oldCreator, address indexed newCreator);

    // In the original, this would have been the constructor
    // but after renaming, it became a public function
    constructor() {
        // Bug recreation: creator not set in actual constructor
        // In the original, the constructor name didn't match the contract name
    }

    /**
     * @notice VULNERABLE: No access control - anyone can become creator
     * @dev This is the equivalent of the original Rubixi bug
     *      The "constructor" became a public function after rename
     */
    function DynamicPyramid() external {
        // BUG: Anyone can call this and become creator!
        // In modern Solidity this is obviously wrong,
        // but in old Solidity with named constructors, this was a real bug
        creator = msg.sender;
        emit CreatorChanged(address(0), msg.sender);
    }

    /**
     * @notice VULNERABLE: Missing onlyCreator modifier
     * @dev Even if creator was set correctly, this has no protection
     */
    function changeCreator(address newCreator) external {
        // BUG: No access control check!
        creator = newCreator;
        emit CreatorChanged(creator, newCreator);
    }

    // Investment function (pyramid scheme mechanics)
    function invest() external payable {
        require(msg.value >= 0.01 ether, "Minimum investment required");

        balances[msg.sender] += msg.value;
        totalInvested += msg.value;
        investors.push(msg.sender);

        emit Investment(msg.sender, msg.value);
    }

    /**
     * @notice VULNERABLE: No access control on fee collection
     * @dev Anyone can collect creator fees
     */
    function collectFees() external {
        // BUG: Should be require(msg.sender == creator)
        // But this check is missing!
        uint256 fees = address(this).balance / 10; // 10% fee

        payable(msg.sender).transfer(fees);
        totalPayout += fees;

        emit Payout(msg.sender, fees);
    }

    /**
     * @notice VULNERABLE: No access control on emergency drain
     * @dev Devastating - anyone can drain all funds
     */
    function emergencyWithdraw(address to) external {
        // BUG: No access control at all!
        uint256 balance = address(this).balance;
        payable(to).transfer(balance);
    }

    function getBalance() external view returns (uint256) {
        return address(this).balance;
    }

    function getInvestorCount() external view returns (uint256) {
        return investors.length;
    }

    receive() external payable {
        balances[msg.sender] += msg.value;
    }
}
