// SPDX-License-Identifier: MIT
// SOURCE: Based on King of the Ether Throne (historical contract from 2016)
// TYPE: Vulnerable
// EXPECTED: Unchecked call detection (HIGH), Access control (CRITICAL)
// DATE_ADDED: 2026-01-17
// NOTES: Original "King of the Ether" game had unchecked send() return value

pragma solidity ^0.8.0;

/**
 * @title KingOfEther
 * @notice Simplified version of the King of the Ether game
 * @dev Original vulnerability: Unchecked .send() return value
 *
 * ATTACK VECTOR:
 * 1. Attacker becomes king with a contract that reverts on receive
 * 2. Next player tries to become king, sends ETH
 * 3. Contract tries to send ETH to previous king (attacker)
 * 4. Attacker's contract reverts, but send() return value not checked
 * 5. Game is permanently stuck - no one can become new king
 *
 * This demonstrates why you must ALWAYS check return values!
 */
contract KingOfEther {
    address public king;
    uint256 public prize;
    uint256 public claimPrice;

    event NewKing(address indexed oldKing, address indexed newKing, uint256 prize);

    constructor() payable {
        king = msg.sender;
        prize = msg.value;
        claimPrice = 1 ether;
    }

    /**
     * @notice VULNERABLE: Unchecked send() return value
     * @dev If previous king is a contract that reverts, send fails silently
     *      The game becomes permanently stuck
     */
    function claimThrone() external payable {
        require(msg.value >= claimPrice, "Not enough ETH to claim throne");

        address previousKing = king;
        uint256 previousPrize = prize;

        // Update state
        king = msg.sender;
        prize = msg.value;
        claimPrice = msg.value * 3 / 2; // 50% increase

        // VULNERABILITY: Return value not checked!
        // If previousKing is a contract that reverts, this fails silently
        // The ETH meant for previousKing is stuck in this contract
        payable(previousKing).send(previousPrize);

        emit NewKing(previousKing, msg.sender, prize);
    }

    /**
     * @notice VULNERABLE: Also unchecked .call()
     * @dev Alternative version with same vulnerability using .call()
     */
    function claimThroneV2() external payable {
        require(msg.value >= claimPrice, "Not enough ETH");

        address previousKing = king;
        uint256 previousPrize = prize;

        king = msg.sender;
        prize = msg.value;
        claimPrice = msg.value * 3 / 2;

        // VULNERABILITY: Return value ignored!
        previousKing.call{value: previousPrize}("");

        emit NewKing(previousKing, msg.sender, prize);
    }

    function getKing() external view returns (address, uint256) {
        return (king, prize);
    }
}

/**
 * @title KingAttacker
 * @notice Contract that becomes king and then blocks all future kings
 */
contract KingAttacker {
    KingOfEther public target;

    constructor(address _target) {
        target = KingOfEther(_target);
    }

    // Become the king
    function attack() external payable {
        target.claimThrone{value: msg.value}();
    }

    // Revert on receive - blocks anyone from taking the throne
    receive() external payable {
        revert("You shall not pass!");
    }
}
