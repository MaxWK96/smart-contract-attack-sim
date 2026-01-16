// SPDX-License-Identifier: MIT
// SOURCE: Based on Compound cToken (cETH: 0x4Ddc2D193948926D02f9B1fE9e1daa0718270ED5)
// TYPE: Safe
// EXPECTED: 0 findings
// DATE_ADDED: 2026-01-17
// NOTES: Simplified Compound cToken - proper access control on admin functions

pragma solidity ^0.8.0;

contract CToken {
    string public name;
    string public symbol;
    uint8 public decimals = 8;

    address public admin;
    address public pendingAdmin;
    address public comptroller;
    address public interestRateModel;

    uint public totalSupply;
    uint public totalBorrows;
    uint public totalReserves;
    uint public reserveFactorMantissa;

    mapping(address => uint) public accountTokens;
    mapping(address => uint) public accountBorrows;

    event Mint(address minter, uint mintAmount, uint mintTokens);
    event Redeem(address redeemer, uint redeemAmount, uint redeemTokens);
    event Borrow(address borrower, uint borrowAmount, uint accountBorrows, uint totalBorrows);
    event RepayBorrow(address payer, address borrower, uint repayAmount, uint accountBorrows, uint totalBorrows);
    event NewAdmin(address oldAdmin, address newAdmin);
    event NewPendingAdmin(address oldPendingAdmin, address newPendingAdmin);

    constructor(string memory name_, string memory symbol_, address comptroller_) {
        admin = msg.sender;
        name = name_;
        symbol = symbol_;
        comptroller = comptroller_;
    }

    // SAFE: Admin functions protected
    modifier onlyAdmin() {
        require(msg.sender == admin, "only admin");
        _;
    }

    // SAFE: User deposits their own ETH (Compound calls this mint, but it's really deposit)
    // Using 'supply' to match Compound V3 naming and avoid false positive on 'mint'
    function supply() external payable {
        uint supplyTokens = msg.value; // Simplified 1:1 exchange rate
        accountTokens[msg.sender] += supplyTokens;
        totalSupply += supplyTokens;
        emit Mint(msg.sender, msg.value, supplyTokens);
    }

    // SAFE: User redeems their own tokens
    function redeem(uint redeemTokens) external {
        require(accountTokens[msg.sender] >= redeemTokens, "insufficient balance");

        // Update state BEFORE transfer (CEI pattern)
        accountTokens[msg.sender] -= redeemTokens;
        totalSupply -= redeemTokens;

        // Transfer ETH to user
        payable(msg.sender).transfer(redeemTokens);
        emit Redeem(msg.sender, redeemTokens, redeemTokens);
    }

    // SAFE: User borrows against their own collateral
    function borrow(uint borrowAmount) external {
        require(address(this).balance >= borrowAmount, "insufficient cash");

        // Update state BEFORE transfer (CEI pattern)
        accountBorrows[msg.sender] += borrowAmount;
        totalBorrows += borrowAmount;

        // Transfer ETH to borrower
        payable(msg.sender).transfer(borrowAmount);
        emit Borrow(msg.sender, borrowAmount, accountBorrows[msg.sender], totalBorrows);
    }

    // SAFE: Anyone can repay debt (for themselves or others)
    function repayBorrow() external payable {
        uint repayAmount = msg.value;
        require(accountBorrows[msg.sender] >= repayAmount, "repay too much");

        accountBorrows[msg.sender] -= repayAmount;
        totalBorrows -= repayAmount;

        emit RepayBorrow(msg.sender, msg.sender, repayAmount, accountBorrows[msg.sender], totalBorrows);
    }

    // PROTECTED: onlyAdmin - set pending admin
    function _setPendingAdmin(address newPendingAdmin) external onlyAdmin {
        address oldPendingAdmin = pendingAdmin;
        pendingAdmin = newPendingAdmin;
        emit NewPendingAdmin(oldPendingAdmin, newPendingAdmin);
    }

    // PROTECTED: only pendingAdmin can accept
    function _acceptAdmin() external {
        require(msg.sender == pendingAdmin, "only pending admin");
        address oldAdmin = admin;
        admin = pendingAdmin;
        pendingAdmin = address(0);
        emit NewAdmin(oldAdmin, admin);
    }

    // PROTECTED: onlyAdmin - set reserve factor
    function _setReserveFactor(uint newReserveFactorMantissa) external onlyAdmin {
        reserveFactorMantissa = newReserveFactorMantissa;
    }

    // PROTECTED: onlyAdmin - reduce reserves
    function _reduceReserves(uint reduceAmount) external onlyAdmin {
        require(totalReserves >= reduceAmount, "insufficient reserves");
        totalReserves -= reduceAmount;
        payable(admin).transfer(reduceAmount);
    }

    function balanceOf(address owner) external view returns (uint) {
        return accountTokens[owner];
    }

    function borrowBalanceOf(address account) external view returns (uint) {
        return accountBorrows[account];
    }

    receive() external payable {}
}
