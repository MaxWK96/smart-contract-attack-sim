#!/usr/bin/env python3
"""Test safe contracts to verify zero false positives."""

import json
import urllib.request
import urllib.error

API_URL = "http://localhost:3000/api/analyze"

SAFE_CONTRACTS = {
    "1. ReentrancyGuard": '''// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

abstract contract ReentrancyGuard {
    uint256 private constant _NOT_ENTERED = 1;
    uint256 private constant _ENTERED = 2;
    uint256 private _status;
    constructor() { _status = _NOT_ENTERED; }
    modifier nonReentrant() {
        require(_status != _ENTERED, "ReentrancyGuard: reentrant call");
        _status = _ENTERED;
        _;
        _status = _NOT_ENTERED;
    }
}

contract SafeVault is ReentrancyGuard {
    mapping(address => uint256) public balances;

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    function withdraw() external nonReentrant {
        uint256 bal = balances[msg.sender];
        balances[msg.sender] = 0;
        (bool success, ) = msg.sender.call{value: bal}("");
        require(success);
    }
}''',

    "2. onlyOwner": '''// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract OwnedContract {
    address public owner;

    constructor() {
        owner = msg.sender;
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "Not owner");
        _;
    }

    function withdrawAll(address to) external onlyOwner {
        payable(to).transfer(address(this).balance);
    }

    function setOwner(address newOwner) external onlyOwner {
        owner = newOwner;
    }
}''',

    "3. Checked calls": '''// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract CheckedCalls {
    address public owner;

    constructor() {
        owner = msg.sender;
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "Not owner");
        _;
    }

    function sendEther(address to, uint256 amount) external onlyOwner {
        (bool success, ) = to.call{value: amount}("");
        require(success, "Transfer failed");
    }

    function sendWithSend(address payable to, uint256 amount) external onlyOwner {
        bool success = to.send(amount);
        require(success, "Send failed");
    }
}''',

    "4. Protected selfdestruct": '''// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract ProtectedDestruct {
    address public owner;

    constructor() {
        owner = msg.sender;
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "Not owner");
        _;
    }

    function destroy() external onlyOwner {
        selfdestruct(payable(owner));
    }
}''',

    "5. CEI pattern": '''// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract CEIVault {
    mapping(address => uint256) public balances;

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    function withdraw() external {
        uint256 bal = balances[msg.sender];
        require(bal > 0, "No balance");
        balances[msg.sender] = 0;  // Effect BEFORE interaction
        (bool success, ) = msg.sender.call{value: bal}("");
        require(success);
    }
}''',

    "6. Safe delegatecall": '''// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract SafeDelegatecall {
    address public owner;
    address public implementation;

    constructor(address impl) {
        owner = msg.sender;
        implementation = impl;
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "Not owner");
        _;
    }

    function upgradeImplementation(address newImpl) external onlyOwner {
        require(newImpl != address(0), "Invalid address");
        implementation = newImpl;
    }

    function execute(bytes calldata data) external onlyOwner {
        (bool success, ) = implementation.delegatecall(data);
        require(success, "Delegatecall failed");
    }
}''',

    "7. Ownable (OZ style)": '''// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

abstract contract Ownable {
    address private _owner;

    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);

    constructor() {
        _owner = msg.sender;
        emit OwnershipTransferred(address(0), msg.sender);
    }

    function owner() public view returns (address) {
        return _owner;
    }

    modifier onlyOwner() {
        require(owner() == msg.sender, "Ownable: caller is not the owner");
        _;
    }

    function transferOwnership(address newOwner) public onlyOwner {
        require(newOwner != address(0), "Ownable: new owner is the zero address");
        emit OwnershipTransferred(_owner, newOwner);
        _owner = newOwner;
    }
}

contract Treasury is Ownable {
    function withdraw(address to, uint256 amount) external onlyOwner {
        payable(to).transfer(amount);
    }
}''',

    "8. AccessControl (OZ style)": '''// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract AccessControlled {
    bytes32 public constant ADMIN_ROLE = keccak256("ADMIN_ROLE");
    bytes32 public constant WITHDRAWER_ROLE = keccak256("WITHDRAWER_ROLE");

    mapping(bytes32 => mapping(address => bool)) private _roles;

    constructor() {
        _roles[ADMIN_ROLE][msg.sender] = true;
        _roles[WITHDRAWER_ROLE][msg.sender] = true;
    }

    modifier onlyRole(bytes32 role) {
        require(_roles[role][msg.sender], "AccessControl: missing role");
        _;
    }

    function grantRole(bytes32 role, address account) external onlyRole(ADMIN_ROLE) {
        _roles[role][account] = true;
    }

    function withdraw(address to, uint256 amount) external onlyRole(WITHDRAWER_ROLE) {
        payable(to).transfer(amount);
    }
}''',

    "9. Pull-over-push": '''// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract PullPayment {
    mapping(address => uint256) public pendingWithdrawals;

    function pay(address recipient, uint256 amount) internal {
        pendingWithdrawals[recipient] += amount;
    }

    function withdraw() external {
        uint256 amount = pendingWithdrawals[msg.sender];
        require(amount > 0, "Nothing to withdraw");
        pendingWithdrawals[msg.sender] = 0;
        payable(msg.sender).transfer(amount);
    }
}''',

    "10. Timelock admin": '''// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract TimelockAdmin {
    address public owner;
    address public pendingOwner;
    uint256 public ownershipTransferTime;
    uint256 public constant TIMELOCK_DELAY = 2 days;

    constructor() {
        owner = msg.sender;
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "Not owner");
        _;
    }

    function proposeNewOwner(address newOwner) external onlyOwner {
        pendingOwner = newOwner;
        ownershipTransferTime = block.timestamp + TIMELOCK_DELAY;
    }

    function acceptOwnership() external {
        require(msg.sender == pendingOwner, "Not pending owner");
        require(block.timestamp >= ownershipTransferTime, "Timelock not expired");
        owner = pendingOwner;
        pendingOwner = address(0);
    }

    function emergencyWithdraw(address to) external onlyOwner {
        payable(to).transfer(address(this).balance);
    }
}'''
}

def test_contract(name, code):
    """Test a single contract and return results."""
    data = json.dumps({"code": code}).encode('utf-8')
    req = urllib.request.Request(
        API_URL,
        data=data,
        headers={'Content-Type': 'application/json'}
    )

    try:
        with urllib.request.urlopen(req, timeout=30) as response:
            result = json.loads(response.read().decode('utf-8'))
            total = result.get('summary', {}).get('total', 0)
            vulns = result.get('vulnerabilities', [])
            return total, vulns
    except urllib.error.URLError as e:
        return -1, [f"Error: {e}"]
    except Exception as e:
        return -1, [f"Error: {e}"]

def main():
    print("=" * 60)
    print("SAFE CONTRACT FALSE POSITIVE TEST SUITE")
    print("=" * 60)
    print()

    passed = 0
    failed = 0

    for name, code in SAFE_CONTRACTS.items():
        total, vulns = test_contract(name, code)

        if total == 0:
            print(f"[PASS] {name}: 0 vulnerabilities")
            passed += 1
        elif total == -1:
            print(f"[ERROR] {name}: {vulns[0]}")
            failed += 1
        else:
            print(f"[FAIL] {name}: {total} vulnerabilities found")
            for v in vulns:
                if isinstance(v, dict):
                    print(f"       - {v.get('type', 'unknown')}: {v.get('title', 'no title')}")
                    print(f"         Location: line {v.get('location', {}).get('line', '?')}")
                else:
                    print(f"       - {v}")
            failed += 1
        print()

    print("=" * 60)
    print(f"RESULTS: {passed} passed, {failed} failed")
    print("=" * 60)

    if failed == 0:
        print("\nSUCCESS: Zero false positives!")
    else:
        print(f"\nFAILURE: {failed} false positive(s) to fix")

if __name__ == "__main__":
    main()
