#!/usr/bin/env python3
"""
Proxy Contract False Positive Test Suite
Tests that proxy contracts with custom access control are NOT flagged.
"""

import json
import urllib.request
import urllib.error
from datetime import datetime

API_URL = "http://localhost:3000/api/analyze"

# =============================================================================
# USDC AdminUpgradeabilityProxy Pattern
# Uses ifAdmin modifier that routes non-admin calls to fallback
# =============================================================================
USDC_PROXY = '''// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * USDC-style AdminUpgradeabilityProxy
 * The ifAdmin modifier routes admin calls to admin functions,
 * and non-admin calls to the fallback (implementation)
 */
contract AdminUpgradeabilityProxy {
    bytes32 private constant ADMIN_SLOT = keccak256("org.zeppelinos.proxy.admin");
    bytes32 private constant IMPLEMENTATION_SLOT = keccak256("org.zeppelinos.proxy.implementation");

    constructor(address _logic, address _admin, bytes memory _data) payable {
        _setAdmin(_admin);
        _setImplementation(_logic);
        if (_data.length > 0) {
            (bool success, ) = _logic.delegatecall(_data);
            require(success);
        }
    }

    // Internal admin getter
    function _admin() internal view returns (address adm) {
        bytes32 slot = ADMIN_SLOT;
        assembly {
            adm := sload(slot)
        }
    }

    function _setAdmin(address newAdmin) internal {
        bytes32 slot = ADMIN_SLOT;
        assembly {
            sstore(slot, newAdmin)
        }
    }

    function _implementation() internal view returns (address impl) {
        bytes32 slot = IMPLEMENTATION_SLOT;
        assembly {
            impl := sload(slot)
        }
    }

    function _setImplementation(address newImplementation) internal {
        bytes32 slot = IMPLEMENTATION_SLOT;
        assembly {
            sstore(slot, newImplementation)
        }
    }

    /**
     * ifAdmin modifier - KEY PATTERN
     * Routes admin calls to admin functions, non-admin calls to fallback
     * This IS access control - admin functions are protected!
     */
    modifier ifAdmin() {
        if (msg.sender == _admin()) {
            _;
        } else {
            _fallback();
        }
    }

    // PROTECTED by ifAdmin - only admin can call
    function changeAdmin(address newAdmin) external ifAdmin {
        require(newAdmin != address(0), "Cannot change admin to zero");
        _setAdmin(newAdmin);
    }

    // PROTECTED by ifAdmin - only admin can call
    function upgradeTo(address newImplementation) external ifAdmin {
        _setImplementation(newImplementation);
    }

    // PROTECTED by ifAdmin - only admin can call
    function upgradeToAndCall(address newImplementation, bytes calldata data) external payable ifAdmin {
        _setImplementation(newImplementation);
        (bool success, ) = newImplementation.delegatecall(data);
        require(success);
    }

    function _fallback() internal {
        address impl = _implementation();
        assembly {
            calldatacopy(0, 0, calldatasize())
            let result := delegatecall(gas(), impl, 0, calldatasize(), 0, 0)
            returndatacopy(0, 0, returndatasize())
            switch result
            case 0 { revert(0, returndatasize()) }
            default { return(0, returndatasize()) }
        }
    }

    fallback() external payable {
        _fallback();
    }

    receive() external payable {
        _fallback();
    }
}'''

# =============================================================================
# OpenZeppelin TransparentUpgradeableProxy Pattern
# =============================================================================
OZ_TRANSPARENT_PROXY = '''// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * OpenZeppelin-style TransparentUpgradeableProxy
 * Admin functions protected by ifAdmin modifier
 */
contract TransparentUpgradeableProxy {
    bytes32 internal constant _ADMIN_SLOT = 0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103;
    bytes32 internal constant _IMPLEMENTATION_SLOT = 0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc;

    constructor(address _logic, address admin_, bytes memory _data) payable {
        _changeAdmin(admin_);
        _upgradeTo(_logic);
        if (_data.length > 0) {
            (bool success, ) = _logic.delegatecall(_data);
            require(success);
        }
    }

    function _getAdmin() internal view returns (address) {
        return _getAddressSlot(_ADMIN_SLOT);
    }

    function _getImplementation() internal view returns (address) {
        return _getAddressSlot(_IMPLEMENTATION_SLOT);
    }

    function _getAddressSlot(bytes32 slot) internal view returns (address result) {
        assembly {
            result := sload(slot)
        }
    }

    function _setAddressSlot(bytes32 slot, address value) internal {
        assembly {
            sstore(slot, value)
        }
    }

    function _changeAdmin(address newAdmin) internal {
        _setAddressSlot(_ADMIN_SLOT, newAdmin);
    }

    function _upgradeTo(address newImplementation) internal {
        _setAddressSlot(_IMPLEMENTATION_SLOT, newImplementation);
    }

    /**
     * ifAdmin modifier - routes based on msg.sender
     */
    modifier ifAdmin() {
        if (msg.sender == _getAdmin()) {
            _;
        } else {
            _fallback();
        }
    }

    // PROTECTED by ifAdmin
    function admin() external ifAdmin returns (address) {
        return _getAdmin();
    }

    // PROTECTED by ifAdmin
    function implementation() external ifAdmin returns (address) {
        return _getImplementation();
    }

    // PROTECTED by ifAdmin
    function changeAdmin(address newAdmin) external ifAdmin {
        _changeAdmin(newAdmin);
    }

    // PROTECTED by ifAdmin
    function upgradeTo(address newImplementation) external ifAdmin {
        _upgradeTo(newImplementation);
    }

    // PROTECTED by ifAdmin
    function upgradeToAndCall(address newImplementation, bytes calldata data) external payable ifAdmin {
        _upgradeTo(newImplementation);
        (bool success, ) = newImplementation.delegatecall(data);
        require(success);
    }

    function _fallback() internal {
        address impl = _getImplementation();
        assembly {
            calldatacopy(0, 0, calldatasize())
            let result := delegatecall(gas(), impl, 0, calldatasize(), 0, 0)
            returndatacopy(0, 0, returndatasize())
            switch result
            case 0 { revert(0, returndatasize()) }
            default { return(0, returndatasize()) }
        }
    }

    fallback() external payable {
        _fallback();
    }

    receive() external payable {
        _fallback();
    }
}'''

# =============================================================================
# UUPS Proxy Pattern
# =============================================================================
UUPS_PROXY = '''// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * UUPS (Universal Upgradeable Proxy Standard) Pattern
 * Upgrade logic is in the implementation, not proxy
 */
contract UUPSProxy {
    bytes32 internal constant _IMPLEMENTATION_SLOT = 0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc;

    constructor(address _logic, bytes memory _data) payable {
        _setImplementation(_logic);
        if (_data.length > 0) {
            (bool success, ) = _logic.delegatecall(_data);
            require(success);
        }
    }

    function _getImplementation() internal view returns (address impl) {
        assembly {
            impl := sload(_IMPLEMENTATION_SLOT)
        }
    }

    function _setImplementation(address newImplementation) internal {
        assembly {
            sstore(_IMPLEMENTATION_SLOT, newImplementation)
        }
    }

    function _fallback() internal {
        address impl = _getImplementation();
        assembly {
            calldatacopy(0, 0, calldatasize())
            let result := delegatecall(gas(), impl, 0, calldatasize(), 0, 0)
            returndatacopy(0, 0, returndatasize())
            switch result
            case 0 { revert(0, returndatasize()) }
            default { return(0, returndatasize()) }
        }
    }

    fallback() external payable {
        _fallback();
    }

    receive() external payable {
        _fallback();
    }
}'''

# =============================================================================
# Beacon Proxy Pattern
# =============================================================================
BEACON_PROXY = '''// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

interface IBeacon {
    function implementation() external view returns (address);
}

/**
 * Beacon Proxy Pattern
 * Gets implementation from a beacon contract
 */
contract BeaconProxy {
    bytes32 internal constant _BEACON_SLOT = 0xa3f0ad74e5423aebfd80d3ef4346578335a9a72aeaee59ff6cb3582b35133d50;

    constructor(address beacon, bytes memory data) payable {
        _setBeacon(beacon);
        if (data.length > 0) {
            address impl = IBeacon(beacon).implementation();
            (bool success, ) = impl.delegatecall(data);
            require(success);
        }
    }

    function _getBeacon() internal view returns (address beacon) {
        assembly {
            beacon := sload(_BEACON_SLOT)
        }
    }

    function _setBeacon(address newBeacon) internal {
        assembly {
            sstore(_BEACON_SLOT, newBeacon)
        }
    }

    function _implementation() internal view returns (address) {
        return IBeacon(_getBeacon()).implementation();
    }

    function _fallback() internal {
        address impl = _implementation();
        assembly {
            calldatacopy(0, 0, calldatasize())
            let result := delegatecall(gas(), impl, 0, calldatasize(), 0, 0)
            returndatacopy(0, 0, returndatasize())
            switch result
            case 0 { revert(0, returndatasize()) }
            default { return(0, returndatasize()) }
        }
    }

    fallback() external payable {
        _fallback();
    }

    receive() external payable {
        _fallback();
    }
}'''

# =============================================================================
# Custom onlyAdmin pattern (explicit require check)
# =============================================================================
CUSTOM_ADMIN_PATTERN = '''// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * Contract using custom admin check with require
 */
contract CustomAdminContract {
    address public admin;
    address public implementation;

    constructor() {
        admin = msg.sender;
    }

    modifier onlyAdmin() {
        require(msg.sender == admin, "Not admin");
        _;
    }

    // PROTECTED by onlyAdmin
    function changeAdmin(address newAdmin) external onlyAdmin {
        admin = newAdmin;
    }

    // PROTECTED by onlyAdmin
    function setImplementation(address newImpl) external onlyAdmin {
        implementation = newImpl;
    }

    // PROTECTED by onlyAdmin
    function withdrawAll(address to) external onlyAdmin {
        payable(to).transfer(address(this).balance);
    }

    receive() external payable {}
}'''

# =============================================================================
# If-statement guard pattern
# =============================================================================
IF_GUARD_PATTERN = '''// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/**
 * Contract using if-statement guard for access control
 */
contract IfGuardContract {
    address public owner;
    uint256 public value;

    constructor() {
        owner = msg.sender;
    }

    // PROTECTED by if-statement guard
    function setOwner(address newOwner) external {
        if (msg.sender != owner) {
            revert("Not owner");
        }
        owner = newOwner;
    }

    // PROTECTED by if-statement guard
    function withdrawAll(address to) external {
        if (msg.sender != owner) {
            revert("Not owner");
        }
        payable(to).transfer(address(this).balance);
    }

    // PROTECTED by if-statement guard (inverted logic)
    function setValue(uint256 newValue) external {
        if (msg.sender == owner) {
            value = newValue;
        } else {
            revert("Not owner");
        }
    }

    receive() external payable {}
}'''

PROXY_CONTRACTS = [
    ("USDC AdminUpgradeabilityProxy", USDC_PROXY),
    ("OpenZeppelin TransparentUpgradeableProxy", OZ_TRANSPARENT_PROXY),
    ("UUPS Proxy", UUPS_PROXY),
    ("Beacon Proxy", BEACON_PROXY),
    ("Custom onlyAdmin Pattern", CUSTOM_ADMIN_PATTERN),
    ("If-statement Guard Pattern", IF_GUARD_PATTERN),
]


def test_contract(name, code):
    """Test a single contract and return results."""
    data = json.dumps({"code": code}).encode('utf-8')
    req = urllib.request.Request(
        API_URL,
        data=data,
        headers={'Content-Type': 'application/json'}
    )

    try:
        with urllib.request.urlopen(req, timeout=60) as response:
            result = json.loads(response.read().decode('utf-8'))
            total = result.get('summary', {}).get('total', 0)
            vulns = result.get('vulnerabilities', [])
            return total, vulns
    except urllib.error.URLError as e:
        return -1, [f"Error: {e}"]
    except Exception as e:
        return -1, [f"Error: {e}"]


def main():
    print("=" * 70)
    print("PROXY CONTRACT FALSE POSITIVE TEST SUITE")
    print(f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 70)
    print()

    passed = 0
    failed = 0

    for name, code in PROXY_CONTRACTS:
        total, vulns = test_contract(name, code)

        if total == 0:
            print(f"[PASS] {name}: 0 vulnerabilities")
            passed += 1
        elif total == -1:
            print(f"[ERROR] {name}: {vulns[0]}")
            failed += 1
        else:
            print(f"[FAIL] {name}: {total} vulnerabilities found (FALSE POSITIVES)")
            for v in vulns:
                if isinstance(v, dict):
                    print(f"       - {v.get('type', 'unknown')}: {v.get('title', 'no title')}")
                    print(f"         Line {v.get('location', {}).get('line', '?')}, Confidence: {v.get('confidence', '?')}")
                else:
                    print(f"       - {v}")
            failed += 1
        print()

    print("=" * 70)
    print(f"RESULTS: {passed} passed, {failed} failed")
    print("=" * 70)

    if failed == 0:
        print("\nSUCCESS: Zero false positives on proxy contracts!")
    else:
        print(f"\nFAILURE: {failed} false positive(s) to fix")

    return failed == 0


if __name__ == "__main__":
    success = main()
    exit(0 if success else 1)
